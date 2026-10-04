# Releasing FR_OS

A router installs an update only if the release is signed with a key it
trusts (`frfw.release_signing`; review triage A4). Each release carries:

| Asset | What it is |
|---|---|
| `FR_OS-<version>-amd64.iso` | the installer / live image |
| `frfw-<version>.tar.gz` | the source (`git archive` of the tagged commit) plus the compiled XDP program at `bpf/xdp_sni_filter.o` (ROADMAP P4-1) — what the updater installs |
| `SHA256SUMS` | sha256 of both |
| `SHA256SUMS.sig` | Ed25519 signature over `SHA256SUMS` |

The updater downloads the tarball, `SHA256SUMS` and the signature,
checks the signature against the public keys in `src/frfw/release_keys/`
of the version *already installed*, checks the tarball against the
signed checksum, and only then extracts and installs it. It checks again
when it reuses a cached copy (rollback).

## One-time setup: the signing key

Do this on your own machine, not in CI, and keep the private key offline.

```bash
openssl genpkey -algorithm ed25519 -out fros-release.key
chmod 600 fros-release.key
openssl pkey -in fros-release.key -pubout -out src/frfw/release_keys/fros-release-1.pem
```

1. Commit `src/frfw/release_keys/fros-release-1.pem` (the **public** key).
2. In GitHub: *Settings → Secrets and variables → Actions → New repository
   secret*, name `FROS_RELEASE_SIGNING_KEY`, value: the whole content of
   `fros-release.key` (the **private** key, including the BEGIN/END lines).
3. Store `fros-release.key` somewhere safe (password manager, offline
   backup). Anyone who has it can publish updates that every router
   installs as root.

Until a public key is committed, every build refuses every update — that
is on purpose.

## Before tagging: the adversarial review (J2)

Every release is reviewed by at least two different AI models before it
is tagged (security-lessons J2); one model's blind spots are rarely
another's.

1. Pick the commit you mean to release and run
   [review-prompt.md](review-prompt.md) against it with each model. Save
   each report as `docs/reviews/v<VERSION>-<MODEL>.md`.
2. Triage the reports into one record, `docs/reviews/v<VERSION>.md`,
   starting from [reviews/TEMPLATE.md](reviews/TEMPLATE.md): the
   reviewed commit, the models, and one table row per distinct finding
   with its severity and status. Check each finding against the code the
   way [review-triage.md](review-triage.md) did -- reviews overstate and
   miss things.
3. Close every **critical** and **high** finding: `fixed` (with the
   commit or PR), `accepted` (with the reason), `not a bug` or
   `duplicate`. Medium and low findings may stay open as issues.
4. Merge the record to `main` with the version bump.

The release workflow enforces this: before it builds anything it runs
`scripts/check_release_review.py <VERSION>`, which refuses the release
when the record is missing, names fewer than two models, reviewed a
commit that isn't part of this release or is older than the previous
release, or still has an open critical/high finding. Run it locally
first:

```bash
python3 scripts/check_release_review.py 0.3.0
```

## Dependencies: requirements.lock

The router installs its Python dependencies only from `requirements.lock`
(review FR-001): exact versions, the sha256 of every release file, wheels
only, installed with `pip --require-hashes` by both the image build and
the updater; frfw itself is then installed with `--no-deps
--no-build-isolation`, so nothing unpinned comes from PyPI. The lock
travels inside the signed source tarball.

To change a dependency, edit `pyproject.toml`, run the tests against the
new versions, and regenerate the lock from that environment:

```bash
pip freeze > /tmp/tested.txt
scripts/lock-requirements.sh /tmp/tested.txt
```

Review the diff of `requirements.lock` like code: it is what runs as root.

## Publishing a release

1. Bump `__version__` in `src/frfw/__init__.py` and `version` in
   `pyproject.toml`, and merge it to `main` together with the review
   record (above).
2. Create the GitHub release with its tag (`vX.Y.Z`) on that commit.
3. Run the *Build installer ISO* workflow on `main` with `release_tag` =
   `vX.Y.Z`. It checks the review record, builds the ISO, packages the
   source, writes `SHA256SUMS`, signs it, checks that the signing key's
   public half is one this commit ships, boot-tests the ISO and uploads
   all four assets.
   Without the `FROS_RELEASE_SIGNING_KEY` secret it refuses to publish.

Users can check a download the same way:

```bash
openssl pkeyutl -verify -pubin -inkey fros-release-1.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum -c --ignore-missing SHA256SUMS
```

## Security releases

A release that fixes a vulnerability must say so, so routers can tell
(security-lessons G10/J3): put **`[security]` in the release title**
(for example `v0.3.1 [security]`), or a line `Security: yes` in its
notes. Routers then show a red "Security update available" banner on
every webUI page, and those with `update.auto_install_security: true`
install it by themselves within about 12 hours -- after verifying its
signature like any other update. Say what was fixed in the notes, and
link the GitHub Security Advisory. The fix-time targets are in
[SECURITY.md](../SECURITY.md).

## Rotating the key

Add the new public key next to the old one and release that build signed
with the **old** key — routers only trust keys they already have. Sign
later releases with the new key, then remove the old public key in a
release after that. If a private key leaks, remove its public key in a
release signed with the other key and publish it immediately.

## Limits

- Releases published before signing existed (v0.1.0) aren't signed, so
  a router refuses to update or roll back *to* them.
- The Python dependencies `pip` pulls for a release still come from PyPI
  unpinned (`>=` floors in `pyproject.toml`).
