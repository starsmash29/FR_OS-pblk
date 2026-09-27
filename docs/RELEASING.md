# Releasing FR_OS

A router installs an update only if the release is signed with a key it
trusts (`frfw.release_signing`; review triage A4). Each release carries:

| Asset | What it is |
|---|---|
| `FR_OS-<version>-amd64.iso` | the installer / live image |
| `frfw-<version>.tar.gz` | the source (`git archive` of the tagged commit) — what the updater installs |
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

## Publishing a release

1. Bump `__version__` in `src/frfw/__init__.py` and `version` in
   `pyproject.toml`, merge to `main`.
2. Create the GitHub release with its tag (`vX.Y.Z`) on that commit.
3. Run the *Build installer ISO* workflow on `main` with `release_tag` =
   `vX.Y.Z`. It builds the ISO, packages the source, writes
   `SHA256SUMS`, signs it, checks that the signing key's public half is
   one this commit ships, boot-tests the ISO and uploads all four assets.
   Without the `FROS_RELEASE_SIGNING_KEY` secret it refuses to publish.

Users can check a download the same way:

```bash
openssl pkeyutl -verify -pubin -inkey fros-release-1.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum -c --ignore-missing SHA256SUMS
```

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
