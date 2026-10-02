# Contributing to FR_OS — for people and AI agents

FR_OS is a Debian-based firewall/router OS. It has an nftables ruleset
generator, privileged helpers behind Unix sockets, a FastAPI webUI, eBPF/XDP
programs and a live-build installer image. This file says how to pick up
work, the rules every change follows, and what "done" means.

These rules apply to every contributor: a person, a coding agent, or an
AI tool working on someone's behalf.

## Start here

| Read | For |
|---|---|
| [ROADMAP.md](ROADMAP.md), section **Planned work** | What is open. Every item has a stable ID (`P4-1`, `SEC-3`, `NET-4`, …) |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the parts fit together, and why |
| [docs/security-lessons.md](docs/security-lessons.md) | The security requirements every feature must meet (IDs like `I1`, `G3`) |
| [docs/reviews/](docs/reviews/) | The latest adversarial review and what is still open from it |
| [docs/CONFIG_SCHEMA.md](docs/CONFIG_SCHEMA.md) | The `config.yaml` schema |
| [DESIGN.md](DESIGN.md) | The webUI design system |
| [docs/stitch-screens.md](docs/stitch-screens.md) | Inventory of the designed screens. Screen names are as the Stitch project has them |
| [SECURITY.md](SECURITY.md) | How vulnerabilities are reported. Never in a public issue or PR |
| [.claude/skills/](.claude/skills/) | Vendored defensive-security reference playbooks (CIS hardening, eBPF monitoring, segmentation, SLSA/Sigstore, SBOM). Guidance to read, not code to run — see `.claude/skills/VENDOR.md` |

## Taking an item

> **External contributions are paused (owner's decision, 2026-10-02).**
> Until this notice is removed, do not open claim issues, branches or pull
> requests. Every open claim issue is marked `hold`; the integrating agent
> (Claude Code) implements the open roadmap items itself. The steps below
> describe how contributions work once the pause is lifted.


1. **Pick an item.** Choose an item from **Planned work** in ROADMAP.md. Its status must be *Planned*, *Extends* or *Partly*, not *Claimed*.
2. **Claim it.** Open an issue using the *Roadmap item* template, titled `<ID>: <short title>`. If an open issue already claims the ID, pick something else or offer to help in that issue.
3. **Propose a design first for large items.** Write a short design in the issue (approach, files, risks) and wait for a reply before writing code. This applies to anything that touches:
   - the privileged helpers (`frfw.helper.*`);
   - the update or signing path (`frfw.update`, `frfw.release_signing`);
   - the ruleset builder's rule order (`frfw.nft.builder`);
   - the installer image, or the boot sequence.
4. **One item per branch and PR.**
   - Branch: `agent/<id>-<slug>`, for example `agent/sec-3-metrics-token`.
   - PR title: `<ID>: <what it does>`, based on `main`.
   - Keep the PR to that item. Mention other problems you notice in the PR, or open a separate issue.

## Ground rules (not negotiable)

**Language and style**
- Everything committed is in **English**: code, comments, docs, commit messages and UI text.
- Match the surrounding code: its comment density, its naming, and its habit of saying *why* (with security-lessons or review IDs) in docstrings.

**Secrets and trust**
- **Never commit a secret**: private keys, tokens, passwords, API keys, real config files.
- `src/frfw/release_keys/` holds **public** keys only.
- Never ask for, generate or handle the release signing key.
- Don't change the signing and review steps of `.github/workflows/build-installer.yml` unless the maintainer asks you to.
- FR_OS stays 100% local: no telemetry, no cloud calls, no vendor login (security-lessons G11). Anything that talks to the internet must be opt-in, and documented in the PR.

**Privilege boundaries** (security-lessons A1, I1)
- The webUI and the network-parsing daemons never run privileged code. Root work goes through the apply-helper (`frfw.helper.server`). Each command is allowed per peer uid in `frfw.helper.peer`. Parser daemons get the short `SENSOR_COMMANDS` list only.
- Every new service gets its own unprivileged account and a full systemd sandbox. List it in `tests/test_systemd_sandbox.py`.
- A service listens only where it is needed and is off unless configured (security-lessons I1, K7).

**Untrusted input**
- Every value that reaches an argv, an nft script or a config file goes through `frfw.validate`, with `--` before positional values (security-lessons F1).
- Regexes use `\Z`, not `$`.

**Dependencies**
- A new Python dependency goes into `pyproject.toml`, and `requirements.lock` is regenerated with `scripts/lock-requirements.sh` (docs/RELEASING.md, "Dependencies").
- Say in the PR why the dependency is needed.
- Never install anything unpinned on the router.

**Tests and history**
- Never weaken, skip, delete or quarantine a test to get green. A failing test is a finding.
- No force-push to shared branches, and no rewriting of others' history.

## Definition of done

A PR is ready for review when all of the following hold.

- **Tests.** Every change comes with tests.
  - Prefer the real thing over mocks: real `nft`, real network namespaces (see `tests/test_iot_isolation.py`), real sockets. Root-only tests skip themselves without root.
  - Run the whole suite, in two separate invocations (mixing them loses the `webui_env` fixture):
    ```bash
    python3 -m pytest tests --ignore=tests/webui -q
    python3 -m pytest tests/webui -q
    ```
  - Shell scripts pass `shellcheck` (`tests/test_installer.py` runs it).
- **Boot test, when it applies.** If the change touches the image, boot, services, networking, the installer or anything that runs at boot, the *Build installer ISO* workflow with `boot_test=true` must pass. When the router gains new behaviour, add a check for it to `installer/qemu-boot-test.py`. If you can't run the workflow, say so in the PR; the integrator runs it.
- **Docs updated.**
  - The item's ROADMAP row: set its Status, and name the modules and tests.
  - ARCHITECTURE.md for design decisions.
  - docs/CONFIG_SCHEMA.md for new config keys.
  - The "Current state" column of docs/security-lessons.md when a security item changes.
- **PR description.** It says:
  - what changed and why;
  - how it was tested, with the commands and results;
  - what is *not* done or not verified.

## Review and merge

Every PR is reviewed by the maintainer's integrating agent (Claude Code), which:
- checks the PR against this file and docs/security-lessons.md;
- runs the full test suite and, where it applies, the boot test;
- asks for changes, or pushes fixes with a merge commit (never a rebase of your branch);
- merges only with the repository owner's approval.

The integrator decides the merge order of overlapping PRs. A PR that falls behind `main` gets `main` merged into it, not rebased.

### Approval flow (how an item gets the go-ahead)

Picking up an item needs the owner's go-ahead, recorded on its **claim
issue**. The `approved` and `hold` labels now exist in the repository and are
the machine-readable signal; the `Mehet` / `Várj` comment says the same thing
in words. Read the label first, the comment as the fallback. Two roles, kept
separate:

- **The owner's integrating agent (Claude Code)** records the owner's
  decision on each claim issue: the label **`approved`** or **`hold`**, or a
  comment **"Mehet"** (go) / **"Várj"** (wait). It is the only actor that
  applies these, and it is the only actor that merges a PR — always after the
  owner's "Mehet", never on its own.
- **The dispatcher agent (JARVIS)** reads the claim issues hourly. It does not
  touch an item marked `hold` / "Várj"; it hands out an item marked
  `approved` / "Mehet". On GitHub it only ever opens claim issues — it does
  **not** merge, close, label, or comment to drive state.

So the lifecycle of an item is: a claim issue is opened (JARVIS or a
contributor) → the integrating agent marks it `approved` or `hold` on the
owner's word → JARVIS dispatches the approved ones → the contributor opens
one PR per item → the integrating agent reviews it (above) and merges it only
after the owner's "Mehet". An item with no mark, or marked `hold`, is not
started.

**Releases are not part of contributions.** Before each release, the maintainer runs an adversarial review with two models and triages it (docs/RELEASING.md, security-lessons J2).

## Repository map

| Path | What |
|---|---|
| `src/frfw/config/` | Config schema, loader and validation |
| `src/frfw/nft/` | Ruleset builder (`build_ruleset`, `RuntimeSets`) and schedules |
| `src/frfw/provision.py` | `apply_all`: the order in which everything is applied |
| `src/frfw/helper/` | Root apply- and update-helpers, protocol and peer policy |
| `src/frfw/webui/` | FastAPI app: routes, templates, auth, MFA |
| `src/frfw/ai_ids/`, `tlsfp/`, `appid/`, `iot/` | Parser daemons (unprivileged, `fr_os-sensor`) |
| `bpf/` | XDP programs (C, verifier-checked) |
| `systemd/` | Units; every one is sandboxed |
| `scripts/` | First boot, system integration, lock file |
| `installer/` | live-build tree, ISO tooling, QEMU boot test |
| `tests/`, `tests/webui/` | Test suites, run separately |

### Local setup
- Python 3.11 and Debian 12 (bookworm) are the targets.
- Install with `pip install -e '.[webui,dev]'`.
- Kernel tests need root and the `nft`, `ip` and `clang` binaries.
