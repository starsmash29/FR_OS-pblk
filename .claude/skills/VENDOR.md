# Vendored skills

These skills are copied from third-party libraries, not written for FR_OS.
They give any contributor (person or agent) working in this repo reference
playbooks for the defensive security work the ROADMAP calls for.

Skills live here, in the repository, because a cloud Claude Code session
loads `.claude/skills/` from the clone but does **not** install plugins that
`.claude/settings.json` enables. Skills that need their upstream scripts to
work are therefore not vendored; they are offered as pinned plugins instead
(see "Plugins" below).

## Rules for everything here

- **Prose only.** Each skill's `SKILL.md` and its Markdown references, plus
  the upstream licence file. No `scripts/`, hooks, agents or binaries:
  third-party code is not carried in this repo, the same supply-chain risk
  `generating-and-analyzing-sboms` and `verifying-build-provenance-with-slsa-sigstore`
  warn against. If a skill's workflow is worth automating for FR_OS, write it
  as a reviewed `frfw` module with tests, per AGENTS.md.
- **Pinned and read.** Every file was read before it was committed, at the
  commit named below. Vendored prose is still untrusted third-party text.
- **Nothing installs unpinned.** A skill that tells the agent to install a
  tool names an exact version. One known exception remains:
  `generating-and-analyzing-sboms` still shows Syft's and Grype's
  `curl … | sh` installers from upstream. Don't follow those lines; install a
  pinned release instead.
- `tests/test_claude_skills.py` checks these rules.

## Sources

| Skills | Repository | Commit | Licence |
|---|---|---|---|
| the five `mukul975` skills listed below | https://github.com/mukul975/anthropic-cybersecurity-skills | `54a798831d2266a3ca61ce68a7acb80b81160d57` (2026-08-31) | Apache-2.0 (`LICENSE` in this directory) |
| `owasp-security` | https://github.com/agamm/claude-code-owasp (`.claude/skills/owasp-security`) | `8ac7965caa212b4a850aff8d3df0081ab3fa9eed` (2026-09-24) | MIT (`owasp-security/LICENSE`) |
| `vibesec` | https://github.com/BehiSecc/VibeSec-Skill | `0590993b35ad51961f65a4d01cf1196dfead05bb` (2026-02-17) | Apache-2.0 (`vibesec/LICENSE`) |
| `property-based-testing`, `agentic-actions-auditor` | https://github.com/trailofbits/skills (`plugins/<name>/skills/<name>`) | `442fc9d6c89b1e937e6f7a477e7071ea75fcbea4` (2026-10-09) | CC-BY-SA-4.0 (`LICENSE` in each directory); copied unmodified |
| `agnix` | https://github.com/agent-sh/agnix (`plugin/skills/agnix`) | `004b7ea143de549c13e89614fd73be0497abbdd0` (2026-10-09) | MIT (`agnix/LICENSE`) |

The `mukul975` library is **not affiliated with Anthropic**; the "anthropic"
in its name is the author's, not an endorsement.

Changes from upstream:
- `vibesec/SKILL.md`: `name: VibeSec-Skill` became `name: vibesec`, so the
  name matches the directory and the lowercase-and-hyphens rule for skill names.
- `agnix/SKILL.md`: the install step named an unpinned `npm install -g agnix`;
  it now names `agnix@0.57.0`, the release the reviewed commit ships. The
  release binaries are built without the `telemetry` Cargo feature, and
  telemetry is opt-in even when compiled in, so the linter sends nothing.

## The skills, and why each is here

| Skill | Relevance to FR_OS |
|---|---|
| `hardening-linux-endpoint-with-cis-benchmark` | Baseline for the router image's own hardening (sysctl, auditd, SSH, OpenSCAP). Note: some of its generic sysctl advice is host-oriented (e.g. `ip_forward=0`); a router forwards by design, so apply it with judgement. |
| `implementing-ebpf-security-monitoring` | Background for the XDP/eBPF work (`bpf/`, `frfw.xdp`), and a reference if runtime process/syscall monitoring is ever added. |
| `implementing-network-segmentation-with-firewall-zones` | Zone and inter-zone policy design, relevant to `frfw.nft.builder` and `frfw.segments` (SEC-16, NET-*). Switch-vendor syntax is illustrative, not what FR_OS emits. |
| `verifying-build-provenance-with-slsa-sigstore` | Supply-chain verification, relevant to the release-signing path (`frfw.release_signing`) and FND-3 / KEY-* / SEC-15. |
| `generating-and-analyzing-sboms` | SBOM and CVE correlation, relevant to the hash-locked dependency work (`requirements.lock`) and supply-chain items. |
| `owasp-security` | Security review of the FastAPI webUI (`frfw.webui`) against OWASP Top 10:2025 and ASVS 5.0. It asks for a reachable path before a finding is reported, which keeps reviews free of pattern-match noise. |
| `vibesec` | Secure-coding checklist for web code (CSRF, SSRF, open redirect, path traversal, uploads). Overlaps `owasp-security`; some advice (`.env` secrets, JS examples) is generic web-app advice, not FR_OS practice. |
| `property-based-testing` | Hypothesis tests for parsers and validators: `frfw.validate`, the config loader, the ruleset builder's input handling. |
| `agentic-actions-auditor` | Review of `.github/workflows/` wherever an AI agent runs in CI. |
| `agnix` | Lints `AGENTS.md`, `CLAUDE.md` and the skills in this directory. A developer tool; nothing of it goes on the router. |

The `mukul975` library also carries offensive/dual-use skills (e.g. a VLAN
double-tagging attack tool). Those were deliberately not vendored: this repo
is public and its contributor guide is defensive. If an authorized test of
FR_OS's own VLAN segmentation is ever needed, the defensive counterpart lives
in `implementing-network-segmentation-with-firewall-zones` and the real
on-the-wire coverage is in `tests/test_xdp_live.py` (SEC-16).

## Plugins (local sessions only)

`.claude/settings.json` declares an inline marketplace, `fr-os-reviewed`, and
enables six Trail of Bits plugins from it, each pinned to the reviewed commit
`442fc9d6c89b1e937e6f7a477e7071ea75fcbea4` by `sha`. These need their
upstream scripts or subagents, so they are plugins rather than vendored prose:

| Plugin | Use in FR_OS | Note |
|---|---|---|
| `static-analysis` | Semgrep and CodeQL over `src/frfw/`, SARIF output | Needs `semgrep` / `codeql` installed at a pinned version. Its scan script always passes `--metrics=off`. |
| `insecure-defaults` | Fail-open defaults, fallback secrets, debug features | Runs as a multi-agent workflow, so one run can cost many tokens. |
| `sharp-edges` | Footgun APIs and dangerous config in Python and C | Uses its `sharp-edges-analyzer` agent. |
| `differential-review` | Security review of a PR or diff | Uses its `adversarial-modeler` agent. |
| `c-review` | The XDP programs in `bpf/` | Local Python scripts, no network. |
| `supply-chain-risk-auditor` | Risk of the dependencies in `requirements.lock` | Sends package names and versions to public APIs (OSV, PyPI, deps.dev, GitHub, OpenSSF Scorecard) and runs `pip-audit`; reads a `gh` token if one exists and sends it only to api.github.com. A developer-machine tool; G11 concerns the router. |

Enabling a plugin in a project file does not install it: each person installs
it once with `/plugin install <name>@fr-os-reviewed`, after trusting the
folder. Cloud sessions do not install project plugins at all.

Deliberately **not** offered, though in the same Trail of Bits repository:
`modern-python` (its SessionStart hook puts shims on `PATH` that refuse
`pip install` and `python3 script.py`, which breaks the `pip` /
`requirements.lock` workflow of docs/RELEASING.md) and `gh-cli` (it
intercepts GitHub fetches and forces the `gh` CLI, which cloud sessions do
not have).

## Updating

Re-copy from a newer upstream commit, read every changed file, and update
the commit in the table above (and the `sha` in `.claude/settings.json` for
plugins). Keep leaving out scripts.
