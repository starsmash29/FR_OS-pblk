# Vendored skills

These skills are copied from a third-party library, not written for FR_OS.
They give any contributor (person or agent) working in this repo reference
playbooks for the defensive security work the ROADMAP calls for.

## Source

- **Repository:** https://github.com/mukul975/anthropic-cybersecurity-skills
- **Commit:** `54a798831d2266a3ca61ce68a7acb80b81160d57` (2026-08-31)
- **License:** Apache-2.0 (see `LICENSE` in this directory; each `SKILL.md`
  keeps its upstream `author` and `license` frontmatter).
- **Not affiliated with Anthropic.** It is an independent community project,
  as its own README states. The "anthropic" in the name is the author's, not
  an endorsement.

## What was taken, and what was left out

Only the prose was vendored: each skill's `SKILL.md`, its `references/`, and
`assets/` where present. The upstream `scripts/` directories (an `agent.py`
per skill, plus helpers) were **not** copied. We treat these as written
guidance to read, not code to run: the scripts are unreviewed third-party
Python, some of them install software from the network (`helm repo add`,
`curl ... | ...`), which would be a supply-chain risk to carry in this repo
(the very thing `generating-and-analyzing-sboms` and
`verifying-build-provenance-with-slsa-sigstore` warn against). If a skill's
workflow is worth automating for FR_OS, write it as a reviewed `frfw` module
with tests, per AGENTS.md — don't run the upstream script.

## The skills, and why each is here

| Skill | Relevance to FR_OS |
|---|---|
| `hardening-linux-endpoint-with-cis-benchmark` | Baseline for the router image's own hardening (sysctl, auditd, SSH, OpenSCAP). Note: some of its generic sysctl advice is host-oriented (e.g. `ip_forward=0`); a router forwards by design, so apply it with judgement. |
| `implementing-ebpf-security-monitoring` | Background for the XDP/eBPF work (`bpf/`, `frfw.xdp`), and a reference if runtime process/syscall monitoring is ever added. |
| `implementing-network-segmentation-with-firewall-zones` | Zone and inter-zone policy design, relevant to `frfw.nft.builder` and `frfw.segments` (SEC-16, NET-*). Switch-vendor syntax is illustrative, not what FR_OS emits. |
| `verifying-build-provenance-with-slsa-sigstore` | Supply-chain verification, relevant to the release-signing path (`frfw.release_signing`) and FND-3 / KEY-* / SEC-15. |
| `generating-and-analyzing-sboms` | SBOM and CVE correlation, relevant to the hash-locked dependency work (`requirements.lock`) and supply-chain items. |

The upstream library also carries offensive/dual-use skills (e.g. a VLAN
double-tagging attack tool). Those were deliberately not vendored: this repo
is public and its contributor guide is defensive. If an authorized test of
FR_OS's own VLAN segmentation is ever needed, the defensive counterpart lives
in `implementing-network-segmentation-with-firewall-zones` and the real
on-the-wire coverage is in `tests/test_xdp_live.py` (SEC-16).

## Updating

Re-copy from a newer upstream commit and update the commit hash above. Keep
leaving out `scripts/`. Read anything new before committing it — vendored
prose is still untrusted third-party text.
