# Research first

Before writing a helper, a parser or a whole module, spend a few minutes
proving it doesn't already exist. FR_OS is large (over a hundred test
files, dozens of modules), and the most common waste is re-implementing
something `frfw` already has, slightly differently.

## In this order

1. **The repo.** Search `src/frfw/` and `tests/` for the concept, not just
   the name: `frfw.validate` for any input checking, `frfw.helper.peer` for
   who may call what, `frfw.nft.builder` for ruleset shape, `provision.py`
   for apply order. A grep for the config key and the systemd unit name
   usually finds the neighbours.
2. **The docs.** ARCHITECTURE.md (search it, it is long), ROADMAP.md for an
   item that already covers this, `docs/reviews/` for a finding about it.
3. **The vendored skills.** `.claude/skills/VENDOR.md` lists defensive
   playbooks (CIS hardening, eBPF monitoring, network segmentation,
   OWASP, property-based testing, SBOM, SLSA). Read the matching one.
4. **Debian and upstream.** Is there a Debian 12 package or a kernel/nftables
   feature that does this? A packaged, maintained tool beats new code on a
   router. Check the licence is AGPL-compatible.
5. **Python libraries,** last. A new dependency costs a lockfile change
   (`scripts/lock-requirements.sh`), a reason in the PR and the owner's yes.

If a search channel isn't available in this session (no network, no `gh`),
say which one you skipped. "Found nothing" and "didn't look" are different
reports.

## Decide

| What you found | Do |
|---|---|
| It exists in `frfw` | Use or extend it; mirror its tests |
| A Debian package or kernel feature does it | Integrate it, sandboxed, off unless configured |
| A library does most of it | Propose it in the plan, with the reason |
| Nothing fits | Build it, small, following the closest pattern you found |

Put one line of what you found in the plan ("Kutatás: ..."), so the owner
sees the decision wasn't a guess.
