# Verify

"Done" means the commands ran and the results are written down, not that
the change looks right. Run these on the final head of the branch, after
the review fixes.

## The gates

1. **Both full suites, separately** (mixing them loses the `webui_env`
   fixture). Follow the setup in `docs/integrator-handover.md`: Python
   3.11 venv, bpffs mounted, `/sys/fs/bpf/fr_os_xdp` removed.
   ```bash
   python3 -m pytest tests --ignore=tests/webui -q
   python3 -m pytest tests/webui -q
   ```
   Count skips as well as failures. A root-only test that skipped did not
   verify anything; say so.
2. **Shell:** `shellcheck` on every changed `.sh` (the installer test runs it,
   but run it directly for a clear report).
3. **XDP:** if `bpf/` changed, rebuild the object (`scripts/build-xdp-object.sh`)
   and note the verifier result and instruction count.
4. **Boot test, when it applies** (image, boot, services, networking,
   installer, anything that runs at boot): the *Build installer ISO*
   workflow with `boot_test=true`, BIOS and UEFI, on this branch's head.
   If you can't dispatch it from here, say so; don't claim it.
5. **Diff sanity:** `git diff --stat main...HEAD`. Anything there the plan
   didn't mention? Any generated file, lockfile or binary that shouldn't be?
6. **Docs:** ROADMAP row status and modules/tests named; ARCHITECTURE.md;
   `docs/CONFIG_SCHEMA.md`; security-lessons "Current state".
7. **Secrets grep** on the diff: keys, tokens, passwords, `BEGIN ... PRIVATE KEY`.

## Report

```
VERIFICATION <branch> @ <short sha>
Suite (core):  PASS  812 passed, 14 skipped (root)
Suite (webui): PASS  203 passed
shellcheck:    PASS  2 files
XDP:           n/a
Boot test:     PASS  BIOS+UEFI, run <id>   | NOT RUN: <reason>
Docs:          ROADMAP, CONFIG_SCHEMA updated
Diff:          7 files, all in plan
Overall:       READY for "Mehet?" | NOT READY: <what>
```

This block goes into the PR body under "how it was tested", together with
the RED/GREEN evidence from `tdd.md`.

## When the build or a suite breaks

Fix one error at a time: read the context around it, find the root cause,
make the smallest change, rerun. Fix imports and types before logic. Stop
and ask when a fix creates more errors than it removes, when the same error
survives three attempts, when the fix needs an architecture change, or when
the cause is a missing dependency (that is a plan change, not a build fix).

Before merging, `main` must be an ancestor of the head; if it isn't, merge
`main` in (never rebase) and run the gates again on the merged head.
