# Review with fresh eyes

The context that wrote the code is the worst reviewer of it: it remembers
what it meant, not what it wrote. So review from a fresh start. If the
session can start a subagent, give it the diff, the plan and this file and
nothing else. If not, do a separate pass: re-read the diff cold, file by
file, as if someone else wrote it.

## Process

1. `git diff main...HEAD` (and `git status` for anything unstaged).
2. Read each changed file in full, not just the hunks: callers, imports,
   the test that covers it.
3. Hold it against the plan: everything in it done? Anything done that was
   not in it?
4. Go through the checklist below, most severe first.
5. Report only what you are confident is real.

## Only report what you can prove

Before writing a finding, answer four questions. If any answer is "no" or
"not sure", lower the severity or drop it.

1. Can I name the file and line?
2. Can I describe the failure: which input, which state, what goes wrong?
3. Did I read the surrounding code (the caller, the validator one frame up,
   the test)?
4. Would the severity hold up if the owner asked "really?"

A HIGH or CRITICAL finding carries the snippet, the scenario, and why the
existing guards don't stop it. A clean review is a valid result: say
"APPROVE, no findings" and stop. Invented nits are the main way an AI
reviewer wastes the owner's time.

## FR_OS checklist

**Critical (block the PR)**
- A secret, private key, token or real config committed. Anything but public
  keys in `src/frfw/release_keys/`.
- Untrusted input reaching an argv, an nft script or a config file without
  `frfw.validate`, or without `--` before positional values (F1). A regex
  anchored with `$` instead of `\Z`.
- Privileged work outside the apply-helper; a new helper command not gated
  per peer uid in `frfw.helper.peer`; a parser daemon given more than
  `SENSOR_COMMANDS` (A1, I1).
- A new service without its own account and a full systemd sandbox, or not
  listed in `tests/test_systemd_sandbox.py`. A service listening where it
  isn't needed, or on by default (I1, K7).
- Anything that phones home, or reaches the internet without being opt-in
  and documented (G11).
- A test skipped, weakened, deleted or quarantined.
- Signing or review steps of `build-installer.yml` changed unasked.

**High**
- Change in a design-first area that wasn't in the approved plan.
- Rule-order change in `frfw.nft.builder` without a test pinning the order.
- New config key missing from `docs/CONFIG_SCHEMA.md` or the schema.
- New dependency not in `pyproject.toml` / `requirements.lock`, or unpinned
  on the router.
- Boot-time behaviour changed with no boot-test check added.
- XDP program changed without a verifier/instruction-count note (see how
  PR #79 reported it).

**Medium**
- Error paths that fail open on a firewall (allow on error).
- Docs not updated: ROADMAP row, ARCHITECTURE.md, security-lessons
  "Current state".
- Shell that `shellcheck` would flag.

Skip style preferences the surrounding code doesn't follow, and "consider
adding error handling" where a caller already handles it.

## Output

```
REVIEW: <branch> vs main  (<n> files)
Verdict: APPROVE | REQUEST CHANGES
| Sev | File:line | Problem | Fix |
...
Not reviewed: <anything you couldn't check, e.g. the XDP program on real hardware>
```

Fix the findings with a regression test each (back to `tdd.md`), then
review the fixes the same way.
