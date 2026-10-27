# Learn: make the next session better

The loop ends by asking: did this session discover something a future
session would otherwise rediscover the hard way? Most sessions produce
nothing worth keeping, and that's fine. Write a lesson only when it would
change what someone does next time.

## What is worth keeping

- A root cause that wasn't obvious from the error (a verifier limit, a
  Python-version difference in the test suite, a systemd sandbox setting
  that silently blocks a socket).
- A workaround for a tool, kernel or Debian quirk, with the version.
- A pattern this repo uses that a newcomer would get wrong.
- A mistake the owner had to correct more than once.

Not worth keeping: what was done (that's the handover and the PR), general
programming advice, anything already in AGENTS.md.

## Where it goes

Pick the place the next reader will actually look. In order:

| Lesson about | Write it in |
|---|---|
| A security requirement | `docs/security-lessons.md` (new ID or the "Current state" of one), with the owner's yes |
| How a part works or why it was built that way | ARCHITECTURE.md, in that part's section |
| How the owner and integrator work together | `docs/integrator-handover.md`, "How the owner and the integrator work" |
| A test trick | a comment in the test, or the test's module docstring |
| A rule for every contributor | propose it to the owner for AGENTS.md; don't add it yourself |

All of it in English, committed with the work that taught it.

## Turning a repeated workflow into a skill

If the same multi-step procedure has been done by hand three times, it may
deserve a skill. In this repo a new skill is a reviewed decision:

- Propose it to the owner first, with the procedure and where it recurred.
- It must be prose only (`.md` and a `LICENSE`), its `name` must match its
  directory, it must be listed in `.claude/skills/VENDOR.md`, and every
  install command in it must name an exact version.
  `tests/test_claude_skills.py` checks all of this.
- If the procedure needs code to run, it isn't a skill here: write it as a
  `frfw` module or a script under `scripts/`, with tests, per AGENTS.md.

## Quality check before saving a lesson

Is it specific (names the file, version, error)? Is it true (you saw it,
not guessed it)? Is it new (not already in the docs)? Would it change a
decision? If any answer is no, don't write it.
