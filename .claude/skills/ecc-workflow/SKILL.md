---
name: ecc-workflow
description: The FR_OS engineering loop, adapted from ECC (affaan-m/ECC) - plan, research first, test first, implement, fresh-eyes review, verify, hand over, learn. Use it for every change in this repository - a ROADMAP item (P4-1, SEC-3, NET-4 ...), a bug fix, a refactor, a webUI screen, an nft builder change, XDP/eBPF work, the installer, a hackathon demo - and whenever the owner says "plan", "design", "review", "verify", "fix the build", "save the session", "where were we", "continue", "Mehet" or asks for a summary of what was done. Use it even for small changes; the loop scales down, it is not skipped.
---

# ECC workflow for FR_OS

This skill is a working method, not a rulebook. The rules live in
`AGENTS.md`, `docs/integrator-handover.md` and `docs/security-lessons.md`,
and they always win: if anything here disagrees with them, follow them and
mention the conflict to the owner. What this skill adds is the *order* of
work and the *evidence* each step leaves behind, so that a change arrives
planned, tested, reviewed and handed over instead of merely written.

Adapted from ECC (MIT, see `LICENSE` in this directory). ECC enforces much
of this with hooks and dedicated subagents; this repo carries prose only
(`.claude/skills/VENDOR.md`), so here each step is something you do
deliberately. Where a step says "fresh context", use a subagent if the
session offers one; otherwise do the step as a separate, explicit pass.

## The loop

```
orient -> plan -> research -> test (RED) -> implement (GREEN) -> refactor
      -> review (fresh eyes) -> verify -> hand over -> learn
```

| Step | What it produces | Read |
|---|---|---|
| Orient | You know the state of `main`, the open item and what not to retry | `references/sessions.md` (resume) |
| Plan | A short design the owner can say "Mehet" to | `references/plan.md` |
| Research | Evidence that the thing does not already exist, in the repo or upstream | `references/research-first.md` |
| Test first | A failing test, run, failing for the intended reason | `references/tdd.md` |
| Implement | The smallest change that turns it green | `references/tdd.md` |
| Review | Findings you can cite to a line, or a clean APPROVE | `references/review.md` |
| Verify | A PASS/FAIL report from the real commands | `references/verify.md` |
| Security | The checks this change touches (code and agent config) | `references/security.md` |
| Hand over | `docs/integrator-handover.md` updated, PR body with evidence | `references/sessions.md` |
| Learn | A lesson written where the next session will find it | `references/learn.md` |

Open a reference when you reach its step, not all at once. Each one is
short and specific to this repository.

## How big a loop

Scale the loop to the change; don't drop steps, shrink them.

- **Typo, comment, doc-only fix:** plan in one sentence, no new test, run the
  suites anyway (docs are tested here too, e.g. `tests/test_claude_skills.py`),
  short review of the diff, verify, one line in the PR body.
- **Normal ROADMAP item:** the full loop. Plan in Hungarian for the owner,
  wait for "Mehet", then go. "Do it" in the request is not "Mehet": the
  go-ahead is his answer to a plan, so the first reply to any new item is
  the plan.
- **Design-first areas** (AGENTS.md: privileged helpers `frfw.helper.*`, the
  update/signing path, the nft builder's rule order, the installer or boot
  sequence): the plan is written out in full and nothing is edited before
  "Mehet". These are the places where a wrong guess costs a broken router.

## Time-boxed mode (hackathon, demo, deadline)

When the owner says there is a deadline, a hackathon or a demo, the loop
gets *narrower*, not *looser*:

- The plan still comes first and you still wait for "Mehet". Urgency
  ("csináld meg", "sietünk", "holnap kell") is not a go-ahead on a plan he
  hasn't seen; the owner decided this explicitly (2026-10-27). Code written
  before he agrees on the slice is the most expensive kind to throw away
  the night before a demo. Make waiting cheap instead: a shorter plan, and
  research done while he reads it, but no edits to the repository until he
  answers.
- Plan the smallest vertical slice that can be shown working end to end,
  and say in the plan what is deliberately left out.
- Keep every non-negotiable from AGENTS.md: tests with the change, no
  weakened tests, no secrets, privilege boundaries, `frfw.validate` on
  untrusted input, no telemetry. A demo that breaks these is not a shortcut,
  it is a regression someone has to find later.
- Prefer showing a real run (real `nft`, a network namespace, the QEMU boot
  test) over a mock; it is what convinces a jury and it is what the test
  suite already knows how to do.
- Write the handover entry before the time runs out, not after. A session
  that ends mid-demo with no handover loses the most expensive context.

## Talking to the owner

- Chat in Hungarian. Everything committed is in English (code, comments,
  docs, commit messages, the handover file).
- Ask before acting when a step cannot be undone or the owner's decision is
  needed (merge, anything in the design-first areas, a new dependency,
  anything that reaches the internet). Otherwise start, and report.
- Reports are short: what changed, the evidence (commands and results),
  what is not done or not verified, and the one question you need answered.
  End a PR report with "Mehet?" as the handover file describes.

## When things go wrong

- A test you didn't touch fails: it is a finding, not noise. Stop, find out
  why, and say so. Never skip, weaken or delete a test to get green.
- The same error survives three honest attempts: stop and write down what
  was tried and why it failed (`references/sessions.md`, "What did not
  work"), then ask. A fourth blind attempt costs more than the question.
- Context is getting long: hand over at the next natural boundary
  (`references/sessions.md`, "Compacting"), not in the middle of an edit.
