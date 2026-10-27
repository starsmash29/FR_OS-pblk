# Sessions: resume, hand over, compact

Every Claude Code session starts with no memory of the last one. In this
repo the bridge is `docs/integrator-handover.md`: committed, in English,
read at the start and updated at the end. ECC kept these notes in a private
folder; here they live in the repo so cloud sessions see them too.

## Resume (start of a session)

1. Read `docs/integrator-handover.md` whole, then `git log --oneline -15`
   and the open PRs/branches.
2. Brief the owner in Hungarian, in this shape, before touching any file:
   ```
   ÁLLAPOT (main @ <sha>, handover <date>)
   Mit építünk: <2-3 sentences>
   Kész és bizonyított: <items, with the evidence>
   Folyamatban: <branch / item - what's left>
   NE próbáld újra: <every failed approach and why> (or "nincs")
   Nyitott kérdések: <...>
   Következő lépés: <the exact next step>
   ```
3. If the handover is more than 7 days older than `main`'s last commit, or
   names files that no longer exist, say so.
4. Then wait for the owner, unless the next step is already approved
   ("Mehet" on record).

"Ne próbáld újra" is never skipped. Without it, the next session repeats
the failed approach.

## Hand over (end of a session, or before context runs out)

Update `docs/integrator-handover.md` in place (keep its structure: working
agreements, recently merged, open items). Add or refresh a section for the
work in progress:

```markdown
## In progress (updated YYYY-MM-DD, main at <sha>)

**Item:** <ID> on `agent/<id>-<slug>`. <What it is, enough for someone with
no memory of this session.>

**Works, with evidence**
- <thing> - <test command / boot-test run / measurement>

**Did not work, and why** (don't retry)
- <approach> - <exact error or reason>

**Not tried yet**
- <idea specific enough to start on>

**Files**
| File | State | Note |

**Decisions** - <decision> - <reason>
**Open questions / blockers** - <...>
**Exact next step** - <so precise that resuming needs no thinking>
```

Only list something under "works" with evidence; without it, it goes under
"not tried yet". Write "none" rather than dropping a section. Commit the
handover on the item's branch with the work, and update "Recently merged"
when the PR lands. Show the owner the diff of the handover and ask if it is
accurate.

## Compacting a long session

Long sessions get worse before they hit the limit. Hand over (above) and
start fresh, or compact, at a natural boundary:

| Moment | Compact / fresh session? |
|---|---|
| Research done, plan approved | Yes: keep the plan, drop the exploration |
| An item merged, next one starting | Yes |
| Debugging finished, moving to new work | Yes, after the "did not work" notes are written |
| Halfway through an edit or a failing test | No: finish to green first |
| Between RED and GREEN | No |

Before compacting, make sure the plan, the evidence and the "did not work"
list are in the handover file, because those are what a summary loses.
