# Plan

A plan exists so the owner can say "Mehet" or "Várj" to something concrete,
and so the implementation has a checklist to be held against. It is short.
A plan the owner has to read twice is too long.

## Before writing it

1. Find the item. Most work is a ROADMAP row with a stable ID; read its row
   and any review finding it cites (`docs/reviews/`). If there is no ID,
   say so in the plan.
2. Ground it in the code. Find the closest existing example for each of:
   naming, error handling, logging, how config reaches the module
   (`frfw.config`, `docs/CONFIG_SCHEMA.md`), how root work is reached
   (`frfw.helper`), and the matching test file. Name the file. If there is
   no similar code, say so; don't invent a pattern.
3. Check `docs/security-lessons.md` for the IDs this change touches (I1, F1,
   G11 ...). Name them in the plan; they become review and test targets.

## The plan (in Hungarian, to the owner)

```
Tétel: <ID> - <one line>
Cél: <what the router does afterwards that it doesn't do now>
Megközelítés: <2-4 sentences, and why this over the obvious alternative>
Fájlok: <path - CREATE/UPDATE - why>, ...
Tesztek: <test file - what it proves>; boot teszt kell? igen/nem, miért
Biztonság: <security-lessons IDs and how they are met>
Kockázatok: <risk - mitigation>
Nem része: <what is deliberately left out>
Mehet?
```

Keep the structure; drop a line only if it is truly empty ("Kockázatok:
nincs ismert" is fine and useful).

## Sizing

Each phase of a bigger item should be mergeable on its own. If the plan
only works when every phase lands, split it differently: first the smallest
slice that works end to end, then the full happy path, then edge cases,
then performance. One item, one branch (`agent/<id>-<slug>`), one PR.

## Red flags in your own plan

- A step with no file path, or a phase with no test.
- "Refactor X while we're there": that's a second item.
- A new dependency without a reason, or anything that talks to the
  internet. Both need the owner's explicit yes (AGENTS.md).
- Touching a design-first area without saying so up front.

After "Mehet", the plan becomes the checklist for `review.md` and the
"what changed" section of the PR body.
