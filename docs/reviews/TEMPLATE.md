# Adversarial review – v<VERSION>

<!-- Copy to docs/reviews/v<VERSION>.md before tagging (security-lessons J2,
docs/RELEASING.md). scripts/check_release_review.py checks the three fields
and the table; the release workflow refuses to publish without them. -->

- **Reviewed commit:** `<full or short sha of main that was reviewed>`
- **Models:** <model A>, <model B>
- **Reports:** `docs/reviews/v<VERSION>-<model A>.md`, `docs/reviews/v<VERSION>-<model B>.md`
- **Date:** <YYYY-MM-DD>

Each finding was re-checked against the source before it went into this
table. Where the reviewers rated the same issue differently, the severity
below is ours, with the reason.

| ID | Severity | Finding | Status | Sources |
|---|---|---|---|---|
| R1 | high | <what, where (file:line)> | fixed in <sha / PR> | <model A> #3, <model B> #7 |
| R2 | medium | ... | accepted: <why it can wait, and until when> | <model B> #2 |
| R3 | low | ... | not a bug: <why> | <model A> #11 |

Status: `fixed ...`, `accepted: <reason>`, `not a bug: <reason>` or
`duplicate of Rn` close a finding. A critical or high finding with any other
status (open, reported, needs verification) blocks the release.
