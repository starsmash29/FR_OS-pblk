#!/usr/bin/env python3
"""Is there an adversarial review on record for this release? (security-lessons J2)

Every release is reviewed first by at least two different AI models with
docs/review-prompt.md, and the findings are triaged into
docs/reviews/v<VERSION>.md (format: docs/reviews/TEMPLATE.md). The release
workflow runs this before it builds anything and refuses to publish when:

- the record is missing;
- it names fewer than two different models;
- the reviewed commit isn't part of the release, or is older than the
  previous release (the review would be about other code);
- a critical or high finding is still open -- fixed, accepted (with the
  reason) or rejected as not a bug are the ways to close one.

Usage: check_release_review.py VERSION [--root DIR]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

#: How a critical/high finding may end. Anything else ("open", "reported",
#: "needs verification", "in progress") blocks the release.
CLOSED = ("fixed", "accepted", "not a bug", "duplicate")
BLOCKING = ("critical", "high")
_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)


def _field(text: str, name: str) -> str | None:
    # "- **Models:** a, b" and "Models: a, b" alike.
    m = re.search(rf"^\s*[-*]?\s*\**{name}\**\s*:\s*\**\s*(.+?)\s*$", text, re.M | re.I)
    return m.group(1).strip("`* ") if m else None


def _findings(text: str) -> list[dict[str, str]]:
    """Rows of every markdown table that has Severity and Status columns."""
    rows, header = [], None
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            header = None
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if header is None:
            lowered = [c.lower() for c in cells]
            if "severity" in lowered and "status" in lowered:
                header = lowered
            continue
        if set("".join(cells)) <= set("-: "):
            continue  # the |---|---| line
        rows.append(dict(zip(header, cells)))
    return rows


def _previous_release(root: Path, version: tuple[int, ...]) -> str | None:
    tags = _git(root, "tag", "-l", "v*").stdout.split()
    older = [(tuple(map(int, m.groups())), t) for t in tags if (m := _VERSION_RE.match(t))]
    older = [(v, t) for v, t in older if v < version]
    return max(older)[1] if older else None


def check(version: str, root: Path) -> list[str]:
    m = _VERSION_RE.match(version)
    if not m:
        return [f"not a version: {version!r}"]
    version = ".".join(m.groups())
    record = root / "docs" / "reviews" / f"v{version}.md"
    if not record.exists():
        return [f"no adversarial review on record: {record.relative_to(root)} is missing "
                "(docs/RELEASING.md, 'Before tagging')"]
    text = record.read_text()
    problems = []

    models = [s.strip().lower() for s in re.split(r"[,;]", _field(text, "Models") or "") if s.strip()]
    if len(set(models)) < 2:
        problems.append("the record must name at least two different models (\"Models: a, b\")")

    commit = _field(text, "Reviewed commit")
    if not commit:
        problems.append("the record must say which commit was reviewed (\"Reviewed commit: <sha>\")")
    elif _git(root, "cat-file", "-e", f"{commit}^{{commit}}").returncode != 0:
        problems.append(f"reviewed commit {commit} doesn't exist in this repository")
    else:
        if _git(root, "merge-base", "--is-ancestor", commit, "HEAD").returncode != 0:
            problems.append(f"reviewed commit {commit} is not part of this release (not an ancestor of HEAD)")
        previous = _previous_release(root, tuple(map(int, m.groups())))
        if previous and _git(root, "merge-base", "--is-ancestor", commit, previous).returncode == 0:
            problems.append(f"reviewed commit {commit} is from before the previous release {previous}")

    rows = _findings(text)
    if not any(re.search(r"\|\s*severity\s*\|", line, re.I) for line in text.splitlines()):
        problems.append("the record needs a findings table with Severity and Status columns "
                        "(an empty table if the reviews found nothing)")
    for row in rows:
        severity = row.get("severity", "").lower()
        status = row.get("status", "").lower()
        if any(s in severity for s in BLOCKING) and not status.startswith(CLOSED):
            problems.append(f"open {severity} finding {row.get('id', '?')}: {row.get('finding', '')[:80]} "
                            f"(status: {row.get('status') or 'none'})")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("version")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    problems = check(args.version, args.root)
    for problem in problems:
        print(f"::error::{problem}")
    if not problems:
        print(f"adversarial review for v{args.version.lstrip('v')} is on record and closed")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
