"""Who changed what in the webUI (phase 18).

With more than one account, "who applied this?" needs an answer. Every
change request (any non-GET request by a logged-in account) and every
login attempt is appended as one JSON line: time, user, role, client
address, method, path and the response status. Form contents are never
recorded -- they can contain passwords.

The file is capped at MAX_BYTES; when full it is rotated to `.1` (one old
generation kept), so it can't fill the disk of a small router.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

MAX_BYTES = 1024 * 1024

_lock = threading.Lock()


def append(path: Path, entry: dict) -> None:
    line = json.dumps({"ts": time.time(), **entry}, sort_keys=True) + "\n"
    with _lock:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and path.stat().st_size + len(line) > MAX_BYTES:
                path.replace(path.with_name(path.name + ".1"))
            with path.open("a") as f:
                f.write(line)
        except OSError:
            # Auditing must never break the request it describes.
            pass


def read_recent(path: Path, limit: int = 200) -> list[dict]:
    """Newest first, across the current and the rotated file."""
    entries: list[dict] = []
    for candidate in (path, path.with_name(path.name + ".1")):
        try:
            lines = candidate.read_text().splitlines()
        except OSError:
            continue
        for line in reversed(lines):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict):
                entries.append(entry)
            if len(entries) >= limit:
                return entries
    return entries
