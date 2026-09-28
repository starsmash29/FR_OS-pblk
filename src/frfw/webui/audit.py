"""Who changed what in the webUI (phase 18).

With more than one account, "who applied this?" needs an answer. Every
change request (any non-GET request by a logged-in account) and every
login attempt is appended as one JSON line: time, user, role, client
address, method, path and the response status. Form contents are never
recorded -- they can contain passwords.

The file is capped at MAX_BYTES; when full it is rotated to `.1` (one old
generation kept), so it can't fill the disk of a small router.

Security-lessons G9/E6: on a router the log is root's
(/var/log/fr_os/audit.log, 0640 root:fr_os-webui). The webUI reads it but
can't write it: `route()` sends its appends to the apply-helper, which
writes them. So a compromised webUI can add lines, but not rewrite or
remove the ones that show what it did. Entries with an `alert` are the
security events an admin is shown on the dashboard until they have seen
them: a new admin, a new ZTNA user, a sign-in from a new address, a
second factor removed, management opened to the WAN.
"""

from __future__ import annotations

import grp
import json
import os
import threading
import time
from pathlib import Path
from typing import Callable

MAX_BYTES = 1024 * 1024

_lock = threading.Lock()


#: Logs another process writes for us: path -> a function taking the entry.
_writers: dict[str, Callable[[dict], object]] = {}


def route(path: Path, writer: Callable[[dict], object] | None) -> None:
    """Send every append to `path` to `writer` (None: write directly)."""
    if writer is None:
        _writers.pop(str(path), None)
    else:
        _writers[str(path)] = writer


def append(path: Path, entry: dict) -> None:
    writer = _writers.get(str(path))
    if writer is not None:
        try:
            writer(entry)
        except Exception:  # noqa: BLE001 -- auditing must never break the request it describes
            pass
        return
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


def alert(path: Path, message: str, **entry) -> None:
    """An audit entry that is also a security alert (see the module doc)."""
    append(path, {**entry, "alert": message})


def alerts_since(path: Path, since: float, limit: int = 50) -> list[dict]:
    """Alerts newer than `since`, newest first."""
    return [e for e in read_recent(path, limit=2000)
            if e.get("alert") and float(e.get("ts") or 0) > since][:limit]


def seen(path: Path, user: str) -> float:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return 0.0
    value = data.get(user) if isinstance(data, dict) else None
    return float(value) if isinstance(value, (int, float)) else 0.0


def mark_seen(path: Path, user: str, until: float | None = None) -> None:
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    data[user] = time.time() if until is None else until
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(path)


def prepare(path: Path, group: str = "fr_os-webui") -> None:
    """Create the root-owned log the way it must be: the directory 0750 and
    the file 0640, group `group` (the webUI, which reads it) -- never
    briefly world-readable. A no-op once it exists."""
    if path.exists():
        return
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    os.close(fd)
    if os.geteuid() == 0:
        try:
            gid = grp.getgrnam(group).gr_gid
        except KeyError:
            return
        os.chown(path.parent, 0, gid)
        os.chown(path, 0, gid)
