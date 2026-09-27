"""Handing the generated admin password over on the console -- privately,
and only until it is changed.

First boot generates the webUI admin password on a box that has no other
admin session, so the console is the only place to show it. It used to
be prepended to /etc/issue, which is world-readable and was never
cleaned up: any local process, and anyone reading an old serial log,
had the live admin credential forever (review triage A5).

Now it goes into ISSUE_PATH, a root-only (0600) file in /etc/issue.d.
agetty runs as root and prints /etc/issue.d/*.issue after /etc/issue
before every login prompt, so the console still shows it; no other
account can read it. `clear_if_changed` deletes it as soon as the
password no longer works for its account (changed in the webUI or with
set-admin-password); fr-initial-password.path runs it whenever the
account file changes. It also moves a v0.1.0-style line out of
/etc/issue.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from frfw.admin_account import AdminStore

ISSUE_PATH = Path("/etc/issue.d/fr_os-initial-admin.issue")
LEGACY_ISSUE_PATH = Path("/etc/issue")

_LINE = "FR_OS: initial webUI admin login is '{user}' / '{password}'"
_LINE_RE = re.compile(r"^FR_OS: initial webUI admin login is '([^']+)' / '([^']+)'$", re.M)
# The v0.1.0 block in /etc/issue: the login line, the optional hint and
# the "Change it..." line, then a blank line.
_LEGACY_BLOCK_RE = re.compile(
    r"^FR_OS: initial webUI admin login is '[^']+' / '[^']+'\n"
    r"(?:webUI: .*\n)?"
    r"Change it after logging in, then this line stays until you edit /etc/issue\.\n\n?",
    re.M,
)


def write(username: str, password: str, *, path: Path | None = None) -> None:
    """Create the file 0600 root-only from the start (never briefly readable)."""
    path = ISSUE_PATH if path is None else path
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(_LINE.format(user=username, password=password) + "\n")
        fh.write("It disappears from this screen once you change it in the webUI.\n\n")
    tmp.replace(path)


def read(path: Path | None = None) -> tuple[str, str] | None:
    path = ISSUE_PATH if path is None else path
    try:
        match = _LINE_RE.search(path.read_text())
    except OSError:
        return None
    return (match.group(1), match.group(2)) if match else None


def migrate_legacy(*, legacy_path: Path | None = None, path: Path | None = None) -> bool:
    """Move a v0.1.0 password line out of the world-readable /etc/issue."""
    legacy_path = LEGACY_ISSUE_PATH if legacy_path is None else legacy_path
    path = ISSUE_PATH if path is None else path
    try:
        text = legacy_path.read_text()
    except OSError:
        return False
    found = _LINE_RE.search(text)
    if not found:
        return False
    if read(path) is None:
        write(found.group(1), found.group(2), path=path)
    cleaned = _LEGACY_BLOCK_RE.sub("", text)
    cleaned = _LINE_RE.sub("", cleaned) if _LINE_RE.search(cleaned) else cleaned
    with legacy_path.open("w") as fh:  # in place: keep the file's mode/owner
        fh.write(cleaned)
    return True


def clear_if_changed(store: AdminStore | None = None, *, path: Path | None = None) -> bool:
    """Delete the console copy once the password no longer logs in."""
    path = ISSUE_PATH if path is None else path
    shown = read(path)
    if shown is None:
        return False
    username, password = shown
    if (store or AdminStore()).verify(username, password) is not None:
        return False
    path.unlink(missing_ok=True)
    return True
