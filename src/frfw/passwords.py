"""What a password must not be (security-lessons G6).

Length alone let "password", "12345678" and "qwertyui" through -- the
first things a credential-stuffing run tries. Every password set through
FR_OS (webUI accounts, first-run setup, the CLI, ZTNA users) is now
refused when it is:

- shorter than MIN_LENGTH (12 since review v0.2.1 FR-NEW-007: a
  passphrase of a few words, not a short "complex" string -- there are
  no composition rules, which only get in a password manager's way);
- one of the 10,000 most common passwords (data/common-passwords.txt,
  SecLists, MIT; compared case-insensitively, also with trailing digits
  and punctuation removed, so "Password123!" counts as "password");
- or contains the account's own username.

The list is local: nothing is sent anywhere to check a password.
"""

from __future__ import annotations

import functools
import re
from importlib import resources

MIN_LENGTH = 12

_TRAILING = re.compile(r"[\d\W_]+\Z")


class WeakPasswordError(ValueError):
    pass


@functools.lru_cache(maxsize=1)
def common_passwords() -> frozenset[str]:
    text = resources.files("frfw").joinpath("data/common-passwords.txt").read_text()
    return frozenset(line for line in text.splitlines() if line and not line.startswith("#"))


def problem(password: str, username: str | None = None) -> str | None:
    """Why `password` is refused, or None when it is acceptable."""
    if len(password) < MIN_LENGTH:
        return f"Password must be at least {MIN_LENGTH} characters"
    lowered = password.lower()
    common = common_passwords()
    stem = _TRAILING.sub("", lowered)
    if lowered in common or (len(stem) >= 4 and stem in common):
        return "That password is one of the most common ones attackers try first -- choose another"
    if len(set(lowered)) <= 2:
        return "That password is too repetitive -- choose another"
    if username and len(username) >= 3 and username.lower() in lowered:
        return "The password must not contain the username"
    return None


def check(password: str, username: str | None = None) -> None:
    reason = problem(password, username)
    if reason:
        raise WeakPasswordError(reason)
