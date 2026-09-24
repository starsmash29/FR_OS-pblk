"""The local accounts that log into the webUI (phase 18: several, with roles).

Lives in core `frfw` (not `frfw.webui`) and is stdlib-only, because
`firewall-cli set-admin-password` needs it without requiring the webUI's
extra dependencies (fastapi, itsdangerous, ...) to be installed -- the
CLI and the webUI share these accounts, not just their concept.

Password-hashed with PBKDF2-HMAC-SHA256 from `hashlib` -- deliberately
not bcrypt/argon2, to avoid pulling a compiled C extension into a package
meant to install on whatever odd-architecture homelab hardware this
project targets. PBKDF2 with a high iteration count is a perfectly
adequate KDF for a handful of local accounts.

Roles (phase 18):

- `admin`: everything, including managing accounts.
- `viewer`: every screen read-only; can only change its own password.

The store always keeps at least one admin: deleting or demoting the last
one is refused, so the webUI can never lock itself out (the CLI's
`set-admin-password`, run as root, remains the recovery path anyway).

File format: `{"version": 2, "users": {name: {"password_hash", "role"}}}`.
The pre-phase-18 single-account format (`{"username", "password_hash"}`)
is still read, as one admin, and rewritten in the new format on the next
change.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from frfw import paths

AUTH_FILE_PATH = paths.WEBUI_AUTH_PATH

_PBKDF2_ALGORITHM = "pbkdf2_sha256"
_PBKDF2_ITERATIONS = 200_000

ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"
ROLES = (ROLE_ADMIN, ROLE_VIEWER)

MIN_PASSWORD_LENGTH = 8
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")


class AccountError(Exception):
    """A refused account change (bad name/role/password, last admin...)."""


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"{_PBKDF2_ALGORITHM}${_PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations_str, salt_hex, digest_hex = stored.split("$")
        if algorithm != _PBKDF2_ALGORITHM:
            return False
        iterations = int(iterations_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, AttributeError):
        return False

    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return hmac.compare_digest(actual, expected)


@dataclass(frozen=True)
class AdminAccount:
    username: str
    password_hash: str
    role: str = ROLE_ADMIN

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    def session_version(self) -> str:
        """Changes whenever the password does: a session cookie carries it,
        so changing a password (or deleting and re-creating the account)
        ends every session opened with the old one."""
        return hashlib.sha256(self.password_hash.encode()).hexdigest()[:16]


def validate_username(username: str) -> None:
    if not isinstance(username, str) or not _USERNAME_RE.match(username):
        raise AccountError(
            "Username must start with a lowercase letter or '_' and use only "
            "lowercase letters, digits, '_', '.', '-' (max 32 characters)"
        )


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AccountError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")


class AdminStore:
    """Reads/writes the webUI account file."""

    def __init__(self, path: Path = AUTH_FILE_PATH) -> None:
        self.path = path

    # -- reading -----------------------------------------------------------

    def exists(self) -> bool:
        """Whether any account exists (False means first-run setup)."""
        return bool(self.users())

    def users(self) -> dict[str, AdminAccount]:
        if not self.path.is_file():
            return {}
        data = json.loads(self.path.read_text())
        if "users" not in data:  # pre-phase-18 single-account file
            return {data["username"]: AdminAccount(data["username"], data["password_hash"], ROLE_ADMIN)}
        return {
            name: AdminAccount(name, entry["password_hash"], entry.get("role", ROLE_ADMIN))
            for name, entry in data["users"].items()
        }

    def get(self, username: str) -> AdminAccount | None:
        return self.users().get(username)

    def verify(self, username: str, password: str) -> AdminAccount | None:
        """The account, if the password is right; None otherwise."""
        account = self.get(username)
        if account is None:
            # Still run a hash to keep the timing similar whether or not
            # the username exists, rather than short-circuiting.
            hash_password(password)
            return None
        return account if verify_password(password, account.password_hash) else None

    # -- writing -----------------------------------------------------------

    def _write(self, users: dict[str, AdminAccount]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 2,
            "users": {
                name: {"password_hash": a.password_hash, "role": a.role}
                for name, a in sorted(users.items())
            },
        }
        tmp_path = self.path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data, indent=1))
        tmp_path.chmod(0o640)
        tmp_path.replace(self.path)

    def set_password(self, username: str, password: str, role: str | None = None) -> None:
        """Create the account or change its password. A new account gets
        `role` (default admin -- this is also the CLI's recovery path); an
        existing one keeps its role unless `role` is given."""
        users = self.users()
        existing = users.get(username)
        new_role = role or (existing.role if existing else ROLE_ADMIN)
        if new_role not in ROLES:
            raise AccountError(f"Unknown role {new_role!r}")
        self._check_keeps_an_admin(users, username, new_role)
        users[username] = AdminAccount(username, hash_password(password), new_role)
        self._write(users)

    def add_user(self, username: str, password: str, role: str) -> None:
        validate_username(username)
        validate_password(password)
        if role not in ROLES:
            raise AccountError(f"Unknown role {role!r}")
        if username in self.users():
            raise AccountError(f"User {username!r} already exists")
        self.set_password(username, password, role)

    def set_role(self, username: str, role: str) -> None:
        if role not in ROLES:
            raise AccountError(f"Unknown role {role!r}")
        users = self.users()
        if username not in users:
            raise AccountError(f"No such user {username!r}")
        self._check_keeps_an_admin(users, username, role)
        users[username] = AdminAccount(username, users[username].password_hash, role)
        self._write(users)

    def delete_user(self, username: str) -> None:
        users = self.users()
        if username not in users:
            raise AccountError(f"No such user {username!r}")
        self._check_keeps_an_admin(users, username, None)
        del users[username]
        self._write(users)

    @staticmethod
    def _check_keeps_an_admin(users: dict[str, AdminAccount], username: str, new_role: str | None) -> None:
        admins_after = {n for n, a in users.items() if a.is_admin and n != username}
        if new_role == ROLE_ADMIN:
            admins_after.add(username)
        if not admins_after:
            raise AccountError("At least one admin account must remain")
