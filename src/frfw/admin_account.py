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
import os
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


#: Names a first-run setup won't accept for the admin account: the ones
#: every credential-stuffing list tries first (security-lessons G1).
RESERVED_USERNAMES = frozenset({"admin", "administrator", "root", "user", "fr_os", "fros"})


@dataclass(frozen=True)
class AdminAccount:
    username: str
    password_hash: str
    role: str = ROLE_ADMIN
    #: Set on the account first boot generates: the first sign-in goes to
    #: the setup step (own username, own password) before anything else.
    must_change: bool = False

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
            name: AdminAccount(name, entry["password_hash"], entry.get("role", ROLE_ADMIN),
                               bool(entry.get("must_change", False)))
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
                name: {"password_hash": a.password_hash, "role": a.role,
                       **({"must_change": True} if a.must_change else {})}
                for name, a in sorted(users.items())
            },
        }
        tmp_path = self.path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data, indent=1))
        tmp_path.chmod(0o640)
        if os.geteuid() == 0:
            # Written by root (`firewall-cli set-admin-password`, first
            # boot): hand the file to whoever owns the state directory --
            # the webUI's own account -- or the webUI can't read it and
            # every page is a 500 (found booting the image for real).
            parent = self.path.parent.stat()
            os.chown(tmp_path, parent.st_uid, parent.st_gid)
        tmp_path.replace(self.path)

    def set_password(self, username: str, password: str, role: str | None = None, *,
                     must_change: bool = False) -> None:
        """Create the account or change its password. A new account gets
        `role` (default admin -- this is also the CLI's recovery path); an
        existing one keeps its role unless `role` is given. `must_change`
        marks a generated password (first boot): the first sign-in then
        has to finish setup."""
        users = self.users()
        existing = users.get(username)
        new_role = role or (existing.role if existing else ROLE_ADMIN)
        if new_role not in ROLES:
            raise AccountError(f"Unknown role {new_role!r}")
        self._check_keeps_an_admin(users, username, new_role)
        users[username] = AdminAccount(username, hash_password(password), new_role, must_change)
        self._write(users)

    def complete_setup(self, current: str, new_username: str, password: str) -> AdminAccount:
        """First-run setup (security-lessons G1): the generated account
        becomes `new_username` with the admin's own password; the
        generated name and password stop working at once."""
        validate_username(new_username)
        if new_username in RESERVED_USERNAMES:
            raise AccountError(f"Choose a username other than {new_username!r} -- it's the first one attackers try")
        validate_password(password)
        users = self.users()
        account = users.get(current)
        if account is None or not account.must_change:
            raise AccountError("This account has already been set up")
        if new_username != current and new_username in users:
            raise AccountError(f"User {new_username!r} already exists")
        if verify_password(password, account.password_hash):
            raise AccountError("Choose a new password, not the generated one")
        del users[current]
        users[new_username] = AdminAccount(new_username, hash_password(password), account.role)
        self._write(users)
        return users[new_username]

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
