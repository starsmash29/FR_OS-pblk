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
import fcntl
import functools
import json
import os
import re
import secrets
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path

from frfw import paths

AUTH_FILE_PATH = paths.WEBUI_AUTH_PATH

#: Security-lessons G2. New hashes: scrypt from hashlib (OpenSSL, no
#: compiled dependency), with OWASP's N=2^15, r=8, p=3 -- as strong as
#: their N=2^17, p=1 at a quarter of the memory (32 MiB per check), which
#: matters on a small router. Stored as scrypt$N$r$p$salt$digest.
SCRYPT_ALGORITHM = "scrypt"
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 3
#: The least work a stored scrypt hash may ask for (N*r*p) -- H1: a
#: stored hash can't lower how hard a password is checked.
_SCRYPT_MIN_COST = SCRYPT_N * SCRYPT_R * SCRYPT_P
_SCRYPT_MAXMEM = 256 * 1024 * 1024

#: Hashes written before G2: PBKDF2-SHA256, 200 000 iterations. Still
#: accepted at sign-in, never below that floor, and replaced by a scrypt
#: hash on the next successful sign-in (`needs_rehash`); the old one is
#: not kept anywhere.
_PBKDF2_ALGORITHM = "pbkdf2_sha256"
MIN_PBKDF2_ITERATIONS = 200_000

ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"
ROLES = (ROLE_ADMIN, ROLE_VIEWER)

MIN_PASSWORD_LENGTH = 8
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}\Z")


class AccountError(Exception):
    """A refused account change (bad name/role/password, last admin...)."""


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                            maxmem=_SCRYPT_MAXMEM, dklen=32)
    return f"{SCRYPT_ALGORITHM}${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """True if `password` matches `stored`. Fails closed on anything it
    doesn't fully understand or that is weaker than the floors."""
    try:
        fields = stored.split("$")
        if fields[0] == SCRYPT_ALGORITHM and len(fields) == 6:
            n, r, p = (int(x) for x in fields[1:4])
            salt, expected = bytes.fromhex(fields[4]), bytes.fromhex(fields[5])
            if n * r * p < _SCRYPT_MIN_COST or r < SCRYPT_R or n & (n - 1) or len(salt) < 16 or len(expected) != 32:
                return False
            actual = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, maxmem=_SCRYPT_MAXMEM, dklen=32)
        elif fields[0] == _PBKDF2_ALGORITHM and len(fields) == 4:
            iterations = int(fields[1])
            salt, expected = bytes.fromhex(fields[2]), bytes.fromhex(fields[3])
            if iterations < MIN_PBKDF2_ITERATIONS or len(salt) < 16 or len(expected) != 32:
                return False
            actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        else:
            return False
    except (ValueError, AttributeError, TypeError, MemoryError):
        return False
    return hmac.compare_digest(actual, expected)


def needs_rehash(stored: str) -> bool:
    """Whether a hash that just verified should be replaced: anything that
    isn't scrypt with today's parameters."""
    return not stored.startswith(f"{SCRYPT_ALGORITHM}${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}$")


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
    #: Second factors (security-lessons G5): {"totp": {"secret",
    #: "last_step"}, "webauthn": [{"id", "public_key", "sign_count",
    #: "rp_id", "name", "added"}]}. Secrets -- never shown after enrolment.
    mfa: dict = field(default_factory=dict, compare=False, repr=False)

    @property
    def has_mfa(self) -> bool:
        return bool(self.mfa.get("totp")) or bool(self.mfa.get("webauthn"))

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


#: Which account files this thread holds the lock of (it is re-entrant).
_held = threading.local()


def _serialized(method):
    """Run a read-modify-write of the account file under its lock."""
    @functools.wraps(method)
    def locked(self, *args, **kwargs):
        with self.lock():
            return method(self, *args, **kwargs)
    return locked


class AdminStore:
    """Reads/writes the webUI account file.

    Every change is a read-modify-write of one JSON file, done under an
    exclusive `flock` on its directory (security-lessons J1): the webUI
    serves requests on many threads and `firewall-cli` is another
    process, and without it two changes at the same moment lost one of
    them -- or both finished a first-run setup. Readers need no lock:
    the file is replaced atomically."""

    def __init__(self, path: Path = AUTH_FILE_PATH) -> None:
        self.path = path

    @contextmanager
    def lock(self):
        held = getattr(_held, "paths", None)
        if held is None:
            held = _held.paths = set()
        key = str(self.path.resolve())
        if key in held:
            yield
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # The directory, not the file: the file is replaced on every
        # write, a lock on it would be on the old inode.
        fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            held.add(key)
            try:
                yield
            finally:
                held.discard(key)
        finally:
            os.close(fd)

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
                               bool(entry.get("must_change", False)), dict(entry.get("mfa") or {}))
            for name, entry in data["users"].items()
        }

    def policy(self) -> dict:
        """Account-wide rules: {"require_mfa_for_admins": bool}."""
        if not self.path.is_file():
            return {}
        return dict(json.loads(self.path.read_text()).get("policy") or {})

    def get(self, username: str) -> AdminAccount | None:
        return self.users().get(username)

    def verify(self, username: str, password: str) -> AdminAccount | None:
        """The account, if the password is right; None otherwise. A hash
        from before security-lessons G2 is replaced by a scrypt one right
        here, on the successful sign-in -- the old hash isn't kept."""
        account = self.get(username)
        if account is None:
            # Still run a hash to keep the timing similar whether or not
            # the username exists, rather than short-circuiting.
            hash_password(password)
            return None
        if not verify_password(password, account.password_hash):
            return None
        if needs_rehash(account.password_hash):
            with self.lock():
                users = self.users()
                current = users.get(username)
                if current is None or current.password_hash != account.password_hash:
                    # Changed meanwhile (a parallel sign-in upgraded it, or
                    # the password was changed): check against what is there now.
                    return current if current and verify_password(password, current.password_hash) else None
                users[username] = replace(current, password_hash=hash_password(password))
                self._write(users)
                account = users[username]
        return account

    # -- writing -----------------------------------------------------------

    def _write(self, users: dict[str, AdminAccount], policy: dict | None = None) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        policy = self.policy() if policy is None else policy
        data = {
            "version": 2,
            "users": {
                name: {"password_hash": a.password_hash, "role": a.role,
                       **({"must_change": True} if a.must_change else {}),
                       **({"mfa": a.mfa} if a.mfa else {})}
                for name, a in sorted(users.items())
            },
            **({"policy": policy} if policy else {}),
        }
        tmp_path = self.path.with_suffix(".tmp")
        tmp_path.unlink(missing_ok=True)
        # Security-lessons G3: 0600 from creation -- only the webUI account
        # reads the hashes, and never through a moment of 0644.
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(data, indent=1))
        if os.geteuid() == 0:
            # Written by root (`firewall-cli set-admin-password`, first
            # boot): hand the file to whoever owns the state directory --
            # the webUI's own account -- or the webUI can't read it and
            # every page is a 500 (found booting the image for real).
            parent = self.path.parent.stat()
            os.chown(tmp_path, parent.st_uid, parent.st_gid)
        tmp_path.replace(self.path)

    @_serialized
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
        # A password change keeps the account's second factors.
        users[username] = AdminAccount(username, hash_password(password), new_role, must_change,
                                       dict(existing.mfa) if existing else {})
        self._write(users)

    @_serialized
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

    @_serialized
    def add_user(self, username: str, password: str, role: str) -> None:
        validate_username(username)
        validate_password(password)
        if role not in ROLES:
            raise AccountError(f"Unknown role {role!r}")
        if username in self.users():
            raise AccountError(f"User {username!r} already exists")
        self.set_password(username, password, role)

    @_serialized
    def set_role(self, username: str, role: str) -> None:
        if role not in ROLES:
            raise AccountError(f"Unknown role {role!r}")
        users = self.users()
        if username not in users:
            raise AccountError(f"No such user {username!r}")
        self._check_keeps_an_admin(users, username, role)
        users[username] = replace(users[username], role=role)
        self._write(users)

    @_serialized
    def delete_user(self, username: str) -> None:
        users = self.users()
        if username not in users:
            raise AccountError(f"No such user {username!r}")
        self._check_keeps_an_admin(users, username, None)
        del users[username]
        self._write(users)

    @_serialized
    def set_mfa(self, username: str, mfa: dict) -> AdminAccount:
        users = self.users()
        if username not in users:
            raise AccountError(f"No such user {username!r}")
        users[username] = replace(users[username], mfa=mfa)
        self._write(users)
        return users[username]

    def reset_mfa(self, username: str) -> None:
        """Remove every second factor (recovery: `firewall-cli mfa-reset`,
        or an admin on the Users screen)."""
        self.set_mfa(username, {})

    @_serialized
    def set_policy(self, *, require_mfa_for_admins: bool) -> None:
        policy = self.policy()
        policy["require_mfa_for_admins"] = bool(require_mfa_for_admins)
        self._write(self.users(), policy)

    @staticmethod
    def _check_keeps_an_admin(users: dict[str, AdminAccount], username: str, new_role: str | None) -> None:
        admins_after = {n for n, a in users.items() if a.is_admin and n != username}
        if new_role == ROLE_ADMIN:
            admins_after.add(username)
        if not admins_after:
            raise AccountError("At least one admin account must remain")
