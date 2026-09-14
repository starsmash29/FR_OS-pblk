"""The single local admin account used to log into the webUI.

Lives in core `frfw` (not `frfw.webui`) and is stdlib-only, because
`firewall-cli set-admin-password` needs it without requiring the webUI's
extra dependencies (fastapi, itsdangerous, ...) to be installed -- the
CLI and the webUI share this account, not just its concept.

Password-hashed with PBKDF2-HMAC-SHA256 from `hashlib` -- deliberately
not bcrypt/argon2, to avoid pulling a compiled C extension into a package
meant to install on whatever odd-architecture homelab hardware this
project targets. PBKDF2 with a high iteration count is a perfectly
adequate KDF for a single local admin account.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from pathlib import Path

from frfw import paths

AUTH_FILE_PATH = paths.WEBUI_AUTH_PATH

_PBKDF2_ALGORITHM = "pbkdf2_sha256"
_PBKDF2_ITERATIONS = 200_000


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


class AdminStore:
    """Reads/writes the single-admin-account file."""

    def __init__(self, path: Path = AUTH_FILE_PATH) -> None:
        self.path = path

    def exists(self) -> bool:
        return self.path.is_file()

    def load(self) -> AdminAccount | None:
        if not self.exists():
            return None
        data = json.loads(self.path.read_text())
        return AdminAccount(username=data["username"], password_hash=data["password_hash"])

    def set_password(self, username: str, password: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"username": username, "password_hash": hash_password(password)}
        tmp_path = self.path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data))
        tmp_path.chmod(0o640)
        tmp_path.replace(self.path)

    def verify(self, username: str, password: str) -> bool:
        account = self.load()
        if account is None or account.username != username:
            # Still run a hash to keep the timing similar whether or not
            # the username exists, rather than short-circuiting.
            hash_password(password)
            return False
        return verify_password(password, account.password_hash)
