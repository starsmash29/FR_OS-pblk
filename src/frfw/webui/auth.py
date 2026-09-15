"""Session handling for the webUI, plus the admin-account types it needs.

The admin account itself (`AdminAccount`/`AdminStore`, PBKDF2 hashing)
lives in `frfw.admin_account` -- it's stdlib-only and shared with
`firewall-cli set-admin-password`, which must not require the webUI's
extra dependencies. Only the session-cookie signing here needs
itsdangerous, so that stays webUI-only.

Sessions are a signed (not encrypted) cookie -- the payload (just a
username) isn't secret, only tamper-proof, so a plain signed timed token
needs no server-side session store.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from frfw import paths
from frfw.admin_account import AdminAccount, AdminStore

__all__ = ["AdminAccount", "AdminStore", "SessionManager", "COOKIE_NAME"]

SECRET_KEY_PATH = paths.WEBUI_SECRET_KEY_PATH

COOKIE_NAME = "fr_os_session"
_SESSION_MAX_AGE_SECONDS = 12 * 3600


def _load_or_create_secret_key(path: Path = SECRET_KEY_PATH) -> bytes:
    if path.is_file():
        return path.read_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_bytes(key)
    tmp_path.chmod(0o600)
    tmp_path.replace(path)
    return key


class SessionManager:
    def __init__(self, secret_key_path: Path = SECRET_KEY_PATH) -> None:
        self._serializer = URLSafeTimedSerializer(_load_or_create_secret_key(secret_key_path))

    def create_cookie_value(self, username: str) -> str:
        return self._serializer.dumps({"username": username})

    def username_from_cookie(self, cookie_value: str | None) -> str | None:
        if not cookie_value:
            return None
        try:
            data = self._serializer.loads(cookie_value, max_age=_SESSION_MAX_AGE_SECONDS)
        except (BadSignature, SignatureExpired):
            return None
        return data.get("username")
