"""Session handling for the webUI, plus the admin-account types it needs.

The admin account itself (`AdminAccount`/`AdminStore`, PBKDF2 hashing)
lives in `frfw.admin_account` -- it's stdlib-only and shared with
`firewall-cli set-admin-password`, which must not require the webUI's
extra dependencies. Only the session-cookie signing here needs
itsdangerous, so that stays webUI-only.

Sessions are a signed (not encrypted) cookie -- the payload (a username,
the account's session version and a session id) isn't secret, only
tamper-proof -- and the session id must also still be in the server-side
SessionStore (security-lessons G7), so logging out really ends it. The session
version (phase 18, `AdminAccount.session_version`) changes with the
password, and every request re-reads the account (frfw.webui.deps.
require_login), so deleting an account, changing its role or password
takes effect on that account's open sessions at once.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
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


class SessionStore:
    """The sessions that are still valid, on the server (security-lessons
    G7). A cookie alone used to be enough until it expired: logging out
    only deleted it in the browser, so a stolen copy kept working for up
    to 12 h. Now every cookie names a session id that must also be listed
    here; logout, "log out everywhere", a password change or reset and
    deleting the account remove it.

    Only a SHA-256 of each id is stored, so the file itself holds nothing
    a browser could present. 0600, next to the session key; if it is
    lost, everyone is signed out (fails closed)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    @staticmethod
    def _key(sid: str) -> str:
        return hashlib.sha256(sid.encode()).hexdigest()

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.unlink(missing_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(data))
        tmp.replace(self.path)

    def add(self, username: str) -> str:
        sid = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            data = {k: v for k, v in self._load().items() if v.get("expires", 0) > now}
            data[self._key(sid)] = {"user": username, "expires": now + _SESSION_MAX_AGE_SECONDS}
            self._save(data)
        return sid

    def valid(self, sid: str, username: str) -> bool:
        entry = self._load().get(self._key(sid))
        return isinstance(entry, dict) and entry.get("user") == username and entry.get("expires", 0) > time.time()

    def revoke(self, sid: str) -> None:
        with self._lock:
            data = self._load()
            if data.pop(self._key(sid), None) is not None:
                self._save(data)

    def revoke_user(self, username: str) -> int:
        with self._lock:
            data = self._load()
            kept = {k: v for k, v in data.items() if v.get("user") != username}
            if len(kept) != len(data):
                self._save(kept)
            return len(data) - len(kept)


class SessionManager:
    def __init__(self, secret_key_path: Path = SECRET_KEY_PATH, sessions_path: Path | None = None) -> None:
        self._serializer = URLSafeTimedSerializer(_load_or_create_secret_key(secret_key_path))
        self.sessions = SessionStore(sessions_path or secret_key_path.with_name("sessions.json"))

    def create_cookie_value(self, account: AdminAccount) -> str:
        sid = self.sessions.add(account.username)
        return self._serializer.dumps({"username": account.username, "v": account.session_version(), "sid": sid})

    def _load(self, cookie_value: str | None) -> dict | None:
        if not cookie_value:
            return None
        try:
            data = self._serializer.loads(cookie_value, max_age=_SESSION_MAX_AGE_SECONDS)
        except (BadSignature, SignatureExpired):
            return None
        if not isinstance(data, dict) or not isinstance(data.get("username"), str) or not isinstance(data.get("sid"), str):
            return None
        return data

    def session_from_cookie(self, cookie_value: str | None) -> tuple[str, str] | None:
        """(username, session version) from a valid, unexpired cookie whose
        session the server still has."""
        data = self._load(cookie_value)
        if data is None or not self.sessions.valid(data["sid"], data["username"]):
            return None
        return data["username"], str(data.get("v", ""))

    def revoke_cookie(self, cookie_value: str | None) -> None:
        """Logout: this browser's session ends on the server too."""
        data = self._load(cookie_value)
        if data is not None:
            self.sessions.revoke(data["sid"])

    def revoke_user(self, username: str) -> int:
        """Every session of `username` ends ("log out everywhere", a
        password change or reset, deletion)."""
        return self.sessions.revoke_user(username)
