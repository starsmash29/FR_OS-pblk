"""Second factors for webUI sign-in (security-lessons G5).

FortiBleed-style campaigns logged in with stolen or default passwords;
CISA's first recommendation was phishing-resistant MFA. FR_OS offers:

- **Security keys / passkeys (FIDO2, WebAuthn)** -- phishing-resistant:
  the browser binds each signature to the origin, so a look-alike site
  gets nothing usable. Verified with `py_webauthn`; browsers only allow
  it on a *name* (https://fr-router.lan/), never on an IP address.
- **Authenticator app codes (TOTP, RFC 6238)** via `pyotp` -- works
  everywhere, also on https://192.168.1.1/. Each 30 s step is accepted
  once (replayed codes are refused).

No protocol or crypto of our own (security-lessons F4): both come from
maintained libraries.

After the password, an account with a factor gets no session, only a
*login ticket*: a random 256-bit id in a cookie that the server keeps for
5 minutes, usable once, bound to the account and its password version,
and dropped after 5 wrong codes. Only the second step turns it into a
session.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import time
from dataclasses import dataclass, field

import pyotp
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from frfw.admin_account import AdminAccount
from frfw.validate import ArgumentError, hostname as valid_hostname

TICKET_COOKIE = "fr_os_mfa"
TICKET_SECONDS = 300
MAX_CODE_ATTEMPTS = 5
#: Wrong second factors per *account* (across tickets and addresses)
#: before its second step is refused for a while: someone who has the
#: password can't spread a code search over many tickets or a botnet.
MAX_ACCOUNT_FAILURES = 10
ACCOUNT_LOCK_SECONDS = 15 * 60
TOTP_ISSUER = "FR_OS"
RP_NAME = "FR_OS router"


# -- TOTP --------------------------------------------------------------------------------

def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str, host: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=f"{username}@{host}", issuer_name=TOTP_ISSUER)


def totp_step(secret: str, code: str, *, last_step: int = -1, now: float | None = None) -> int | None:
    """The time step `code` is valid for (current, or one either side for
    clock drift), if it is newer than `last_step` -- a code is accepted
    once. None when it doesn't match or was used already."""
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return None
    totp = pyotp.TOTP(secret)
    now = time.time() if now is None else now
    step = int(now // totp.interval)
    for candidate in (step - 1, step, step + 1):
        if candidate > last_step and secrets.compare_digest(totp.at(candidate * totp.interval), code):
            return candidate
    return None


# -- WebAuthn ------------------------------------------------------------------------------

def rp_id_for(host: str | None) -> str | None:
    """The relying-party id for the name the browser used, or None where
    WebAuthn can't work: browsers refuse IP addresses as RP ids."""
    if not host:
        return None
    try:
        valid_hostname(host)
    except ArgumentError:
        return None
    if all(part.isdigit() for part in host.split(".")):
        return None  # an IPv4 address also passes the host-name syntax
    return host.lower()


def origin_for(scheme: str, host: str, port: int | None) -> str:
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{host}" + ("" if port in (None, default) else f":{port}")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def registration_options(account: AdminAccount, rp_id: str) -> tuple[str, bytes]:
    existing = [PublicKeyCredentialDescriptor(id=_unb64(c["id"]))
                for c in account.mfa.get("webauthn", []) if c.get("rp_id") == rp_id]
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=hashlib.sha256(account.username.encode()).digest(),
        user_name=account.username,
        exclude_credentials=existing,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    return options_to_json(options), options.challenge


def verify_registration(credential_json: str, challenge: bytes, rp_id: str, origin: str, name: str) -> dict:
    verified = verify_registration_response(
        credential=credential_json,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
    )
    return {
        "id": _b64(verified.credential_id),
        "public_key": _b64(verified.credential_public_key),
        "sign_count": verified.sign_count,
        "rp_id": rp_id,
        "name": (name or "Security key").strip()[:40] or "Security key",
        "added": int(time.time()),
    }


def authentication_options(account: AdminAccount, rp_id: str) -> tuple[str, bytes]:
    allowed = [PublicKeyCredentialDescriptor(id=_unb64(c["id"]))
               for c in account.mfa.get("webauthn", []) if c.get("rp_id") == rp_id]
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allowed,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return options_to_json(options), options.challenge


def verify_authentication(account: AdminAccount, credential_json: str, challenge: bytes,
                          rp_id: str, origin: str) -> dict:
    """The updated credential list (new sign count) on success; raises on
    anything else -- an unknown key, a wrong origin or challenge, a bad
    signature, a sign count that went backwards."""
    import json

    credential_id = json.loads(credential_json).get("id", "")
    stored = [dict(c) for c in account.mfa.get("webauthn", [])]
    match = next((c for c in stored if c["id"] == credential_id and c.get("rp_id") == rp_id), None)
    if match is None:
        raise ValueError("this security key is not registered for this account")
    verified = verify_authentication_response(
        credential=credential_json,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=_unb64(match["public_key"]),
        credential_current_sign_count=match["sign_count"],
    )
    match["sign_count"] = verified.new_sign_count
    return {**account.mfa, "webauthn": stored}


# -- login tickets and pending challenges -----------------------------------------------------

@dataclass
class _Entry:
    user: str
    version: str
    expires: float
    attempts: int = 0
    data: dict = field(default_factory=dict)


class TicketStore:
    """Short-lived, single-use server-side state keyed by a random id: the
    password-then-second-factor login tickets, and the challenges of an
    enrolment in progress. In memory -- a webUI restart just means
    signing in again."""

    def __init__(self, lifetime: float = TICKET_SECONDS) -> None:
        self.lifetime = lifetime
        self._entries: dict[str, _Entry] = {}
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(tid: str) -> str:
        return hashlib.sha256(tid.encode()).hexdigest()

    def create(self, account: AdminAccount) -> str:
        tid = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._entries = {k: v for k, v in self._entries.items() if v.expires > now}
            self._entries[self._key(tid)] = _Entry(account.username, account.session_version(), now + self.lifetime)
        return tid

    def get(self, tid: str | None, account_of) -> tuple[_Entry, AdminAccount] | None:
        """The live entry and its (re-read) account, or None -- expired,
        unknown, or the password changed since."""
        if not tid:
            return None
        entry = self._entries.get(self._key(tid))
        if entry is None or entry.expires <= time.time():
            return None
        account = account_of(entry.user)
        if account is None or account.session_version() != entry.version:
            return None
        return entry, account

    def account_locked(self, username: str) -> bool:
        """Too many wrong second factors for `username` lately."""
        cutoff = time.time() - ACCOUNT_LOCK_SECONDS
        with self._lock:
            recent = [t for t in self._failures.get(username, []) if t > cutoff]
            self._failures[username] = recent
            return len(recent) >= MAX_ACCOUNT_FAILURES

    def fail(self, tid: str) -> bool:
        """Count a wrong code; True while the ticket may still be used."""
        with self._lock:
            entry = self._entries.get(self._key(tid))
            if entry is None:
                return False
            self._failures.setdefault(entry.user, []).append(time.time())
            entry.attempts += 1
            if entry.attempts >= MAX_CODE_ATTEMPTS:
                del self._entries[self._key(tid)]
                return False
            return True

    def consume(self, tid: str) -> bool:
        """Use a ticket up; True only for the one caller that got it."""
        with self._lock:
            return self._entries.pop(self._key(tid), None) is not None
