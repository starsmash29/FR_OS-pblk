"""Security-lessons G5: a second factor for webUI sign-in.

The password alone must stop being enough once an account has a factor:
the password step gives only a short-lived, single-use ticket, and only
a valid TOTP code or a security-key assertion turns it into a session.
WebAuthn is exercised end to end with a software authenticator (real
ES256 keys, real CBOR attestation and assertion), so the tests run the
same py_webauthn verification a browser's answer goes through.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import threading
import time

import cbor2
import pyotp
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from frfw import cli
from frfw.admin_account import ROLE_ADMIN, ROLE_VIEWER
from frfw.webui import mfa
from frfw.webui.app import create_app
from frfw.webui.auth import COOKIE_NAME

ORIGIN = "https://fr-router.lan"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SoftKey:
    """A FIDO2 authenticator in software: one ES256 credential, "none"
    attestation, user presence, a counter."""

    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = hashlib.sha256(str(id(self)).encode() + str(time.time()).encode()).digest()
        self.counter = 0

    def _cose_public_key(self) -> bytes:
        numbers = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")})

    @staticmethod
    def _client_data(kind: str, challenge: str, origin: str) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False}).encode()

    def create(self, options: dict, origin: str = ORIGIN, rp_id: str | None = None) -> dict:
        rp_id = rp_id or options["rp"]["id"]
        auth_data = (hashlib.sha256(rp_id.encode()).digest() + bytes([0x41]) + struct.pack(">I", self.counter)
                     + bytes(16) + struct.pack(">H", len(self.credential_id)) + self.credential_id
                     + self._cose_public_key())
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {"id": b64(self.credential_id), "rawId": b64(self.credential_id), "type": "public-key",
                "response": {"clientDataJSON": b64(client_data), "attestationObject": b64(attestation)},
                "clientExtensionResults": {}}

    def get(self, options: dict, origin: str = ORIGIN, rp_id: str | None = None, counter: int | None = None) -> dict:
        rp_id = rp_id or options["rpId"]
        self.counter = self.counter + 1 if counter is None else counter
        auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([0x01]) + struct.pack(">I", self.counter)
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        signature = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64(self.credential_id), "rawId": b64(self.credential_id), "type": "public-key",
                "response": {"clientDataJSON": b64(client_data), "authenticatorData": b64(auth_data),
                             "signature": b64(signature), "userHandle": None},
                "clientExtensionResults": {}}


@pytest.fixture
def store(webui_env):
    store = webui_env["admin_store"]
    store.set_password("boss", "adminpass-001", ROLE_ADMIN)
    store.set_password("guest", "viewerpass-01", ROLE_VIEWER)
    return store


def _client(app, base_url: str = ORIGIN) -> TestClient:
    return TestClient(app, base_url=base_url, follow_redirects=False)


def _signed_in(app, username="boss", password="adminpass-001", base_url: str = ORIGIN) -> TestClient:
    client = _client(app, base_url)
    assert client.post("/login", data={"username": username, "password": password}).headers["location"] == "/"
    return client


def _add_totp(app, username="boss", password="adminpass-001", base_url: str = ORIGIN) -> str:
    """Enrol an authenticator app the way a user does; returns its secret."""
    client = _signed_in(app, username, password, base_url)
    page = client.get("/account/mfa/totp").text
    tid = page.split('name="tid" value="')[1].split('"')[0]
    secret = page.split("Key: <code>")[1].split("<")[0]
    response = client.post("/account/mfa/totp", data={"tid": tid, "code": pyotp.TOTP(secret).now(),
                                                      "password": password})
    assert "success" in response.headers["location"], response.headers["location"]
    return secret


def _add_key(app, key: SoftKey, username="boss", password="adminpass-001") -> None:
    client = _signed_in(app, username, password)
    start = client.post("/account/mfa/webauthn/options", json={"password": password, "name": "yubi"}).json()
    response = client.post("/account/mfa/webauthn/register",
                           json={"tid": start["tid"], "credential": key.create(start["options"])})
    assert response.status_code == 200, response.text


def _password_step(app, username="boss", password="adminpass-001", base_url: str = ORIGIN) -> TestClient:
    client = _client(app, base_url)
    response = client.post("/login", data={"username": username, "password": password})
    assert response.status_code == 303 and response.headers["location"] == "/login/mfa"
    assert COOKIE_NAME not in response.cookies  # no session from the password alone
    return client


def _next_code(secret: str) -> str:
    """A valid code for the *next* time step (accepted for clock drift),
    so a test never collides with a code already used this step."""
    totp = pyotp.TOTP(secret)
    return totp.at(time.time() + totp.interval)


# -- TOTP -------------------------------------------------------------------------------------


def test_the_password_alone_no_longer_signs_in(app, store):
    secret = _add_totp(app)
    client = _password_step(app)
    assert client.get("/").status_code == 303  # the ticket is not a session
    assert client.get("/account").headers["location"] == "/login"
    response = client.post("/login/mfa/totp", data={"code": _next_code(secret)})
    assert response.headers["location"] == "/"
    assert client.get("/account").status_code == 200


def test_a_totp_code_works_only_once(app, store):
    secret = _add_totp(app)
    code = _next_code(secret)
    assert _password_step(app).post("/login/mfa/totp", data={"code": code}).headers["location"] == "/"
    replay = _password_step(app).post("/login/mfa/totp", data={"code": code})
    assert replay.headers["location"].startswith("/login/mfa?error=")


def test_the_same_code_in_parallel_signs_in_once(app, store):
    secret = _add_totp(app)
    code = _next_code(secret)
    clients = [_password_step(app) for _ in range(6)]
    results = []

    def attempt(client):
        results.append(client.post("/login/mfa/totp", data={"code": code}).headers["location"])

    threads = [threading.Thread(target=attempt, args=(c,)) for c in clients]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("/") == 1, results


def test_wrong_codes_use_up_the_ticket_and_count_as_failed_logins(app, store, webui_env):
    _add_totp(app)
    client = _password_step(app)
    for _ in range(mfa.MAX_CODE_ATTEMPTS - 1):
        assert client.post("/login/mfa/totp", data={"code": "000000"}).headers["location"].startswith("/login/mfa")
    last = client.post("/login/mfa/totp", data={"code": "000000"})
    assert last.headers["location"].startswith("/login?")  # the ticket is gone: start over
    assert client.get("/login/mfa").headers["location"].startswith("/login?")
    assert webui_env["helper"].banned  # and the brute-force guard jailed the address


def test_a_ticket_is_single_use(app, store):
    secret = _add_totp(app)
    client = _password_step(app)
    ticket = client.cookies[mfa.TICKET_COOKIE]
    assert client.post("/login/mfa/totp", data={"code": _next_code(secret)}).headers["location"] == "/"
    thief = _client(app)
    thief.cookies.set(mfa.TICKET_COOKIE, ticket, path="/login")
    assert thief.get("/login/mfa").headers["location"].startswith("/login?")


def test_an_expired_ticket_is_refused(app, store, monkeypatch):
    secret = _add_totp(app)
    client = _password_step(app)
    real_time = time.time
    monkeypatch.setattr(mfa.time, "time", lambda: real_time() + mfa.TICKET_SECONDS + 1)
    assert client.post("/login/mfa/totp", data={"code": _next_code(secret)}).headers["location"].startswith("/login?")


def test_a_ticket_dies_with_a_password_change(app, store):
    secret = _add_totp(app)
    client = _password_step(app)
    store.set_password("boss", "otherpass-001", ROLE_ADMIN)
    assert client.post("/login/mfa/totp", data={"code": _next_code(secret)}).headers["location"].startswith("/login?")


def test_a_forged_ticket_gets_nothing(app, store):
    _add_totp(app)
    client = _client(app)
    client.cookies.set(mfa.TICKET_COOKIE, "made-up", path="/login")
    assert client.post("/login/mfa/totp", data={"code": "123456"}).headers["location"].startswith("/login?")
    assert client.get("/").status_code == 303


def test_enrolment_needs_the_password_and_a_working_code(app, store):
    client = _signed_in(app)
    page = client.get("/account/mfa/totp").text
    tid = page.split('name="tid" value="')[1].split('"')[0]
    secret = page.split("Key: <code>")[1].split("<")[0]
    wrong_password = client.post("/account/mfa/totp", data={"tid": tid, "code": pyotp.TOTP(secret).now(),
                                                            "password": "not-it"})
    assert "error" in wrong_password.headers["location"]
    wrong_code = client.post("/account/mfa/totp", data={"tid": tid, "code": "000000", "password": "adminpass-001"})
    assert "error" in wrong_code.headers["location"]
    assert not store.get("boss").has_mfa
    # Another account can't finish someone else's enrolment.
    other = _signed_in(app, "guest", "viewerpass-01")
    stolen = other.post("/account/mfa/totp", data={"tid": tid, "code": pyotp.TOTP(secret).now(),
                                                   "password": "viewerpass-01"})
    assert "error" in stolen.headers["location"] and not store.get("guest").has_mfa


def test_removing_a_factor_needs_the_password(app, store):
    _add_totp(app)
    client = _signed_in_with_totp(app)
    assert "error" in client.post("/account/mfa/remove", data={"kind": "totp", "password": "x"}).headers["location"]
    assert store.get("boss").has_mfa
    client.post("/account/mfa/remove", data={"kind": "totp", "password": "adminpass-001"})
    assert not store.get("boss").has_mfa


def _signed_in_with_totp(app) -> TestClient:
    client = _password_step(app)
    secret = app.state.admin_store.get("boss").mfa["totp"]["secret"]
    # The earliest step in the +-1 window that no earlier sign-in used.
    totp = pyotp.TOTP(secret)
    last = app.state.admin_store.get("boss").mfa["totp"]["last_step"]
    now_step = int(time.time() // totp.interval)
    candidate = max(now_step - 1, last + 1)
    assert candidate <= now_step + 1, "no unused TOTP step left in the window"
    response = client.post("/login/mfa/totp", data={"code": totp.at(candidate * totp.interval)})
    assert response.headers["location"] == "/"
    return client


def test_a_viewer_can_add_a_second_factor_too(app, store):
    _add_totp(app, "guest", "viewerpass-01")
    assert store.get("guest").has_mfa


def test_the_totp_secret_is_never_shown_after_enrolment(app, store):
    secret = _add_totp(app)
    client = _signed_in_with_totp(app)
    for path in ("/account", "/account/mfa", "/users"):
        assert secret not in client.get(path).text


# -- the admin policy and recovery ---------------------------------------------------------------------


def test_required_mfa_confines_an_admin_without_one_to_enrolment(app, store):
    admin = _signed_in(app)
    admin.post("/users/mfa-policy", data={"require": "true"})
    assert admin.get("/").headers["location"] == "/account/mfa"
    assert admin.get("/rules").headers["location"] == "/account/mfa"
    assert admin.post("/rules/add", data={}).headers["location"] == "/account/mfa"
    assert admin.get("/account/mfa").status_code == 200
    _add_totp_on(admin)
    assert admin.get("/").status_code == 200
    # Viewers aren't forced (they can't change anything anyway).
    assert _signed_in(app, "guest", "viewerpass-01").get("/").status_code == 200


def _add_totp_on(client: TestClient) -> None:
    page = client.get("/account/mfa/totp").text
    tid = page.split('name="tid" value="')[1].split('"')[0]
    secret = page.split("Key: <code>")[1].split("<")[0]
    client.post("/account/mfa/totp", data={"tid": tid, "code": pyotp.TOTP(secret).now(), "password": "adminpass-001"})


def test_an_admin_reset_removes_the_factors_and_ends_the_sessions(app, store):
    store.add_user("boss2", "adminpass-002", ROLE_ADMIN)
    _add_totp(app, "boss2", "adminpass-002")
    assert store.get("boss2").has_mfa
    victim_session = _password_step(app, "boss2", "adminpass-002")  # mid-login
    admin = _signed_in(app)
    admin.post("/users/boss2/mfa-reset")
    assert not store.get("boss2").has_mfa
    # A sign-in half-way through gets no session from it either.
    assert victim_session.post("/login/mfa/totp", data={"code": "123456"}).headers["location"] != "/"
    assert _signed_in(app, "boss2", "adminpass-002").get("/").status_code == 200


def test_the_cli_reset(app, store, webui_env, monkeypatch, capsys):
    from frfw import paths
    from frfw.admin_account import AdminStore

    _add_totp(app)
    session = _signed_in_with_totp(app)
    monkeypatch.setattr(cli, "AdminStore", lambda: AdminStore(store.path))
    monkeypatch.setattr(paths, "WEBUI_SECRET_KEY_PATH", store.path.with_name("secret.key"))
    assert cli.main(["mfa-reset", "boss"]) == 0
    assert not store.get("boss").has_mfa
    assert session.get("/account").status_code == 303  # its session ended with it
    assert cli.main(["mfa-reset", "nobody"]) == 1


def test_mfa_routes_need_the_right_role(app, store):
    viewer = _signed_in(app, "guest", "viewerpass-01")
    assert viewer.post("/users/mfa-policy", data={"require": "true"}).status_code == 403
    assert viewer.post("/users/boss/mfa-reset").status_code == 403
    assert not store.policy().get("require_mfa_for_admins")


# -- security keys (WebAuthn) -----------------------------------------------------------------------


def test_a_security_key_signs_in(app, store):
    key = SoftKey()
    _add_key(app, key)
    stored = store.get("boss").mfa["webauthn"][0]
    assert stored["rp_id"] == "fr-router.lan" and stored["name"] == "yubi"
    client = _password_step(app)
    options = client.post("/login/mfa/webauthn/options").json()
    response = client.post("/login/mfa/webauthn/verify", json=key.get(options))
    assert response.status_code == 200 and response.json() == {"redirect": "/"}
    assert client.get("/account").status_code == 200
    assert store.get("boss").mfa["webauthn"][0]["sign_count"] == key.counter


def test_a_phishing_origin_is_refused(app, store):
    key = SoftKey()
    _add_key(app, key)
    client = _password_step(app)
    options = client.post("/login/mfa/webauthn/options").json()
    # The browser signs the origin it really is on: a look-alike site.
    response = client.post("/login/mfa/webauthn/verify", json=key.get(options, origin="https://fr-router.lan.evil.test"))
    assert response.status_code == 403
    assert client.get("/account").status_code == 303


def test_a_replayed_assertion_is_refused(app, store):
    key = SoftKey()
    _add_key(app, key)
    client = _password_step(app)
    options = client.post("/login/mfa/webauthn/options").json()
    assertion = key.get(options)
    assert client.post("/login/mfa/webauthn/verify", json=assertion).status_code == 200
    again = _password_step(app)
    again.post("/login/mfa/webauthn/options")  # a new challenge; the old answer doesn't fit it
    assert again.post("/login/mfa/webauthn/verify", json=assertion).status_code == 403


def test_a_cloned_key_is_detected_by_its_counter(app, store):
    key = SoftKey()
    _add_key(app, key)
    client = _password_step(app)
    options = client.post("/login/mfa/webauthn/options").json()
    assert client.post("/login/mfa/webauthn/verify", json=key.get(options, counter=10)).status_code == 200
    clone = _password_step(app)
    options = clone.post("/login/mfa/webauthn/options").json()
    assert clone.post("/login/mfa/webauthn/verify", json=key.get(options, counter=5)).status_code == 403


def test_an_unregistered_key_is_refused(app, store):
    _add_key(app, SoftKey())
    client = _password_step(app)
    options = client.post("/login/mfa/webauthn/options").json()
    assert client.post("/login/mfa/webauthn/verify", json=SoftKey().get(options)).status_code == 403


def test_verify_without_options_is_refused(app, store):
    key = SoftKey()
    _add_key(app, key)
    client = _password_step(app)
    fake_options = {"challenge": b64(b"x" * 32), "rpId": "fr-router.lan"}
    assert client.post("/login/mfa/webauthn/verify", json=key.get(fake_options)).status_code == 400


def test_registration_checks_origin_and_password(app, store):
    client = _signed_in(app)
    assert client.post("/account/mfa/webauthn/options", json={"password": "wrong"}).status_code == 403
    start = client.post("/account/mfa/webauthn/options", json={"password": "adminpass-001"}).json()
    bad = client.post("/account/mfa/webauthn/register",
                      json={"tid": start["tid"], "credential": SoftKey().create(start["options"],
                                                                                origin="https://evil.test")})
    assert bad.status_code == 400 and not store.get("boss").has_mfa
    # The enrolment id is single-use, also after a failure.
    retry = client.post("/account/mfa/webauthn/register",
                        json={"tid": start["tid"], "credential": SoftKey().create(start["options"])})
    assert retry.status_code == 400 and not store.get("boss").has_mfa


def test_no_security_keys_on_an_ip_address(app, store):
    assert mfa.rp_id_for("192.168.1.1") is None
    assert mfa.rp_id_for("fr-router.lan") == "fr-router.lan"
    assert mfa.rp_id_for(None) is None
    client = _signed_in(app, base_url="https://192.168.1.1")
    assert client.post("/account/mfa/webauthn/options", json={"password": "adminpass-001"}).status_code == 400
    assert "not an IP address" in client.get("/account/mfa").text


def test_keys_added_by_name_offer_the_app_code_on_an_ip(app, store):
    _add_key(app, SoftKey())
    client = _password_step(app, base_url="https://192.168.1.1")
    page = client.get("/login/mfa").text
    assert "only when the router is opened by the name" in page
    assert client.post("/login/mfa/webauthn/options").status_code == 400


def test_the_stored_factors_never_leave_in_a_page(app, store):
    secret = _add_totp(app)
    client = _signed_in_with_totp(app)
    start = client.post("/account/mfa/webauthn/options", json={"password": "adminpass-001"}).json()
    assert client.post("/account/mfa/webauthn/register",
                       json={"tid": start["tid"], "credential": SoftKey().create(start["options"])}).status_code == 200
    stored = store.get("boss").mfa
    for path in ("/account", "/account/mfa", "/users", "/"):
        body = client.get(path).text
        assert secret not in body
        assert stored["webauthn"][0]["public_key"] not in body


def test_wrong_codes_across_many_tickets_lock_the_account(app, store, webui_env):
    """Someone who has the password can't search the code space by
    taking a new ticket every 5 tries, from ever-new addresses."""
    secret = _add_totp(app)
    ticket_before_lock = _password_step(app)
    guard = webui_env["bruteforce_guard"]
    wrong = 0
    while wrong < mfa.MAX_ACCOUNT_FAILURES:
        client = _password_step(app)
        for _ in range(2):
            client.post("/login/mfa/totp", data={"code": "000000"})
            wrong += 1
        guard.record_success("testclient")  # as if each came from a fresh address
    locked = _client(app).post("/login", data={"username": "boss", "password": "adminpass-001"})
    assert locked.headers["location"].startswith("/login?error=Too+many+wrong+second-factor")
    assert mfa.TICKET_COOKIE not in locked.cookies
    # The right code doesn't get through a ticket taken just before either.
    response = ticket_before_lock.post("/login/mfa/totp", data={"code": _next_code(secret)})
    assert response.headers["location"].startswith("/login?")
