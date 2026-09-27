"""Security-lessons H1: the client never chooses how strictly it is
checked. Every authentication path -- webUI login and session, the ZTNA
gate, the /metrics token, the helper sockets -- fails closed on forged,
missing, replayed and downgraded credentials, and no request field,
header or cookie lowers the check.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time

import pytest
from fastapi.testclient import TestClient
from itsdangerous import URLSafeTimedSerializer

from frfw.admin_account import ROLE_ADMIN, ROLE_VIEWER, AdminStore, hash_password, verify_password
from frfw.helper import client as helper_client
from frfw.helper.peer import PeerPolicy
from frfw.helper.server import ApplyHelperServer
from frfw.helper.update_server import UpdateHelperServer
from frfw.metrics import generate_metrics_token, metrics_token_ok
from frfw.webui.auth import COOKIE_NAME

# -- webUI login ---------------------------------------------------------------------


@pytest.fixture
def admin(webui_env):
    webui_env["admin_store"].set_password("netadmin", "correct-horse-1", ROLE_ADMIN)
    return webui_env["admin_store"]


@pytest.mark.parametrize("username, password", [
    ("netadmin", "wrong"),
    ("netadmin", ""),
    ("netadmin\n", "correct-horse-1"),
    ("NETADMIN", "correct-horse-1"),
    ("netadmin ", "correct-horse-1"),
    ("nobody", "correct-horse-1"),
    ("netadmin", "correct-horse-1 "),
])
def test_login_rejects_wrong_or_mangled_credentials(client, admin, username, password):
    response = client.post("/login", data={"username": username, "password": password})
    # An empty field is refused by form validation (422), the rest by the check.
    assert response.status_code == 422 or response.headers["location"].startswith("/login?error=")
    assert COOKIE_NAME not in response.cookies


def test_login_rejects_missing_fields(client, admin):
    assert client.post("/login", data={"username": "netadmin"}).status_code == 422
    assert client.post("/login", data={}).status_code == 422


# -- webUI session ---------------------------------------------------------------------


def _session_cookie(client, username="netadmin", password="correct-horse-1") -> str:
    response = client.post("/login", data={"username": username, "password": password})
    return response.cookies[COOKIE_NAME]


def _get_with(app, cookie: str | None, path="/"):
    fresh = TestClient(app, follow_redirects=False)
    if cookie is not None:
        fresh.cookies.set(COOKIE_NAME, cookie)
    return fresh.get(path)


def test_missing_session_is_rejected(app, admin):
    assert _get_with(app, None).headers["location"] == "/login"


@pytest.mark.parametrize("cookie", ["", "x", "null", "e30", "eyJ1c2VybmFtZSI6Im5ldGFkbWluIn0.AAAA.BBBB"])
def test_forged_sessions_are_rejected(app, admin, cookie):
    assert _get_with(app, cookie).status_code == 303


def test_a_session_signed_with_another_key_is_rejected(app, admin):
    account = admin.get("netadmin")
    forged = URLSafeTimedSerializer(os.urandom(32)).dumps({"username": "netadmin", "v": account.session_version()})
    assert _get_with(app, forged).headers["location"] == "/login"


def test_a_tampered_session_is_rejected(client, app, admin):
    cookie = _session_cookie(client)
    payload, rest = cookie.split(".", 1)
    tampered = payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB") + "." + rest
    assert _get_with(app, tampered).headers["location"] == "/login"


def test_a_viewer_cannot_upgrade_itself(client, app, admin, webui_env):
    """No field, header or cookie may turn a viewer into an admin."""
    admin.set_password("watcher", "viewer-pass-1", ROLE_VIEWER)
    cookie = _session_cookie(client, "watcher", "viewer-pass-1")
    fresh = TestClient(app, follow_redirects=False)
    fresh.cookies.set(COOKIE_NAME, cookie)
    fresh.cookies.set("role", "admin")
    headers = {"X-FROS-Role": "admin", "X-Forwarded-User": "netadmin", "X-Remote-User": "netadmin",
               "X-Forwarded-For": "127.0.0.1"}
    response = fresh.post("/apply?role=admin&as=netadmin", data={"role": "admin", "username": "netadmin"},
                          headers=headers)
    assert response.status_code == 403
    assert fresh.get("/users", headers=headers).status_code == 403


def test_a_session_is_not_replayable_after_a_password_change(client, app, admin):
    cookie = _session_cookie(client)
    admin.set_password("netadmin", "a-new-password-2")
    assert _get_with(app, cookie).headers["location"] == "/login"


def test_a_session_is_not_replayable_after_the_account_is_deleted(client, app, admin):
    cookie = _session_cookie(client)
    admin.set_password("second", "second-pass-1", ROLE_ADMIN)
    admin.delete_user("netadmin")
    assert _get_with(app, cookie).headers["location"] == "/login"


def test_an_expired_session_is_rejected(client, app, admin, monkeypatch):
    cookie = _session_cookie(client)
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 13 * 3600)
    assert _get_with(app, cookie).headers["location"] == "/login"


def test_x_forwarded_for_does_not_dodge_the_brute_force_guard(app, admin, webui_env):
    attacker = TestClient(app, client=("203.0.113.50", 1234), follow_redirects=False)
    for i in range(10):
        attacker.post("/login", data={"username": "netadmin", "password": "wrong"},
                      headers={"X-Forwarded-For": f"10.0.0.{i}", "X-Real-IP": f"10.0.1.{i}"})
    assert {ip for ip, _ in webui_env["helper"].banned} == {"203.0.113.50"}


# -- stored hashes ---------------------------------------------------------------------


@pytest.mark.parametrize("stored", [
    "",
    "plain$correct-horse-1",
    "none$$$",
    "pbkdf2_sha256$1${salt}${digest}",       # downgraded to one iteration
    "pbkdf2_sha256$199999${salt}${digest}",
    "pbkdf2_sha1$200000${salt}${digest}",
    "pbkdf2_sha256$200000$${digest}",        # no salt
])
def test_a_weak_or_unknown_stored_hash_never_verifies(stored):
    salt = os.urandom(16)
    iterations = int(stored.split("$")[1]) if stored.count("$") == 3 and stored.split("$")[1].isdigit() else 1
    digest = hashlib.pbkdf2_hmac("sha256", b"correct-horse-1", salt, iterations).hex()
    assert not verify_password("correct-horse-1", stored.format(salt=salt.hex(), digest=digest))


def test_a_real_hash_still_verifies():
    assert verify_password("correct-horse-1", hash_password("correct-horse-1"))


# -- ZTNA gate ------------------------------------------------------------------------


@pytest.fixture
def ztna_on(webui_env):
    import yaml

    webui_env["config_path"].write_text(yaml.safe_dump({
        "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"}, "lan": {"device": "eth1", "zone": "lan"}},
        "rules": [], "nat": {"masquerade": [{"out_zone": "wan"}]},
        "ztna": {"enabled": True, "users": [{"username": "alice", "password_hash": hash_password("alice-pass-1")}]},
    }))
    return webui_env["helper"]


@pytest.mark.parametrize("username, password", [
    ("alice", "wrong"), ("alice", ""), ("bob", "alice-pass-1"), ("alice\n", "alice-pass-1"), ("ALICE", "alice-pass-1"),
])
def test_ztna_rejects_wrong_credentials(app, ztna_on, username, password):
    user = TestClient(app, client=("192.168.1.50", 5555), follow_redirects=False)
    user.post("/ztna/login", data={"username": username, "password": password})
    assert ztna_on.ztna_status("192.168.1.50")["authorized"] is False


def test_ztna_authorizes_the_connecting_address_not_a_claimed_one(app, ztna_on):
    user = TestClient(app, client=("192.168.1.50", 5555), follow_redirects=False)
    user.post("/ztna/login", data={"username": "alice", "password": "alice-pass-1", "ip": "192.168.1.99"},
              headers={"X-Forwarded-For": "192.168.1.99"})
    assert ztna_on.ztna_status("192.168.1.50")["authorized"] is True
    assert ztna_on.ztna_status("192.168.1.99")["authorized"] is False


# -- /metrics token ---------------------------------------------------------------------


@pytest.fixture
def metrics_config():
    token, digest = generate_metrics_token()
    return token, {"metrics": {"token_sha256": digest}}


@pytest.mark.parametrize("header", [
    None, "", "Bearer", "Bearer ", "Basic {token}", "Token {token}", "Bearer {token}x", "Bearer x{token}",
    "Bearer {upper}", "bearer-{token}",
])
def test_metrics_rejects_missing_forged_or_mangled_tokens(metrics_config, header):
    token, raw = metrics_config
    if header is not None:
        header = header.format(token=token, upper=token.upper())
    assert not metrics_token_ok(raw, header)
    assert metrics_token_ok(raw, f"Bearer {token}")


@pytest.mark.parametrize("digest", ["", "0" * 63, "not-hex" * 10, 12345, None])
def test_a_broken_configured_token_fails_closed(metrics_config, digest):
    token, _ = metrics_config
    raw = {"metrics": {"token_sha256": digest}}
    if digest is None:
        pytest.skip("no token configured means a public endpoint (review triage E3)")
    assert not metrics_token_ok(raw, f"Bearer {token}")


# -- the helper sockets ------------------------------------------------------------------


@pytest.fixture
def sensor_helper(tmp_path):
    """An apply-helper that sees the test process as a network-parsing daemon."""
    config = tmp_path / "config.yaml"
    config.write_text("version: 1\n")
    server = ApplyHelperServer(tmp_path / "apply.sock", config, backup_dir=tmp_path / "b",
                               peer_policy=PeerPolicy(sensor_uids=frozenset({os.geteuid()})))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield tmp_path / "apply.sock", config
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()


@pytest.mark.parametrize("claims", [
    {"uid": 0}, {"role": "full"}, {"peer": {"uid": 0}}, {"auth": "root"}, {"sudo": True},
])
def test_the_helper_ignores_what_a_request_claims_about_its_sender(sensor_helper, claims):
    sock, config = sensor_helper
    response = helper_client.send_command({"cmd": "save_config", "yaml": "version: 2\n", **claims}, sock)
    assert not response["ok"] and "not allowed" in response["message"]
    assert config.read_text() == "version: 1\n"


def test_the_update_helper_takes_no_verification_switch(tmp_path, monkeypatch):
    """No request field can skip the release signature check (A4)."""
    from frfw import update

    seen = []
    monkeypatch.setattr(update, "apply_update", lambda version, **kw: seen.append((version, kw)) or version)
    sock = tmp_path / "update.sock"
    server = UpdateHelperServer(sock, state_path=tmp_path / "s.json", releases_dir=tmp_path / "r",
                                peer_policy=PeerPolicy(full_uids=frozenset({os.geteuid()})))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        helper_client.send_command({"cmd": "apply", "version": "0.2.0", "skip_verify": True,
                                    "insecure": True, "verify": False, "keys": ["/tmp/evil.pem"]}, sock)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    [(version, kwargs)] = seen
    assert version == "0.2.0"
    assert set(kwargs) == {"repo", "state_path", "releases_dir"}
