from __future__ import annotations

from fastapi.testclient import TestClient

from frfw.admin_account import hash_password
from frfw.config import load_config


def _seed_interface(client):
    # frfw.config.loader requires at least one interface for *any* config
    # to validate at all -- every test below that saves anything through
    # try_save needs this first, same as test_ai_ids_routes.py's pattern.
    client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )


def _enable_ztna_with_user(logged_in_client, username="alice", password="zebra-lamp-42"):
    _seed_interface(logged_in_client)
    # The user must exist *before* enabling: /ztna/settings validates the
    # whole config immediately, and enabled=true with zero users is
    # rejected by _parse_ztna (see test_enabling_with_no_users_is_rejected).
    logged_in_client.post(
        "/ztna/users/add", data={"new_username": username, "new_password": password}
    )
    logged_in_client.post(
        "/ztna/settings", data={"enabled": "true", "session_ttl_seconds": 3600}
    )


# --- admin settings screen (require_login) ----------------------------------


def test_ztna_admin_page_requires_login(client):
    response = client.get("/ztna")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_ztna_admin_page_shows_disabled_by_default(logged_in_client):
    response = logged_in_client.get("/ztna")
    assert response.status_code == 200
    assert "Disabled" in response.text
    assert "badge-red" in response.text


def test_save_settings_persists_enabled_and_ttl(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    logged_in_client.post(
        "/ztna/users/add", data={"new_username": "alice", "new_password": "zebra-lamp-4242"}
    )
    response = logged_in_client.post(
        "/ztna/settings", data={"enabled": "true", "session_ttl_seconds": 1800}
    )
    assert "success" in response.headers["location"]

    config = load_config(webui_env["config_path"])
    # enabling with no users yet is allowed at the settings-save level
    # (the two are separate forms) but parse_config itself would reject
    # enabled+no-users -- try_save's validation catches that combination.
    assert config.ztna.session_ttl_seconds == 1800


def test_enabling_with_no_users_is_rejected_by_validation(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    response = logged_in_client.post(
        "/ztna/settings", data={"enabled": "true", "session_ttl_seconds": 3600}
    )
    assert "error" in response.headers["location"]
    assert "no+users" in response.headers["location"].lower()


def test_add_user_hashes_password_before_saving(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    logged_in_client.post(
        "/ztna/users/add", data={"new_username": "alice", "new_password": "zebra-lamp-4242"}
    )
    config = load_config(webui_env["config_path"])
    assert len(config.ztna.users) == 1
    assert config.ztna.users[0].username == "alice"
    assert config.ztna.users[0].password_hash != "zebra-lamp-4242"
    assert config.ztna.users[0].password_hash.startswith("scrypt$")


def test_add_user_rejects_short_password(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    response = logged_in_client.post(
        "/ztna/users/add", data={"new_username": "alice", "new_password": "short"}
    )
    assert "error" in response.headers["location"]

    config = load_config(webui_env["config_path"])
    assert config.ztna.users == []


def test_remove_user(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    logged_in_client.post(
        "/ztna/users/add", data={"new_username": "alice", "new_password": "zebra-lamp-4242"}
    )
    response = logged_in_client.post("/ztna/users/remove/alice")
    assert "success" in response.headers["location"]

    config = load_config(webui_env["config_path"])
    assert config.ztna.users == []


def test_remove_nonexistent_user_reports_error(logged_in_client):
    _seed_interface(logged_in_client)
    response = logged_in_client.post("/ztna/users/remove/nobody")
    assert "error" in response.headers["location"]


def test_admin_page_lists_gated_rules(logged_in_client):
    _seed_interface(logged_in_client)
    logged_in_client.post(
        "/interfaces/save", data={"name": "lan", "device": "eth1", "zone": "lan", "address": ""}
    )
    logged_in_client.post(
        "/rules/add",
        data={
            "name": "gated-rule",
            "action": "accept",
            "from_zone": "lan",
            "to_zone": "wan",
            "require_ztna": "true",
        },
    )

    page = logged_in_client.get("/ztna")
    assert "gated-rule" in page.text


# --- public end-user pages ---------------------------------------------------


def test_login_page_is_public(client):
    response = client.get("/ztna/login")
    assert response.status_code == 200
    assert "Sign in" in response.text


def test_status_page_is_public(client):
    response = client.get("/ztna/status")
    assert response.status_code == 200
    assert "Not authorized" in response.text


def test_login_fails_when_gate_disabled(client):
    response = client.post("/ztna/login", data={"username": "alice", "password": "zebra-lamp-42"})
    assert response.status_code == 303
    assert "error" in response.headers["location"]
    assert "disabled" in response.headers["location"].lower()


def test_login_fails_with_wrong_password(logged_in_client, client):
    _enable_ztna_with_user(logged_in_client)

    response = client.post("/ztna/login", data={"username": "alice", "password": "wrong-password"})
    assert "error" in response.headers["location"]


def test_login_fails_with_unknown_username(logged_in_client, client):
    _enable_ztna_with_user(logged_in_client)

    response = client.post("/ztna/login", data={"username": "mallory", "password": "zebra-lamp-42"})
    assert "error" in response.headers["location"]


def test_successful_login_authorizes_ip_and_redirects_to_status(logged_in_client, client, webui_env):
    _enable_ztna_with_user(logged_in_client)

    response = client.post("/ztna/login", data={"username": "alice", "password": "zebra-lamp-42"})
    assert response.status_code == 303
    assert response.headers["location"].startswith("/ztna/status")

    status = client.get("/ztna/status")
    assert "Authorized" in status.text
    assert "alice" in status.text


def test_login_reports_helper_failure(logged_in_client, client, webui_env):
    _enable_ztna_with_user(logged_in_client)
    webui_env["helper"].authorize_ztna = lambda ip, username: {
        "ok": False,
        "message": "kernel exploded",
    }

    response = client.post("/ztna/login", data={"username": "alice", "password": "zebra-lamp-42"})
    assert "error" in response.headers["location"]
    assert "kernel+exploded" in response.headers["location"]


def test_status_page_shows_what_the_sign_in_is_bound_to(logged_in_client, client):
    """ROADMAP SEC-6: the user sees that the session is this device's --
    the hardware address the router saw -- not their address's."""
    from tests.webui.conftest import FAKE_CLIENT_MAC

    _enable_ztna_with_user(logged_in_client)
    client.post("/ztna/login", data={"username": "alice", "password": "zebra-lamp-42"})
    status = client.get("/ztna/status")
    bound = status.text.split('id="ztna-bound">')[1].split("</dd>")[0]
    assert FAKE_CLIENT_MAC in bound


def test_status_page_names_the_wireguard_key_for_a_tunnel_client(logged_in_client, client, webui_env):
    _enable_ztna_with_user(logged_in_client)
    webui_env["helper"].ztna_status = lambda ip: {"ok": True, "authorized": True, "username": "alice",
                                                  "expires_in": 60, "mac": ""}
    bound = client.get("/ztna/status").text.split('id="ztna-bound">')[1].split("</dd>")[0]
    assert "your WireGuard key" in bound


def test_a_client_behind_another_router_is_told_to_use_wireguard(logged_in_client, client, webui_env):
    _enable_ztna_with_user(logged_in_client)
    webui_env["helper"].ztna_status = lambda ip: {"ok": True, "authorized": False, "direct": False}
    status = client.get("/ztna/status")
    assert "Not authorized" in status.text
    assert 'id="ztna-not-direct"' in status.text and "WireGuard VPN" in status.text
    assert "not currently authorized" not in status.text


def test_status_page_shows_not_authorized_before_login(logged_in_client, client):
    _enable_ztna_with_user(logged_in_client)
    response = client.get("/ztna/status")
    assert "Not authorized" in response.text


# --- brute-force rate limiting -----------------------------------------------


def test_five_failed_ztna_logins_from_same_ip_trigger_a_ban(app, logged_in_client, webui_env):
    _enable_ztna_with_user(logged_in_client)
    attacker = TestClient(app, client=("198.51.100.5", 12345), follow_redirects=False)

    for _ in range(4):
        response = attacker.post("/ztna/login", data={"username": "alice", "password": "wrong"})
        assert "error" in response.headers["location"]
        assert "blocked" not in response.headers["location"].lower()

    fifth = attacker.post("/ztna/login", data={"username": "alice", "password": "wrong"})
    assert "blocked" in fifth.headers["location"].lower()

    assert webui_env["helper"].banned == [("198.51.100.5", 60 * 60)]


def test_successful_ztna_login_resets_the_failure_counter(app, logged_in_client, webui_env):
    _enable_ztna_with_user(logged_in_client)
    attacker = TestClient(app, client=("198.51.100.9", 12345), follow_redirects=False)

    for _ in range(4):
        attacker.post("/ztna/login", data={"username": "alice", "password": "wrong"})
    success = attacker.post("/ztna/login", data={"username": "alice", "password": "zebra-lamp-42"})
    assert success.headers["location"].startswith("/ztna/status")

    for _ in range(4):
        response = attacker.post("/ztna/login", data={"username": "alice", "password": "wrong"})
        assert "error" in response.headers["location"]

    assert webui_env["helper"].banned == []


def test_ztna_and_admin_login_failures_share_the_same_ip_counter(app, logged_in_client, webui_env):
    """The guard is keyed purely by source IP, not by which login form was
    used -- an attacker can't dodge the threshold by alternating between
    /login and /ztna/login from the same address."""
    _enable_ztna_with_user(logged_in_client)
    attacker = TestClient(app, client=("198.51.100.20", 12345), follow_redirects=False)

    attacker.post("/login", data={"username": "admin", "password": "wrong"})
    attacker.post("/login", data={"username": "admin", "password": "wrong"})
    attacker.post("/ztna/login", data={"username": "alice", "password": "wrong"})
    attacker.post("/ztna/login", data={"username": "alice", "password": "wrong"})
    fifth = attacker.post("/login", data={"username": "admin", "password": "wrong"})

    assert "blocked" in fifth.headers["location"].lower()
    assert webui_env["helper"].banned == [("198.51.100.20", 60 * 60)]
