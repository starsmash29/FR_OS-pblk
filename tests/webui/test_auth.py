from __future__ import annotations

from fastapi.testclient import TestClient


def test_unauthenticated_dashboard_redirects_to_login(client):
    response = client.get("/")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_login_page_shows_first_run_setup(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert "Create admin account" in response.text


def test_first_run_creates_admin_and_logs_in(client, webui_env):
    response = client.post(
        "/login",
        data={"username": "admin", "password": "hunter22", "password_confirm": "hunter22"},
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert response.cookies.get("fr_os_session")
    assert webui_env["admin_store"].exists()


def test_first_run_rejects_mismatched_passwords(client):
    response = client.post(
        "/login",
        data={"username": "admin", "password": "hunter22", "password_confirm": "different"},
    )
    assert response.status_code == 303
    assert "error" in response.headers["location"]


def test_first_run_rejects_short_password(client):
    response = client.post(
        "/login", data={"username": "admin", "password": "short", "password_confirm": "short"}
    )
    assert response.status_code == 303
    assert "error" in response.headers["location"]


def test_login_with_correct_password_succeeds(client, webui_env):
    webui_env["admin_store"].set_password("admin", "hunter22")
    response = client.post("/login", data={"username": "admin", "password": "hunter22"})
    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_login_with_wrong_password_fails(client, webui_env):
    webui_env["admin_store"].set_password("admin", "hunter22")
    response = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert response.status_code == 303
    assert response.headers["location"] == "/login?error=Invalid+credentials"


def test_logged_in_client_can_reach_dashboard(logged_in_client):
    response = logged_in_client.get("/")
    assert response.status_code == 200
    assert "fr-router" in response.text or "?" in response.text


def test_logout_clears_session(logged_in_client):
    response = logged_in_client.post("/logout")
    assert response.status_code == 303

    dashboard = logged_in_client.get("/")
    assert dashboard.status_code == 303
    assert dashboard.headers["location"] == "/login"


# --- brute-force rate limiting -------------------------------------------


def test_five_failed_logins_from_same_ip_trigger_a_ban(app, webui_env):
    webui_env["admin_store"].set_password("admin", "hunter22")
    attacker = TestClient(app, client=("203.0.113.5", 12345), follow_redirects=False)

    for _ in range(4):
        response = attacker.post("/login", data={"username": "admin", "password": "wrong"})
        assert response.headers["location"] == "/login?error=Invalid+credentials"

    fifth = attacker.post("/login", data={"username": "admin", "password": "wrong"})
    assert "blocked" in fifth.headers["location"].lower()

    assert webui_env["helper"].banned == [("203.0.113.5", 60 * 60)]


def test_failed_logins_from_different_ips_do_not_share_a_counter(app, webui_env):
    webui_env["admin_store"].set_password("admin", "hunter22")

    for i in range(4):
        attacker = TestClient(app, client=(f"203.0.113.{i}", 12345), follow_redirects=False)
        attacker.post("/login", data={"username": "admin", "password": "wrong"})

    assert webui_env["helper"].banned == []


def test_successful_login_resets_the_failure_counter(app, webui_env):
    webui_env["admin_store"].set_password("admin", "hunter22")
    attacker = TestClient(app, client=("203.0.113.9", 12345), follow_redirects=False)

    for _ in range(4):
        attacker.post("/login", data={"username": "admin", "password": "wrong"})
    success = attacker.post("/login", data={"username": "admin", "password": "hunter22"})
    assert success.status_code == 303 and success.headers["location"] == "/"

    # The 4 prior failures must not carry over after the reset.
    for _ in range(4):
        response = attacker.post("/login", data={"username": "admin", "password": "wrong"})
        assert response.headers["location"] == "/login?error=Invalid+credentials"

    assert webui_env["helper"].banned == []


def test_first_run_account_creation_is_not_rate_limited(app, webui_env):
    attacker = TestClient(app, client=("203.0.113.7", 12345), follow_redirects=False)

    for _ in range(10):
        response = attacker.post(
            "/login", data={"username": "admin", "password": "short", "password_confirm": "different"}
        )
        assert response.status_code == 303

    assert webui_env["helper"].banned == []
