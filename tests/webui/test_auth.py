from __future__ import annotations


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
