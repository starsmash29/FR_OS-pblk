"""Security-lessons G1: no default credentials. The account first boot
generates is `admin` with a random password; its first sign-in must
choose a username that isn't a default and a new password before it can
do anything else.
"""

from __future__ import annotations

import pytest

from frfw import cli
from frfw.admin_account import ROLE_ADMIN, AdminStore

GENERATED = "Gen3rated-by-first-boot"


@pytest.fixture
def generated(webui_env):
    webui_env["admin_store"].set_password("admin", GENERATED, ROLE_ADMIN, must_change=True)
    return webui_env["admin_store"]


def _login(client, username="admin", password=GENERATED):
    return client.post("/login", data={"username": username, "password": password})


def test_the_generated_account_can_only_reach_setup(client, generated):
    assert _login(client).headers["location"] == "/"
    for method, path in (("get", "/"), ("get", "/rules"), ("post", "/apply"), ("get", "/users")):
        response = getattr(client, method)(path)
        assert response.status_code == 303 and response.headers["location"] == "/setup", path
    assert client.get("/setup").status_code == 200


@pytest.mark.parametrize("username", ["admin", "root", "administrator"])
def test_setup_refuses_default_usernames(client, generated, username):
    _login(client)
    response = client.post("/setup", data={"username": username, "password": "my-own-pass-1",
                                           "password_confirm": "my-own-pass-1"})
    assert response.headers["location"].startswith("/setup?error=")
    assert generated.get("admin").must_change


def test_setup_refuses_keeping_the_generated_password(client, generated):
    _login(client)
    response = client.post("/setup", data={"username": "netadmin", "password": GENERATED,
                                           "password_confirm": GENERATED})
    assert "error=" in response.headers["location"]
    assert generated.get("netadmin") is None


def test_setup_refuses_a_mismatched_confirmation(client, generated):
    _login(client)
    response = client.post("/setup", data={"username": "netadmin", "password": "my-own-pass-1",
                                           "password_confirm": "my-own-pass-2"})
    assert "error=" in response.headers["location"]


def test_setup_renames_the_account_and_the_old_login_stops_working(client, generated):
    _login(client)
    response = client.post("/setup", data={"username": "netadmin", "password": "my-own-pass-1",
                                           "password_confirm": "my-own-pass-1"})
    assert response.status_code == 303 and response.headers["location"] == "/"
    assert client.get("/").status_code == 200  # the new session cookie works
    assert generated.get("admin") is None
    account = generated.get("netadmin")
    assert account.role == ROLE_ADMIN and not account.must_change
    assert generated.verify("admin", GENERATED) is None
    assert generated.verify("netadmin", "my-own-pass-1") is not None


def test_an_account_that_was_set_up_never_sees_setup(logged_in_client):
    assert logged_in_client.get("/setup").headers["location"] == "/"
    response = logged_in_client.post("/setup", data={"username": "other", "password": "my-own-pass-1",
                                                     "password_confirm": "my-own-pass-1"})
    assert response.headers["location"] == "/"


def test_first_boot_generation_marks_the_account(tmp_path, monkeypatch, capsys):
    store = AdminStore(tmp_path / "auth.json")
    monkeypatch.setattr(cli, "AdminStore", lambda: store)
    assert cli.main(["set-admin-password", "--generate"]) == 0
    assert store.get("admin").must_change


def test_after_setup_the_console_copy_is_removed(client, generated, tmp_path):
    """G1 relies on A5: the generated password leaves the console once
    it no longer works -- which setup makes happen."""
    from frfw import initial_password

    issue = tmp_path / "fr_os-initial-admin.issue"
    initial_password.write("admin", GENERATED, path=issue)
    assert initial_password.clear_if_changed(generated, path=issue) is False
    _login(client)
    client.post("/setup", data={"username": "netadmin", "password": "my-own-pass-1",
                                "password_confirm": "my-own-pass-1"})
    assert initial_password.clear_if_changed(generated, path=issue) is True
    assert not issue.exists()
