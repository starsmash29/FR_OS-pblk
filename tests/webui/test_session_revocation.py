"""Security-lessons G7: sessions can be killed on the server.

Before, logging out only deleted the cookie in the browser: a copy of it
(stolen, or left on a shared computer) kept working for up to 12 hours.
Every scenario here replays a copied cookie from a second client.
"""

from __future__ import annotations

import json
import stat

import pytest
from fastapi.testclient import TestClient

from frfw.admin_account import ROLE_ADMIN, ROLE_VIEWER
from frfw.webui.auth import COOKIE_NAME


@pytest.fixture
def accounts(webui_env):
    store = webui_env["admin_store"]
    store.set_password("boss", "adminpass-001", ROLE_ADMIN)
    store.set_password("guest", "viewerpass-01", ROLE_VIEWER)
    return store


def _sign_in(app, username, password) -> tuple[TestClient, str]:
    client = TestClient(app, follow_redirects=False)
    response = client.post("/login", data={"username": username, "password": password})
    assert response.headers["location"] == "/"
    return client, response.cookies[COOKIE_NAME]


def _replay(app, cookie) -> int:
    thief = TestClient(app, follow_redirects=False)
    thief.cookies.set(COOKIE_NAME, cookie)
    return thief.get("/account").status_code


def test_logout_ends_the_session_on_the_server(app, accounts):
    client, cookie = _sign_in(app, "boss", "adminpass-001")
    assert _replay(app, cookie) == 200  # a copy works while the session lives...
    client.post("/logout")
    assert _replay(app, cookie) == 303  # ...and not after logout


def test_log_out_everywhere_ends_every_session_of_the_account_only(app, accounts):
    laptop, laptop_cookie = _sign_in(app, "guest", "viewerpass-01")  # a viewer may do it too
    _phone, phone_cookie = _sign_in(app, "guest", "viewerpass-01")
    _admin, admin_cookie = _sign_in(app, "boss", "adminpass-001")
    response = laptop.post("/account/logout-everywhere")
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert _replay(app, laptop_cookie) == 303
    assert _replay(app, phone_cookie) == 303
    assert _replay(app, admin_cookie) == 200  # someone else's sessions are untouched


def test_changing_the_password_ends_every_other_session(app, accounts):
    laptop, _ = _sign_in(app, "guest", "viewerpass-01")
    _phone, phone_cookie = _sign_in(app, "guest", "viewerpass-01")
    laptop.post("/account/password", data={"current_password": "viewerpass-01", "new_password": "newsecret-099",
                                           "new_password_confirm": "newsecret-099"})
    assert laptop.get("/account").status_code == 200  # this browser got a fresh session
    assert _replay(app, phone_cookie) == 303


def test_a_reset_by_an_admin_ends_the_users_sessions(app, accounts):
    _guest, guest_cookie = _sign_in(app, "guest", "viewerpass-01")
    admin, _ = _sign_in(app, "boss", "adminpass-001")
    admin.post("/users/guest/password", data={"new_password": "resetpass-077"})
    assert _replay(app, guest_cookie) == 303
    # The old session stays dead even if the password were set back.
    accounts.set_password("guest", "viewerpass-01")
    assert _replay(app, guest_cookie) == 303


def test_deleting_an_account_ends_its_sessions(app, accounts):
    _guest, guest_cookie = _sign_in(app, "guest", "viewerpass-01")
    admin, _ = _sign_in(app, "boss", "adminpass-001")
    admin.post("/users/guest/delete")
    accounts.set_password("guest", "viewerpass-01", ROLE_VIEWER)  # same name re-created
    assert _replay(app, guest_cookie) == 303


def test_a_lost_session_list_signs_everyone_out(app, accounts, webui_env, tmp_path):
    _client, cookie = _sign_in(app, "boss", "adminpass-001")
    (tmp_path / "sessions.json").unlink()
    assert _replay(app, cookie) == 303


def test_the_session_list_holds_no_usable_token(app, accounts, tmp_path):
    _client, cookie = _sign_in(app, "boss", "adminpass-001")
    path = tmp_path / "sessions.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    sids = list(json.loads(path.read_text()))
    assert sids and all(sid not in cookie for sid in sids)  # only hashes are stored


def test_a_signed_cookie_without_a_server_side_session_is_refused(app, accounts, webui_env):
    """An old-format cookie (before G7: no session id), validly signed."""
    manager = webui_env["session_manager"]
    account = accounts.get("boss")
    forged = manager._serializer.dumps({"username": "boss", "v": account.session_version()})
    assert _replay(app, forged) == 303
    unknown = manager._serializer.dumps({"username": "boss", "v": account.session_version(), "sid": "made-up"})
    assert _replay(app, unknown) == 303
