"""The webUI's side of an apply held for confirmation (ROADMAP SEC-26).

An Apply asks the helper to hold it, with who applied it; while it waits
every page says so -- an apply that moved the webUI lands the admin on
whatever page they sign in to -- with Confirm and Go back for an admin
and the bare notice for a viewer; Confirm sends the pending apply's own
id. A reverted apply's config can be loaded back to fix it. The
helper's side is tests/test_helper.py, the revert tests/test_apply_confirm.py.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from frfw.admin_account import ROLE_ADMIN, ROLE_VIEWER
from frfw.webui.app import create_app

PENDING = {"id": "a1b2c3d4e5f60718", "remaining": 287, "seconds": 300, "by": "admin",
           "addresses": ["192.168.1.1", "10.0.30.1"]}


def test_an_apply_asks_to_be_held_and_says_until_when(logged_in_client, webui_env):
    helper = webui_env["helper"]
    helper.hold_applies = True
    response = logged_in_client.post("/apply")
    assert "success=Applied+--+confirm+it+within+300+s" in response.headers["location"]
    assert helper.apply_requests == [{"dry_run": False, "confirm": True, "user": "admin"}]


def test_every_page_shows_the_pending_apply_with_its_buttons(logged_in_client, webui_env):
    webui_env["helper"].pending = dict(PENDING)
    for page in ("/", "/rules", "/interfaces", "/system"):
        html = logged_in_client.get(page).text
        assert "This apply is waiting for confirmation." in html, page
        assert "goes back to the config applied before it in 287 s (applied by admin)" in html
        assert "The webUI now listens on 192.168.1.1, 10.0.30.1." in html
        assert 'action="/apply/confirm"' in html and 'name="id" value="a1b2c3d4e5f60718"' in html
        assert 'action="/apply/revert"' in html


def test_no_banner_while_nothing_waits_or_the_helper_can_t_answer(logged_in_client, webui_env):
    assert "waiting for confirmation" not in logged_in_client.get("/").text

    def unreachable():
        raise OSError("cannot reach apply-helper")

    webui_env["helper"].apply_status = unreachable
    assert logged_in_client.get("/").status_code == 200


def test_confirm_sends_the_pending_apply_s_id(logged_in_client, webui_env):
    helper = webui_env["helper"]
    helper.pending = dict(PENDING)
    stale = logged_in_client.post("/apply/confirm", data={"id": "0000000000000000"})
    assert "error=That+is+not+the+apply" in stale.headers["location"] and helper.pending
    done = logged_in_client.post("/apply/confirm", data={"id": PENDING["id"]})
    assert "success=Apply+confirmed" in done.headers["location"]
    assert helper.confirmed == [PENDING["id"]] and helper.pending is None
    assert "waiting for confirmation" not in logged_in_client.get("/").text


def test_go_back_now_and_load_the_unconfirmed_config(logged_in_client, webui_env):
    helper = webui_env["helper"]
    helper.pending = dict(PENDING)
    assert "success=" in logged_in_client.post("/apply/revert").headers["location"]
    html = logged_in_client.get("/").text
    assert "An apply was not confirmed" in html and 'action="/apply/rejected/restore"' in html
    assert "success=" in logged_in_client.post("/apply/rejected/restore").headers["location"]
    assert "An apply was not confirmed" not in logged_in_client.get("/").text


def test_a_viewer_sees_the_notice_but_can_neither_confirm_nor_go_back(webui_env):
    webui_env["admin_store"].set_password("boss", "adminpass-001", ROLE_ADMIN)
    webui_env["admin_store"].add_user("guest", "viewerpass-01", ROLE_VIEWER)
    viewer = TestClient(create_app(**webui_env), follow_redirects=False)
    viewer.post("/login", data={"username": "guest", "password": "viewerpass-01"})
    helper = webui_env["helper"]
    helper.pending = dict(PENDING)
    html = viewer.get("/").text
    assert "This apply is waiting for confirmation." in html and 'action="/apply/confirm"' not in html
    for path, data in (("/apply/confirm", {"id": PENDING["id"]}), ("/apply/revert", {}),
                       ("/apply/rejected/restore", {})):
        assert viewer.post(path, data=data).status_code == 403, path
    assert helper.pending is not None and helper.confirmed == []
