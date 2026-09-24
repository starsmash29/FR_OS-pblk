from __future__ import annotations

import pytest

from frfw import update as update_mod


@pytest.fixture(autouse=True)
def no_network_check(monkeypatch):
    """The /update page calls frfw.update.check_latest on every load (see
    that route's docstring for why it's unprivileged and uncached) --
    monkeypatch it everywhere in this file so route tests never make a
    real HTTPS call to GitHub."""
    result = update_mod.UpdateCheckResult(
        current_version="0.1.0",
        latest=update_mod.ReleaseInfo(tag="v0.2.0", version="0.2.0", notes="release notes here"),
        update_available=True,
        checked_at="2026-01-01T00:00:00Z",
    )
    monkeypatch.setattr(update_mod, "check_latest", lambda *a, **kw: result)
    return result


def test_update_page_requires_login(client):
    response = client.get("/update")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_update_page_shows_installed_and_latest_version(logged_in_client):
    page = logged_in_client.get("/update")
    assert page.status_code == 200
    assert "0.1.0" in page.text
    assert "0.2.0" in page.text
    assert "release notes here" in page.text


def test_update_page_shows_no_releases_message(logged_in_client, monkeypatch):
    no_release = update_mod.UpdateCheckResult(
        current_version="0.1.0", latest=None, update_available=False, checked_at="x"
    )
    monkeypatch.setattr(update_mod, "check_latest", lambda *a, **kw: no_release)

    page = logged_in_client.get("/update")
    assert "No releases have been published" in page.text


def test_update_page_shows_check_error(logged_in_client, monkeypatch):
    def boom(*a, **kw):
        raise update_mod.UpdateError("network unreachable")

    monkeypatch.setattr(update_mod, "check_latest", boom)

    page = logged_in_client.get("/update")
    assert "network unreachable" in page.text


def test_apply_update_success_redirects_with_flash(logged_in_client, webui_env):
    response = logged_in_client.post("/update/apply", data={"version": "0.2.0"})
    assert response.status_code == 303
    assert "success" in response.headers["location"]
    assert webui_env["update_helper"].applied == ["0.2.0"]


def test_apply_update_failure_redirects_with_error(logged_in_client, webui_env):
    webui_env["update_helper"].apply_result = {"ok": False, "message": "download failed"}
    response = logged_in_client.post("/update/apply", data={"version": "0.2.0"})
    assert "error" in response.headers["location"]

    page = logged_in_client.get(response.headers["location"])
    assert "download failed" in page.text


def test_rollback_success_redirects_with_flash(logged_in_client, webui_env):
    response = logged_in_client.post("/update/rollback")
    assert response.status_code == 303
    assert "success" in response.headers["location"]
    assert webui_env["update_helper"].rolled_back == 1


def test_rollback_failure_redirects_with_error(logged_in_client, webui_env):
    webui_env["update_helper"].rollback_result = {"ok": False, "message": "no previous version"}
    response = logged_in_client.post("/update/rollback")
    assert "error" in response.headers["location"]


def test_page_shows_rollback_button_only_when_previous_version_recorded(
    logged_in_client, webui_env
):
    state_path = webui_env["update_state_path"]

    page = logged_in_client.get("/update")
    assert "Roll back to" not in page.text

    update_mod.save_state(
        update_mod.UpdateState(current_version="0.2.0", previous_version="0.1.0"), state_path
    )
    page = logged_in_client.get("/update")
    assert "Roll back to 0.1.0" in page.text
