from __future__ import annotations

import pytest

from frfw import __version__
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
    assert f"{__version__} “Ice Breaker”" in page.text  # the installed version
    assert "Update available: 0.2.0 “Ice Breaker”" in page.text
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


# --- security-lessons J3: the opt-in -----------------------------------------------------


def test_admin_turns_automatic_security_updates_on_and_off(logged_in_client, webui_env):
    import yaml

    webui_env["config_path"].write_text(yaml.safe_dump({
        "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"}, "lan": {"device": "eth1", "zone": "lan"}},
        "rules": [], "nat": {"masquerade": [{"out_zone": "wan"}]},
    }))
    assert 'id="auto-security" name="enabled" value="true">' in logged_in_client.get("/update").text  # off
    response = logged_in_client.post("/update/auto-security", data={"enabled": "true"})
    assert "success=Security+releases+will+be+installed" in response.headers["location"]
    assert yaml.safe_load(webui_env["config_path"].read_text())["update"]["auto_install_security"] is True
    assert 'id="auto-security" name="enabled" value="true" checked>' in logged_in_client.get("/update").text
    logged_in_client.post("/update/auto-security", data={})
    assert yaml.safe_load(webui_env["config_path"].read_text())["update"]["auto_install_security"] is False


def test_a_failed_automatic_install_shows_on_the_update_screen(logged_in_client, webui_env):
    import json

    from frfw import __version__

    webui_env["update_check_path"].write_text(json.dumps({
        "current_version": __version__, "update_available": True, "latest_version": "99.0.0", "security": True,
        "error": None, "auto_install_error": "signature does not verify", "checked_at": "2026-09-28T10:00:00Z",
    }))
    page = logged_in_client.get("/update").text
    assert "Installing security release 99.0.0 automatically failed: signature does not verify" in page


# --- ROADMAP SEC-14: the kernel card ------------------------------------------------------


MINIMAL_CONFIG = {
    "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}},
    "interfaces": {"wan": {"device": "eth0", "zone": "wan"}, "lan": {"device": "eth1", "zone": "lan"}},
    "rules": [], "nat": {"masquerade": [{"out_zone": "wan"}]},
}


def test_the_kernel_card_says_what_runs(logged_in_client):
    page = logged_in_client.get("/update").text
    assert "running kernel 6.1.0-53-amd64; nothing staged" in page
    assert 'id="kernel-try"' not in page  # nothing is ready
    assert 'id="kernel-check"' in page


def test_a_ready_kernel_has_a_try_button_that_asks_first(logged_in_client, webui_env):
    helper = webui_env["update_helper"]
    helper.kernel_status = {**helper.kernel_status, "ready": "6.1.0-54-amd64",
                            "last_check": {"at": "2026-10-05T10:00:00+00:00", "message": "kernel 6.1.0-54-amd64 is "
                                           "ready to try", "error": False}}
    page = logged_in_client.get("/update").text
    assert 'id="kernel-try"' in page and "Try kernel 6.1.0-54-amd64 (reboots the router)" in page
    assert 'data-confirm="Reboot the router now to try kernel 6.1.0-54-amd64?"' in page
    response = logged_in_client.post("/update/kernel/try")
    assert response.status_code == 303 and "success=kernel_try+done" in response.headers["location"]
    assert helper.kernel_commands[-1] == "kernel_try"


@pytest.mark.parametrize("path,cmd", [("/update/kernel/check", "kernel_check"),
                                      ("/update/kernel/cancel", "kernel_cancel")])
def test_the_other_kernel_buttons_go_to_the_helper(logged_in_client, webui_env, path, cmd):
    response = logged_in_client.post(path)
    assert response.status_code == 303 and "success=" in response.headers["location"]
    assert webui_env["update_helper"].kernel_commands[-1] == cmd


def test_a_kernel_the_helper_refuses_is_an_error_on_the_page(logged_in_client, webui_env):
    helper = webui_env["update_helper"]
    helper.kernel = lambda cmd: ({"ok": True, "kernel": helper.kernel_status} if cmd == "kernel_status"
                                 else {"ok": False, "message": "no kernel is ready to try"})
    response = logged_in_client.post("/update/kernel/try")
    assert "error=no+kernel+is+ready+to+try" in response.headers["location"]


def test_the_page_renders_without_the_update_helper(logged_in_client, webui_env):
    def down(cmd):
        raise ConnectionRefusedError("no such socket")

    webui_env["update_helper"].kernel = down
    page = logged_in_client.get("/update")
    assert page.status_code == 200 and "Kernel status unavailable" in page.text


def test_kernel_updates_are_on_by_default_and_can_be_switched_off(logged_in_client, webui_env):
    import yaml

    webui_env["config_path"].write_text(yaml.safe_dump(MINIMAL_CONFIG))
    assert 'id="kernel-updates" name="enabled" value="true" checked>' in logged_in_client.get("/update").text
    response = logged_in_client.post("/update/kernel-updates", data={})
    assert "success=Kernel+updates+are+off" in response.headers["location"]
    assert yaml.safe_load(webui_env["config_path"].read_text())["update"]["kernel_updates"] is False
    assert 'id="kernel-updates" name="enabled" value="true">' in logged_in_client.get("/update").text
