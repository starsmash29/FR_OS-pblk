from __future__ import annotations

from frfw.config import load_config


def _seed_interface(client):
    # frfw.config.loader requires at least one interface for *any* config
    # to validate at all -- same pattern as test_ztna_routes.py's helper.
    client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )


def test_system_page_requires_login(client):
    response = client.get("/system")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_system_page_shows_classical_only_by_default(logged_in_client):
    response = logged_in_client.get("/system")
    assert response.status_code == 200
    assert "Classical only" in response.text
    assert "badge-red" in response.text


def test_system_page_reports_this_hosts_real_openssl_version(logged_in_client):
    # No mocking here -- this sandbox's actual OpenSSL version string
    # should show up verbatim, since capability detection is a live
    # check against the real interpreter, not a fixture.
    import ssl

    response = logged_in_client.get("/system")
    assert ssl.OPENSSL_VERSION in response.text


def test_save_pqc_settings_persists_enabled(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    response = logged_in_client.post("/system/pqc/settings", data={"enabled": "true"})
    assert "success" in response.headers["location"]

    config = load_config(webui_env["config_path"])
    assert config.pqc.enabled is True


def test_save_pqc_settings_can_disable_again(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    logged_in_client.post("/system/pqc/settings", data={"enabled": "true"})
    logged_in_client.post("/system/pqc/settings", data={"enabled": "false"})

    config = load_config(webui_env["config_path"])
    assert config.pqc.enabled is False


def test_system_page_shows_enabled_but_not_active_when_host_unsupported(logged_in_client):
    # This sandbox's real OpenSSL predates 3.5, so enabling PQC in config
    # alone can never flip the badge to "Quantum-safe" -- it must show
    # the honest middle state instead of a false positive.
    _seed_interface(logged_in_client)
    logged_in_client.post("/system/pqc/settings", data={"enabled": "true"})

    response = logged_in_client.get("/system")
    assert "Enabled, not yet active" in response.text
    # "badge-green" alone also appears in base.html's shared <style> block
    # regardless of whether it's used -- check for an actual rendered
    # badge element instead of the CSS class definition.
    assert 'class="badge badge-green"' not in response.text


def test_dashboard_shows_pqc_badge(logged_in_client):
    response = logged_in_client.get("/")
    assert "Management session" in response.text
    assert "Classical only" in response.text
