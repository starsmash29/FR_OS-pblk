from __future__ import annotations

from frfw.adblock import write_hosts_file
from frfw.config import load_config


def _seed_interface(client):
    # frfw.config.loader requires at least one interface for *any* config
    # to validate at all -- same pattern as test_ztna_routes.py's helper.
    client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )


def test_adblock_page_requires_login(client):
    response = client.get("/adblock")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_adblock_page_shows_disabled_by_default(logged_in_client):
    response = logged_in_client.get("/adblock")
    assert response.status_code == 200
    assert "Disabled" in response.text
    assert "badge-red" in response.text


def test_adblock_page_shows_live_domain_count(logged_in_client, webui_env):
    write_hosts_file({"a.example.com", "b.example.com"}, webui_env["adblock_hosts_path"])
    response = logged_in_client.get("/adblock")
    assert response.status_code == 200
    assert "<dd>2</dd>" in response.text


def test_save_settings_persists_enabled_and_source_urls(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    response = logged_in_client.post(
        "/adblock/settings",
        data={
            "enabled": "true",
            "source_urls": "https://a.example/hosts\nhttps://b.example/hosts",
            "xdp_critical_limit": 25,
        },
    )
    assert "success" in response.headers["location"]

    config = load_config(webui_env["config_path"])
    assert config.adblocker.enabled is True
    assert config.adblocker.source_urls == ["https://a.example/hosts", "https://b.example/hosts"]
    assert config.adblocker.xdp_critical_limit == 25


def test_save_settings_dedupes_and_strips_urls(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    logged_in_client.post(
        "/adblock/settings",
        data={
            "source_urls": "https://a.example/hosts\n\nhttps://a.example/hosts\n  \n",
            "xdp_critical_limit": 0,
        },
    )
    config = load_config(webui_env["config_path"])
    assert config.adblocker.source_urls == ["https://a.example/hosts"]


def test_save_settings_can_disable_again(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    logged_in_client.post(
        "/adblock/settings",
        data={"enabled": "true", "source_urls": "https://a.example/hosts"},
    )
    logged_in_client.post("/adblock/settings", data={"enabled": "false", "source_urls": ""})

    config = load_config(webui_env["config_path"])
    assert config.adblocker.enabled is False


def test_save_settings_rejects_invalid_url(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    response = logged_in_client.post(
        "/adblock/settings", data={"source_urls": "not-a-valid-url"}
    )
    assert "error" in response.headers["location"]


def test_refresh_now_success(logged_in_client, webui_env):
    response = logged_in_client.post("/adblock/refresh")
    assert "success" in response.headers["location"]
    assert webui_env["helper"].refresh_adblock_calls == 1


def test_refresh_now_failure(logged_in_client, webui_env):
    webui_env["helper"].refresh_adblock_result = {"ok": False, "message": "all sources failed"}
    response = logged_in_client.post("/adblock/refresh")
    assert "error" in response.headers["location"]
    assert "all+sources+failed" in response.headers["location"]
