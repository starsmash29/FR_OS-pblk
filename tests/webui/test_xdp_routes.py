from __future__ import annotations

import json

from frfw.config import load_config
from frfw.webui.routes import xdp as xdp_route


def _add_wan(client):
    client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )


def test_xdp_page_requires_login(client):
    response = client.get("/xdp")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_page_shows_disabled_by_default(logged_in_client):
    response = logged_in_client.get("/xdp")
    assert response.status_code == 200
    assert "Disabled" in response.text
    assert "badge-red" in response.text


def test_save_settings_persists_interfaces_and_blocklist(logged_in_client, webui_env):
    _add_wan(logged_in_client)

    response = logged_in_client.post(
        "/xdp/settings",
        data={
            "enabled": "true",
            "interfaces": ["wan"],
            "blocklist": "ads.example.com\ntracker.example.net",
        },
    )
    assert "success" in response.headers["location"]

    config = load_config(webui_env["config_path"])
    assert config.xdp_sni_filter.enabled is True
    assert config.xdp_sni_filter.interfaces == ["wan"]
    assert config.xdp_sni_filter.blocklist == ["ads.example.com", "tracker.example.net"]


def test_blocklist_textarea_accepts_commas_and_dedupes(logged_in_client, webui_env):
    _add_wan(logged_in_client)

    logged_in_client.post(
        "/xdp/settings",
        data={
            "enabled": "true",
            "interfaces": ["wan"],
            "blocklist": "a.example.com, b.example.com,\na.example.com\nc.example.com",
        },
    )

    config = load_config(webui_env["config_path"])
    assert config.xdp_sni_filter.blocklist == [
        "a.example.com",
        "b.example.com",
        "c.example.com",
    ]


def test_save_settings_rejects_unknown_interface(logged_in_client, webui_env):
    response = logged_in_client.post(
        "/xdp/settings",
        data={"enabled": "true", "interfaces": ["nonexistent"], "blocklist": ""},
    )
    assert "error" in response.headers["location"]
    assert not webui_env["config_path"].exists()


def test_enabled_page_lists_configured_domains(logged_in_client):
    _add_wan(logged_in_client)
    logged_in_client.post(
        "/xdp/settings",
        data={"enabled": "true", "interfaces": ["wan"], "blocklist": "ads.example.com"},
    )

    page = logged_in_client.get("/xdp")
    assert "ads.example.com" in page.text
    # never attached in this test (no real kernel/bpftool) -- distinct from
    # "Disabled" so an admin can tell "configured but not yet applied"
    # apart from "turned off".
    assert "Not attached yet" in page.text
    assert "badge-red" in page.text


def test_remove_domain(logged_in_client, webui_env):
    _add_wan(logged_in_client)
    logged_in_client.post(
        "/xdp/settings",
        data={
            "enabled": "true",
            "interfaces": ["wan"],
            "blocklist": "a.example.com\nb.example.com",
        },
    )

    response = logged_in_client.post("/xdp/blocklist/remove", data={"domain": "a.example.com"})
    assert "success" in response.headers["location"]

    config = load_config(webui_env["config_path"])
    assert config.xdp_sni_filter.blocklist == ["b.example.com"]


def test_native_mode_shows_green_badge(logged_in_client, webui_env):
    _add_wan(logged_in_client)
    logged_in_client.post(
        "/xdp/settings",
        data={"enabled": "true", "interfaces": ["wan"], "blocklist": "a.example.com"},
    )
    webui_env["xdp_state_path"].write_text(json.dumps({"attached": {"eth0": "xdpdrv"}}))

    page = logged_in_client.get("/xdp")
    assert "badge-green" in page.text
    assert "Native" in page.text


def test_generic_mode_shows_yellow_badge(logged_in_client, webui_env):
    _add_wan(logged_in_client)
    logged_in_client.post(
        "/xdp/settings",
        data={"enabled": "true", "interfaces": ["wan"], "blocklist": "a.example.com"},
    )
    webui_env["xdp_state_path"].write_text(json.dumps({"attached": {"eth0": "xdpgeneric"}}))

    page = logged_in_client.get("/xdp")
    assert "badge-yellow" in page.text
    assert "Generic" in page.text


def test_available_interfaces_checkboxes_only_show_defined_interfaces(logged_in_client):
    _add_wan(logged_in_client)
    page = logged_in_client.get("/xdp")
    assert 'value="wan"' in page.text
    assert 'value="lan"' not in page.text


def test_logs_stream_requires_login(client):
    response = client.get("/xdp/logs/stream")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_logs_stream_relays_valid_json_lines_and_drops_garbage(logged_in_client, monkeypatch):
    lines = [
        '{"ts": 1.0, "saddr": "1.2.3.4", "sport": 111, "daddr": "5.6.7.8", "dport": 443, "sni": "bad.example.com"}',
        "not json, should be dropped",
        "",
        '{"ts": 2.0, "saddr": "9.9.9.9", "sport": 222, "daddr": "8.8.8.8", "dport": 443, "sni": "also-bad.example.com"}',
    ]
    monkeypatch.setattr(xdp_route, "_iter_journal_lines", lambda cmd: iter(lines))

    with logged_in_client.stream("GET", "/xdp/logs/stream") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(response.iter_text())

    assert "bad.example.com" in body
    assert "also-bad.example.com" in body
    assert "not json" not in body
    assert body.count("data: ") == 2
