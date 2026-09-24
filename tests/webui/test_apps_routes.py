"""Route tests for the /apps screen (phase 16)."""

from __future__ import annotations

import json
import time

import yaml


def _write_config(webui_env, *, adblocker=None, **app_control):
    config = {
        "version": 1,
        "hostname": "router",
        "zones": {"wan": {}, "lan": {}},
        "interfaces": {
            "wan": {"device": "eth0", "zone": "wan"},
            "lan": {"device": "eth1", "zone": "lan", "address": "10.0.1.1/24"},
        },
        "rules": [],
        "nat": {"masquerade": [{"out_zone": "wan"}]},
        "dhcp": {"lan": {"range_start": "10.0.1.100", "range_end": "10.0.1.200", "dns_servers": ["1.1.1.1"]}},
    }
    if adblocker is not None:
        config["adblocker"] = adblocker
    if app_control:
        config["app_control"] = app_control
    webui_env["config_path"].write_text(yaml.safe_dump(config))


def _saved(webui_env) -> dict:
    return yaml.safe_load(webui_env["config_path"].read_text()).get("app_control", {})


_RESOLVER = {"enabled": True, "source_urls": ["https://x/ads"], "serve_lan": True, "query_logging": True}


def test_apps_page_requires_login(client):
    assert client.get("/apps").status_code == 303


def test_apps_page_lists_catalog_and_usage(logged_in_client, webui_env):
    _write_config(webui_env, adblocker=_RESOLVER, enabled=True, blocked_apps=["tiktok"])
    now = time.time()
    webui_env["appid_usage_path"].write_text(json.dumps({
        "generated": now,
        "apps": {"netflix": {
            "hits_24h": 12, "active_clients": 1, "last_seen": now,
            "clients": {"10.0.1.50": {"hits_24h": 12, "last_seen": now, "active": True, "sources": ["dns"]}},
        }},
    }))
    webui_env["iot_inventory_path"].write_text(json.dumps({
        "devices": [{"ip": "10.0.1.50", "mac": "aa:bb:cc:dd:ee:01", "hostname": "living-room-tv"}],
    }))
    page = logged_in_client.get("/apps")
    assert page.status_code == 200
    text = page.text
    assert "Netflix" in text and "Roblox" in text
    assert "living-room-tv" in text
    # The used app is listed first, and the blocked one is marked.
    assert text.index("Netflix") < text.index("Roblox")
    assert 'value="tiktok" checked' in text
    assert "v2fly/domain-list-community" in text


def test_settings_keep_blocked_list(logged_in_client, webui_env):
    _write_config(webui_env, adblocker=_RESOLVER, enabled=False, blocked_apps=["roblox"])
    response = logged_in_client.post("/apps/settings", data={"enabled": "true"})
    assert "success=" in response.headers["location"]
    saved = _saved(webui_env)
    assert saved["enabled"] is True
    assert saved["blocked_apps"] == ["roblox"]


def test_observe_sni_without_xdp_is_rejected(logged_in_client, webui_env):
    _write_config(webui_env, adblocker=_RESOLVER)
    response = logged_in_client.post("/apps/settings", data={"enabled": "true", "observe_sni": "true"})
    assert "error=" in response.headers["location"]
    assert _saved(webui_env) == {}


def test_block_list_is_saved_in_catalog_order(logged_in_client, webui_env):
    _write_config(webui_env, adblocker=_RESOLVER, enabled=True)
    response = logged_in_client.post("/apps/block", data={"blocked_apps": ["roblox", "tiktok"]})
    assert "success=" in response.headers["location"]
    assert _saved(webui_env)["blocked_apps"] == ["tiktok", "roblox"]


def test_blocking_without_lan_resolver_is_rejected(logged_in_client, webui_env):
    _write_config(webui_env, adblocker={"enabled": True, "source_urls": ["https://x/ads"]}, enabled=True)
    response = logged_in_client.post("/apps/block", data={"blocked_apps": ["tiktok"]})
    assert "error=" in response.headers["location"]
    assert _saved(webui_env).get("blocked_apps", []) == []


def test_metrics_report_app_usage(logged_in_client, webui_env):
    _write_config(webui_env, adblocker=_RESOLVER, enabled=True, blocked_apps=["tiktok"])
    webui_env["appid_usage_path"].write_text(json.dumps({
        "generated": 1, "apps": {"netflix": {"hits_24h": 12, "active_clients": 2, "last_seen": 1, "clients": {}}},
    }))
    text = logged_in_client.get("/metrics").text
    assert 'fros_app_active_clients{app="netflix",category="streaming"} 2' in text
    assert 'fros_app_hits_24h{app="netflix",category="streaming"} 12' in text
    assert 'fros_app_blocked{app="tiktok"} 1' in text
