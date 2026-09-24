"""Route tests for the /iot screen (phase 14)."""

from __future__ import annotations

import yaml

ESP_MAC = "24:0a:c4:11:22:33"


def _write_config(webui_env, **iot):
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
    }
    if iot:
        config["iot"] = iot
    webui_env["config_path"].write_text(yaml.safe_dump(config))


def _saved_iot(webui_env) -> dict:
    return yaml.safe_load(webui_env["config_path"].read_text()).get("iot", {})


def test_iot_page_requires_login(client):
    assert client.get("/iot").status_code == 303


def test_iot_page_renders_disabled_state(logged_in_client, webui_env):
    _write_config(webui_env)
    page = logged_in_client.get("/iot")
    assert page.status_code == 200
    assert "IoT isolation is disabled." in page.text
    assert "No devices found yet." in page.text


def test_save_settings_round_trips_and_keeps_mac_lists(logged_in_client, webui_env):
    _write_config(webui_env, enabled=False, trusted_macs=["aa:bb:cc:dd:ee:01"])
    response = logged_in_client.post(
        "/iot/settings",
        data={"enabled": "true", "zones": ["lan"], "auto_isolate": "true", "isolation_mode": "block"},
    )
    assert response.status_code == 303
    assert "success=" in response.headers["location"]
    saved = _saved_iot(webui_env)
    assert saved["enabled"] is True
    assert saved["zones"] == ["lan"]
    assert saved["isolation_mode"] == "block"
    assert saved["trusted_macs"] == ["aa:bb:cc:dd:ee:01"]


def test_save_settings_rejects_internet_facing_zone(logged_in_client, webui_env):
    _write_config(webui_env)
    response = logged_in_client.post("/iot/settings", data={"enabled": "true", "zones": ["wan"]})
    assert "error=" in response.headers["location"]
    assert _saved_iot(webui_env) == {}


def test_scan_now_discovers_classifies_and_auto_isolates(logged_in_client, webui_env):
    _write_config(webui_env, enabled=True, zones=["lan"], auto_isolate=True)
    webui_env["helper"].leases = [{"ip": "10.0.1.50", "mac": ESP_MAC, "hostname": "esp_112233"}]

    response = logged_in_client.post("/iot/scan")
    assert response.status_code == 303
    assert "success=" in response.headers["location"]
    assert webui_env["helper"].iot_isolated == [ESP_MAC]

    page = logged_in_client.get("/iot").text
    assert ESP_MAC in page
    assert "Espressif Inc." in page
    assert "_esphomelib._tcp" in page
    assert "badge-red\">isolated" in page


def test_scan_now_refused_when_disabled(logged_in_client, webui_env):
    _write_config(webui_env)
    response = logged_in_client.post("/iot/scan")
    assert "error=" in response.headers["location"]


def test_trusting_a_device_releases_it_immediately(logged_in_client, webui_env):
    _write_config(webui_env, enabled=True, zones=["lan"], auto_isolate=True)
    webui_env["helper"].leases = [{"ip": "10.0.1.50", "mac": ESP_MAC, "hostname": "esp_112233"}]
    logged_in_client.post("/iot/scan")
    assert webui_env["helper"].iot_isolated == [ESP_MAC]

    response = logged_in_client.post("/iot/device", data={"mac": ESP_MAC.upper(), "action": "trust"})
    assert "success=" in response.headers["location"]
    assert _saved_iot(webui_env)["trusted_macs"] == [ESP_MAC]
    assert webui_env["helper"].iot_isolated == []  # no rescan needed


def test_manual_isolate_then_clear(logged_in_client, webui_env):
    _write_config(webui_env, enabled=True, zones=["lan"])
    other = "00:11:22:33:44:55"
    logged_in_client.post("/iot/device", data={"mac": other, "action": "isolate"})
    assert _saved_iot(webui_env)["isolated_macs"] == [other]
    assert webui_env["helper"].iot_isolated == [other]

    logged_in_client.post("/iot/device", data={"mac": other, "action": "clear"})
    assert _saved_iot(webui_env)["isolated_macs"] == []
    assert webui_env["helper"].iot_isolated == []


def test_device_action_rejects_unknown_action_and_bad_mac(logged_in_client, webui_env):
    _write_config(webui_env, enabled=True, zones=["lan"])
    assert "error=" in logged_in_client.post("/iot/device", data={"mac": ESP_MAC, "action": "nuke"}).headers["location"]
    assert "error=" in logged_in_client.post("/iot/device", data={"mac": "bogus", "action": "trust"}).headers["location"]


def test_nav_has_iot_link(logged_in_client, webui_env):
    _write_config(webui_env)
    assert 'href="/iot"' in logged_in_client.get("/iot").text


def test_metrics_include_iot_families_when_enabled(logged_in_client, webui_env):
    _write_config(webui_env, enabled=True, zones=["lan"], auto_isolate=True)
    webui_env["helper"].leases = [{"ip": "10.0.1.50", "mac": ESP_MAC, "hostname": "esp_112233"}]
    logged_in_client.post("/iot/scan")

    text = logged_in_client.get("/metrics").text
    assert "# TYPE fros_iot_devices gauge" in text
    assert 'fros_iot_devices{category="iot"} 1' in text
    assert 'fros_iot_devices{category="general"} 0' in text
    assert "fros_iot_isolated_devices 1" in text


def test_metrics_omit_iot_families_when_disabled(client, webui_env):
    _write_config(webui_env)
    assert "fros_iot_devices" not in client.get("/metrics").text
