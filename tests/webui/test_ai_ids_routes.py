from __future__ import annotations

from frfw.config import load_config


def _seed_dhcp_device(client, mac: str = "aa:bb:cc:dd:ee:ff", hostname: str = "nas") -> None:
    client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )
    client.post(
        "/interfaces/save",
        data={"name": "lan", "device": "eth1", "zone": "lan", "address": "10.0.0.1/24"},
    )
    client.post(
        "/dhcp/lan/save",
        data={
            "range_start": "10.0.0.100",
            "range_end": "10.0.0.200",
            "dns_servers": "1.1.1.1",
            "lease_time": 3600,
        },
    )
    client.post(
        "/dhcp/lan/reservations/add",
        data={"mac": mac, "address": "10.0.0.50", "hostname": hostname},
    )


def test_ai_ids_page_requires_login(client):
    response = client.get("/ai-ids")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_page_shows_mock_banner_and_disabled_message_by_default(logged_in_client):
    response = logged_in_client.get("/ai-ids")
    assert response.status_code == 200
    assert "MOCK DATA" in response.text
    assert "AI IDS is disabled" in response.text


def test_save_settings_enables_and_persists(logged_in_client, webui_env):
    logged_in_client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )
    response = logged_in_client.post(
        "/ai-ids/settings",
        data={
            "enabled": "true",
            "learning_days": 5,
            "retrain_time": "04:15",
            "excluded_macs": "aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66",
        },
    )
    assert "success" in response.headers["location"]

    config = load_config(webui_env["config_path"])
    assert config.ai_ids.enabled is True
    assert config.ai_ids.learning_days == 5
    assert config.ai_ids.retrain_time == "04:15"
    assert config.ai_ids.excluded_macs == ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]


def test_save_settings_rejects_bad_retrain_time(logged_in_client, webui_env):
    response = logged_in_client.post(
        "/ai-ids/settings",
        data={"enabled": "true", "learning_days": 5, "retrain_time": "not-a-time", "excluded_macs": ""},
    )
    assert "error" in response.headers["location"]
    assert not webui_env["config_path"].exists()


def test_enabled_page_lists_dhcp_reserved_devices(logged_in_client):
    _seed_dhcp_device(logged_in_client)
    logged_in_client.post(
        "/ai-ids/settings",
        data={"enabled": "true", "learning_days": 7, "retrain_time": "03:30", "excluded_macs": ""},
    )

    page = logged_in_client.get("/ai-ids")
    assert "nas" in page.text
    assert "aa:bb:cc:dd:ee:ff" in page.text
    assert "Force Retrain" in page.text
    assert "Lock Profile" in page.text


def test_lock_and_retrain_flow(logged_in_client):
    _seed_dhcp_device(logged_in_client)
    logged_in_client.post(
        "/ai-ids/settings",
        data={"enabled": "true", "learning_days": 7, "retrain_time": "03:30", "excluded_macs": ""},
    )

    r = logged_in_client.post("/ai-ids/aa:bb:cc:dd:ee:ff/lock")
    assert "success" in r.headers["location"]
    assert "Locked" in logged_in_client.get("/ai-ids").text

    r = logged_in_client.post("/ai-ids/aa:bb:cc:dd:ee:ff/retrain")
    assert "success" in r.headers["location"]
    # after an explicit retrain the device is unlocked again
    assert "Lock Profile" in logged_in_client.get("/ai-ids").text


def test_retrain_unknown_mac_shows_error_not_crash(logged_in_client):
    _seed_dhcp_device(logged_in_client)
    logged_in_client.post(
        "/ai-ids/settings",
        data={"enabled": "true", "learning_days": 7, "retrain_time": "03:30", "excluded_macs": ""},
    )

    r = logged_in_client.post("/ai-ids/ff:ff:ff:ff:ff:ff/retrain")
    assert r.status_code == 303
    assert "error" in r.headers["location"]


def test_retrain_all(logged_in_client):
    _seed_dhcp_device(logged_in_client, mac="aa:bb:cc:dd:ee:ff", hostname="nas")
    logged_in_client.post(
        "/dhcp/lan/reservations/add",
        data={"mac": "11:22:33:44:55:66", "address": "10.0.0.51", "hostname": "laptop"},
    )
    logged_in_client.post(
        "/ai-ids/settings",
        data={"enabled": "true", "learning_days": 7, "retrain_time": "03:30", "excluded_macs": ""},
    )
    logged_in_client.post("/ai-ids/aa:bb:cc:dd:ee:ff/lock")

    r = logged_in_client.post("/ai-ids/retrain-all")
    assert "success" in r.headers["location"]
    assert "Locked" not in logged_in_client.get("/ai-ids").text


def test_dashboard_shows_progress_bar_only_when_enabled(logged_in_client):
    dashboard = logged_in_client.get("/")
    assert "AI IDS/IPS learning progress" not in dashboard.text

    _seed_dhcp_device(logged_in_client)
    logged_in_client.post(
        "/ai-ids/settings",
        data={"enabled": "true", "learning_days": 7, "retrain_time": "03:30", "excluded_macs": ""},
    )

    dashboard = logged_in_client.get("/")
    assert "AI IDS/IPS learning progress" in dashboard.text
