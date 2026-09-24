from __future__ import annotations

from frfw.config import load_config


def test_ai_ids_page_requires_login(client):
    response = client.get("/ai-ids")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_page_shows_disabled_state_by_default(logged_in_client):
    response = logged_in_client.get("/ai-ids")
    assert response.status_code == 200
    assert "Detection:" in response.text
    assert "disabled" in response.text.lower()


def test_save_settings_enables_and_persists(logged_in_client, webui_env):
    logged_in_client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )
    response = logged_in_client.post(
        "/ai-ids/settings",
        data={
            "enabled": "true",
            "excluded_macs": "aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66",
            "quarantine_duration_seconds": 900,
        },
    )
    assert "success" in response.headers["location"]

    config = load_config(webui_env["config_path"])
    assert config.ai_ids.enabled is True
    assert config.ai_ids.excluded_macs == ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
    assert config.ai_ids.quarantine_duration_seconds == 900


def test_save_settings_rejects_bad_duration(logged_in_client, webui_env):
    response = logged_in_client.post(
        "/ai-ids/settings",
        data={"enabled": "true", "excluded_macs": "", "quarantine_duration_seconds": 0},
    )
    assert "error" in response.headers["location"]
    assert not webui_env["config_path"].exists()


def test_page_shows_currently_quarantined_hosts(logged_in_client, webui_env):
    webui_env["helper"].quarantined["10.0.0.9"] = 3599
    response = logged_in_client.get("/ai-ids")
    assert "10.0.0.9" in response.text
    assert "3599s" in response.text


def test_page_shows_no_hosts_quarantined_message_when_empty(logged_in_client):
    response = logged_in_client.get("/ai-ids")
    assert "No hosts currently quarantined" in response.text


def test_page_shows_quarantine_error_when_helper_reports_failure(logged_in_client, webui_env):
    webui_env["helper"].ids_quarantine_status = lambda: {"ok": False, "message": "nft not found"}
    response = logged_in_client.get("/ai-ids")
    assert "Could not read kernel quarantine state" in response.text
    assert "nft not found" in response.text


def test_page_shows_recent_flagged_events(logged_in_client, webui_env):
    from frfw.ai_ids.daemon import IDSDaemon
    from frfw.ai_ids.engine import AnomalyEngine
    from frfw.config import parse_config

    config = parse_config(
        {
            "version": 1, "hostname": "t", "zones": {"wan": {}},
            "interfaces": {"wan": {"device": "eth0", "zone": "wan"}}, "rules": [], "nat": {},
        }
    )
    daemon = IDSDaemon(
        config,
        engine=AnomalyEngine(window_seconds=10.0),
        quarantine_fn=lambda ip, d: {"ok": True},
        conntrack_fn=lambda: {"ok": True, "flows": []},
        events_path=webui_env["ai_ids_state_path"],
    )
    now = daemon._clock()
    for i in range(20):
        daemon.engine.observe_connection("10.0.0.42", f"203.0.113.{i}", now=now)
    daemon.evaluate_and_enforce()

    response = logged_in_client.get("/ai-ids")
    assert "10.0.0.42" in response.text
    assert "destination-scan pattern" in response.text


def test_page_shows_no_anomalies_message_when_events_log_empty(logged_in_client):
    response = logged_in_client.get("/ai-ids")
    assert "No anomalies flagged yet" in response.text


def test_dashboard_shows_ai_ids_card_only_when_enabled(logged_in_client):
    dashboard = logged_in_client.get("/")
    assert "host(s) currently quarantined" not in dashboard.text

    logged_in_client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )
    logged_in_client.post(
        "/ai-ids/settings",
        data={"enabled": "true", "excluded_macs": "", "quarantine_duration_seconds": 7200},
    )

    dashboard = logged_in_client.get("/")
    assert "host(s) currently quarantined" in dashboard.text


def test_dashboard_shows_quarantined_count(logged_in_client, webui_env):
    logged_in_client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )
    logged_in_client.post(
        "/ai-ids/settings",
        data={"enabled": "true", "excluded_macs": "", "quarantine_duration_seconds": 7200},
    )
    webui_env["helper"].quarantined["10.0.0.9"] = 100

    dashboard = logged_in_client.get("/")
    assert "1</strong> host(s) currently quarantined" in dashboard.text
