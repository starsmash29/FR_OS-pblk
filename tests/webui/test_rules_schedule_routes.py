"""Route tests for scheduled rules and the schedule time zone (phase 17)."""

from __future__ import annotations

from frfw.config import load_config
from tests.webui.test_routes import _seed_wan_lan


def test_add_scheduled_rule_with_mac(logged_in_client, webui_env):
    _seed_wan_lan(logged_in_client)
    r = logged_in_client.post(
        "/rules/add",
        data={
            "name": "kids-bedtime", "action": "reject", "from_zone": "lan", "to_zone": "wan",
            "src_mac": "AA:BB:CC:DD:EE:01",
            "schedule_days": ["mon", "tue", "wed", "thu", "fri"],
            "schedule_start": "21:30", "schedule_end": "06:30", "cut_established": "true",
        },
    )
    assert "success" in r.headers["location"], r.headers["location"]
    rule = load_config(webui_env["config_path"]).rules[0]
    assert rule.src_mac == "aa:bb:cc:dd:ee:01"
    assert rule.schedule.days == (0, 1, 2, 3, 4)
    assert rule.schedule.cut_established is True

    page = logged_in_client.get("/rules").text
    assert "Mon-Fri 21:30-06:30" in page
    assert "active now" in page or "inactive" in page
    assert "cuts open connections" in page


def test_schedule_without_days_means_every_day_and_bad_times_are_rejected(logged_in_client, webui_env):
    _seed_wan_lan(logged_in_client)
    r = logged_in_client.post("/rules/add", data={
        "name": "night", "action": "drop", "from_zone": "lan", "to_zone": "wan",
        "schedule_start": "23:00", "schedule_end": "05:00",
    })
    assert "success" in r.headers["location"]
    assert load_config(webui_env["config_path"]).rules[0].schedule.days == tuple(range(7))

    r = logged_in_client.post("/rules/add", data={
        "name": "broken", "action": "drop", "from_zone": "lan", "to_zone": "wan",
        "schedule_start": "23:00",
    })
    assert "error=" in r.headers["location"]
    assert [rule.name for rule in load_config(webui_env["config_path"]).rules] == ["night"]


def test_timezone_is_saved_validated_and_cleared(logged_in_client, webui_env):
    _seed_wan_lan(logged_in_client)
    r = logged_in_client.post("/rules/timezone", data={"timezone": "Europe/Budapest"})
    assert "success" in r.headers["location"]
    assert load_config(webui_env["config_path"]).timezone == "Europe/Budapest"
    assert "Router time now" in logged_in_client.get("/rules").text

    r = logged_in_client.post("/rules/timezone", data={"timezone": "Nowhere/Land"})
    assert "error=" in r.headers["location"]
    assert load_config(webui_env["config_path"]).timezone == "Europe/Budapest"

    logged_in_client.post("/rules/timezone", data={"timezone": ""})
    assert load_config(webui_env["config_path"]).timezone is None
