"""ROADMAP SEC-30: the Rules screen places a new rule where it takes effect
and lets the admin move rules up or down.

CSRF on the new POST route and its editor-only role are covered by the
route-walking tests (test_csrf.py, test_rbac.py); here we check the
behaviour: a deny added behind a broad accept lands in front of it, and the
move buttons reorder config.yaml (Apply still waits for confirmation).
"""

from __future__ import annotations

from frfw.config import load_config
from tests.webui.test_routes import _seed_wan_lan


def _names(path):
    return [r.name for r in load_config(path).rules]


def test_new_deny_is_placed_before_the_rule_that_would_shadow_it(logged_in_client, webui_env):
    _seed_wan_lan(logged_in_client)
    logged_in_client.post("/rules/add", data={
        "name": "lan-to-wan", "action": "accept", "from_zone": "lan", "to_zone": "wan"})
    r = logged_in_client.post("/rules/add", data={
        "name": "block-host", "action": "drop", "from_zone": "lan", "to_zone": "wan",
        "src_address": "192.168.1.50/32"})
    assert "success" in r.headers["location"]
    assert "placed" in r.headers["location"].replace("%20", " ").replace("+", " ")
    assert _names(webui_env["config_path"]) == ["block-host", "lan-to-wan"]


def test_move_up_and_down_reorders_config(logged_in_client, webui_env):
    _seed_wan_lan(logged_in_client)
    for name in ("a", "b", "c"):
        logged_in_client.post("/rules/add", data={
            "name": name, "action": "accept", "from_zone": "lan", "to_zone": "wan",
            "proto": "tcp", "dst_port": {"a": 1, "b": 2, "c": 3}[name]})
    assert _names(webui_env["config_path"]) == ["a", "b", "c"]

    r = logged_in_client.post("/rules/move/c", data={"direction": "up"})
    assert "success" in r.headers["location"]
    assert _names(webui_env["config_path"]) == ["a", "c", "b"]

    r = logged_in_client.post("/rules/move/a", data={"direction": "down"})
    assert "success" in r.headers["location"]
    assert _names(webui_env["config_path"]) == ["c", "a", "b"]


def test_move_at_the_edge_is_an_error_and_changes_nothing(logged_in_client, webui_env):
    _seed_wan_lan(logged_in_client)
    logged_in_client.post("/rules/add", data={
        "name": "only", "action": "accept", "from_zone": "lan", "to_zone": "wan"})
    r = logged_in_client.post("/rules/move/only", data={"direction": "up"})
    assert "error=" in r.headers["location"]
    assert _names(webui_env["config_path"]) == ["only"]


def test_move_rejects_a_bad_direction_and_unknown_rule(logged_in_client, webui_env):
    _seed_wan_lan(logged_in_client)
    logged_in_client.post("/rules/add", data={
        "name": "a", "action": "accept", "from_zone": "lan", "to_zone": "wan"})
    r = logged_in_client.post("/rules/move/a", data={"direction": "sideways"})
    assert "error=" in r.headers["location"]
    r = logged_in_client.post("/rules/move/nope", data={"direction": "up"})
    assert "error=" in r.headers["location"]
    assert _names(webui_env["config_path"]) == ["a"]


def test_the_rules_screen_shows_the_move_buttons(logged_in_client, webui_env):
    _seed_wan_lan(logged_in_client)
    logged_in_client.post("/rules/add", data={
        "name": "a", "action": "accept", "from_zone": "lan", "to_zone": "wan"})
    page = logged_in_client.get("/rules").text
    assert "/rules/move/a" in page
    assert 'value="up"' in page and 'value="down"' in page
