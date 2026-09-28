"""Security-lessons K2 on the Rules screen: the rule check, temporary
rules, last match, and a warning when a new rule is a problem."""

from __future__ import annotations

import time

import pytest
import yaml
from fastapi.testclient import TestClient

from frfw import rule_hits
from frfw.admin_account import ROLE_ADMIN
from frfw.config import load_config
from frfw.webui.app import create_app


@pytest.fixture
def admin(webui_env):
    webui_env["admin_store"].set_password("boss", "orchid-lamp-7", ROLE_ADMIN)
    webui_env["config_path"].write_text(yaml.safe_dump({
        "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"},
                       "lan": {"device": "eth1", "zone": "lan", "address": "192.168.1.1/24"}},
        "rules": [{"name": "lan-out", "action": "accept", "from_zone": "lan", "to_zone": "wan"}],
        "nat": {"masquerade": [{"out_zone": "wan"}]},
    }))
    client = TestClient(create_app(**webui_env), follow_redirects=False)
    client.post("/login", data={"username": "boss", "password": "orchid-lamp-7"})
    client.env = webui_env
    return client


def test_a_clean_rule_set(admin):
    assert "No problems found" in admin.get("/rules").text


def test_a_dangerous_new_rule_is_saved_with_a_warning(admin):
    response = admin.post("/rules/add", data={"name": "oops", "action": "accept", "from_zone": "wan",
                                              "to_zone": "lan"})
    assert "error=Rule+%27oops%27+saved%2C+but+it+opens+all+of+the+lan+zone" in response.headers["location"]
    page = admin.get("/rules").text
    assert "open-from-internet" in page and "oops" in page


def test_a_temporary_rule(admin):
    admin.post("/rules/add", data={"name": "fix-printer", "action": "accept", "from_zone": "lan", "to_zone": "wan",
                                   "proto": "tcp", "dst_port": "9100", "expires": "2099-01-01T12:00"})
    rule = load_config(admin.env["config_path"]).rules[-1]
    assert rule.name == "fix-printer" and rule.expires is not None
    assert "2099-01-01 12:00" in admin.get("/rules").text


def test_expired_rules_can_be_cleared(admin):
    admin.post("/rules/add", data={"name": "old-fix", "action": "accept", "from_zone": "lan", "to_zone": "wan",
                                   "proto": "tcp", "dst_port": "9100", "expires": "2020-01-01T12:00"})
    page = admin.get("/rules").text
    assert "expired" in page and "Remove expired rules" in page
    assert "old-fix" in admin.post("/rules/remove-expired").headers["location"]
    assert [r.name for r in load_config(admin.env["config_path"]).rules] == ["lan-out"]


def test_last_match_and_unused(admin):
    now = time.time()
    rule_hits.record({"lan-out": 0}, ["lan-out"], now=now - 100 * 24 * 3600)
    page = admin.get("/rules").text
    assert "unused" in page and "no traffic has matched it for 90 days" in page
    rule_hits.record({"lan-out": 5}, ["lan-out"], now=now)
    page = admin.get("/rules").text
    assert "No problems found" in page and time.strftime("%Y-%m-%d", time.localtime(now)) in page
