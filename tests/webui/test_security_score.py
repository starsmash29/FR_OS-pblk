"""Security-lessons K8: the security checklist -- K1-K7 and friends as a
score, on its own screen and on the dashboard, each item linking to the
screen that fixes it."""

from __future__ import annotations

import json

import pytest
import yaml
from fastapi.testclient import TestClient

from frfw import __version__, integrity, security_score, skeleton
from frfw.admin_account import ROLE_ADMIN
from frfw.webui.app import create_app

GOOD = "orchid-lamp-7"


@pytest.fixture
def env(webui_env, monkeypatch):
    monkeypatch.setattr(integrity, "cached_check", lambda: integrity.IntegrityReport(10))
    webui_env["admin_store"].set_password("boss", GOOD, ROLE_ADMIN)
    webui_env["config_path"].write_text(skeleton.build_skeleton_config("eth0", "eth1"))
    webui_env["update_check_path"].write_text(json.dumps({"current_version": __version__,
                                                         "update_available": False}))
    return webui_env


def _page(env, path="/security") -> str:
    client = TestClient(create_app(**env), follow_redirects=False)
    client.post("/login", data={"username": "boss", "password": GOOD})
    return client.get(path).text


def _states(env) -> dict[str, str]:
    client = TestClient(create_app(**env), follow_redirects=False)
    client.post("/login", data={"username": "boss", "password": GOOD})
    from frfw.webui.routes.security import score_for

    class Req:
        app = client.app

    raw = yaml.safe_load(env["config_path"].read_text())
    score = score_for(Req, raw, env["admin_store"], env["helper"])
    return {c.id: c.state for c in score.checks}


def test_a_fresh_router(env):
    states = _states(env)
    assert states == {
        "default-user": "ok", "mfa": "fail", "wan-management": "ok", "updates": "ok", "auto-security": "fail",
        "rules": "ok", "logging": "ok", "segments": "ok", "listening": "ok", "integrity": "ok",
    }


def test_each_fix_shows(env):
    client = TestClient(create_app(**env), follow_redirects=False)
    client.post("/login", data={"username": "boss", "password": GOOD})
    # Signed in already: with a second factor the next sign-in would ask for it.
    env["admin_store"].set_mfa("boss", {"totp": {"secret": "JBSWY3DPEHPK3PXP", "last_step": -1}})
    raw = yaml.safe_load(env["config_path"].read_text())
    raw["update"] = {"auto_install_security": True}
    env["config_path"].write_text(yaml.safe_dump(raw))
    assert set(_states(env).values()) == {"ok"}
    page = client.get("/security").text
    assert 'id="score">100%' in page
    assert "Every checked item is in order" in client.get("/").text


def test_what_goes_wrong_shows_up(env):
    raw = yaml.safe_load(env["config_path"].read_text())
    raw["management"] = {"allow_wan": True}
    raw["rules"].append({"name": "everything", "action": "accept"})
    raw["rules"].append({"name": "lan-to-router", "action": "accept", "from_zone": "lan", "to_zone": "self"})
    raw["logging"] = {"drops": False}
    raw.pop("iot")
    env["config_path"].write_text(yaml.safe_dump(raw))
    env["update_check_path"].write_text(json.dumps({"current_version": __version__, "update_available": True,
                                                    "latest_version": "99.0.0", "security": True}))
    env["helper"].listeners = [{"proto": "tcp", "address": "0.0.0.0", "port": 8080, "device": None,
                                "process": "rogue"}]
    states = _states(env)
    for check in ("wan-management", "updates", "rules", "logging", "segments", "listening"):
        assert states[check] == "fail", check
    dashboard = _page(env, "/")
    assert "FR_OS 99.0.0 is available -- a security release" in dashboard
    assert "management.allow_wan is on" in dashboard and "tcp/8080" in dashboard


def test_default_names_and_missing_facts():
    from frfw.admin_account import AdminAccount

    accounts = {"root": AdminAccount("root", "x"), "boss": AdminAccount("boss", "x")}
    score = security_score.evaluate(config=None, accounts=accounts, policy={}, update_check=None,
                                    integrity=None, lint_findings=None, surface_rows=None)
    states = {c.id: c.state for c in score.checks}
    assert states["default-user"] == "fail" and states["config"] == "fail"
    report = integrity.IntegrityReport(0, verifiable=False, note="development install")
    from frfw.config import parse_config

    score = security_score.evaluate(config=parse_config(yaml.safe_load(skeleton.build_skeleton_config("a", "b"))),
                                    accounts={}, policy={}, update_check=None, integrity=report,
                                    lint_findings=None, surface_rows=None)
    unknown = {c.id for c in score.checks if c.state == "unknown"}
    assert unknown == {"updates", "rules", "listening", "integrity"}
    assert score.known == len(score.checks) - 4  # unknowns count neither way
