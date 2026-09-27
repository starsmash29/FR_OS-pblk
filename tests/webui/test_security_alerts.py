"""Security-lessons G9: detect persistence.

- the audit log is root's: the webUI only *adds* to it, through the
  apply-helper (E6);
- a new admin, a new ZTNA user, a sign-in from a new address, a second
  factor removed, management opened to the WAN -- each is an alert on the
  dashboard until an admin has seen it;
- a check of the installed software against its install-time hashes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import stat
from importlib import metadata
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from frfw import integrity, paths
from frfw.admin_account import ROLE_ADMIN, ROLE_VIEWER
from frfw.helper import server as helper_server
from frfw.webui import audit
from frfw.webui.app import create_app

GOOD = "orchid-lamp-7"


def _from(app, ip="192.168.1.10") -> TestClient:
    return TestClient(app, follow_redirects=False, client=(ip, 50000))


def _signed_in(app, username="boss", password=GOOD, ip="192.168.1.10") -> TestClient:
    client = _from(app, ip)
    assert client.post("/login", data={"username": username, "password": password}).headers["location"] == "/"
    return client


@pytest.fixture
def env(webui_env):
    webui_env["admin_store"].set_password("boss", GOOD, ROLE_ADMIN)
    webui_env["admin_store"].add_user("guest", "violet-anchor-9", ROLE_VIEWER)
    webui_env["config_path"].write_text(yaml.safe_dump({
        "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"},
                       "lan": {"device": "eth1", "zone": "lan", "address": "192.168.1.1/24"}},
        "rules": [], "nat": {"masquerade": [{"out_zone": "wan"}]},
    }))
    return webui_env


def _alerts(env) -> list[str]:
    return [e["alert"] for e in audit.read_recent(env["audit_log_path"]) if e.get("alert")]


# -- the audit log is root's ------------------------------------------------------------


def test_on_a_router_the_webui_appends_through_the_helper(env, monkeypatch, tmp_path):
    """create_app without an injected helper is the real router: every
    audit append goes to the apply-helper, never into the file."""
    from frfw.webui import helper_client

    sent = []
    monkeypatch.setattr(helper_client.SocketHelperClient, "audit_append", lambda self, entry: sent.append(entry))
    log = tmp_path / "root-owned-audit.log"
    try:
        create_app(**{**env, "helper": None, "audit_log_path": log})
        audit.append(log, {"user": "boss", "event": "login"})
    finally:
        audit.route(log, None)
    assert sent == [{"user": "boss", "event": "login"}]
    assert not log.exists()


def test_the_helper_writes_what_the_webui_sends(tmp_path):
    server = type("S", (), {"audit_log_path": tmp_path / "log" / "audit.log"})()
    reply = helper_server._handle_audit_append({"entry": {"user": "boss", "event": "login", "status": 303}}, server)
    assert reply == {"ok": True}
    entry = json.loads(server.audit_log_path.read_text())
    assert entry["via"] == "webui" and entry["user"] == "boss" and isinstance(entry["ts"], float)
    assert stat.S_IMODE(server.audit_log_path.stat().st_mode) == 0o640
    assert stat.S_IMODE(server.audit_log_path.parent.stat().st_mode) == 0o750


@pytest.mark.parametrize("entry", [
    {"ts": 1},  # the time is the helper's
    {"via": "cli"},  # so is the origin
    {"x": {"nested": 1}},
    {"x": [1, 2]},
    {"not an identifier": 1},
    {f"k{i}": i for i in range(21)},
    "just a string",
])
def test_the_helper_refuses_malformed_entries(tmp_path, entry):
    server = type("S", (), {"audit_log_path": tmp_path / "audit.log"})()
    assert helper_server._handle_audit_append({"entry": entry}, server)["ok"] is False
    assert not server.audit_log_path.exists()


def test_long_values_are_cut(tmp_path):
    server = type("S", (), {"audit_log_path": tmp_path / "audit.log"})()
    helper_server._handle_audit_append({"entry": {"event": "x" * 5000}}, server)
    assert len(json.loads(server.audit_log_path.read_text())["event"]) == 500


def test_only_the_webui_may_append():
    from frfw.helper import peer

    assert "audit_append" not in peer.SENSOR_COMMANDS


# -- alerts --------------------------------------------------------------------------------


def test_a_new_admin_is_an_alert_on_the_dashboard(env):
    app = create_app(**env)
    admin = _signed_in(app)
    admin.post("/users/add", data={"new_username": "helpdesk", "new_password": "violet-anchor-8", "role": "admin"})
    admin.post("/users/add", data={"new_username": "reader", "new_password": "violet-anchor-7", "role": "viewer"})
    admin.post("/users/guest/role", data={"role": "admin"})
    assert _alerts(env) == ["'guest' made an admin by 'boss'", "new admin account 'helpdesk' added by 'boss'"]
    page = admin.get("/").text
    assert "Security alerts (2 new)" in page and "helpdesk" in page


def test_the_other_persistence_events_are_alerts(env):
    app = create_app(**env)
    admin = _signed_in(app)
    env["admin_store"].add_user("ops", "violet-anchor-6", ROLE_ADMIN)
    admin.post("/users/ops/password", data={"new_password": "violet-anchor-5"})
    admin.post("/ztna/users/add", data={"new_username": "alice", "new_password": "violet-anchor-4"})
    admin.post("/system/management", data={"allow_wan": "true"})
    admin.post("/users/mfa-policy", data={})  # already off: nothing to report
    # Turning the requirement off takes an admin who has a second factor.
    env["admin_store"].set_policy(require_mfa_for_admins=True)
    env["admin_store"].set_mfa("boss", {"totp": {"secret": "JBSWY3DPEHPK3PXP", "last_step": -1}})
    admin.post("/users/mfa-policy", data={})
    got = "\n".join(_alerts(env))
    assert "password of admin 'ops' reset by 'boss'" in got
    assert "new ZTNA user 'alice' set by 'boss'" in got
    assert "opened management (webUI, SSH) to the internet" in got
    assert "turned the second-factor requirement for admins off" in got
    assert got.count("second-factor requirement") == 1


def test_a_sign_in_from_a_new_address_is_an_alert(env):
    app = create_app(**env)
    _signed_in(app, ip="192.168.1.10")  # the first: nothing to compare with
    _signed_in(app, ip="192.168.1.10")
    assert _alerts(env) == []
    _signed_in(app, ip="198.51.100.23")
    assert _alerts(env) == ["'boss' signed in from a new address 198.51.100.23"]


def test_seen_alerts_go_away_and_new_ones_come_back(env):
    app = create_app(**env)
    admin = _signed_in(app)
    admin.post("/users/add", data={"new_username": "helpdesk", "new_password": "violet-anchor-8", "role": "admin"})
    page = admin.get("/").text
    until = page.split('name="until" value="')[1].split('"')[0]
    admin.post("/alerts/seen", data={"until": until})
    assert "Security alerts" not in admin.get("/").text
    admin.post("/users/guest/role", data={"role": "admin"})
    assert "Security alerts (1 new)" in admin.get("/").text
    # Seen is per admin: another admin still sees both.
    other = _signed_in(app, "helpdesk", "violet-anchor-8")
    assert "Security alerts (2 new)" in other.get("/").text


def test_viewers_do_not_get_the_alerts(env):
    app = create_app(**env)
    _signed_in(app).post("/users/add", data={"new_username": "helpdesk", "new_password": "violet-anchor-8",
                                             "role": "admin"})
    viewer = _signed_in(app, "guest", "violet-anchor-9")
    assert "Security alerts" not in viewer.get("/").text
    assert viewer.post("/alerts/seen", data={"until": "0"}).status_code == 403


def test_console_changes_are_alerts_too(env, monkeypatch, tmp_path):
    from frfw import cli
    from frfw.admin_account import AdminStore

    monkeypatch.setattr(cli, "AdminStore", lambda: AdminStore(tmp_path / "auth.json"))
    answers = iter(["zebra-lamp-42", "zebra-lamp-42"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert cli.main(["set-admin-password", "--username", "rescue"]) == 0
    alerts = [e for e in audit.read_recent(paths.AUDIT_LOG_PATH) if e.get("alert")]
    assert alerts[0]["alert"].startswith("admin account 'rescue' set from the console")
    assert alerts[0]["user"] == "console"
    assert stat.S_IMODE(paths.AUDIT_LOG_PATH.stat().st_mode) == 0o640


# -- software integrity -----------------------------------------------------------------------


def _fake_install(tmp_path: Path, files: dict[str, bytes]) -> metadata.Distribution:
    site = tmp_path / "site"
    dist_info = site / "frfw-9.9.9.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text("Metadata-Version: 2.1\nName: frfw\nVersion: 9.9.9\n")
    rows = []
    for name, content in files.items():
        path = site / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        rows.append(f"{name},sha256={digest},{len(content)}")
    rows.append("frfw-9.9.9.dist-info/RECORD,,")
    (dist_info / "RECORD").write_text("\n".join(rows) + "\n")
    return metadata.PathDistribution(dist_info)


def test_an_untouched_install_is_ok(tmp_path):
    dist = _fake_install(tmp_path, {"frfw/__init__.py": b"x = 1\n", "frfw/cli.py": b"print(1)\n"})
    report = integrity.check(dist)
    assert report.ok and report.checked == 2


def test_a_patched_or_deleted_file_is_found(tmp_path):
    dist = _fake_install(tmp_path, {"frfw/__init__.py": b"x = 1\n", "frfw/admin_account.py": b"def verify(): ...\n",
                                    "frfw/cli.py": b"print(1)\n"})
    (tmp_path / "site" / "frfw" / "admin_account.py").write_bytes(b"def verify(): return True  # implant\n")
    (tmp_path / "site" / "frfw" / "cli.py").unlink()
    report = integrity.check(dist)
    assert not report.ok
    assert report.modified == ["frfw/admin_account.py"] and report.missing == ["frfw/cli.py"]
    assert report.summary == "1 modified and 1 missing of 3 installed files"


def test_a_development_install_is_not_called_clean(tmp_path):
    dist = _fake_install(tmp_path, {"bin/firewall-cli": b"#!/bin/sh\n"})
    report = integrity.check(dist)
    assert not report.verifiable and not report.ok


def test_a_changed_install_shows_on_the_dashboard_and_system_screen(env, monkeypatch):
    changed = integrity.IntegrityReport(10, modified=["frfw/admin_account.py"])
    monkeypatch.setattr(integrity, "cached_check", lambda: changed)
    admin = _signed_in(create_app(**env))
    assert "Installed software changed" in admin.get("/").text
    assert "frfw/admin_account.py" in admin.get("/system").text


def test_the_cli_exit_code(monkeypatch, capsys):
    from frfw import cli

    monkeypatch.setattr(integrity, "check", lambda: integrity.IntegrityReport(3, missing=["frfw/x.py"]))
    assert cli.main(["integrity"]) == 1
    assert "missing:  frfw/x.py" in capsys.readouterr().out
    monkeypatch.setattr(integrity, "check", lambda: integrity.IntegrityReport(3))
    assert cli.main(["integrity"]) == 0
