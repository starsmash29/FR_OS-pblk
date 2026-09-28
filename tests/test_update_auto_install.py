"""Security-lessons J3: patch faster than attackers weaponise.

With `update.auto_install_security: true` (off by default),
fr-update-check.timer installs a security release by itself --
`apply_update` verifies its signature first, as for any update -- and the
admins get an alert either way. Nothing else is installed on its own: an
ordinary release, a router that hasn't opted in, or a config that can't
be read all leave the software as it is.
"""

from __future__ import annotations

import json

import pytest
import yaml

from frfw import __version__, cli, paths
from frfw import update as update_mod
from frfw.config import ConfigError, parse_config
from frfw.webui import audit

NEWER = "99.0.0"

_BASE = {
    "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}},
    "interfaces": {"wan": {"device": "eth0", "zone": "wan"}, "lan": {"device": "eth1", "zone": "lan"}},
    "rules": [], "nat": {"masquerade": [{"out_zone": "wan"}]},
}


def _config(tmp_path, **update) -> str:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({**_BASE, "update": update}))
    return str(path)


@pytest.fixture
def release(monkeypatch):
    """The latest release on GitHub; `installs` records apply_update calls."""
    state = {"name": f"FR_OS {NEWER} [security]", "installs": [], "fail": None}

    def fetch(url, timeout):
        return {"tag_name": f"v{NEWER}", "name": state["name"], "body": "", "html_url": ""}

    def apply(version, *, repo=update_mod.DEFAULT_REPO, **kw):
        if state["fail"]:
            raise update_mod.UpdateError(state["fail"])
        state["installs"].append((version, repo))
        return version

    monkeypatch.setattr(update_mod, "_fetch_json", fetch)
    monkeypatch.setattr(update_mod, "apply_update", apply)
    return state


def _alerts() -> list[str]:
    return [e["alert"] for e in audit.read_recent(paths.AUDIT_LOG_PATH) if e.get("alert")]


def test_off_by_default():
    assert parse_config(_BASE).update.auto_install_security is False


def test_the_setting_must_be_a_boolean():
    with pytest.raises(ConfigError, match="auto_install_security"):
        parse_config({**_BASE, "update": {"auto_install_security": "yes"}})


def test_an_opted_in_router_installs_a_security_release(tmp_path, release):
    assert cli.main(["update", "auto", _config(tmp_path, auto_install_security=True)]) == 0
    assert release["installs"] == [(NEWER, update_mod.DEFAULT_REPO)]
    assert _alerts() == [f"security release {NEWER} installed automatically (was {__version__})"]
    entry = [e for e in audit.read_recent(paths.AUDIT_LOG_PATH) if e.get("alert")][0]
    assert entry["user"] == "fr-update-check"


def test_it_installs_from_the_configured_repo(tmp_path, release):
    cli.main(["update", "auto", _config(tmp_path, auto_install_security=True, repo="someone/fork")])
    assert release["installs"] == [(NEWER, "someone/fork")]


def test_without_the_opt_in_it_only_announces(tmp_path, release):
    assert cli.main(["update", "auto", _config(tmp_path)]) == 0
    assert release["installs"] == [] and _alerts() == []
    assert json.loads(paths.UPDATE_CHECK_PATH.read_text())["security"] is True


def test_an_ordinary_release_is_never_installed_by_itself(tmp_path, release):
    release["name"] = f"FR_OS {NEWER}"
    cli.main(["update", "auto", _config(tmp_path, auto_install_security=True)])
    assert release["installs"] == []


def test_an_unreadable_config_installs_nothing(tmp_path, release):
    (tmp_path / "bad.yaml").write_text("update: [not, a, mapping")
    cli.main(["update", "auto", str(tmp_path / "bad.yaml")])
    cli.main(["update", "auto", str(tmp_path / "missing.yaml")])
    assert release["installs"] == []


def test_a_failed_install_is_an_alert_and_on_the_update_screen(tmp_path, release):
    release["fail"] = "signature does not verify"
    assert cli.main(["update", "auto", _config(tmp_path, auto_install_security=True)]) == 1
    assert _alerts() == [f"automatic install of security release {NEWER} failed: signature does not verify"]
    data = json.loads(paths.UPDATE_CHECK_PATH.read_text())
    assert data["auto_install_error"] == "signature does not verify"
    assert data["security"] is True  # the red banner stays
