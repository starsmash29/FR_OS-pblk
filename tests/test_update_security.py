"""Security-lessons G10: a security release is announced loudly.

- a release is a security release when its title carries "[security]"
  or its notes a "Security: yes" line (docs/RELEASING.md);
- fr-update-check.timer runs `firewall-cli update auto`, which records
  what it found in a small cache;
- every webUI page shows that (tests/webui/test_update_banner.py).
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from frfw import __version__, cli, paths
from frfw import update as update_mod

NEWER = "99.0.0"


def _release(tag=f"v{NEWER}", name="", body="") -> dict:
    return {"tag_name": tag, "name": name, "body": body, "published_at": "2026-09-01T00:00:00Z",
            "html_url": f"https://github.com/x/y/releases/tag/{tag}"}


@pytest.mark.parametrize("name, notes, expected", [
    ("FR_OS 1.2.3 [security]", "", True),
    ("FR_OS 1.2.3 [SECURITY]", "", True),
    ("FR_OS 1.2.3", "Fixes a login bypass.\n\nSecurity: yes\n", True),
    ("FR_OS 1.2.3", "security: Yes", True),
    ("FR_OS 1.2.3", "Security: no", False),
    ("FR_OS 1.2.3", "Improves security: yes, a bit", False),  # only a line of its own counts
    ("FR_OS 1.2.3", "", False),
])
def test_what_makes_a_security_release(name, notes, expected):
    assert update_mod.is_security_release(name, notes) is expected


def test_the_flag_comes_from_the_github_release(monkeypatch):
    monkeypatch.setattr(update_mod, "_fetch_json", lambda url, timeout: _release(name=f"FR_OS {NEWER} [security]"))
    assert update_mod.check_latest("0.1.0", repo="x/y").latest.security is True


def test_the_cache_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(update_mod, "_fetch_json", lambda url, timeout: _release(body="Security: yes"))
    path = tmp_path / "update_check.json"
    update_mod.write_check_cache(update_mod.check_latest("0.1.0", repo="x/y"), path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    data = update_mod.read_check_cache(path, current_version="0.1.0")
    assert (data["latest_version"], data["security"], data["update_available"]) == (NEWER, True, True)
    # After updating, the old finding is not about this version any more.
    assert update_mod.read_check_cache(path, current_version=NEWER) is None


def test_a_security_release_older_than_what_runs_is_no_alarm(tmp_path, monkeypatch):
    monkeypatch.setattr(update_mod, "_fetch_json", lambda url, timeout: _release(tag="v0.0.1", body="Security: yes"))
    path = tmp_path / "update_check.json"
    update_mod.write_check_cache(update_mod.check_latest("0.1.0", repo="x/y"), path)
    assert update_mod.read_check_cache(path)["security"] is False


def test_a_broken_cache_is_no_cache(tmp_path):
    (tmp_path / "c.json").write_text("{nope")
    assert update_mod.read_check_cache(tmp_path / "c.json") is None
    (tmp_path / "c.json").write_text("[1]")
    assert update_mod.read_check_cache(tmp_path / "c.json") is None


# -- firewall-cli update auto -------------------------------------------------------------


def test_update_auto_records_what_it_found(monkeypatch, capsys):
    monkeypatch.setattr(update_mod, "_fetch_json", lambda url, timeout: _release(name="[security]"))
    assert cli.main(["update", "auto", "/nonexistent/config.yaml"]) == 0
    assert "SECURITY update available" in capsys.readouterr().out
    data = json.loads(paths.UPDATE_CHECK_PATH.read_text())
    assert data["current_version"] == __version__ and data["security"] is True and data["error"] is None


def test_a_failed_check_keeps_the_last_finding(monkeypatch):
    monkeypatch.setattr(update_mod, "_fetch_json", lambda url, timeout: _release(name="[security]"))
    cli.main(["update", "auto", "/nonexistent/config.yaml"])

    def offline(url, timeout):
        raise update_mod.UpdateError("network unreachable")

    monkeypatch.setattr(update_mod, "_fetch_json", offline)
    assert cli.main(["update", "auto", "/nonexistent/config.yaml"]) == 1
    data = json.loads(paths.UPDATE_CHECK_PATH.read_text())
    assert data["security"] is True and data["latest_version"] == NEWER  # still announced
    assert data["error"] == "network unreachable"


def test_the_timer_runs_the_check():
    root = Path(__file__).resolve().parents[1]
    service = (root / "systemd" / "fr-update-check.service").read_text()
    timer = (root / "systemd" / "fr-update-check.timer").read_text()
    assert "firewall-cli update auto" in service
    assert "OnUnitActiveSec=12h" in timer and "Persistent=true" in timer
    for installer in ("scripts/install-system-integration.sh",
                      "installer/live-build/config/hooks/0100-install-frfw.hook.chroot"):
        assert "fr-update-check.timer" in (root / installer).read_text(), installer
