"""Security-lessons F2/G4: the management plane (webUI :443, SSH :22) is
not reachable from the internet unless management.allow_wan says so.

Before: the webUI listened on 0.0.0.0, sshd on every address, and only
the admin's own rules decided whether :443/:22 were open from the WAN.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

from frfw import management
from frfw.apply import check_syntax
from frfw.config import ConfigError, parse_config
from frfw.nft.builder import build_ruleset
from frfw.skeleton import build_skeleton_config


def _config(**management_section):
    raw = yaml.safe_load(build_skeleton_config("eth0", "eth1"))
    raw["zones"]["guest"] = {}
    raw["interfaces"]["guest"] = {"device": "eth2", "zone": "guest", "address": "10.9.0.1/24"}
    if management_section:
        raw["management"] = management_section
    return parse_config(raw)


def test_defaults_to_every_zone_that_is_not_the_internet():
    config = _config()
    assert management.management_zones(config) == ["guest", "lan"]
    assert management.blocked_zones(config) == ["wan"]
    assert management.listen_addresses(config) == ["127.0.0.1", "10.9.0.1", "192.168.1.1"]


def test_management_zones_can_be_narrowed():
    config = _config(zones=["lan"])
    assert management.blocked_zones(config) == ["guest", "wan"]
    assert management.listen_addresses(config) == ["127.0.0.1", "192.168.1.1"]


def test_the_internet_needs_the_explicit_opt_in():
    with pytest.raises(ConfigError, match="allow_wan"):
        _config(zones=["lan", "wan"])
    config = _config(zones=["lan", "wan"], allow_wan=True)
    assert management.listen_addresses(config) == ["0.0.0.0"]
    assert management.blocked_zones(config) == ["guest"]
    everywhere = _config(allow_wan=True)
    assert management.blocked_zones(everywhere) == []


def test_ruleset_drops_management_from_the_wan_before_admin_rules():
    raw = yaml.safe_load(build_skeleton_config("eth0", "eth1"))
    # An admin rule that would open the webUI to the internet.
    raw["rules"].append({"name": "oops", "action": "accept", "from_zone": "wan", "to_zone": "self",
                         "proto": "tcp", "dst_port": 443})
    ruleset = build_ruleset(parse_config(raw))
    drop = 'iifname @wan_ifaces tcp dport { 22, 443 } drop comment "no-management-from-wan"'
    assert drop in ruleset
    assert ruleset.index(drop) < ruleset.index('comment "rule:oops"')
    assert "no-management-from-lan" not in ruleset
    check_syntax_if_nft(ruleset)


def test_allow_wan_leaves_the_drop_out():
    raw = yaml.safe_load(build_skeleton_config("eth0", "eth1"))
    raw["management"] = {"allow_wan": True}
    assert "no-management-from" not in build_ruleset(parse_config(raw))


def check_syntax_if_nft(ruleset: str) -> None:
    if shutil.which("nft") and os.geteuid() == 0:
        check_syntax(ruleset)


# -- sshd --------------------------------------------------------------------------


@pytest.fixture
def fake_sshd(tmp_path):
    """An `sshd` whose `-t` result the test decides."""
    script = tmp_path / "sshd"
    verdict = tmp_path / "verdict"
    verdict.write_text("0")
    script.write_text(f"#!/bin/sh\nexit $(cat {verdict})\n")
    script.chmod(0o755)
    return script, verdict


def test_sshd_listens_on_the_management_addresses_only(tmp_path, fake_sshd, monkeypatch):
    sshd, _ = fake_sshd
    reloads = []
    monkeypatch.setattr(management.svc, "systemctl",
                        lambda action, unit, timeout=None: reloads.append((action, unit))
                        or subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr("os.geteuid", lambda: 0)
    dropin = tmp_path / "40-fr_os-management.conf"
    management.sync_sshd(_config(zones=["lan"]), dropin_path=dropin, sshd_binary=str(sshd))
    listen = [line for line in dropin.read_text().splitlines() if line.startswith("ListenAddress")]
    assert listen == ["ListenAddress 127.0.0.1", "ListenAddress 192.168.1.1"]
    assert reloads == [("try-reload-or-restart", "ssh")]


def test_a_dropin_sshd_rejects_is_rolled_back(tmp_path, fake_sshd, monkeypatch):
    sshd, verdict = fake_sshd
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(management.svc, "systemctl",
                        lambda *a, **k: subprocess.CompletedProcess([], 0, "", ""))
    dropin = tmp_path / "40-fr_os-management.conf"
    dropin.write_text("# the previous one\n")
    verdict.write_text("1")
    with pytest.raises(management.ManagementError):
        management.sync_sshd(_config(), dropin_path=dropin, sshd_binary=str(sshd))
    assert dropin.read_text() == "# the previous one\n"


# -- the real webUI process --------------------------------------------------------


@pytest.mark.skipif(not shutil.which("ss") or not shutil.which("openssl"), reason="needs ss and openssl")
def test_the_webui_does_not_listen_on_every_address(tmp_path):
    """Start the real fr-webui with a skeleton config: it must listen on
    loopback and the LAN address (not configured on this machine --
    IP_FREEBIND), and not on 0.0.0.0."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(build_skeleton_config("eth0", "eth1", lan_address="10.99.0.1/24"))
    port = 18000 + os.getpid() % 1000
    proc = subprocess.Popen(
        [sys.executable, "-m", "frfw.webui.server", "--config", str(config_path), "--port", str(port),
         "--cert", str(tmp_path / "cert.pem"), "--key", str(tmp_path / "key.pem")],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "OPENSSL_CONF": "/dev/null"},
    )
    try:
        listening = None
        for _ in range(100):
            listening = management.webui_listening(port)
            if listening and len(listening) >= 2:
                break
            if proc.poll() is not None:
                pytest.fail(proc.stderr.read())
            time.sleep(0.2)
        assert listening == {"127.0.0.1", "10.99.0.1"}
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
