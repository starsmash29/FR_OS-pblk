"""The console's port summary (frfw.console_ports).

First boot's one-off line in /etc/issue went stale as soon as a port's
role or a cable moved; the summary is rewritten on every link change.
It shows the roles the applied config gives, and only warns about a
misplaced LAN cable: it never moves a role (the owner's decision).
"""

from __future__ import annotations

import json
import stat
import subprocess
from pathlib import Path

from frfw import cli, console_ports, netdetect
from frfw.console_ports import Role

REPO_ROOT = Path(__file__).resolve().parents[1]

CONFIG = """
version: 1
hostname: fr-os
interfaces:
  wan: {device: enp4s0, zone: wan}
  lan: {device: enp3s0, zone: lan, address: 10.73.1.1/24}
  iot: {device: enp3s0.30, zone: iot, address: 10.73.30.1/24, vlan: {parent: enp3s0, id: 30}}
zones: {wan: {}, lan: {}, iot: {}}
"""


def port(name, link, speed=None):
    return netdetect.DetectedInterface(name=name, mac_address=None, driver="r8169", link_up=link, speed_mbps=speed)


def test_roles_come_from_the_config_with_vlans_on_their_parent():
    roles = console_ports.roles_by_device(CONFIG)
    assert roles["enp4s0"] == [Role("wan", "wan")]
    assert roles["enp3s0"] == [Role("lan", "lan"), Role("iot", "iot", 30)]


def test_a_missing_or_broken_config_gives_no_roles():
    assert console_ports.roles_by_device(None) == {}
    assert console_ports.roles_by_device("interfaces: [") == {}
    assert console_ports.roles_by_device("interfaces: 3") == {}


def test_every_port_with_its_link_role_and_address():
    text = console_ports.render(
        [port("enp2s0", False), port("enp3s0", True, 100), port("enp4s0", True, 1000)],
        console_ports.roles_by_device(CONFIG),
        {"enp3s0": ["10.73.1.1/24"], "enp4s0": ["192.168.1.23/24"]},
        ["127.0.0.1", "10.73.1.1"],
    )
    lines = text.splitlines()
    assert lines[0] == "FR_OS ports:"
    enp2, enp3, enp4 = lines[1:4]
    assert "enp2s0" in enp2 and "no link" in enp2 and "not assigned" in enp2 and "no address" in enp2
    assert "link 100 Mbit/s" in enp3 and "LAN, IOT on VLAN 30  10.73.1.1/24" in enp3 and "10.73.1.1/24" in enp3
    assert "link 1000 Mbit/s" in enp4 and "WAN" in enp4 and "192.168.1.23/24" in enp4
    # Loopback is where the webUI always listens; not an address to show.
    assert "webUI: https://10.73.1.1/ (from the LAN)" in lines
    assert "WARNING" not in text
    assert text.endswith("\n\n")


def test_a_lan_cable_in_the_wrong_port_is_a_warning_and_the_role_stays():
    roles = console_ports.roles_by_device(CONFIG)
    text = console_ports.render(
        [port("enp2s0", True, 1000), port("enp3s0", False), port("enp4s0", True, 1000)],
        roles, {}, ["10.73.1.1"],
    )
    assert "WARNING: the LAN port (enp3s0) has no link, but enp2s0 (no role) has one" in text
    assert console_ports.roles_by_device(CONFIG) == roles  # nothing moved


def test_no_warning_when_no_spare_port_has_a_link():
    text = console_ports.render(
        [port("enp2s0", False), port("enp3s0", False), port("enp4s0", True)],
        console_ports.roles_by_device(CONFIG), {}, None,
    )
    assert "WARNING" not in text


def test_before_any_role_it_says_how_to_assign_them():
    text = console_ports.render([port("ens3", True)], {}, {}, None)
    assert "not assigned" in text and "firewall-cli assign-interfaces" in text


def test_agetty_escapes_are_printed_literally():
    text = console_ports.render([port("we\\ird", True)], {}, {}, None)
    assert "we\\\\ird" in text


def test_addresses_come_from_ip_json():
    out = json.dumps([
        {"ifname": "lo", "addr_info": [{"local": "127.0.0.1", "prefixlen": 8}]},
        {"ifname": "enp4s0", "addr_info": [{"local": "192.168.1.23", "prefixlen": 24}]},
        {"ifname": "enp2s0", "addr_info": []},
    ])
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, out, "")

    assert console_ports.ipv4_addresses(run) == {"lo": ["127.0.0.1/8"], "enp4s0": ["192.168.1.23/24"]}
    assert calls == [["ip", "-j", "-4", "address", "show"]]


def test_no_addresses_when_ip_fails():
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "", "error")

    assert console_ports.ipv4_addresses(run) == {}


def test_written_world_readable_and_only_when_changed(tmp_path):
    path = tmp_path / "issue.d" / "fr_os-ports.issue"
    assert console_ports.write("one\n", path=path) is True
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    assert console_ports.write("one\n", path=path) is False
    assert console_ports.write("two\n", path=path) is True
    assert path.read_text() == "two\n"


def test_first_boots_old_line_leaves_etc_issue(tmp_path):
    issue = tmp_path / "issue"
    issue.write_text(
        "FR_OS webUI: https://10.73.1.1/ from a computer on the LAN port (enp3s0); WAN is enp4s0 (...)\n"
        "\n"
        "Debian GNU/Linux 12 \\n \\l\n"
        "\n"
    )
    issue.chmod(0o644)
    assert console_ports.remove_legacy_line(issue) is True
    assert issue.read_text() == "Debian GNU/Linux 12 \\n \\l\n\n"
    assert stat.S_IMODE(issue.stat().st_mode) == 0o644
    assert console_ports.remove_legacy_line(issue) is False


def test_the_cli_prints_without_writing(monkeypatch, capsys):
    monkeypatch.setattr(console_ports, "summary", lambda: "FR_OS ports:\n  ens3\n\n")
    monkeypatch.setattr(console_ports, "write", lambda *a, **k: (_ for _ in ()).throw(AssertionError("wrote")))
    assert cli.main(["console-ports", "--print"]) == 0
    assert capsys.readouterr().out.startswith("FR_OS ports:")


def test_first_boot_no_longer_writes_the_one_off_line_and_starts_the_watcher():
    script = (REPO_ROOT / "scripts" / "fr-first-boot.sh").read_text()
    assert "/etc/issue.new" not in script and "WEBUI_HINT" not in script
    assert "    fr-console-ports \\\n" in script
