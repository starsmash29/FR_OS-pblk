"""First boot's WAN/LAN choice (ROADMAP SEC-8, review v0.2.0 R14).

The upstream port is the one where a DHCP server already answers, and the
LAN -- where FR_OS serves DHCP itself -- is never a port that has one.
frfw.netdetect.dhcp_server_answers asks each port with a raw DHCPDISCOVER;
choose_wan_lan decides. The probe is checked against a real dnsmasq DHCP
server in a network namespace.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import time

import pytest

from frfw import cli, netdetect
from frfw.netdetect import DetectedInterface


def _iface(name: str, link_up: bool | None = True) -> DetectedInterface:
    return DetectedInterface(name=name, mac_address="52:54:00:00:00:01", driver="virtio_net",
                             link_up=link_up, speed_mbps=None)


@pytest.mark.parametrize("answering, expected", [
    ({"ens4"}, ("ens4", "ens3")),            # cabled "backwards": the second port is upstream
    ({"ens3"}, ("ens3", "ens4")),
    (set(), ("ens3", "ens4")),               # nothing answers: port order, said plainly
    ({"ens3", "ens4"}, (None, None)),        # never serve DHCP where a server already runs
])
def test_the_wan_is_where_a_dhcp_server_answers(answering, expected):
    choice = netdetect.choose_wan_lan([_iface("ens3"), _iface("ens4")], lambda name: name in answering)
    assert (choice.wan, choice.lan) == expected
    assert choice.basis


def test_with_three_ports_the_lan_is_one_with_a_link():
    ports = [_iface("eno1"), _iface("eno2", link_up=False), _iface("eno3")]
    choice = netdetect.choose_wan_lan(ports, lambda name: name == "eno1")
    assert (choice.wan, choice.lan) == ("eno1", "eno3")


def test_one_port_is_no_choice():
    choice = netdetect.choose_wan_lan([_iface("ens3")], lambda name: True)
    assert (choice.wan, choice.lan) == (None, None)


def test_every_port_is_asked_and_at_the_same_time():
    asked = []

    def slow(name):
        asked.append(name)
        time.sleep(0.3)
        return False

    started = time.monotonic()
    netdetect.choose_wan_lan([_iface(f"eth{n}") for n in range(4)], slow)
    assert sorted(asked) == ["eth0", "eth1", "eth2", "eth3"]
    assert time.monotonic() - started < 1.0  # in parallel, not 4 x 0.3 s


def test_the_discover_is_a_well_formed_broadcast():
    mac = bytes.fromhex("525400000001")
    frame = netdetect._discover_frame(mac, 0x1234ABCD)
    assert frame[:6] == b"\xff" * 6 and frame[6:12] == mac and frame[12:14] == b"\x08\x00"
    ip = frame[14:34]
    assert netdetect._checksum(ip) == 0  # the header checksums to zero with its checksum in
    assert ip[16:20] == b"\xff\xff\xff\xff" and ip[9] == 17
    bootp = frame[42:]
    assert bootp[0] == 1 and struct.unpack("!I", bootp[4:8])[0] == 0x1234ABCD
    assert struct.unpack("!H", bootp[10:12])[0] == 0x8000  # broadcast the answer: no address yet
    assert bootp[28:34] == mac
    assert bootp[240:243] == bytes([53, 1, 1])  # DHCPDISCOVER


def _reply(xid: int, message_type: int, *, dport: int = 68) -> bytes:
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 2, 1, 6, 0, xid, 0, 0x8000,
                        bytes(4), bytes([10, 0, 0, 50]), bytes(4), bytes(4), bytes(16), b"", b"")
    payload = bootp + b"\x63\x82\x53\x63" + bytes([53, 1, message_type, 255])
    udp = struct.pack("!HHHH", 67, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, bytes([10, 0, 0, 1]), b"\xff" * 4)
    return b"\xff" * 6 + bytes(6) + b"\x08\x00" + ip + udp


def test_only_an_offer_for_our_discover_counts():
    assert netdetect._is_offer(_reply(7, 2), 7)
    assert not netdetect._is_offer(_reply(8, 2), 7)          # someone else's exchange
    assert not netdetect._is_offer(_reply(7, 5), 7)          # an ACK, not an OFFER
    assert not netdetect._is_offer(_reply(7, 2, dport=67), 7)
    assert not netdetect._is_offer(netdetect._discover_frame(bytes(6), 7), 7)  # our own DISCOVER
    assert not netdetect._is_offer(_reply(7, 2)[:200], 7)    # truncated


def test_the_cli_prints_the_choice_and_why(monkeypatch, capsys):
    monkeypatch.setattr(netdetect, "list_interfaces", lambda: [_iface("ens3"), _iface("ens4")])
    monkeypatch.setattr(netdetect, "dhcp_server_answers", lambda name: name == "ens4")
    assert cli.main(["detect-wan-lan"]) == 0
    first, second = capsys.readouterr().out.splitlines()
    assert first == "ens4 ens3" and "ens4" in second

    monkeypatch.setattr(netdetect, "dhcp_server_answers", lambda name: True)
    assert cli.main(["detect-wan-lan"]) == 1
    first, second = capsys.readouterr().out.splitlines()
    assert first == "" and "ens3" in second and "ens4" in second


# --- the probe against a real DHCP server ---------------------------------------

NS = "frw-upstream"


def _skip_reason() -> str | None:
    if os.geteuid() != 0:
        return "needs root"
    for tool in ("ip", "dnsmasq"):
        if shutil.which(tool) is None:
            return f"{tool} not installed"
    return None


@pytest.fixture
def ports(tmp_path):
    """Two veth ports in this namespace: frw0 is cabled to a namespace
    with a real dnsmasq DHCP server, frw2 to one without."""
    def sh(*cmd):
        subprocess.run(cmd, check=True, capture_output=True)

    subprocess.run(["ip", "netns", "del", NS], capture_output=True)
    for dev in ("frw0", "frw2"):
        subprocess.run(["ip", "link", "del", dev], capture_output=True)
    sh("ip", "netns", "add", NS)
    sh("ip", "link", "add", "frw0", "type", "veth", "peer", "name", "frw1", "netns", NS)
    sh("ip", "link", "add", "frw2", "type", "veth", "peer", "name", "frw3", "netns", NS)
    sh("ip", "-n", NS, "addr", "add", "10.77.0.1/24", "dev", "frw1")
    for dev in ("frw1", "frw3", "lo"):
        sh("ip", "-n", NS, "link", "set", dev, "up")
    server = subprocess.Popen([
        "ip", "netns", "exec", NS, "dnsmasq", "--keep-in-foreground", "--port=0", "--interface=frw1",
        "--bind-interfaces", "--dhcp-range=10.77.0.50,10.77.0.60,1h", f"--dhcp-leasefile={tmp_path / 'leases'}",
        "--conf-file=/dev/null", "--user=root",
    ])
    time.sleep(0.5)
    try:
        yield
    finally:
        server.terminate()
        server.wait(timeout=5)
        subprocess.run(["ip", "netns", "del", NS], capture_output=True)
        for dev in ("frw0", "frw2"):
            subprocess.run(["ip", "link", "del", dev], capture_output=True)


@pytest.mark.skipif(_skip_reason() is not None, reason=str(_skip_reason()))
def test_the_probe_hears_a_real_dhcp_server_and_only_where_there_is_one(ports, tmp_path):
    assert netdetect.dhcp_server_answers("frw0", timeout=2, attempts=2)
    assert not netdetect.dhcp_server_answers("frw2", timeout=1, attempts=1)
    # A DISCOVER takes no lease: nothing was handed out.
    leases = tmp_path / "leases"
    assert not leases.exists() or leases.read_text().strip() == ""
    choice = netdetect.choose_wan_lan(
        [_iface("frw2"), _iface("frw0")],
        lambda name: netdetect.dhcp_server_answers(name, timeout=1, attempts=2),
    )
    assert (choice.wan, choice.lan) == ("frw0", "frw2")
