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

import ipaddress

import yaml

from frfw import cli, netdetect, skeleton
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


def _reply(xid: int, message_type: int, *, dport: int = 68, offered: bytes = bytes([10, 0, 0, 50]),
           mask: bytes | None = None) -> bytes:
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 2, 1, 6, 0, xid, 0, 0x8000,
                        bytes(4), offered, bytes(4), bytes(4), bytes(16), b"", b"")
    options = bytes([53, 1, message_type]) + (bytes([1, 4]) + mask if mask else b"")
    payload = bootp + b"\x63\x82\x53\x63" + options + bytes([255])
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


# --- NET-12: the LAN out of the upstream network's way --------------------------
#
# The LAN used to be 192.168.1.1/24 -- the address of most home routers
# and ISP boxes, the network FR_OS's WAN then sits in. Found on a Telekom
# line. The default is now an uncommon range, and first boot moves the LAN
# out of whatever network the WAN's DHCP server offers.


def test_an_offer_says_which_network_it_offers_an_address_in():
    telekom = _reply(7, 2, offered=bytes([192, 168, 1, 23]), mask=bytes([255, 255, 255, 0]))
    assert netdetect._offered_network(telekom, 7) == ipaddress.IPv4Network("192.168.1.0/24")
    wide = _reply(7, 2, offered=bytes([10, 20, 30, 40]), mask=bytes([255, 0, 0, 0]))
    assert netdetect._offered_network(wide, 7) == ipaddress.IPv4Network("10.0.0.0/8")
    # No mask from the server: the address's /24.
    assert netdetect._offered_network(_reply(7, 2), 7) == ipaddress.IPv4Network("10.0.0.0/24")
    assert netdetect._offered_network(_reply(7, 5), 7) is None


@pytest.mark.parametrize("upstream, lan", [
    ([], "10.73.1.1/24"),
    (["192.168.1.0/24"], "10.73.1.1/24"),   # a Telekom (or any home) router upstream
    (["10.73.0.0/16"], "172.29.73.1/24"),
    (["10.0.0.0/8"], "172.29.73.1/24"),      # a wide upstream, the whole block
    (["10.0.0.0/8", "172.16.0.0/12"], "192.168.173.1/24"),
])
def test_the_lan_is_the_first_choice_outside_the_upstream_network(upstream, lan):
    assert skeleton.lan_address_avoiding([ipaddress.IPv4Network(n) for n in upstream]) == lan


def test_with_every_choice_taken_there_is_no_lan_address():
    with pytest.raises(ValueError):
        skeleton.lan_address_avoiding([ipaddress.IPv4Network("0.0.0.0/0")])


def test_the_choice_keeps_the_wan_s_offered_network():
    offer = ipaddress.IPv4Network("192.168.1.0/24")
    choice = netdetect.choose_wan_lan([_iface("ens3"), _iface("ens4")],
                                      lambda name: offer if name == "ens4" else None)
    assert (choice.wan, choice.lan, choice.wan_network) == ("ens4", "ens3", offer)


def test_the_cli_prints_the_choice_and_why(monkeypatch, capsys):
    monkeypatch.setattr(netdetect, "list_interfaces", lambda: [_iface("ens3"), _iface("ens4")])
    telekom = ipaddress.IPv4Network("192.168.1.0/24")
    monkeypatch.setattr(netdetect, "dhcp_offer", lambda name: telekom if name == "ens4" else None)
    assert cli.main(["detect-wan-lan"]) == 0
    first, second = capsys.readouterr().out.splitlines()
    assert first == "ens4 ens3 10.73.1.1/24" and "ens4" in second and "192.168.1.0/24" in second

    taken = ipaddress.IPv4Network("10.73.0.0/16")
    monkeypatch.setattr(netdetect, "dhcp_offer", lambda name: taken if name == "ens4" else None)
    assert cli.main(["detect-wan-lan"]) == 0
    first, second = capsys.readouterr().out.splitlines()
    assert first == "ens4 ens3 172.29.73.1/24" and "the LAN moved to 172.29.73.1/24" in second

    monkeypatch.setattr(netdetect, "dhcp_offer", lambda name: telekom)
    assert cli.main(["detect-wan-lan"]) == 1
    first, second = capsys.readouterr().out.splitlines()
    assert first == "" and "ens3" in second and "ens4" in second


def test_assign_interfaces_puts_the_lan_and_its_pool_where_it_is_told(tmp_path, capsys):
    out = tmp_path / "config.yaml"
    assert cli.main(["assign-interfaces", "--wan", "ens4", "--lan", "ens3", "--lan-address", "172.29.73.1/24",
                     "--out", str(out)]) == 0
    raw = yaml.safe_load(out.read_text())
    assert raw["interfaces"]["lan"]["address"] == "172.29.73.1/24"
    assert (raw["dhcp"]["lan"]["range_start"], raw["dhcp"]["lan"]["range_end"]) == ("172.29.73.100",
                                                                                     "172.29.73.199")
    assert raw["management"] == {"addresses": ["172.29.73.1"]}
    for bad in ("172.29.73.1", "300.1.1.1/24", "-x"):
        assert cli.main(["assign-interfaces", "--wan", "ens4", "--lan", "ens3", f"--lan-address={bad}",
                         "--out", str(tmp_path / "other.yaml")]) == 1
    assert not (tmp_path / "other.yaml").exists()


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
def ports(request, tmp_path):
    """Two veth ports in this namespace: frw0 is cabled to a namespace
    with a real dnsmasq DHCP server, frw2 to one without. The server's
    network is 10.77.0.0/24 unless the test says otherwise."""
    net = getattr(request, "param", "10.77.0")
    def sh(*cmd):
        subprocess.run(cmd, check=True, capture_output=True)

    subprocess.run(["ip", "netns", "del", NS], capture_output=True)
    for dev in ("frw0", "frw2"):
        subprocess.run(["ip", "link", "del", dev], capture_output=True)
    sh("ip", "netns", "add", NS)
    sh("ip", "link", "add", "frw0", "type", "veth", "peer", "name", "frw1", "netns", NS)
    sh("ip", "link", "add", "frw2", "type", "veth", "peer", "name", "frw3", "netns", NS)
    sh("ip", "-n", NS, "addr", "add", f"{net}.1/24", "dev", "frw1")
    for dev in ("frw1", "frw3", "lo"):
        sh("ip", "-n", NS, "link", "set", dev, "up")
    server = subprocess.Popen([
        "ip", "netns", "exec", NS, "dnsmasq", "--keep-in-foreground", "--port=0", "--interface=frw1",
        "--bind-interfaces", f"--dhcp-range={net}.50,{net}.60,1h", f"--dhcp-leasefile={tmp_path / 'leases'}",
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


@pytest.mark.skipif(_skip_reason() is not None, reason=str(_skip_reason()))
@pytest.mark.parametrize("ports, lan", [("192.168.1", "10.73.1.1/24"), ("10.73.1", "172.29.73.1/24")],
                         indirect=["ports"], ids=["home-router-upstream", "upstream-on-the-default"])
def test_a_real_server_s_offer_moves_the_lan_out_of_its_network(ports, lan):
    """NET-12 against a real DHCP server: the network it offers comes back
    from the probe, and the LAN goes outside it."""
    offered = netdetect.dhcp_offer("frw0", timeout=2, attempts=2)
    assert offered is not None and offered.prefixlen == 24
    assert skeleton.lan_address_avoiding([offered]) == lan
