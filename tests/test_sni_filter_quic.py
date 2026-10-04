"""ROADMAP SEC-1 (review R8): QUIC is rejected from the SNI filter's ports.

QUIC (HTTP/3, UDP/443) carries its ClientHello encrypted, so the XDP SNI
filter can't read the name in it, and a blocked name stayed reachable over
HTTP/3. While the filter is on, the forward chain rejects UDP/443 from its
devices -- and from the VLAN segments on them -- so clients fall back to
TCP, where the filter sees the name.

Two layers, like tests/test_iot_isolation.py:
- the generated ruleset: which devices, and where in the forward chain;
- real packets: network namespaces joined to this host by veth pairs (one
  with a VLAN on it), this host routing between them with the generated
  FR_OS ruleset loaded, and UDP and TCP exchanges with a real server.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
import time

import pytest

from frfw.config import parse_config
from frfw.nft import build_ruleset
from frfw.nft.builder import sni_filtered_devices

QUIC_COMMENT = 'comment "sni-filter-no-quic"'


def _raw(minimal_config_dict, **xdp):
    raw = minimal_config_dict
    raw["interfaces"]["guest"] = {"device": "eth1.40", "zone": "guest", "vlan": {"parent": "eth1", "id": 40}}
    raw["interfaces"]["dmz"] = {"device": "eth2", "zone": "dmz"}
    raw["interfaces"]["dmzvlan"] = {"device": "eth2.50", "zone": "dmz", "vlan": {"parent": "eth2", "id": 50}}
    raw["zones"].update({"guest": {}, "dmz": {}})
    raw["xdp_sni_filter"] = {"enabled": True, "interfaces": ["lan"], "blocklist": ["blocked.example"], **xdp}
    return raw


def _forward_chain(ruleset: str) -> list[str]:
    chain = ruleset.split("chain forward {", 1)[1].split("\n\t}", 1)[0]
    return [line.strip() for line in chain.splitlines() if line.strip()]


def _quic_rule(ruleset: str) -> str:
    (rule,) = [line for line in _forward_chain(ruleset) if QUIC_COMMENT in line]
    return rule


# --- the generated ruleset ----------------------------------------------------


def test_no_quic_rule_while_the_filter_is_off(minimal_config_dict):
    raw = _raw(minimal_config_dict)
    raw["xdp_sni_filter"]["enabled"] = False
    config = parse_config(raw)
    assert sni_filtered_devices(config) == []
    assert "udp dport 443" not in build_ruleset(config)


def test_the_filtered_port_and_its_vlans_are_covered_and_no_other(minimal_config_dict):
    config = parse_config(_raw(minimal_config_dict))
    # eth1 is the filtered port and eth1.40 a VLAN on it; eth2 and its VLAN
    # are not filtered, and nor is the WAN.
    assert sni_filtered_devices(config) == ["eth1", "eth1.40"]
    assert _quic_rule(build_ruleset(config)) == (
        f'iifname {{ "eth1", "eth1.40" }} udp dport 443 reject {QUIC_COMMENT}'
    )


def test_a_filtered_vlan_device_is_covered_without_its_parent(minimal_config_dict):
    config = parse_config(_raw(minimal_config_dict, interfaces=["dmzvlan"]))
    assert sni_filtered_devices(config) == ["eth2.50"]


def test_the_quic_rule_comes_before_everything_that_could_accept_it(minimal_config_dict):
    raw = _raw(minimal_config_dict)
    # The internet-only IoT isolation accepts an isolated device's traffic
    # to the WAN; the admin rule lan-to-wan accepts everything.
    raw["iot"] = {"enabled": True, "zones": ["lan"], "isolation_mode": "internet_only"}
    chain = _forward_chain(build_ruleset(parse_config(raw)))
    quic = next(i for i, line in enumerate(chain) if QUIC_COMMENT in line)
    quarantine = next(i for i, line in enumerate(chain) if "ids-quarantine-forward" in line)
    first_accept = next(i for i, line in enumerate(chain) if " accept" in line)
    established = chain.index("ct state established,related accept")
    admin = next(i for i, line in enumerate(chain) if "lan-to-wan" in line)
    assert quarantine < quic < first_accept <= established < admin


@pytest.mark.skipif(os.geteuid() != 0 or shutil.which("nft") is None, reason="needs root and nft")
def test_the_ruleset_with_the_quic_rule_passes_nft_check(minimal_config_dict):
    proc = subprocess.run(["nft", "-c", "-f", "-"], input=build_ruleset(parse_config(_raw(minimal_config_dict))),
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


# --- real packets --------------------------------------------------------------

_SERVER = textwrap.dedent(
    """
    import socket, sys, threading
    def udp(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", port))
        while True:
            data, peer = s.recvfrom(2048)
            s.sendto(data, peer)
    def tcp(port):
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port)); s.listen(8)
        while True:
            c, _ = s.accept(); c.sendall(b"ok"); c.close()
    for port in (443, 4443):
        threading.Thread(target=udp, args=(port,), daemon=True).start()
    tcp(443)
    """
)

# One UDP socket per line of stdin: "PORT" sends a datagram and prints OK
# (echoed), REFUSED (an ICMP unreachable came back) or TIMEOUT. Reading
# the commands one by one lets a test reload the ruleset between two sends
# of the same flow.
_UDP_CLIENT = textwrap.dedent(
    """
    import socket, sys
    host, src = sys.argv[1], sys.argv[2]
    socks = {}
    for line in sys.stdin:
        port = int(line)
        s = socks.get(port)
        if s is None:
            s = socks[port] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((src, 0)); s.settimeout(1.5); s.connect((host, port))
        try:
            s.send(b"hello")
            print("OK" if s.recv(16) == b"hello" else "BAD", flush=True)
        except ConnectionRefusedError:
            print("REFUSED", flush=True)
        except OSError:
            print("TIMEOUT", flush=True)
    """
)

_TCP_CLIENT = textwrap.dedent(
    """
    import socket, sys
    try:
        c = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1.5, source_address=(sys.argv[3], 0))
        print("OK" if c.recv(2) == b"ok" else "BAD")
    except OSError:
        print("FAIL")
    """
)

requires_netns = pytest.mark.skipif(
    os.geteuid() != 0 or shutil.which("ip") is None or shutil.which("nft") is None,
    reason="needs root, iproute2 and nft",
)

CLIENT_NS, SERVER_NS = "frq-client", "frq-server"
LAN_DEV, VLAN_DEV, WAN_DEV, DMZ_DEV = "frq-lr", "frq-lr.40", "frq-wr", "frq-dr"
SERVER = "10.81.2.10"
LAN_SRC, GUEST_SRC, DMZ_SRC = "10.81.1.10", "10.81.40.10", "10.81.3.10"


def _router_config(*, sni_filter: bool):
    return parse_config(
        {
            "version": 1,
            "hostname": "t",
            "zones": {"lan": {}, "guest": {}, "dmz": {}, "wan": {}},
            "interfaces": {
                "lan": {"device": LAN_DEV, "zone": "lan", "address": "10.81.1.1/24"},
                "guest": {"device": VLAN_DEV, "zone": "guest", "address": "10.81.40.1/24",
                          "vlan": {"parent": LAN_DEV, "id": 40}},
                "dmz": {"device": DMZ_DEV, "zone": "dmz", "address": "10.81.3.1/24"},
                "wan": {"device": WAN_DEV, "zone": "wan", "address": "10.81.2.1/24"},
            },
            "rules": [
                {"name": f"{zone}-to-wan", "action": "accept", "from_zone": zone, "to_zone": "wan"}
                for zone in ("lan", "guest", "dmz")
            ],
            "nat": {"masquerade": []},
            "xdp_sni_filter": {"enabled": sni_filter, "interfaces": ["lan"], "blocklist": ["blocked.example"]},
        }
    )


def _load(config) -> None:
    subprocess.run(["nft", "-f", "-"], input=build_ruleset(config), text=True, check=True)


@pytest.fixture
def router(tmp_path):
    """A client namespace on two router ports -- the filtered LAN port
    with a VLAN (40) on it, and an unfiltered DMZ port -- and a server
    namespace behind the WAN port. This host routes between them."""
    for f, body in (("server.py", _SERVER), ("udp.py", _UDP_CLIENT), ("tcp.py", _TCP_CLIENT)):
        (tmp_path / f).write_text(body)

    def sh(*cmd, ns=None):
        full = (["ip", "netns", "exec", ns] if ns else []) + list(cmd)
        return subprocess.run(full, capture_output=True, text=True, check=True)

    procs = []
    old_forward = open("/proc/sys/net/ipv4/ip_forward").read().strip()
    try:
        for ns in (CLIENT_NS, SERVER_NS):
            sh("ip", "netns", "add", ns)
        for ns, inner, outer, net in ((CLIENT_NS, "frq-l", LAN_DEV, "10.81.1"),
                                      (CLIENT_NS, "frq-d", DMZ_DEV, "10.81.3"),
                                      (SERVER_NS, "frq-w", WAN_DEV, "10.81.2")):
            sh("ip", "link", "add", inner, "type", "veth", "peer", "name", outer)
            sh("ip", "link", "set", inner, "netns", ns)
            sh("ip", "addr", "add", f"{net}.1/24", "dev", outer)
            sh("ip", "link", "set", outer, "up")
            sh("ip", "addr", "add", f"{net}.10/24", "dev", inner, ns=ns)
            sh("ip", "link", "set", inner, "up", ns=ns)
        try:
            sh("ip", "link", "add", "link", LAN_DEV, "name", VLAN_DEV, "type", "vlan", "id", "40")
            vlan = True
        except subprocess.CalledProcessError:  # a kernel without 802.1Q (8021q)
            vlan = False
        if vlan:
            sh("ip", "addr", "add", "10.81.40.1/24", "dev", VLAN_DEV)
            sh("ip", "link", "set", VLAN_DEV, "up")
            sh("ip", "link", "add", "link", "frq-l", "name", "frq-l.40", "type", "vlan", "id", "40", ns=CLIENT_NS)
            sh("ip", "addr", "add", f"{GUEST_SRC}/24", "dev", "frq-l.40", ns=CLIENT_NS)
            sh("ip", "link", "set", "frq-l.40", "up", ns=CLIENT_NS)
        sh("ip", "link", "set", "lo", "up", ns=CLIENT_NS)
        # Each source address leaves by its own port.
        routes = [(101, LAN_SRC, "10.81.1.1"), (103, DMZ_SRC, "10.81.3.1")]
        if vlan:
            routes.append((140, GUEST_SRC, "10.81.40.1"))
        for table, src, gw in routes:
            sh("ip", "route", "add", "default", "via", gw, "table", str(table), ns=CLIENT_NS)
            sh("ip", "rule", "add", "from", src, "table", str(table), ns=CLIENT_NS)
        sh("ip", "route", "add", "default", "via", "10.81.2.1", ns=SERVER_NS)
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        procs.append(subprocess.Popen(["ip", "netns", "exec", SERVER_NS, sys.executable, str(tmp_path / "server.py")]))
        time.sleep(0.8)

        def udp(src, *ports):
            """Send one datagram per port, in order, on one socket per port."""
            return _udp_session(tmp_path, src, ports)

        def tcp(src, port):
            return sh(sys.executable, str(tmp_path / "tcp.py"), SERVER, str(port), src, ns=CLIENT_NS).stdout.strip()

        yield {"udp": udp, "tcp": tcp, "tmp": tmp_path, "vlan": vlan}
    finally:
        for p in procs:
            p.kill()
        subprocess.run(["nft", "flush", "ruleset"], check=False)
        for ns in (CLIENT_NS, SERVER_NS):
            subprocess.run(["ip", "netns", "del", ns], check=False)
        for dev in (VLAN_DEV, LAN_DEV, DMZ_DEV, WAN_DEV):
            subprocess.run(["ip", "link", "del", dev], check=False, capture_output=True)
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(old_forward)


def _udp_session(tmp_path, src, ports):
    proc = subprocess.run(["ip", "netns", "exec", CLIENT_NS, sys.executable, str(tmp_path / "udp.py"), SERVER, src],
                          input="".join(f"{p}\n" for p in ports), capture_output=True, text=True, check=True)
    return proc.stdout.split()


class _Flow:
    """One UDP client process kept open across a ruleset reload, so its
    second datagram belongs to a flow conntrack already knows."""

    def __init__(self, tmp_path, src):
        self.proc = subprocess.Popen(
            ["ip", "netns", "exec", CLIENT_NS, sys.executable, str(tmp_path / "udp.py"), SERVER, src],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )

    def send(self, port):
        self.proc.stdin.write(f"{port}\n")
        self.proc.stdin.flush()
        return self.proc.stdout.readline().strip()

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=5)


def _needs_vlan(router):
    if not router["vlan"]:
        pytest.skip("this kernel has no 802.1Q VLAN devices (8021q)")


@requires_netns
def test_quic_from_the_filtered_port_is_rejected_and_nothing_else(router):
    _load(_router_config(sni_filter=True))
    assert router["udp"](LAN_SRC, 443, 4443) == ["REFUSED", "OK"]
    assert router["udp"](DMZ_SRC, 443) == ["OK"], "an unfiltered port keeps QUIC"
    # The fallback the reject is for: TLS over TCP, where the SNI filter sees the name.
    assert router["tcp"](LAN_SRC, 443) == "OK"


@requires_netns
def test_quic_from_a_vlan_on_the_filtered_port_is_rejected(router):
    _needs_vlan(router)
    _load(_router_config(sni_filter=True))
    assert router["udp"](GUEST_SRC, 443, 4443) == ["REFUSED", "OK"]
    _load(_router_config(sni_filter=False))
    assert router["udp"](GUEST_SRC, 443) == ["OK"]


@requires_netns
def test_quic_passes_while_the_filter_is_off(router):
    _load(_router_config(sni_filter=False))
    assert router["udp"](LAN_SRC, 443) == ["OK"]


@requires_netns
def test_turning_the_filter_on_ends_a_quic_flow_already_open(router):
    _load(_router_config(sni_filter=False))
    flow = _Flow(router["tmp"], LAN_SRC)
    try:
        assert flow.send(443) == "OK"
        _load(_router_config(sni_filter=True))
        assert flow.send(443) == "REFUSED", "the open flow must not ride the established accept"
    finally:
        flow.close()
