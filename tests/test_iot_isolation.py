"""Tests for frfw.iot_isolation plus the generated IoT firewall rules.

Three layers, like tests/test_ids_quarantine.py:
- unit tests with `nft` mocked;
- real `nft` integration against a throwaway table;
- real *packet-level* tests: two network namespaces joined to this host
  by veth pairs, this host routing between them with the actual
  generated FR_OS ruleset loaded, and TCP connections (plus a real mDNS
  exchange) proving the isolation set and the mDNS reply rule behave as
  designed on the wire -- not just that nft accepts the syntax.
"""

from __future__ import annotations

import os
import shutil
import socket
import struct
import subprocess
import sys
import textwrap
import time

import pytest

from frfw import iot_isolation as iso
from frfw.config import parse_config
from frfw.nft import build_ruleset

requires_nft = pytest.mark.skipif(shutil.which("nft") is None, reason="nft binary not installed")
requires_root = pytest.mark.skipif(os.geteuid() != 0, reason="nftables/netns access requires root")


def _fake(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(["nft"], returncode, stdout=stdout, stderr=stderr)


# --- unit ---------------------------------------------------------------------


def test_normalize_macs_lowercases_dedupes_and_validates():
    assert iso.normalize_macs(["AA:BB:CC:DD:EE:01", "aa:bb:cc:dd:ee:01"]) == ["aa:bb:cc:dd:ee:01"]
    with pytest.raises(iso.IotIsolationError, match="invalid MAC"):
        iso.normalize_macs(["aa:bb:cc:dd:ee"])
    with pytest.raises(iso.IotIsolationError, match="too many"):
        iso.normalize_macs(["aa:bb:cc:dd:ee:01"] * (iso.MAX_ISOLATED + 1))


def test_sync_isolated_is_one_atomic_script(monkeypatch):
    scripts = []

    def fake_run(cmd, input=None, capture_output=True, text=True):
        scripts.append((cmd, input))
        return _fake()

    monkeypatch.setattr(iso.subprocess, "run", fake_run)
    assert iso.sync_isolated(["AA:BB:CC:DD:EE:01", "aa:bb:cc:dd:ee:02"]) == ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
    ((cmd, script),) = scripts
    assert cmd == ["nft", "-f", "-"]
    assert script == (
        "flush set inet fr_os iot_isolated\n"
        "add element inet fr_os iot_isolated { aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:02 }\n"
    )


def test_sync_isolated_empty_only_flushes(monkeypatch):
    scripts = []
    monkeypatch.setattr(iso.subprocess, "run", lambda cmd, input=None, **kw: (scripts.append(input), _fake())[1])
    iso.sync_isolated([])
    assert scripts == ["flush set inet fr_os iot_isolated\n"]


def test_sync_isolated_raises_on_nft_error(monkeypatch):
    monkeypatch.setattr(iso.subprocess, "run", lambda *a, **kw: _fake(1, stderr="Error: No such file or directory"))
    with pytest.raises(iso.IotIsolationError, match="No such file"):
        iso.sync_isolated(["aa:bb:cc:dd:ee:01"])


def test_list_parses_plain_string_elements(monkeypatch):
    out = '{"nftables": [{"metainfo": {}}, {"set": {"name": "iot_isolated", "elem": ["aa:bb:cc:dd:ee:01", "AA:BB:CC:DD:EE:02"]}}]}'
    monkeypatch.setattr(iso, "_run_nft", lambda args: _fake(0, stdout=out))
    assert iso.list_isolated() == ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]


def test_snapshot_never_raises_and_restore_swallows_errors(monkeypatch):
    monkeypatch.setattr(iso, "_run_nft", lambda args: _fake(1, stderr="weird failure"))
    assert iso.snapshot_before_reload() == []
    monkeypatch.setattr(iso.subprocess, "run", lambda *a, **kw: _fake(1, stderr="no set"))
    iso.restore_after_reload(["aa:bb:cc:dd:ee:01"])  # must not raise


# --- ruleset rendering ----------------------------------------------------------


def _iot_raw(minimal_config_dict, **iot):
    raw = dict(minimal_config_dict)
    raw["iot"] = {"enabled": True, "zones": ["lan"], **iot}
    return raw


def test_iot_set_and_rules_only_rendered_when_enabled(minimal_config_dict):
    assert "iot_isolated" not in build_ruleset(parse_config(minimal_config_dict))
    ruleset = build_ruleset(parse_config(_iot_raw(minimal_config_dict)))
    assert "set iot_isolated {\n\t\ttype ether_addr\n\t}" in ruleset


def test_iot_input_rules_precede_established_accept(minimal_config_dict):
    ruleset = build_ruleset(parse_config(_iot_raw(minimal_config_dict)))
    input_chain = ruleset.split("chain input {")[1].split("chain forward {")[0]
    lines = [l.strip() for l in input_chain.splitlines() if l.strip()]
    assert lines[3] == 'iifname @lan_ifaces udp sport 5353 udp dport 53530 accept comment "iot-mdns-replies"'
    assert lines[4].startswith("ether saddr @iot_isolated udp dport { 53, 67 } accept")
    assert lines[6] == 'ether saddr @iot_isolated drop comment "iot-isolated-input"'
    assert lines.index('ct state established,related accept') > 6


def test_internet_only_mode_allows_masquerade_zones(minimal_config_dict):
    ruleset = build_ruleset(parse_config(_iot_raw(minimal_config_dict)))
    forward = ruleset.split("chain forward {")[1].split("chain output {")[0]
    lines = [l.strip() for l in forward.splitlines() if l.strip()]
    assert lines[1] == 'ether saddr @iot_isolated oifname @wan_ifaces accept comment "iot-isolated-internet"'
    assert lines[2] == 'ether saddr @iot_isolated drop comment "iot-isolated-forward"'
    assert lines[3] == "ct state established,related accept"


def test_block_mode_has_no_internet_exception(minimal_config_dict):
    ruleset = build_ruleset(parse_config(_iot_raw(minimal_config_dict, isolation_mode="block")))
    assert "iot-isolated-internet" not in ruleset
    assert "iot-isolated-forward" in ruleset


@requires_nft
def test_iot_ruleset_passes_nft_syntax_check(minimal_config_dict):
    for mode in ("internet_only", "block"):
        ruleset = build_ruleset(parse_config(_iot_raw(minimal_config_dict, isolation_mode=mode)))
        proc = subprocess.run(["nft", "-c", "-f", "-"], input=ruleset, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr


# --- real nft set -----------------------------------------------------------------


@pytest.fixture
def real_iot_table(monkeypatch):
    table = "fr_os_iot_test"
    monkeypatch.setattr(iso, "FILTER_TABLE", table)
    monkeypatch.setattr(iso, "IOT_ISOLATED_SET_NAME", "iot_test")
    subprocess.run(["nft", "add", "table", "inet", table], check=True)
    subprocess.run(["nft", "add", "set", "inet", table, "iot_test", "{", "type", "ether_addr", ";", "}"], check=True)
    yield table
    subprocess.run(["nft", "delete", "table", "inet", table], check=False)


@requires_nft
@requires_root
def test_real_sync_replaces_membership_atomically(real_iot_table):
    iso.sync_isolated(["AA:BB:CC:DD:EE:01", "aa:bb:cc:dd:ee:02"])
    assert sorted(iso.list_isolated()) == ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
    iso.sync_isolated(["aa:bb:cc:dd:ee:03"])
    assert iso.list_isolated() == ["aa:bb:cc:dd:ee:03"]
    iso.sync_isolated([])
    assert iso.list_isolated() == []


@requires_nft
@requires_root
def test_real_snapshot_restore_round_trip(real_iot_table):
    iso.sync_isolated(["aa:bb:cc:dd:ee:04"])
    snap = iso.snapshot_before_reload()
    subprocess.run(["nft", "flush", "set", "inet", real_iot_table, "iot_test"], check=True)
    assert iso.list_isolated() == []
    iso.restore_after_reload(snap)
    assert iso.list_isolated() == ["aa:bb:cc:dd:ee:04"]


# --- real packets -----------------------------------------------------------------

_SERVER = textwrap.dedent(
    """
    import socket, sys
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", int(sys.argv[1]))); s.listen(8)
    while True:
        c, _ = s.accept(); c.sendall(b"ok"); c.close()
    """
)

_CLIENT = textwrap.dedent(
    """
    import socket, sys
    try:
        c = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1.5)
        print("OK" if c.recv(2) == b"ok" else "BAD")
    except OSError:
        print("FAIL")
    """
)

_MDNS_RESPONDER = textwrap.dedent(
    """
    import socket, struct, sys
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 5353))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                 struct.pack("4s4s", socket.inet_aton("224.0.0.251"), socket.inet_aton(sys.argv[1])))
    while True:
        data, (ip, port) = s.recvfrom(9000)
        qid = struct.unpack("!H", data[:2])[0]
        q = data[12:]
        local_off = 12 + len(q) - 4 - 7
        ans = b""
        for svc in ("_hap._tcp", "_googlecast._tcp"):
            rdata = b"".join(bytes([len(l)]) + l.encode() for l in svc.split(".")) + struct.pack("!H", 0xC000 | local_off)
            ans += struct.pack("!H", 0xC000 | 12) + struct.pack("!HHIH", 12, 1, 10, len(rdata)) + rdata
        s.sendto(struct.pack("!HHHHHH", qid, 0x8400, 1, 2, 0, 0) + q + ans, (ip, port))
    """
)


def _have_netns() -> bool:
    return os.geteuid() == 0 and shutil.which("ip") is not None and shutil.which("nft") is not None


requires_netns = pytest.mark.skipif(not _have_netns(), reason="needs root, iproute2 and nft")


@pytest.fixture
def two_hosts(tmp_path):
    """IoT host (10.78.1.10, ns frtt-iot) and a peer (10.78.2.10, ns
    frtt-peer), each behind its own veth; this host is the router
    (10.78.1.1 / 10.78.2.1) and forwards between them."""
    for f, body in (("server.py", _SERVER), ("client.py", _CLIENT), ("mdns.py", _MDNS_RESPONDER)):
        (tmp_path / f).write_text(body)

    def sh(*cmd, ns=None, check=True):
        full = (["ip", "netns", "exec", ns] if ns else []) + list(cmd)
        return subprocess.run(full, capture_output=True, text=True, check=check)

    procs = []
    old_forward = open("/proc/sys/net/ipv4/ip_forward").read().strip()
    try:
        for ns, veth, rveth, net in (("frtt-iot", "frtt-i", "frtt-ir", "10.78.1"), ("frtt-peer", "frtt-p", "frtt-pr", "10.78.2")):
            sh("ip", "netns", "add", ns)
            sh("ip", "link", "add", veth, "type", "veth", "peer", "name", rveth)
            sh("ip", "link", "set", veth, "netns", ns)
            sh("ip", "addr", "add", f"{net}.1/24", "dev", rveth)
            sh("ip", "link", "set", rveth, "up")
            sh("ip", "addr", "add", f"{net}.10/24", "dev", veth, ns=ns)
            sh("ip", "link", "set", veth, "up", ns=ns)
            sh("ip", "link", "set", "lo", "up", ns=ns)
            sh("ip", "route", "add", "default", "via", f"{net}.1", ns=ns)
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        procs.append(subprocess.Popen(["ip", "netns", "exec", "frtt-peer", sys.executable, str(tmp_path / "server.py"), "8080"]))
        procs.append(subprocess.Popen([sys.executable, str(tmp_path / "server.py"), "8081"]))
        procs.append(subprocess.Popen(["ip", "netns", "exec", "frtt-iot", sys.executable, str(tmp_path / "mdns.py"), "10.78.1.10"]))
        time.sleep(0.8)

        mac = sh("cat", "/sys/class/net/frtt-i/address", ns="frtt-iot").stdout.strip()

        def connect(host, port):
            return sh(sys.executable, str(tmp_path / "client.py"), host, str(port), ns="frtt-iot").stdout.strip()

        yield {"mac": mac, "connect": connect}
    finally:
        for p in procs:
            p.kill()
        subprocess.run(["nft", "flush", "ruleset"], check=False)
        for ns, rveth in (("frtt-iot", "frtt-ir"), ("frtt-peer", "frtt-pr")):
            subprocess.run(["ip", "netns", "del", ns], check=False)
            subprocess.run(["ip", "link", "del", rveth], check=False, capture_output=True)
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(old_forward)


def _router_config(mode: str):
    return parse_config(
        {
            "version": 1,
            "hostname": "t",
            "zones": {"iotlan": {}, "wan": {}},
            "interfaces": {
                "iotlan": {"device": "frtt-ir", "zone": "iotlan", "address": "10.78.1.1/24"},
                "wan": {"device": "frtt-pr", "zone": "wan", "address": "10.78.2.1/24"},
            },
            "rules": [
                {"name": "iot-to-wan", "action": "accept", "from_zone": "iotlan", "to_zone": "wan"},
                {"name": "iot-to-router", "action": "accept", "from_zone": "iotlan", "to_zone": "self",
                 "proto": "tcp", "dst_port": 8081},
            ],
            "nat": {"masquerade": [{"out_zone": "wan"}]},
            "iot": {"enabled": True, "zones": ["iotlan"], "isolation_mode": mode},
        }
    )


@requires_netns
def test_real_packets_block_mode_isolation_and_reload_survival(two_hosts):
    config = _router_config("block")
    subprocess.run(["nft", "-f", "-"], input=build_ruleset(config), text=True, check=True)
    connect = two_hosts["connect"]

    assert connect("10.78.2.10", 8080) == "OK"
    iso.sync_isolated([two_hosts["mac"].upper()])
    assert connect("10.78.2.10", 8080) == "FAIL"
    assert connect("10.78.1.1", 8081) == "FAIL"

    # A full apply's `flush ruleset` empties the set; snapshot/restore is
    # what keeps the device isolated across it.
    snapshot = iso.snapshot_before_reload()
    subprocess.run(["nft", "-f", "-"], input=build_ruleset(config), text=True, check=True)
    assert connect("10.78.2.10", 8080) == "OK"
    iso.restore_after_reload(snapshot)
    assert connect("10.78.2.10", 8080) == "FAIL"

    iso.sync_isolated([])
    assert connect("10.78.2.10", 8080) == "OK"


@requires_netns
def test_real_packets_internet_only_mode(two_hosts):
    subprocess.run(["nft", "-f", "-"], input=build_ruleset(_router_config("internet_only")), text=True, check=True)
    connect = two_hosts["connect"]
    iso.sync_isolated([two_hosts["mac"]])
    assert connect("10.78.2.10", 8080) == "OK"    # the internet (masquerade zone)
    assert connect("10.78.1.1", 8081) == "FAIL"   # the router, despite an admin accept rule


@requires_netns
def test_real_mdns_discovery_needs_the_generated_reply_rule(two_hosts):
    from frfw.iot import mdns

    config = _router_config("block")
    subprocess.run(["nft", "-f", "-"], input=build_ruleset(config), text=True, check=True)
    assert mdns.discover(["10.78.1.1"], timeout=1.5) == {"10.78.1.10": {"_hap._tcp", "_googlecast._tcp"}}

    without_rule = "\n".join(l for l in build_ruleset(config).splitlines() if "iot-mdns-replies" not in l)
    subprocess.run(["nft", "-f", "-"], input=without_rule, text=True, check=True)
    assert mdns.discover(["10.78.1.1"], timeout=1.0) == {}
