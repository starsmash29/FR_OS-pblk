"""Security-lessons G8: a VPN with keys, not reusable passwords (WireGuard).

- the configuration is validated (keys, tunnel subnet, peers);
- the router's private key is generated once, 0600 in a 0700 directory,
  and never written to config.yaml;
- the ruleset puts wg0 in its zone and opens the listen port;
- `sync` drives `ip`/`wg` in the right order, and removes the tunnel
  when WireGuard is turned off;
- a real encrypted tunnel between two network namespaces (wireguard-go,
  the userspace implementation, stands in for the kernel module this
  sandbox lacks), with FR_OS's own ruleset loaded on the router: a
  client with a configured key reaches the router through the tunnel,
  the same client without the tunnel -- and a key the router doesn't
  know -- don't.
"""

from __future__ import annotations

import base64
import os
import shutil
import stat
import subprocess
import sys
import time
import uuid

import pytest

from frfw import wireguard
from frfw.config import ConfigError, parse_config
from frfw.nft import build_ruleset

KEY_A = base64.b64encode(b"a" * 32).decode()
KEY_B = base64.b64encode(b"b" * 32).decode()


def _config(**wg) -> dict:
    return {
        "version": 1, "hostname": "router",
        "zones": {"wan": {}, "lan": {}, "vpn": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"},
                       "lan": {"device": "eth1", "zone": "lan", "address": "192.168.1.1/24"}},
        "rules": [], "nat": {"masquerade": [{"out_zone": "wan"}]},
        "wireguard": {"enabled": True, "address": "10.99.0.1/24", **wg},
    }


# -- configuration -------------------------------------------------------------------------


def test_a_valid_tunnel():
    wg = parse_config(_config(peers=[{"name": "laptop", "public_key": KEY_A, "address": "10.99.0.2"}])).wireguard
    assert wg.enabled and wg.listen_port == 51820 and wg.zone == "vpn"
    assert wg.peers[0].address == "10.99.0.2/32"


@pytest.mark.parametrize("wg, error", [
    ({"address": ""}, "address"),
    ({"address": "10.99.0.1"}, "prefix"),
    ({"address": "10.99.0.0/24"}, "not a host address"),
    ({"address": "192.168.1.200/24"}, "overlaps interface 'lan'"),
    ({"listen_port": 70000}, "listen_port"),
    ({"peers": [{"name": "x", "public_key": "not-a-key", "address": "10.99.0.2"}]}, "not a WireGuard key"),
    ({"peers": [{"name": "x", "public_key": KEY_A, "address": "10.98.0.2"}]}, "not a free host address"),
    ({"peers": [{"name": "x", "public_key": KEY_A, "address": "10.99.0.1"}]}, "not a free host address"),
    ({"peers": [{"name": "x", "public_key": KEY_A, "address": "10.99.0.0/30"}]}, "single host"),
    ({"peers": [{"name": "x", "public_key": KEY_A, "address": "10.99.0.2"},
                {"name": "y", "public_key": KEY_A, "address": "10.99.0.3"}]}, "same public_key"),
    ({"peers": [{"name": "x", "public_key": KEY_A, "address": "10.99.0.2"},
                {"name": "y", "public_key": KEY_B, "address": "10.99.0.2"}]}, "used twice"),
    ({"peers": [{"name": "x", "public_key": KEY_A, "address": "10.99.0.2"},
                {"name": "x", "public_key": KEY_B, "address": "10.99.0.3"}]}, "duplicate name"),
    ({"peers": [{"name": "bad name", "public_key": KEY_A, "address": "10.99.0.2"}]}, "invalid name"),
])
def test_bad_tunnels_are_refused(wg, error):
    with pytest.raises(ConfigError, match=error):
        parse_config(_config(**wg))


def test_the_tunnel_zone_needs_no_interface_entry():
    """wg0 isn't under 'interfaces'; its zone still counts as used."""
    raw = _config()
    raw["wireguard"]["enabled"] = False
    assert parse_config(raw).wireguard.enabled is False
    del raw["wireguard"]
    with pytest.raises(ConfigError, match="'vpn' is declared but not used"):
        parse_config(raw)


def test_the_tunnel_zone_must_exist_and_not_face_the_internet():
    for zone, error in (("wan", "faces the internet"), ("nosuch", "undefined zone")):
        raw = _config(zone=zone)
        del raw["zones"]["vpn"]
        with pytest.raises(ConfigError, match=error):
            parse_config(raw)


def test_the_private_key_is_refused_in_config_yaml():
    with pytest.raises(ConfigError, match="must not be in config.yaml"):
        parse_config(_config(private_key=KEY_A))


# -- keys --------------------------------------------------------------------------------------


def test_the_router_key_is_made_once_and_kept_private(tmp_path):
    path = tmp_path / "wireguard" / "private.key"
    key = wireguard.ensure_private_key(path)
    assert wireguard.ensure_private_key(path) == key
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert wireguard.router_public_key(path) == wireguard.public_key_of(key)


@pytest.mark.skipif(not shutil.which("wg"), reason="needs wireguard-tools")
def test_keys_match_wg_itself():
    private, public = wireguard.generate_keypair()
    assert subprocess.run(["wg", "pubkey"], input=private, capture_output=True, text=True,
                          check=True).stdout.strip() == public


# -- ruleset ---------------------------------------------------------------------------------


def test_the_ruleset_puts_wg0_in_its_zone_and_opens_the_port():
    ruleset = build_ruleset(parse_config(_config(listen_port=51999)))
    assert 'set vpn_ifaces {\n\t\ttype ifname\n\t\telements = { "wg0" }' in ruleset
    assert 'udp dport 51999 accept comment "wireguard"' in ruleset


def test_a_tunnel_that_is_off_opens_nothing():
    raw = _config()
    raw["wireguard"]["enabled"] = False
    ruleset = build_ruleset(parse_config(raw))
    assert "wg0" not in ruleset and "wireguard" not in ruleset


# -- sync ---------------------------------------------------------------------------------------


class FakeRun:
    def __init__(self, link=False, addresses=()):
        self.calls, self.link, self.addresses = [], link, list(addresses)

    def __call__(self, argv, *, input=None, check=True):
        self.calls.append((argv, input))
        rc, out = 0, ""
        if argv[:3] == ["ip", "link", "show"]:
            rc = 0 if self.link else 1
        elif argv[:2] == ["ip", "-o"]:
            out = "".join(f"5: wg0    inet {a} scope global wg0\n" for a in self.addresses)
        return subprocess.CompletedProcess(argv, rc, out, "")


def test_sync_brings_the_tunnel_up(tmp_path):
    run = FakeRun(addresses=["10.98.0.1/24"])
    config = parse_config(_config(peers=[{"name": "laptop", "public_key": KEY_A, "address": "10.99.0.2"}]))
    result = wireguard.sync(config, key_path=tmp_path / "k", run=run)
    argvs = [c[0] for c in run.calls]
    assert ["ip", "link", "add", "dev", "wg0", "type", "wireguard"] in argvs
    syncconf = next(c for c in run.calls if c[0][:2] == ["wg", "syncconf"])
    assert syncconf[0] == ["wg", "syncconf", "wg0", "/dev/stdin"]
    key = (tmp_path / "k").read_text().strip()
    assert f"PrivateKey = {key}" in syncconf[1] and f"PublicKey = {KEY_A}" in syncconf[1]
    assert not any(key in " ".join(a) for a in argvs)  # never on a command line
    assert ["ip", "addr", "del", "10.98.0.1/24", "dev", "wg0"] in argvs  # a stale address goes
    assert argvs[-2:] == [["ip", "addr", "replace", "10.99.0.1/24", "dev", "wg0"],
                          ["ip", "link", "set", "dev", "wg0", "up"]]
    assert result.message == "WireGuard up: wg0 10.99.0.1/24, UDP 51820, 1 peer(s)"


def test_sync_removes_the_tunnel_when_off(tmp_path):
    raw = _config()
    raw["wireguard"]["enabled"] = False
    run = FakeRun(link=True)
    assert wireguard.sync(parse_config(raw), key_path=tmp_path / "k", run=run).message == "WireGuard off: wg0 removed"
    assert run.calls[-1][0] == ["ip", "link", "del", "dev", "wg0"]
    assert not (tmp_path / "k").exists()


def test_dry_run_touches_nothing(tmp_path):
    run = FakeRun()
    assert "would bring up" in wireguard.sync(parse_config(_config()), dry_run=True, key_path=tmp_path / "k",
                                              run=run).message
    assert run.calls == [] and not (tmp_path / "k").exists()


def test_status_reads_wg_show_dump(tmp_path):
    wireguard.ensure_private_key(tmp_path / "k")
    dump = ("priv\tpub\t51820\toff\n"
            f"{KEY_A}\t(none)\t203.0.113.7:40000\t10.99.0.2/32\t1790000000\t1200\t3400\t25\n")

    def run(argv, *, input=None, check=True):
        return subprocess.CompletedProcess(argv, 0, dump, "")

    status = wireguard.status(key_path=tmp_path / "k", run=run)
    assert status["up"] and status["peers"][KEY_A] == {
        "endpoint": "203.0.113.7:40000", "latest_handshake": 1790000000, "rx_bytes": 1200, "tx_bytes": 3400}


def test_client_config_and_addresses():
    config = parse_config(_config(endpoint="vpn.example.net",
                                  peers=[{"name": "laptop", "public_key": KEY_A, "address": "10.99.0.2"}]))
    assert wireguard.next_free_address(config.wireguard) == "10.99.0.3/32"
    text = wireguard.client_config(config, private_key=KEY_B, address="10.99.0.3/32", router_key=KEY_A)
    assert "Endpoint = vpn.example.net:51820" in text
    assert "AllowedIPs = 10.99.0.0/24, 192.168.1.0/24" in text  # split tunnel: VPN and LAN, not the WAN
    full = wireguard.client_config(config, private_key=KEY_B, address="10.99.0.3/32", router_key=KEY_A,
                                   full_tunnel=True)
    assert "AllowedIPs = 0.0.0.0/0" in full


# -- a real tunnel -----------------------------------------------------------------------------


def _sh(*args, ns=None, check=True, input=None):
    cmd = (["ip", "netns", "exec", ns] if ns else []) + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=check, input=input)


needs_tunnel_tools = pytest.mark.skipif(
    os.geteuid() != 0 or not all(shutil.which(t) for t in ("ip", "nft", "wg", "wireguard-go"))
    or not os.path.exists("/dev/net/tun"),
    reason="needs root, nft, wireguard-tools, wireguard-go and /dev/net/tun",
)


@needs_tunnel_tools
def test_a_real_tunnel_through_fr_os(tmp_path):
    tag = uuid.uuid4().hex[:6]
    router, client = f"wgr{tag}", f"wgc{tag}"
    client_if = f"wgc{tag}"
    procs = []
    try:
        for ns in (router, client):
            _sh("ip", "netns", "add", ns)
            _sh("ip", "link", "set", "lo", "up", ns=ns)
        _sh("ip", "link", "add", f"rw{tag}", "type", "veth", "peer", "name", f"cw{tag}")
        _sh("ip", "link", "set", f"rw{tag}", "netns", router)
        _sh("ip", "link", "set", f"cw{tag}", "netns", client)
        _sh("ip", "addr", "add", "172.30.9.1/24", "dev", f"rw{tag}", ns=router)
        _sh("ip", "addr", "add", "172.30.9.2/24", "dev", f"cw{tag}", ns=client)
        _sh("ip", "link", "set", f"rw{tag}", "up", ns=router)
        _sh("ip", "link", "set", f"cw{tag}", "up", ns=client)

        client_priv, client_pub = wireguard.generate_keypair()
        raw = {
            "version": 1, "hostname": "router",
            "zones": {"wan": {}, "vpn": {}},
            "interfaces": {"wan": {"device": f"rw{tag}", "zone": "wan", "address": "172.30.9.1/24"}},
            "rules": [{"name": "vpn-to-router", "action": "accept", "from_zone": "vpn", "to_zone": "self"}],
            "nat": {"masquerade": [{"out_zone": "wan"}]},
            "wireguard": {"enabled": True, "address": "10.99.0.1/24", "listen_port": 51820,
                          "peers": [{"name": "laptop", "public_key": client_pub, "address": "10.99.0.2"}]},
        }
        config = parse_config(raw)
        # FR_OS's own ruleset on the router: policy drop, wan can only
        # reach the WireGuard port.
        _sh("nft", "-f", "-", ns=router, input=build_ruleset(config))

        env = dict(os.environ, WG_PROCESS_FOREGROUND="1")
        for ns, ifname in ((router, "wg0"), (client, client_if)):
            procs.append(subprocess.Popen(["ip", "netns", "exec", ns, "wireguard-go", ifname], env=env,
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        for ns, ifname in ((router, "wg0"), (client, client_if)):
            for _ in range(50):
                if _sh("ip", "link", "show", "dev", ifname, ns=ns, check=False).returncode == 0:
                    break
                time.sleep(0.1)

        def in_router(argv, *, input=None, check=True):
            proc = _sh(*argv, ns=router, check=False, input=input)
            if check and proc.returncode != 0:
                raise wireguard.WireguardError(proc.stderr)
            return proc

        result = wireguard.sync(config, key_path=tmp_path / "private.key", run=in_router)
        assert result.message.startswith("WireGuard up")
        router_pub = wireguard.router_public_key(tmp_path / "private.key")

        key_file = tmp_path / "client.key"
        key_file.write_text(client_priv)
        _sh("wg", "set", client_if, "private-key", str(key_file), "peer", router_pub,
            "endpoint", "172.30.9.1:51820", "allowed-ips", "10.99.0.0/24", ns=client)
        _sh("ip", "addr", "add", "10.99.0.2/32", "dev", client_if, ns=client)
        _sh("ip", "link", "set", client_if, "up", ns=client)
        _sh("ip", "route", "add", "10.99.0.0/24", "dev", client_if, ns=client)

        procs.append(subprocess.Popen(
            ["ip", "netns", "exec", router, sys.executable, "-c",
             "import socket\ns = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
             "s.bind(('0.0.0.0', 8443)); s.listen()\n"
             "while True:\n    c, _ = s.accept(); c.sendall(b'hello'); c.close()\n"]))

        def reaches(host: str, tries: int = 20) -> bool:
            probe = ("import socket, sys, time\n"
                     f"for _ in range({tries}):\n"
                     f"    try:\n        c = socket.create_connection(('{host}', 8443), timeout=1)\n"
                     "        sys.exit(0 if c.recv(5) == b'hello' else 1)\n"
                     "    except OSError:\n        time.sleep(0.2)\n"
                     "sys.exit(1)\n")
            return _sh(sys.executable, "-c", probe, ns=client, check=False).returncode == 0

        assert reaches("10.99.0.1"), "through the tunnel"
        assert not reaches("172.30.9.1", tries=3), "the same port from the WAN, outside the tunnel, is dropped"
        dump = _sh("wg", "show", "wg0", "dump", ns=router).stdout
        assert client_pub in dump

        # A key the router doesn't know gets nowhere.
        other_priv, _ = wireguard.generate_keypair()
        key_file.write_text(other_priv)
        _sh("wg", "set", client_if, "private-key", str(key_file), ns=client)
        assert not reaches("10.99.0.1", tries=3), "an unknown key"
        # ...and the same short wait is enough for the right key again, so
        # the two "not reaches" above aren't just impatience.
        key_file.write_text(client_priv)
        _sh("wg", "set", client_if, "private-key", str(key_file), ns=client)
        assert reaches("10.99.0.1", tries=3)
    finally:
        for proc in procs:
            proc.kill()
            proc.wait()
        for ns in (router, client):
            _sh("ip", "netns", "del", ns, check=False)
