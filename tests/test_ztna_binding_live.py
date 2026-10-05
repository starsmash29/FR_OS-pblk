"""A ZTNA sign-in is bound to one device, on the wire (ROADMAP SEC-6).

Review v0.2.0 R12: the gate let in a source address, so everyone behind
one NAT got in once one person signed in, and another device on the LAN
could take a signed-in address over. Here everything is real -- network
namespaces, FR_OS's own ruleset, the apply-helper itself (running in the
router's namespace, reading the router's own neighbour table and writing
the router's own nft sets) and an encrypted WireGuard tunnel
(wireguard-go, as in tests/test_wireguard.py):

- a laptop on the LAN signs in and reaches the protected server; another
  device on the LAN that takes the laptop's address over does not, and
  the laptop still does once it has its address back;
- a client behind another router is refused at sign-in -- the router
  can't tell the devices behind it apart -- and gets nowhere;
- a WireGuard client signs in by its tunnel address and gets through,
  but a LAN device using that same address does not.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
import time
import uuid

import pytest
import yaml

from frfw import wireguard
from frfw.admin_account import hash_password
from frfw.config import parse_config
from frfw.helper import client
from frfw.nft import build_ruleset

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0 or not all(shutil.which(t) for t in ("ip", "nft", "wg", "wireguard-go"))
    or not os.path.exists("/dev/net/tun"),
    reason="needs root, nft, iproute2, wireguard-tools, wireguard-go and /dev/net/tun",
)

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
    import socket, sys, time
    for _ in range(int(sys.argv[3])):
        try:
            c = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1)
            sys.exit(0 if c.recv(2) == b"ok" else 1)
        except OSError:
            time.sleep(0.2)
    sys.exit(1)
    """
)

_HELPER = textwrap.dedent(
    """
    import sys
    from pathlib import Path
    from frfw.helper.peer import PeerPolicy
    from frfw.helper.server import ApplyHelperServer
    tmp = Path(sys.argv[1])
    ApplyHelperServer(tmp / "apply.sock", tmp / "config.yaml", backup_dir=tmp / "backups",
                      ztna_state_path=tmp / "ztna-state.json", audit_log_path=tmp / "audit.log",
                      sensor_config_path=tmp / "sensor-config.yaml",
                      peer_policy=PeerPolicy(full_uids=frozenset({0}))).serve_forever()
    """
)

LAPTOP, OTHER, GATEWAY, BEHIND = "10.79.1.10", "10.79.1.11", "10.79.1.20", "10.79.3.10"
SERVER, TUNNEL_CLIENT = "10.79.2.10", "10.99.0.2"


def _sh(*args, ns=None, check=True, input=None):
    cmd = (["ip", "netns", "exec", ns] if ns else []) + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=check, input=input)


def _raw_config(client_pub: str) -> dict:
    gated = {"action": "accept", "to_zone": "srv", "proto": "tcp", "dst_port": 8080, "require_ztna": True}
    return {
        "version": 1, "hostname": "router",
        "zones": {"lan": {}, "srv": {}, "wan": {}, "vpn": {}},
        "interfaces": {
            "lan": {"device": "lanbr", "zone": "lan", "address": "10.79.1.1/24"},
            "srv": {"device": "srv0", "zone": "srv", "address": "10.79.2.1/24"},
            "wan": {"device": "wan0", "zone": "wan", "address": "172.30.9.1/24"},
        },
        "rules": [
            {"name": "gated-lan", "from_zone": "lan", **gated},
            {"name": "gated-vpn", "from_zone": "vpn", **gated},
            # Stands in for the sign-in page: the request that reaches the router.
            {"name": "sign-in", "action": "accept", "from_zone": "lan", "to_zone": "self",
             "proto": "tcp", "dst_port": 8443},
        ],
        "nat": {"masquerade": [{"out_zone": "wan"}]},
        "ztna": {"enabled": True, "session_ttl_seconds": 600,
                 "users": [{"username": "alice", "password_hash": hash_password("zebra-lamp-42")}]},
        "wireguard": {"enabled": True, "address": "10.99.0.1/24", "listen_port": 51820,
                      "peers": [{"name": "laptop", "public_key": client_pub, "address": TUNNEL_CLIENT}]},
    }


@pytest.fixture
def site(tmp_path):
    """The router (its own namespace) with a bridged LAN -- the laptop,
    another device, and a gateway with a network of its own behind it --
    a protected server, and a WireGuard client on the WAN side."""
    tag = uuid.uuid4().hex[:6]
    router, laptop, other, gateway, behind, server, remote = (
        f"zr{tag}", f"zl{tag}", f"zo{tag}", f"zg{tag}", f"zb{tag}", f"zs{tag}", f"zw{tag}")
    namespaces = (router, laptop, other, gateway, behind, server, remote)
    for name, body in (("server.py", _SERVER), ("client.py", _CLIENT), ("helper.py", _HELPER)):
        (tmp_path / name).write_text(body)
    procs = []

    def link(ns_a, if_a, ns_b, if_b):
        _sh("ip", "link", "add", f"t{tag}a", "type", "veth", "peer", "name", f"t{tag}b")
        _sh("ip", "link", "set", f"t{tag}a", "netns", ns_a, "name", if_a)
        _sh("ip", "link", "set", f"t{tag}b", "netns", ns_b, "name", if_b)
        for ns, ifname in ((ns_a, if_a), (ns_b, if_b)):
            _sh("ip", "link", "set", ifname, "up", ns=ns)

    try:
        for ns in namespaces:
            _sh("ip", "netns", "add", ns)
            _sh("ip", "link", "set", "lo", "up", ns=ns)
        _sh("ip", "link", "add", "lanbr", "type", "bridge", ns=router)
        _sh("ip", "link", "set", "lanbr", "up", ns=router)
        _sh("ip", "addr", "add", "10.79.1.1/24", "dev", "lanbr", ns=router)
        for ns, port, address in ((laptop, "pl", LAPTOP), (other, "po", OTHER), (gateway, "pg", GATEWAY)):
            link(router, port, ns, "eth0")
            _sh("ip", "link", "set", port, "master", "lanbr", ns=router)
            _sh("ip", "addr", "add", f"{address}/24", "dev", "eth0", ns=ns)
            _sh("ip", "route", "add", "default", "via", "10.79.1.1", ns=ns)
        # Behind the gateway: routed, so the router sees BEHIND's own
        # address but not its MAC -- it is not a neighbour.
        link(gateway, "eth1", behind, "eth0")
        _sh("ip", "addr", "add", "10.79.3.1/24", "dev", "eth1", ns=gateway)
        _sh("ip", "addr", "add", f"{BEHIND}/24", "dev", "eth0", ns=behind)
        _sh("ip", "route", "add", "default", "via", "10.79.3.1", ns=behind)
        _sh("ip", "route", "add", "10.79.3.0/24", "via", GATEWAY, ns=router)
        link(router, "srv0", server, "eth0")
        _sh("ip", "addr", "add", "10.79.2.1/24", "dev", "srv0", ns=router)
        _sh("ip", "addr", "add", f"{SERVER}/24", "dev", "eth0", ns=server)
        _sh("ip", "route", "add", "default", "via", "10.79.2.1", ns=server)
        link(router, "wan0", remote, "eth0")
        _sh("ip", "addr", "add", "172.30.9.1/24", "dev", "wan0", ns=router)
        _sh("ip", "addr", "add", "172.30.9.2/24", "dev", "eth0", ns=remote)
        for ns in (router, gateway):
            _sh("sysctl", "-qw", "net.ipv4.ip_forward=1", ns=ns)
        # No reverse-path filter on the router: whatever is dropped here is
        # dropped by the gate.
        for conf in ("all", "default", "lanbr"):
            _sh("sysctl", "-qw", f"net.ipv4.conf.{conf}.rp_filter=0", ns=router)
        # What reaches the server from the tunnel client's address, seen
        # on the server itself.
        _sh("nft", "-f", "-", ns=server, input=(
            "table inet probe {\n\tchain inbound {\n\t\ttype filter hook input priority 0;\n"
            f"\t\tip saddr {TUNNEL_CLIENT} tcp dport 8080 tcp flags syn counter\n\t}}\n}}\n"))

        client_priv, client_pub = wireguard.generate_keypair()
        raw = _raw_config(client_pub)
        (tmp_path / "config.yaml").write_text(yaml.safe_dump(raw))
        config = parse_config(raw)
        _sh("nft", "-f", "-", ns=router, input=build_ruleset(config))

        # wireguard-go's control socket is a path, shared by every
        # namespace: the client's interface needs a name of its own.
        client_if = f"wgc{tag}"
        env = dict(os.environ, WG_PROCESS_FOREGROUND="1")
        for ns, ifname in ((router, "wg0"), (remote, client_if)):
            procs.append(subprocess.Popen(["ip", "netns", "exec", ns, "wireguard-go", ifname], env=env,
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        for ns, ifname in ((router, "wg0"), (remote, client_if)):
            for _ in range(50):
                if _sh("ip", "link", "show", "dev", ifname, ns=ns, check=False).returncode == 0:
                    break
                time.sleep(0.1)

        def in_router(argv, *, input=None, check=True):
            proc = _sh(*argv, ns=router, check=False, input=input)
            if check and proc.returncode != 0:
                raise wireguard.WireguardError(proc.stderr)
            return proc

        wireguard.sync(config, key_path=tmp_path / "private.key", run=in_router)
        key_file = tmp_path / "client.key"
        key_file.write_text(client_priv)
        _sh("wg", "set", client_if, "private-key", str(key_file), "peer", wireguard.router_public_key(tmp_path / "private.key"),
            "endpoint", "172.30.9.1:51820", "allowed-ips", "10.99.0.0/24,10.79.2.0/24", ns=remote)
        _sh("ip", "addr", "add", f"{TUNNEL_CLIENT}/32", "dev", client_if, ns=remote)
        _sh("ip", "link", "set", client_if, "up", ns=remote)
        for net in ("10.99.0.0/24", "10.79.2.0/24"):
            _sh("ip", "route", "add", net, "dev", client_if, ns=remote)

        procs.append(subprocess.Popen(["ip", "netns", "exec", server, sys.executable, str(tmp_path / "server.py"), "8080"]))
        procs.append(subprocess.Popen(["ip", "netns", "exec", router, sys.executable, str(tmp_path / "server.py"), "8443"]))
        procs.append(subprocess.Popen(["ip", "netns", "exec", router, sys.executable, str(tmp_path / "helper.py"), str(tmp_path)]))
        sock = tmp_path / "apply.sock"
        for _ in range(100):
            if sock.exists():
                break
            time.sleep(0.1)

        def reaches(ns, host, port=8080, tries=3):
            return _sh(sys.executable, str(tmp_path / "client.py"), host, str(port), str(tries),
                       ns=ns, check=False).returncode == 0

        yield {"ns": dict(router=router, laptop=laptop, other=other, behind=behind, remote=remote, server=server),
               "reaches": reaches, "sock": sock, "sh": _sh}
    finally:
        for proc in procs:
            proc.kill()
            proc.wait()
        for ns in namespaces:
            _sh("ip", "netns", "del", ns, check=False)


def _mac(site, ns):
    return site["sh"]("cat", "/sys/class/net/eth0/address", ns=site["ns"][ns]).stdout.strip()


def test_a_lan_sign_in_is_this_device_s_not_its_address_s(site):
    ns, reaches, sock = site["ns"], site["reaches"], site["sock"]
    assert not reaches(ns["laptop"], SERVER), "the gate is closed before anyone signs in"

    # The sign-in request reaches the router; the apply-helper binds the
    # session to the MAC the router saw it from.
    assert reaches(ns["laptop"], "10.79.1.1", 8443)
    response = client.authorize_ztna(LAPTOP, "alice", sock)
    assert response["ok"], response
    assert response["mac"] == _mac(site, "laptop")
    assert reaches(ns["laptop"], SERVER)
    assert not reaches(ns["other"], SERVER), "signing in let in another device"

    # Another device takes the signed-in address over: not signed in.
    sh = site["sh"]
    sh("ip", "addr", "del", f"{LAPTOP}/24", "dev", "eth0", ns=ns["laptop"])
    sh("ip", "addr", "flush", "dev", "eth0", ns=ns["other"])
    sh("ip", "addr", "add", f"{LAPTOP}/24", "dev", "eth0", ns=ns["other"])
    sh("ip", "route", "add", "default", "via", "10.79.1.1", ns=ns["other"])
    sh("ip", "neigh", "flush", "to", LAPTOP, ns=ns["router"])
    assert reaches(ns["other"], "10.79.1.1", 8443), "the device itself is on the network"
    assert not reaches(ns["other"], SERVER), "a signed-in address let in the device that took it over"
    assert client.ztna_status(LAPTOP, sock)["authorized"] is False

    # The laptop, back with its address, is still signed in: it is the
    # binding that kept the other device out, not a broken network.
    sh("ip", "addr", "flush", "dev", "eth0", ns=ns["other"])
    sh("ip", "addr", "add", f"{LAPTOP}/24", "dev", "eth0", ns=ns["laptop"])
    sh("ip", "route", "add", "default", "via", "10.79.1.1", ns=ns["laptop"])
    sh("ip", "neigh", "flush", "to", LAPTOP, ns=ns["router"])
    assert reaches(ns["laptop"], SERVER, tries=10)
    assert client.ztna_status(LAPTOP, sock)["authorized"] is True


def test_a_client_behind_another_router_is_refused(site):
    ns, reaches, sock = site["ns"], site["reaches"], site["sock"]
    assert reaches(ns["behind"], "10.79.1.1", 8443), "the router does see its requests"
    response = client.authorize_ztna(BEHIND, "alice", sock)
    assert response["ok"] is False
    assert "WireGuard" in response["message"]
    assert client.ztna_sessions_status(sock)["count"] == 0
    assert not reaches(ns["behind"], SERVER)


def test_a_wireguard_sign_in_is_its_key_s_and_only_counts_in_the_tunnel(site):
    ns, reaches, sock = site["ns"], site["reaches"], site["sock"]
    assert not reaches(ns["remote"], SERVER, tries=10), "the gate is closed before anyone signs in"
    response = client.authorize_ztna(TUNNEL_CLIENT, "alice", sock)
    assert response["ok"] and response["mac"] == "", response
    assert reaches(ns["remote"], SERVER, tries=10)

    sh = site["sh"]

    def syns_at_server():
        out = sh("nft", "list", "chain", "inet", "probe", "inbound", ns=ns["server"]).stdout
        return int(out.split("counter packets ")[1].split()[0])

    through_the_tunnel = syns_at_server()
    assert through_the_tunnel > 0

    # A LAN device using the tunnel client's address is not let in by its
    # session: that only counts for traffic that came out of the tunnel.
    # (Its connection couldn't complete anyway -- the replies go into the
    # tunnel -- so what counts is that not even its SYN gets through.)
    sh("ip", "addr", "add", f"{TUNNEL_CLIENT}/32", "dev", "eth0", ns=ns["other"])
    sh("ip", "route", "replace", f"{SERVER}/32", "via", "10.79.1.1", "src", TUNNEL_CLIENT, ns=ns["other"])
    assert not reaches(ns["other"], SERVER)
    assert syns_at_server() == through_the_tunnel, "a LAN device got through on a tunnel client's session"
