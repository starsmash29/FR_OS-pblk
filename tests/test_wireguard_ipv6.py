"""ROADMAP FND-1d (1d-1): IPv6 inside the WireGuard tunnel, and the full
tunnel's IPv6 leak (H1).

- a full-tunnel client configuration routes `::/0` too, so a device's
  IPv6 can never go around the tunnel, and carries the device's IPv6
  tunnel address once the router has its ULA prefix;
- the tunnel's network is the ULA /48's `ffff` /64, the router `::1`,
  each client the host number of its IPv4 tunnel address -- in the
  router's `wg` config (WireGuard takes only the listed addresses from a
  key) and on wg0;
- the ruleset lets a client's IPv6 reach the router's ping and the LAN's
  ULA networks only, and refuses the rest at once (admin-prohibited), with
  IPv6 off on the router or the tunnel's zone kept off IPv6 too: never
  silently, so a device tries IPv4 through the tunnel without waiting;
- the kernel forwards IPv6 while the VPN is on: without it the kernel
  drops a client's packet before the forward chain could refuse it;
- the VPN screen issues configurations with IPv6 and marks the devices
  whose configuration has none.

The container's kernel has no IPv6, so packets through a real tunnel are
in the boot test (installer/qemu-boot-test.py, check_vpn_ipv6).
"""

from __future__ import annotations

import base64
import ipaddress
import shutil
import subprocess

import pytest

from frfw import ipv6, wireguard
from frfw.config import ConfigError, parse_config
from frfw.nft import build_ruleset

KEY_A = base64.b64encode(b"a" * 32).decode()
KEY_B = base64.b64encode(b"b" * 32).decode()
ULA = ipaddress.IPv6Network("fd12:3456:789a::/48")

requires_nft = pytest.mark.skipif(shutil.which("nft") is None, reason="nft binary not installed")


def _raw(ipv6_on: bool = True, **wg) -> dict:
    return {
        "version": 1, "hostname": "router",
        "zones": {"wan": {}, "lan": {}, "vpn": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"},
                       "lan": {"device": "eth1", "zone": "lan", "address": "192.168.1.1/24"}},
        "rules": [{"name": "vpn-to-lan", "action": "accept", "from_zone": "vpn", "to_zone": "lan"}],
        "nat": {"masquerade": [{"out_zone": "wan"}]},
        "ipv6": {"enabled": ipv6_on},
        "wireguard": {"enabled": True, "address": "10.99.0.1/24",
                      "peers": [{"name": "laptop", "public_key": KEY_A, "address": "10.99.0.5"}], **wg},
    }


def _chain(ruleset: str, name: str) -> list[str]:
    body = ruleset.split(f"chain {name} {{")[1].split("\n\t}")[0]
    return [line.strip() for line in body.splitlines()
            if line.strip() and not line.strip().startswith(("type ", "policy"))]


# --- addresses ----------------------------------------------------------------------


def test_the_tunnel_has_the_ula_s_last_64_and_clients_keep_their_host_number():
    wg = parse_config(_raw()).wireguard
    assert ipv6.tunnel_network6(ULA) == ipaddress.IPv6Network("fd12:3456:789a:ffff::/64")
    assert str(wireguard.router_address6(ULA)) == "fd12:3456:789a:ffff::1/64"
    assert wireguard.peer_address6(wg, "10.99.0.5/32", ULA) == "fd12:3456:789a:ffff::5/128"
    wide = parse_config(_raw(address="10.98.0.1/16", peers=[])).wireguard
    assert wireguard.peer_address6(wide, "10.98.3.7/32", ULA) == "fd12:3456:789a:ffff::307/128"


def test_the_router_takes_each_clients_ipv6_address_from_its_key_only_with_the_prefix():
    wg = parse_config(_raw()).wireguard
    assert "AllowedIPs = 10.99.0.5/32\n" in wireguard.render_conf(wg, KEY_B)
    assert "AllowedIPs = 10.99.0.5/32, fd12:3456:789a:ffff::5/128\n" in wireguard.render_conf(wg, KEY_B, ULA)


def test_dual_stack_is_a_flag_of_the_peer():
    raw = _raw()
    assert parse_config(raw).wireguard.peers[0].dual_stack is False
    raw["wireguard"]["peers"][0]["dual_stack"] = True
    assert parse_config(raw).wireguard.peers[0].dual_stack is True
    raw["wireguard"]["peers"][0]["dual_stack"] = "yes"
    with pytest.raises(ConfigError, match="dual_stack"):
        parse_config(raw)


# --- the client's configuration (H1) -------------------------------------------------


def test_a_full_tunnel_routes_ipv6_into_the_tunnel_with_or_without_the_prefix():
    """H1: `0.0.0.0/0` alone sent the device's IPv6 around the tunnel.
    `::/0` goes in even before the router has a ULA prefix (or with IPv6
    off): the router then refuses that IPv6, it never leaks."""
    for config in (parse_config(_raw()), parse_config(_raw(ipv6_on=False))):
        for ula in (None, ULA):
            text = wireguard.client_config(config, private_key=KEY_B, address="10.99.0.6/32", router_key=KEY_A,
                                           full_tunnel=True, ula=ula)
            assert "AllowedIPs = 0.0.0.0/0, ::/0\n" in text
    text = wireguard.client_config(parse_config(_raw()), private_key=KEY_B, address="10.99.0.6/32",
                                   router_key=KEY_A, full_tunnel=True, ula=ULA)
    assert "Address = 10.99.0.6/32, fd12:3456:789a:ffff::6/128\n" in text
    assert "Address = 10.99.0.6/32\n" in wireguard.client_config(
        parse_config(_raw()), private_key=KEY_B, address="10.99.0.6/32", router_key=KEY_A, full_tunnel=True)


def test_a_split_tunnel_adds_the_tunnel_and_the_lans_stable_networks():
    config = parse_config(_raw())
    assert wireguard.split_tunnel_networks(config) == ["10.99.0.0/24", "192.168.1.0/24"]
    assert wireguard.split_tunnel_networks(config, ULA) == [
        "10.99.0.0/24", "192.168.1.0/24", "fd12:3456:789a:ffff::/64", "fd12:3456:789a::/64"]
    # IPv6 off on the router: nothing of the LAN's, which has none.
    assert wireguard.split_tunnel_networks(parse_config(_raw(ipv6_on=False)), ULA) == [
        "10.99.0.0/24", "192.168.1.0/24", "fd12:3456:789a:ffff::/64"]


# --- what the router does with it ------------------------------------------------------


def _blocking_rule(raw: dict) -> dict:
    """A drop by IPv4 address naming the VPN: IPv6 would get around it."""
    raw["rules"].insert(0, {"name": "no-guest-laptop", "action": "drop", "from_zone": "vpn", "to_zone": "lan",
                            "src_address": "10.99.0.5/32"})
    return raw


def test_the_tunnel_is_served_only_with_ipv6_on_and_its_zone_not_kept_off():
    assert ipv6.tunnel_served(parse_config(_raw()))
    assert not ipv6.tunnel_served(parse_config(_raw(ipv6_on=False)))
    assert not ipv6.tunnel_served(parse_config(_blocking_rule(_raw())))
    off = _raw()
    off["wireguard"]["enabled"] = False
    assert not ipv6.tunnel_served(parse_config(off))


def test_with_ipv6_off_a_clients_ipv6_is_refused_not_dropped():
    ruleset = build_ruleset(parse_config(_raw(ipv6_on=False)))
    refused = 'iifname "wg0" meta nfproto ipv6 reject with icmpv6 type admin-prohibited comment'
    rules = _chain(ruleset, "input")
    assert rules.index(f'{refused} "ipv6-vpn-off"') + 1 == rules.index('meta nfproto ipv6 drop comment "ipv6-off"')
    forward = _chain(ruleset, "forward")
    assert forward[:2] == [f'{refused} "ipv6-vpn-not-routed"',
                           'meta nfproto ipv6 drop comment "ipv6-no-routing"']


def test_with_ipv6_on_a_client_reaches_the_lans_ula_networks_only():
    ruleset = build_ruleset(parse_config(_raw()))
    forward = _chain(ruleset, "forward")
    assert forward[:2] == [
        'iifname "wg0" meta nfproto ipv6 ip6 daddr != fc00::/7 reject with icmpv6 type admin-prohibited '
        'comment "ipv6-vpn-ula-only"',
        'oifname "wg0" meta nfproto ipv6 ip6 saddr != fc00::/7 drop comment "ipv6-vpn-ula-only"',
    ]
    assert forward[2] == 'meta nfproto ipv6 iifname != { "eth0", "eth1", "wg0" } drop comment "ipv6-not-routed-here"'
    # Then the admin's rules decide, as over IPv4 ("vpn-to-lan").
    assert any("vpn-to-lan" in r for r in forward)
    served = _chain(ruleset, "ipv6_input")
    ping = served.index('iifname "wg0" icmpv6 type echo-request limit rate 5/second burst 10 packets accept '
                        'comment "ipv6-vpn-ping"')
    assert served[ping + 1] == ('iifname "wg0" meta nfproto ipv6 reject with icmpv6 type admin-prohibited '
                                'comment "ipv6-vpn-not-served"')
    assert served[ping + 2].endswith('comment "ipv6-not-for-the-router"')


def test_a_zone_kept_off_ipv6_keeps_its_vpn_clients_off_it_too():
    """1b's rule for a LAN zone, for the tunnel: a drop by IPv4 address
    would not hold over IPv6, so the tunnel's IPv6 is refused."""
    ruleset = build_ruleset(parse_config(_blocking_rule(_raw())))
    assert "ipv6-vpn-ula-only" not in ruleset and "ipv6-vpn-ping" not in ruleset
    assert _chain(ruleset, "forward")[0] == ('iifname "wg0" meta nfproto ipv6 reject with icmpv6 type '
                                             'admin-prohibited comment "ipv6-vpn-not-routed"')


def test_no_vpn_no_tunnel_rules():
    raw = _raw()
    raw["wireguard"]["enabled"] = False
    assert "ipv6-vpn" not in build_ruleset(parse_config(raw))


@requires_nft
@pytest.mark.parametrize("variant", ["off", "on", "kept-off"])
def test_nft_accepts_every_variant(variant):
    raw = {"off": _raw(ipv6_on=False), "on": _raw(), "kept-off": _blocking_rule(_raw())}[variant]
    proc = subprocess.run(["nft", "-c", "-f", "-"], input=build_ruleset(parse_config(raw)),
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


# --- the kernel ---------------------------------------------------------------------------


def test_the_kernel_forwards_ipv6_while_the_vpn_is_on():
    """Without forwarding the kernel drops a client's packet for the
    internet before the forward chain could refuse it, and the client
    waits for a timeout."""
    assert ipv6.forwarding_wanted(parse_config(_raw(ipv6_on=False)))
    assert ipv6.sysctl_settings(parse_config(_raw(ipv6_on=False)))["ipv6/conf/all/forwarding"] == "1"
    raw = _raw(ipv6_on=False)
    raw["wireguard"]["enabled"] = False
    assert not ipv6.forwarding_wanted(parse_config(raw))


class FakeRun:
    def __init__(self, link=False, addresses=(), addresses6=()):
        self.calls, self.link = [], link
        self.addresses, self.addresses6 = list(addresses), list(addresses6)

    def __call__(self, argv, *, input=None, check=True):
        self.calls.append((argv, input))
        rc, out = 0, ""
        if argv[:3] == ["ip", "link", "show"]:
            rc = 0 if self.link else 1
        elif argv[:3] == ["ip", "-o", "-4"]:
            out = "".join(f"5: wg0    inet {a} scope global wg0\n" for a in self.addresses)
        elif argv[:3] == ["ip", "-o", "-6"]:
            out = "".join(f"5: wg0    inet6 {a} scope global \\       valid_lft forever\n" for a in self.addresses6)
        return subprocess.CompletedProcess(argv, rc, out, "")


@pytest.fixture
def proc(monkeypatch, tmp_path):
    """A /proc/sys/net that has IPv6, wg0 included, forwarding off."""
    root = tmp_path / "proc_sys_net"
    for device in ("all", "default", "wg0"):
        conf = root / "ipv6" / "conf" / device
        conf.mkdir(parents=True)
        (conf / "forwarding").write_text("0\n")
        (conf / "disable_ipv6").write_text("1\n" if device == "wg0" else "0\n")
    monkeypatch.setattr(ipv6, "PROC_NET", root)
    return root


def test_sync_puts_the_tunnels_ipv6_on_wg0(tmp_path, proc):
    ipv6._write_ula_state({"generated": str(ULA)})
    run = FakeRun(addresses6=["fd99:1:2:ffff::1/64"])  # from an older prefix
    result = wireguard.sync(parse_config(_raw(ipv6_on=False)), key_path=tmp_path / "k", run=run)
    argvs = [c[0] for c in run.calls]
    syncconf = next(c for c in run.calls if c[0][:2] == ["wg", "syncconf"])
    assert "AllowedIPs = 10.99.0.5/32, fd12:3456:789a:ffff::5/128" in syncconf[1]
    assert ["ip", "-6", "addr", "del", "fd99:1:2:ffff::1/64", "dev", "wg0"] in argvs
    assert argvs[-2:] == [["ip", "-6", "addr", "replace", "fd12:3456:789a:ffff::1/64", "dev", "wg0", "nodad"],
                          ["ip", "link", "set", "dev", "wg0", "up"]]
    assert (proc / "ipv6/conf/all/forwarding").read_text().strip() == "1"
    assert (proc / "ipv6/conf/wg0/disable_ipv6").read_text().strip() == "0"
    assert result.message.endswith("; IPv6 fd12:3456:789a:ffff::1/64 in the tunnel")


def test_sync_makes_the_ula_prefix_if_there_is_none(tmp_path, proc):
    wireguard.sync(parse_config(_raw(ipv6_on=False)), key_path=tmp_path / "k", run=FakeRun())
    assert ipv6.ula_prefix(parse_config(_raw())) is not None


def test_sync_without_kernel_ipv6_is_ipv4_only(tmp_path):
    run = FakeRun()
    result = wireguard.sync(parse_config(_raw()), key_path=tmp_path / "k", run=run)
    assert not any(c[0][:2] == ["ip", "-6"] for c in run.calls)
    assert "IPv6" not in result.message


def test_turning_the_vpn_off_stops_forwarding_unless_a_lan_has_ipv6(tmp_path, proc):
    raw = _raw(ipv6_on=False)
    raw["wireguard"]["enabled"] = False
    (proc / "ipv6/conf/all/forwarding").write_text("1\n")
    wireguard.sync(parse_config(raw), key_path=tmp_path / "k", run=FakeRun(link=True))
    assert (proc / "ipv6/conf/all/forwarding").read_text().strip() == "0"
