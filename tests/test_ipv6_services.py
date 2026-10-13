"""IPv6, stage FND-1c: the router's services over IPv6, and inbound pinholes.

The config (`ipv6.ula_prefix`, `ipv6.pinholes`, `management.ipv6`) and
what it refuses; the stable (ULA) networks -- the prefix generated once,
the router's addresses put on and taken off with `ip`, undone on a failed
apply; the RA's DNS server option, checked by the real dnsmasq; the
ruleset -- DNS, management and WireGuard in the IPv6 input chain, the ULA
border, the pinholes and the IPv6 brute-force jail, checked by the real
`nft`; and where the webUI and SSH listen. The real thing -- a LAN host
resolving through the router over IPv6, reaching the webUI on its ULA
address, a pinhole from the provider's side -- runs in the boot test
(installer/qemu-boot-test.py).
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess

import pytest

from frfw import bruteforce, ipv6, management, paths, surface
from frfw.config import ConfigError, parse_config
from frfw.nft.builder import RuntimeSets, build_ruleset

requires_nft = pytest.mark.skipif(shutil.which("nft") is None, reason="nft binary not installed")

ULA = "fd12:3456:789a::/48"


def _config(raw, **ipv6_keys):
    raw = dict(raw)
    raw["ipv6"] = {"enabled": True, **ipv6_keys}
    return parse_config(raw)


def _chain(ruleset: str, name: str) -> list[str]:
    body = ruleset.split(f"chain {name} {{", 1)[1].split("\n\t}", 1)[0]
    return [line.strip() for line in body.splitlines() if line.strip()]


def _with_guest(raw):
    raw["interfaces"]["guest"] = {"device": "eth2", "zone": "guest"}
    raw["zones"]["guest"] = {}
    return raw


def _resolver(raw):
    """The ad-block resolver serving the DHCP zones (lan)."""
    raw["adblocker"] = {"enabled": True, "serve_lan": True, "source_urls": ["https://lists.example/hosts"]}
    return raw


@pytest.fixture
def ip_calls(monkeypatch):
    """`ip -6` as frfw.ipv6 runs it: recorded, and successful."""
    calls: list[str] = []

    def run_ip(args):
        calls.append(" ".join(args))
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(ipv6, "_run_ip", run_ip)
    return calls


# --- the config ------------------------------------------------------------------


def test_ula_prefix_is_a_random_ula_48(minimal_config_dict):
    assert _config(minimal_config_dict, ula_prefix=ULA).ipv6.ula_prefix == ULA
    assert _config(minimal_config_dict).ipv6.ula_prefix is None


@pytest.mark.parametrize("value", ["fd12:3456:789a::/56", "fc12:3456:789a::/48", "2001:db8::/48",
                                   "fd00::/48", "fd12:3456:789a::1/48", "not-a-prefix", 48])
def test_a_bad_ula_prefix_is_refused(minimal_config_dict, value):
    with pytest.raises(ConfigError, match="ula_prefix"):
        _config(minimal_config_dict, ula_prefix=value)


PINHOLE = {"name": "nas-https", "zone": "lan", "host": "::5054:ff:fe12:3456", "proto": "tcp", "port": 443}


def test_a_pinhole_by_interface_identifier_or_full_address(minimal_config_dict):
    full = {**PINHOLE, "name": "cam", "host": "2001:DB8:100::BEEF", "proto": "udp", "port": "8000-8010",
            "from": "2001:db8:42:1::5/48"}
    first, second = _config(minimal_config_dict, pinholes=[PINHOLE, full]).ipv6.pinholes
    assert (first.host, first.is_suffix, first.port, first.source) == ("::5054:ff:fe12:3456", True, "443", None)
    assert (second.host, second.is_suffix, second.port, second.source) == (
        "2001:db8:100::beef", False, "8000-8010", "2001:db8:42::/48")


@pytest.mark.parametrize("change, message", [
    ({"host": "::"}, "subnet-router anycast"),
    ({"host": "2001:db8:100::"}, "subnet-router anycast"),
    ({"host": "::1"}, "the router's own address"),
    ({"host": "::fdff:ffff:ffff:ff90"}, "reserved anycast"),
    ({"host": "fd12:3456:789a::5"}, "global unicast"),
    ({"host": "fe80::5"}, "global unicast"),
    ({"host": "ff02::5"}, "global unicast"),
    ({"host": "192.168.1.5"}, "must be an IPv6 address"),
    ({"host": None}, "must be an IPv6 address"),
    ({"proto": "any"}, "proto must be tcp or udp"),
    ({"proto": "icmp"}, "proto must be tcp or udp"),
    ({"port": None}, "port is required"),
    ({"port": "1000-2000"}, "more than one pinhole may open"),
    ({"port": 70000}, "out of range"),
    ({"from": "fd12::/16"}, "can't come from the internet"),
    ({"from": "fe80::/64"}, "can't come from the internet"),
    ({"from": "10.0.0.0/8"}, "must be an IPv6 network"),
    ({"zone": "wan"}, "is not a LAN zone"),
    ({"zone": "dmz"}, "is not a LAN zone"),
    ({"to": "x"}, "unknown key"),
    ({"name": "Bad Name"}, "Invalid"),
])
def test_a_bad_pinhole_is_refused(minimal_config_dict, change, message):
    with pytest.raises(ConfigError, match=message):
        _config(minimal_config_dict, pinholes=[{**PINHOLE, **change}])


def test_pinhole_names_are_unique(minimal_config_dict):
    with pytest.raises(ConfigError, match="named twice"):
        _config(minimal_config_dict, pinholes=[PINHOLE, PINHOLE])


def test_a_pinhole_is_kept_while_ipv6_is_off(minimal_config_dict):
    """The webUI's IPv6 switch keeps the section; nothing renders it."""
    raw = dict(minimal_config_dict)
    raw["ipv6"] = {"enabled": False, "pinholes": [{**PINHOLE, "zone": "nowhere"}]}
    config = parse_config(raw)
    assert config.ipv6.pinholes[0].zone == "nowhere"
    assert "pinhole:" not in build_ruleset(config)


def test_a_pinhole_to_a_lan_zone_without_ipv6_is_kept_and_off(minimal_config_dict, kernel):
    """A zone left out of lan_zones -- or taken off IPv6 later by an
    IPv4-only protection (a drop rule by IPv4 address; until FND-1d the
    SNI filter too, which the boot test found refused) -- keeps its
    pinhole, unused: a pinhole never stands in the way of a protection."""
    _with_guest(minimal_config_dict)
    config = _config(minimal_config_dict, lan_zones=["lan"], pinholes=[{**PINHOLE, "zone": "guest"}])
    assert config.ipv6.pinholes[0].zone == "guest"
    assert "pinhole:" not in build_ruleset(config)
    state = ipv6.status(config, ip_json=lambda *args: [])
    assert state.pinholes == [("nas-https", "guest", "tcp 443", None)]
    assert state.as_dict()["pinholes"] == [["nas-https", "guest", "tcp 443", None]]


def test_a_zones_pinholes_stay_on_with_the_sni_filter(minimal_config_dict):
    """FND-1d: the SNI filter reads IPv6, so its zone keeps IPv6 and its
    pinholes (1c turned them off with the zone)."""
    minimal_config_dict["xdp_sni_filter"] = {"enabled": True, "interfaces": ["lan"], "blocklist": ["x.example"]}
    config = _config(minimal_config_dict, pinholes=[PINHOLE])
    assert config.ipv6.pinholes and "pinhole:nas-https" in build_ruleset(config)


def test_a_drop_rule_by_ipv4_address_still_turns_a_zones_pinholes_off(minimal_config_dict):
    minimal_config_dict["rules"].insert(0, {"name": "no-tv", "action": "drop", "from_zone": "lan",
                                            "to_zone": "wan", "src_address": "10.0.0.9/32"})
    config = _config(minimal_config_dict, pinholes=[PINHOLE])
    assert config.ipv6.pinholes and "pinhole:" not in build_ruleset(config)


@pytest.mark.parametrize("rule", [
    {"name": "no-https-in", "action": "drop", "from_zone": "wan", "to_zone": "lan", "proto": "tcp", "dst_port": 443},
    {"name": "no-web-in", "action": "reject", "to_zone": "lan", "proto": "tcp", "dst_port": "400-500"},
    {"name": "nothing-in", "action": "drop", "from_zone": "wan"},
    {"name": "no-tcp", "action": "drop", "from_zone": "wan", "to_zone": "lan", "proto": "any"},
])
def test_a_pinhole_a_drop_rule_would_be_bypassing_is_refused(minimal_config_dict, rule):
    """A pinhole goes ahead of the rules: a drop that covers it would
    silently stop holding."""
    minimal_config_dict["rules"].append(rule)
    with pytest.raises(ConfigError, match=f"rule '{rule['name']}' drops this traffic"):
        _config(minimal_config_dict, pinholes=[PINHOLE])


@pytest.mark.parametrize("rule", [
    {"name": "other-port", "action": "drop", "from_zone": "wan", "to_zone": "lan", "proto": "tcp", "dst_port": 80},
    {"name": "other-proto", "action": "drop", "from_zone": "wan", "to_zone": "lan", "proto": "udp"},
    {"name": "by-address", "action": "drop", "from_zone": "wan", "to_zone": "lan", "src_address": "198.51.100.0/24"},
    {"name": "lan-out", "action": "drop", "from_zone": "lan", "to_zone": "wan"},
    {"name": "to-router", "action": "drop", "from_zone": "wan", "to_zone": "self"},
    {"name": "allow-in", "action": "accept", "from_zone": "wan", "to_zone": "lan"},
])
def test_rules_a_pinhole_doesnt_get_around_are_fine(minimal_config_dict, rule):
    minimal_config_dict["rules"].append(rule)
    assert _config(minimal_config_dict, pinholes=[PINHOLE]).ipv6.pinholes


def test_management_ipv6_is_off_by_default_and_a_boolean(minimal_config_dict):
    assert _config(minimal_config_dict).management.ipv6 is False
    minimal_config_dict["management"] = {"ipv6": "yes"}
    with pytest.raises(ConfigError, match="management.ipv6 must be true or false"):
        _config(minimal_config_dict)


def test_management_ipv6_is_refused_with_an_input_drop_by_address(minimal_config_dict):
    """Over IPv6 the webUI meets the same input rules, and one by IPv4
    address can't hold there."""
    minimal_config_dict["management"] = {"ipv6": True}
    minimal_config_dict["rules"].append({"name": "no-webui-for-kids", "action": "drop", "from_zone": "lan",
                                         "to_zone": "self", "proto": "tcp", "dst_port": 443,
                                         "src_address": "10.0.0.66/32"})
    with pytest.raises(ConfigError, match="rule 'no-webui-for-kids' keeps hosts off the webUI"):
        _config(minimal_config_dict)
    # Fine with IPv6 off, and with the rule on another port.
    raw = dict(minimal_config_dict)
    raw["ipv6"] = {"enabled": False}
    assert parse_config(raw).management.ipv6 is True
    minimal_config_dict["rules"][-1]["dst_port"] = 53
    minimal_config_dict["rules"][-1]["proto"] = "udp"
    assert _config(minimal_config_dict).management.ipv6 is True


# --- the stable (ULA) networks ---------------------------------------------------


def test_a_generated_ula_prefix_is_rfc_4193(monkeypatch):
    first, second = ipv6.generate_ula_prefix(), ipv6.generate_ula_prefix()
    for prefix in (first, second):
        assert prefix.prefixlen == 48 and prefix.subnet_of(ipaddress.IPv6Network("fd00::/8"))
    assert first != second  # 40 random bits
    monkeypatch.setattr(ipv6.secrets, "randbits", lambda bits: 0)
    assert ipv6.generate_ula_prefix() != ipaddress.IPv6Network("fd00::/48")


def test_the_generated_prefix_is_kept_and_the_config_overrides_it(minimal_config_dict):
    config = _config(minimal_config_dict)
    assert ipv6.ula_prefix(config) is None
    prefix = ipv6.ensure_ula_prefix(config)
    assert ipv6.ensure_ula_prefix(config) == prefix == ipv6.ula_prefix(config)
    assert paths.IPV6_ULA_STATE_PATH.stat().st_mode & 0o777 == 0o644  # the webUI reads it
    override = _config(minimal_config_dict, ula_prefix=ULA)
    assert ipv6.ensure_ula_prefix(override) == ipaddress.IPv6Network(ULA)
    # Taking the override out goes back to the generated one, not a new one.
    assert ipv6.ula_prefix(config) == prefix


def test_each_lan_device_gets_the_ula_64_at_its_prefix_position(minimal_config_dict):
    config = _config(_with_guest(minimal_config_dict), ula_prefix=ULA)
    assert ipv6.ula_addresses(config, ipv6.ula_prefix(config)) == [
        ("lan", "eth1", "fd12:3456:789a::1/64"),
        ("guest", "eth2", "fd12:3456:789a:1::1/64"),
    ]
    assert ipv6.ula_addresses(config, None) == []


def test_sync_puts_the_addresses_on_and_takes_stale_ones_off(minimal_config_dict, ip_calls):
    both = _config(_with_guest(minimal_config_dict), ula_prefix=ULA)
    assert ipv6.sync_ula(both) == ipv6.ula_addresses(both, ipaddress.IPv6Network(ULA))
    assert ip_calls == ["addr replace fd12:3456:789a::1/64 dev eth1 nodad",
                        "addr replace fd12:3456:789a:1::1/64 dev eth2 nodad"]
    ip_calls.clear()
    ipv6.sync_ula(_config(minimal_config_dict, ula_prefix=ULA, lan_zones=["lan"]))
    assert ip_calls == ["addr del fd12:3456:789a:1::1/64 dev eth2",
                        "addr replace fd12:3456:789a::1/64 dev eth1 nodad"]
    assert json.loads(paths.IPV6_ULA_STATE_PATH.read_text())["addresses"] == [["eth1", "fd12:3456:789a::1/64"]]
    ip_calls.clear()
    ipv6.sync_ula(_config(minimal_config_dict, enabled=False))
    assert ip_calls == ["addr del fd12:3456:789a::1/64 dev eth1"]


def test_an_address_already_gone_is_no_error(minimal_config_dict, monkeypatch):
    ipv6._write_ula_state({"generated": ULA, "addresses": [["eth9", "fd12:3456:789a::1/64"]]})
    monkeypatch.setattr(ipv6, "_run_ip", lambda args: subprocess.CompletedProcess(
        args, 2, "", 'Cannot find device "eth9"\n'))
    ipv6.sync_ula(parse_config(minimal_config_dict))
    monkeypatch.setattr(ipv6, "_run_ip", lambda args: subprocess.CompletedProcess(args, 2, "", "RTNETLINK: busy\n"))
    with pytest.raises(ipv6.Ipv6Error, match="cannot put fd12:3456:789a::1/64 on eth1"):
        ipv6.sync_ula(_config(minimal_config_dict, ula_prefix=ULA))


def test_a_tampered_state_file_never_reaches_ip(minimal_config_dict, ip_calls):
    """Only (device, ULA address) pairs come back out of it."""
    ipv6._write_ula_state({"generated": ULA, "addresses": [
        ["eth1", "2001:db8::1/64"], ["-o", "fd12:3456:789a::1/64"], ["eth1; reboot", "fd12::1/64"],
        "junk", ["eth2", "fd12:3456:789a:1::1/64"]]})
    ipv6.sync_ula(parse_config(minimal_config_dict))
    assert ip_calls == ["addr del fd12:3456:789a:1::1/64 dev eth2"]


def test_a_failed_apply_puts_the_addresses_back(minimal_config_dict, ip_calls):
    ipv6.sync_ula(_config(minimal_config_dict, ula_prefix=ULA))
    before = ipv6.UlaState.capture()
    _with_guest(minimal_config_dict)
    ipv6.sync_ula(_config(minimal_config_dict, ula_prefix="fd99:1:2::/48"))
    ip_calls.clear()
    before.restore()
    assert sorted(ip_calls) == sorted([
        "addr del fd99:1:2::1/64 dev eth1", "addr del fd99:1:2:1::1/64 dev eth2",
        "addr replace fd12:3456:789a::1/64 dev eth1 nodad"])
    assert json.loads(paths.IPV6_ULA_STATE_PATH.read_text())["addresses"] == [["eth1", "fd12:3456:789a::1/64"]]


def test_the_lan_keeps_its_addresses_when_the_link_goes_down(minimal_config_dict):
    settings = ipv6.sysctl_settings(_config(minimal_config_dict))
    assert settings["ipv6/conf/eth1/keep_addr_on_down"] == "1"
    assert "ipv6/conf/eth0/keep_addr_on_down" not in settings  # the WAN's are the provider's


def test_the_ra_names_the_resolver_where_it_serves_the_zone(dhcp_config_dict):
    _resolver(_with_guest(dhcp_config_dict))
    config = _config(dhcp_config_dict, ula_prefix=ULA)
    lines = ipv6.render_ra_conf(config, ipaddress.IPv6Network(ULA)).splitlines()
    assert "dhcp-option=tag:lo,option6:dns-server,[fd12:3456:789a::1]" in lines
    assert not any("tag:eth2" in line for line in lines)  # guest has no DHCP pool, so no resolver
    # Without the resolver, no DNS server in the RA.
    dhcp_config_dict["adblocker"]["enabled"] = False
    assert "dns-server" not in ipv6.render_ra_conf(_config(dhcp_config_dict, ula_prefix=ULA),
                                                   ipaddress.IPv6Network(ULA))


@pytest.mark.skipif(shutil.which("dnsmasq") is None, reason="dnsmasq not installed")
def test_real_dnsmasq_accepts_the_ra_config_with_a_dns_server(dhcp_config_dict, tmp_path, monkeypatch):
    monkeypatch.setattr(ipv6, "DNSMASQ_BINARY", shutil.which("dnsmasq"))
    config = _config(_resolver(dhcp_config_dict), ula_prefix=ULA)
    ipv6._test_ra_conf(ipv6.render_ra_conf(config, ipaddress.IPv6Network(ULA)), tmp_path / "ra.conf")


def test_the_resolver_follows_addresses_that_come_later(dhcp_config_dict):
    from frfw.adblock import dns_service

    text = dns_service.render_dnsmasq_config(parse_config(_resolver(dhcp_config_dict)))
    assert "\nbind-dynamic\n" in text and "bind-interfaces" not in text


def test_the_apply_step_puts_the_stable_addresses_on(minimal_config_dict, ip_calls, monkeypatch, tmp_path):
    proc = tmp_path / "proc"
    for device in ("all", "default", "eth0", "eth1"):
        (proc / "ipv6" / "conf" / device).mkdir(parents=True)
        (proc / "ipv4" / "conf" / device).mkdir(parents=True)
        for key in ("accept_ra", "accept_redirects", "accept_source_route", "autoconf", "disable_ipv6",
                    "forwarding", "keep_addr_on_down"):
            (proc / "ipv6" / "conf" / device / key).write_text("0\n")
        (proc / "ipv4" / "conf" / device / "promote_secondaries").write_text("0\n")
    monkeypatch.setattr(ipv6, "PROC_NET", proc)
    monkeypatch.setattr(ipv6, "_systemctl", lambda action, unit=None: None)
    monkeypatch.setattr(ipv6, "service_active", lambda unit=None: False)
    monkeypatch.setattr(ipv6, "_test_ra_conf", lambda text, path: None)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    result = ipv6.sync(_config(minimal_config_dict, ula_prefix=ULA))
    assert "stable addresses eth1 fd12:3456:789a::1/64" in result.message
    assert ip_calls == ["addr replace fd12:3456:789a::1/64 dev eth1 nodad"]
    assert (proc / "ipv6/conf/eth1/keep_addr_on_down").read_text() == "1\n"
    ip_calls.clear()
    assert ipv6.sync(_config(minimal_config_dict, enabled=False)).message == "IPv6 turned off"
    assert ip_calls == ["addr del fd12:3456:789a::1/64 dev eth1"]


# --- status -----------------------------------------------------------------------


def _addr(device, *addresses):
    return {"ifname": device, "addr_info": [
        {"family": "inet6", "local": a.split("/")[0], "prefixlen": int(a.split("/")[1]), "scope": "global"}
        for a in addresses]}


@pytest.fixture
def kernel(monkeypatch):
    monkeypatch.setattr(ipv6, "kernel_has_ipv6", lambda proc_root=None: True)
    monkeypatch.setattr(ipv6, "service_active", lambda unit=None: True)


def test_status_shows_the_stable_networks_and_the_pinholes(minimal_config_dict, kernel):
    full = {**PINHOLE, "name": "cam", "host": "2001:db8:100::beef", "proto": "udp", "port": 5000}
    config = _config(minimal_config_dict, ula_prefix=ULA, pinholes=[PINHOLE, full])
    addrs = [_addr("eth0", "2001:db8:1::5/64"), _addr("eth1", "fd12:3456:789a::1/64", "2001:db8:100::1/64")]
    routes = [{"dst": "2001:db8:100::/56", "type": "unreachable", "dev": "lo", "protocol": "dhcp"}]
    state = ipv6.status(config, ip_json=lambda *args: addrs if args[0] == "addr" else routes)
    # The ULA network is the router's, not the provider's.
    assert state.lan == [("lan", "eth1", "2001:db8:100::/64")]
    assert state.ula == [("lan", "eth1", "fd12:3456:789a::1/64")]
    assert state.pinholes == [("nas-https", "lan", "tcp 443", ["2001:db8:100:0:5054:ff:fe12:3456"]),
                              ("cam", "lan", "udp 5000", ["2001:db8:100::beef"])]
    assert "stable networks come from fd12:3456:789a::/48" in state.summary
    assert state.as_dict()["ula_prefix"] == ULA


def test_the_stable_network_is_there_without_a_prefix_from_the_provider(minimal_config_dict, kernel):
    addrs = [_addr("eth1", "fd12:3456:789a::1/64")]
    state = ipv6.status(_config(minimal_config_dict, ula_prefix=ULA),
                        ip_json=lambda *args: addrs if args[0] == "addr" else [])
    assert state.state == ipv6.NOTHING and state.prefixes == []
    assert state.lan == [("lan", "eth1", "")]
    assert "the router answers there whatever the provider gives" in state.summary


def test_the_cli_lists_the_stable_addresses_and_pinholes(minimal_config_dict, monkeypatch, tmp_path, capsys):
    import yaml

    from frfw.cli import main

    minimal_config_dict["ipv6"] = {"enabled": True, "ula_prefix": ULA, "pinholes": [PINHOLE]}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(minimal_config_dict))
    monkeypatch.setattr(ipv6, "kernel_has_ipv6", lambda proc_root=None: True)
    monkeypatch.setattr(ipv6, "service_active", lambda unit=None: False)
    monkeypatch.setattr(ipv6, "_ip_json", lambda *args: [_addr("eth1", "fd12:3456:789a::1/64")]
                        if args[0] == "addr" else [])
    assert main(["ipv6-status", str(path)]) == 0
    out = capsys.readouterr().out
    assert "  LAN lan (eth1), stable: fd12:3456:789a::1/64\n" in out
    assert "  pinhole nas-https: tcp 443 to no address in lan yet\n" in out


# --- the ruleset --------------------------------------------------------------------


def test_dns_over_ipv6_from_the_zones_the_resolver_serves(dhcp_config_dict):
    _resolver(_with_guest(dhcp_config_dict))
    ruleset = build_ruleset(_config(dhcp_config_dict))
    chain = _chain(ruleset, "ipv6_input")
    assert chain[0] == 'iifname { "lo" } meta l4proto { tcp, udp } th dport 53 accept comment "ipv6-dns"'
    assert not any("eth2" in r for r in chain)  # guest isn't served
    # Without the resolver: nothing.
    dhcp_config_dict["adblocker"]["enabled"] = False
    assert not any("ipv6-dns" in r for r in _chain(build_ruleset(_config(dhcp_config_dict)), "ipv6_input"))


def test_management_over_ipv6_meets_the_admins_rules(minimal_config_dict):
    """Only with management.ipv6; to the router's ULA address on the
    device the packet came in on; `return`, so the admin's input rules
    decide -- as over IPv4."""
    _with_guest(minimal_config_dict)
    minimal_config_dict["management"] = {"zones": ["lan"]}
    assert not any("ipv6-management" in r for r in _chain(build_ruleset(_config(minimal_config_dict)), "ipv6_input"))
    minimal_config_dict["management"]["ipv6"] = True
    ruleset = build_ruleset(_config(minimal_config_dict))
    assert _chain(ruleset, "ipv6_input")[0] == (
        'iifname { "eth1" } ip6 daddr fc00::/7 fib daddr . iif type local tcp dport { 22, 443 } return '
        'comment "ipv6-management"')
    rules = _chain(ruleset, "input")
    jump = rules.index("meta nfproto ipv6 jump ipv6_input")
    # Back in the input chain: the management drop for guest, then the rules.
    assert jump < next(i for i, r in enumerate(rules) if "no-management-from-guest" in r)


def test_wireguard_over_ipv6_from_the_wan(minimal_config_dict):
    minimal_config_dict["zones"]["vpn"] = {}
    minimal_config_dict["wireguard"] = {"enabled": True, "zone": "vpn", "address": "10.99.0.1/24",
                                        "listen_port": 51820}
    chain = _chain(build_ruleset(_config(minimal_config_dict)), "ipv6_input")
    assert 'iifname { "eth0" } udp dport 51820 accept comment "ipv6-wireguard"' in chain


def test_a_lan_source_from_the_internet_is_dropped(minimal_config_dict):
    """ROADMAP FND-1d: a packet from the WAN whose source the router routes
    to a LAN device is spoofed -- a pinhole must not let it make a LAN host
    look like it opened connections (the AI IDS scores IPv6 by MAC). Not a
    strict reverse-path check on the WAN: with two providers the reply
    route may be the other one."""
    rules = _chain(build_ruleset(_config(minimal_config_dict)), "forward")
    assert ('meta nfproto ipv6 iifname { "eth0" } fib saddr oifname { "eth1" } drop '
            'comment "ipv6-lan-source-from-wan"') in rules
    assert not any("iifname { \"eth0\" } fib saddr . iif" in r for r in rules)


def test_ula_never_crosses_the_border(minimal_config_dict):
    rules = _chain(build_ruleset(_config(minimal_config_dict)), "forward")
    wan = '{ "eth0" }'
    assert rules[5:9] == [
        f'iifname {wan} ip6 saddr fc00::/7 drop comment "ipv6-ula-from-internet"',
        f'iifname {wan} ip6 daddr fc00::/7 drop comment "ipv6-ula-from-internet"',
        f'oifname {wan} ip6 saddr fc00::/7 reject with icmpv6 type admin-prohibited comment "ipv6-ula-to-internet"',
        f'oifname {wan} ip6 daddr fc00::/7 reject with icmpv6 type admin-prohibited comment "ipv6-ula-to-internet"',
    ]
    assert rules[3].endswith('comment "ipv6-lan-spoofed"')
    # The router alone: nothing is routed anyway.
    assert "ipv6-ula" not in build_ruleset(_config(minimal_config_dict, lan_zones=[]))


def test_pinholes_are_the_only_way_in_and_go_just_ahead_of_the_drop(minimal_config_dict):
    full = {**PINHOLE, "name": "cam", "host": "2001:db8:100::beef", "proto": "udp", "port": "5000-5010",
            "from": "2001:db8:42::/48"}
    rules = _chain(build_ruleset(_config(minimal_config_dict, pinholes=[PINHOLE, full])), "forward")
    inbound = next(i for i, r in enumerate(rules) if "log-ipv6-inbound" in r)  # then the drop
    assert rules[inbound + 1] == 'meta nfproto ipv6 iifname { "eth0" } drop comment "ipv6-no-inbound"'
    assert rules[inbound - 2:inbound] == [
        'meta nfproto ipv6 iifname { "eth0" } oifname @lan_ifaces ip6 daddr & ::ffff:ffff:ffff:ffff == '
        '::5054:ff:fe12:3456 tcp dport 443 counter accept comment "pinhole:nas-https"',
        'meta nfproto ipv6 iifname { "eth0" } oifname @lan_ifaces ip6 saddr 2001:db8:42::/48 '
        'ip6 daddr 2001:db8:100::beef udp dport 5000-5010 counter accept comment "pinhole:cam"',
    ]
    assert rules.index("ct state established,related accept") < inbound - 2


def test_the_ipv6_jail_holds_an_address_or_a_mac_off_management_only(minimal_config_dict):
    """ROADMAP FND-1d (H3): a host by its MAC, or its address when the
    neighbour table doesn't know it; a /64 jailed before the change
    carries over a reload until it runs out."""
    ruleset = build_ruleset(_config(minimal_config_dict), runtime=RuntimeSets(
        bruteforce_jail6=(("2001:db8:300::7", 600), ("2001:db8:100::/64", 300), ("2001:db8:200::/64", 0)),
        bruteforce_jail_mac=(("52:54:00:12:34:56", 900), ("52:54:00:12:34:57", 0))))
    assert ("\tset bruteforce_jail6 {\n\t\ttype ipv6_addr\n\t\tflags interval, timeout\n"
            "\t\telements = { 2001:db8:300::7 timeout 600s, 2001:db8:100::/64 timeout 300s }\n\t}") in ruleset
    assert ("\tset bruteforce_jail_mac {\n\t\ttype ether_addr\n\t\tflags timeout\n"
            "\t\telements = { 52:54:00:12:34:56 timeout 900s }\n\t}") in ruleset
    top = _chain(ruleset, "input")[:5]
    assert 'ip6 saddr @bruteforce_jail6 tcp dport { 22, 443 } drop comment "bruteforce-jail6"' in top
    assert 'ether saddr @bruteforce_jail_mac tcp dport { 22, 443 } drop comment "bruteforce-jail-mac"' in top
    with pytest.raises(ValueError):
        build_ruleset(_config(minimal_config_dict), runtime=RuntimeSets(bruteforce_jail6=(("not; a net", 5),)))
    # An address inside a /64 jailed before FND-1d: nft refuses the two as
    # conflicting intervals, and the /64 already holds it.
    covered = build_ruleset(_config(minimal_config_dict), runtime=RuntimeSets(
        bruteforce_jail6=(("2001:db8:100::7", 600), ("2001:db8:100::/64", 300))))
    assert "\t\telements = { 2001:db8:100::/64 timeout 300s }\n" in covered
    # A MAC read back from nft that isn't one is left out, never rendered.
    assert "evil" not in build_ruleset(_config(minimal_config_dict), runtime=RuntimeSets(
        bruteforce_jail_mac=(("evil }", 5),)))


def test_a_quarantined_host_reaches_none_of_the_routers_ipv6_services(minimal_config_dict):
    rules = _chain(build_ruleset(_config(minimal_config_dict)), "input")
    assert rules.index('meta nfproto ipv6 ether saddr @ids_quarantine_mac drop comment "ids-quarantine-ipv6"') \
        < rules.index("meta nfproto ipv6 jump ipv6_input")


@requires_nft
def test_nft_accepts_everything_together(dhcp_config_dict):
    _resolver(_with_guest(dhcp_config_dict))
    dhcp_config_dict["adblocker"]["force_dns"] = True
    dhcp_config_dict["management"] = {"ipv6": True}
    dhcp_config_dict["zones"]["vpn"] = {}
    dhcp_config_dict["wireguard"] = {"enabled": True, "zone": "vpn", "address": "10.99.0.1/24"}
    full = {**PINHOLE, "name": "cam", "host": "2001:db8:100::beef", "proto": "udp", "port": "5000-5010",
            "from": "2001:db8:42::/48"}
    config = _config(dhcp_config_dict, pinholes=[PINHOLE, full])
    ruleset = build_ruleset(config, runtime=RuntimeSets(
        bruteforce_jail6=(("2001:db8:100::/64", 600), ("2001:db8:100::7", 600)),
        bruteforce_jail_mac=(("52:54:00:12:34:56", 600),)))
    proc = subprocess.run(["nft", "-c", "-f", "-"], input=ruleset, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


# --- the brute-force jail over IPv6 ------------------------------------------------


@pytest.mark.parametrize("ip, key", [
    ("192.0.2.5", "192.0.2.5"),
    ("2001:db8:100:0:1234:5678:9abc:def0", "2001:db8:100:0:1234:5678:9abc:def0"),
    ("fd12:3456:789a:1:0:0:0:99", "fd12:3456:789a:1::99"),
    ("::ffff:192.0.2.5", "192.0.2.5"),
])
def test_a_source_address_is_itself_not_its_64(ip, key):
    """ROADMAP FND-1d (H3): FND-1c keyed an IPv6 source by its /64, which
    on the LAN is every host on the segment."""
    assert bruteforce.jail_key(ip) == key


def _neighbours(table):
    seen = []

    def neighbour(ip, devices):
        seen.append((ip, frozenset(devices)))
        return table.get(ip)
    return neighbour, seen


def _recording_nft(monkeypatch):
    calls = []
    monkeypatch.setattr(bruteforce, "_run_nft", lambda args: calls.append(args) or subprocess.CompletedProcess(
        args, 0, "", ""))
    return calls


def test_ban_ip_jails_an_ipv6_host_by_its_mac(monkeypatch):
    calls = _recording_nft(monkeypatch)
    neighbour, seen = _neighbours({"fd12:3456:789a:1::99": "52:54:00:12:34:56"})
    assert bruteforce.ban_ip("fd12:3456:789a:1:0:0:0:99", 3600, lan_devices=("eth1",),
                             neighbour=neighbour) == "52:54:00:12:34:56"
    assert seen == [("fd12:3456:789a:1::99", frozenset({"eth1"}))]
    assert calls == [["add", "element", "inet", "fr_os", "bruteforce_jail_mac", "{",
                      "52:54:00:12:34:56 timeout 3600s", "}"]]


def test_ban_ip_jails_an_unknown_ipv6_host_by_its_address_not_its_64(monkeypatch):
    calls = _recording_nft(monkeypatch)
    neighbour, _ = _neighbours({})
    assert bruteforce.ban_ip("2001:db8:100::abcd", 3600, lan_devices=("eth1",), neighbour=neighbour) is None
    assert calls == [["add", "element", "inet", "fr_os", "bruteforce_jail6", "{",
                      "2001:db8:100::abcd timeout 3600s", "}"]]


def test_ban_ip_never_looks_up_an_ipv4_source(monkeypatch):
    calls = _recording_nft(monkeypatch)
    neighbour, seen = _neighbours({"192.0.2.5": "52:54:00:12:34:56"})
    assert bruteforce.ban_ip("192.0.2.5", 60, lan_devices=("eth1",), neighbour=neighbour) is None
    assert seen == []
    assert calls == [["add", "element", "inet", "fr_os", "bruteforce_jail", "{", "192.0.2.5 timeout 60s", "}"]]


def test_the_ipv6_jail_is_read_back_from_nft_json(monkeypatch):
    listing = {"nftables": [{"set": {"elem": [
        {"elem": {"val": {"prefix": {"addr": "2001:db8:100::", "len": 64}}, "expires": 120}},
        {"elem": {"val": "2001:db8:100::7", "expires": 90}},
        {"elem": {"val": {"range": ["2001:db8::", "2001:db8::5"]}, "expires": 1}}]}}]}
    monkeypatch.setattr(bruteforce, "_run_nft", lambda args: subprocess.CompletedProcess(
        args, 0, json.dumps(listing), ""))
    assert bruteforce.snapshot6_before_reload() == [("2001:db8:100::/64", 120), ("2001:db8:100::7", 90)]


@pytest.mark.reads_runtime_sets
def test_the_mac_jail_is_carried_over_a_reload(monkeypatch, minimal_config_dict):
    from frfw import ids_quarantine, provision

    def run_nft(args):
        if args[-1] == "bruteforce_jail_mac":
            return subprocess.CompletedProcess(args, 0, json.dumps({"nftables": [{"set": {"elem": [
                {"elem": {"val": "52:54:00:12:34:56", "expires": 500}}]}}]}), "")
        return subprocess.CompletedProcess(args, 1, "", "Error: No such file or directory")
    monkeypatch.setattr(bruteforce, "_run_nft", run_nft)
    monkeypatch.setattr(ids_quarantine, "_run_nft", run_nft)
    assert bruteforce.snapshot_macs_before_reload() == [("52:54:00:12:34:56", 500)]
    assert ("52:54:00:12:34:56", 500) in bruteforce.list_banned()
    runtime = provision._read_runtime_sets(_config(minimal_config_dict))
    assert runtime.bruteforce_jail_mac == (("52:54:00:12:34:56", 500),)
    assert runtime.bruteforce_jail == runtime.bruteforce_jail6 == ()


@pytest.mark.skipif(shutil.which("nft") is None or os.geteuid() != 0, reason="needs nft and root")
def test_real_jail_round_trip_by_mac_and_by_address(monkeypatch):
    """The sets as build_ruleset declares them, in a throwaway table: a
    known host goes in by its MAC, an unknown one as its address, and
    both read back with their time left, as a reload carries them over."""
    table = "fr_os_jail6_test"
    monkeypatch.setattr(bruteforce, "FILTER_TABLE", table)
    from frfw.nft.builder import _render_bruteforce_jail6_set, _render_bruteforce_jail_mac_set

    declaration = "\n".join([f"table inet {table} {{", *_render_bruteforce_jail6_set(),
                             *_render_bruteforce_jail_mac_set(), "}"])
    subprocess.run(["nft", "-f", "-"], input=declaration, text=True, check=True)
    neighbour, _ = _neighbours({"2001:db8:100::1": "52:54:00:12:34:56"})
    try:
        bruteforce.ban_ip("2001:db8:100::1", 3600, lan_devices=("eth1",), neighbour=neighbour)
        bruteforce.ban_ip("2001:db8:100::2", 3600, lan_devices=("eth1",), neighbour=neighbour)
        (mac,) = bruteforce.snapshot_macs_before_reload()
        (address,) = bruteforce.snapshot6_before_reload()
        assert mac[0] == "52:54:00:12:34:56" and 3500 < mac[1] <= 3600
        assert address[0] == "2001:db8:100::2" and 3500 < address[1] <= 3600
        assert {mac, address} <= set(bruteforce.list_banned())
    finally:
        subprocess.run(["nft", "delete", "table", "inet", table], check=False)


def test_one_lan_host_failing_over_ipv6_no_longer_counts_against_its_neighbours():
    """The H3 bug: under FND-1c, three hosts on the same /64 shared one
    count, and the third one's single failure jailed all of them."""
    from frfw.webui.auth_rate_limiter import BruteforceGuard

    guard = BruteforceGuard(max_attempts=3)
    assert not guard.record_failure("2001:db8:100::1")
    assert not guard.record_failure("2001:db8:100::2")
    assert not guard.record_failure("2001:db8:100::3")
    assert not guard.record_failure("2001:db8:100::1")
    assert guard.record_failure("2001:db8:100::1")


def test_a_host_changing_its_ipv6_address_keeps_its_count():
    """With the MAC from the neighbour table, a host gets no fresh budget
    for a new address; one the table doesn't know counts as its address."""
    from frfw.webui.auth_rate_limiter import BruteforceGuard

    macs = {"2001:db8:100::1": "52:54:00:12:34:56", "2001:db8:100::2": "52:54:00:12:34:56",
            "2001:db8:100::3": "52:54:00:12:34:56"}
    asked = []
    guard = BruteforceGuard(max_attempts=3, device_of=lambda ip: asked.append(ip) or macs.get(ip))
    assert not guard.record_failure("2001:db8:100::1")
    assert not guard.record_failure("2001:db8:100::2")
    assert guard.record_failure("2001:db8:100::3")  # a new address doesn't start over
    assert not guard.record_failure("2001:db8:100::9")  # unknown: its own count
    assert not guard.record_failure("192.0.2.5")
    assert not guard.record_failure("2001:db8:100::1")
    assert asked == ["2001:db8:100::1", "2001:db8:100::2", "2001:db8:100::3", "2001:db8:100::9"]  # cached


def test_the_device_lookup_is_cached_for_a_minute_only(monkeypatch):
    from frfw.webui import auth_rate_limiter
    from frfw.webui.auth_rate_limiter import BruteforceGuard

    clock = [1000.0]
    monkeypatch.setattr(auth_rate_limiter, "_now", lambda: clock[0])
    answers = iter(["52:54:00:12:34:56", None])
    guard = BruteforceGuard(max_attempts=2, device_of=lambda ip: next(answers))
    assert not guard.record_failure("2001:db8:100::1")
    clock[0] += auth_rate_limiter.DEVICE_CACHE_SECONDS
    # The host left the table: its address now counts on its own.
    assert not guard.record_failure("2001:db8:100::1")


def test_the_helper_lookup_falls_back_to_the_address():
    from frfw.helper.client import HelperError
    from frfw.webui.auth_rate_limiter import device_lookup

    class Helper:
        def __init__(self, answer):
            self.answer = answer

        def source_device(self, ip):
            if isinstance(self.answer, Exception):
                raise self.answer
            return self.answer

    assert device_lookup(Helper({"ok": True, "device": "52:54:00:12:34:56"}))("2001:db8::1") == "52:54:00:12:34:56"
    assert device_lookup(Helper({"ok": True, "device": None}))("2001:db8::1") is None
    assert device_lookup(Helper({"ok": False, "message": "no"}))("2001:db8::1") is None
    assert device_lookup(Helper(HelperError("down")))("2001:db8::1") is None


# --- where the webUI and SSH listen ------------------------------------------------


def test_management_listens_on_the_ula_addresses_only_when_asked(minimal_config_dict):
    _with_guest(minimal_config_dict)
    minimal_config_dict["interfaces"]["lan"]["address"] = "10.0.0.1/24"
    minimal_config_dict["management"] = {"zones": ["lan"]}
    config = _config(minimal_config_dict, ula_prefix=ULA)
    assert management.listen_addresses(config) == ["127.0.0.1", "10.0.0.1"]
    minimal_config_dict["management"]["ipv6"] = True
    config = _config(minimal_config_dict, ula_prefix=ULA)
    assert management.listen_addresses(config) == ["127.0.0.1", "10.0.0.1", "fd12:3456:789a::1"]
    assert "ListenAddress fd12:3456:789a::1\n" in management.sshd_dropin(config)
    # Never the provider's, not even with allow_wan.
    minimal_config_dict["management"]["allow_wan"] = True
    assert management.listen_addresses(_config(minimal_config_dict, ula_prefix=ULA)) == [
        "0.0.0.0", "fd12:3456:789a::1"]
    del minimal_config_dict["management"]["zones"]
    assert management.listen_addresses(_config(minimal_config_dict, ula_prefix=ULA)) == [
        "0.0.0.0", "fd12:3456:789a::1", "fd12:3456:789a:1::1"]


def test_a_ula_address_coming_or_going_doesnt_count_as_moving_management(minimal_config_dict):
    """SEC-27's guard is about IPv4: it still reaches the router."""
    minimal_config_dict["interfaces"]["lan"]["address"] = "10.0.0.1/24"
    minimal_config_dict["management"] = {"ipv6": True}
    before = _config(minimal_config_dict, ula_prefix=ULA)
    after = _config(minimal_config_dict, ula_prefix="fd99:1:2::/48")
    assert management.moves_management(after, before) is None


def test_the_recorded_listen_addresses_may_be_ipv6(tmp_path):
    path = tmp_path / "listen.json"
    management.record_webui_listen(["127.0.0.1", "fd12:3456:789a::1"], path)
    assert management.recorded_webui_listen(path) == ["127.0.0.1", "fd12:3456:789a::1"]


def test_sshd_is_reloaded_when_it_misses_an_address(minimal_config_dict, monkeypatch, tmp_path):
    """sshd skips an address that wasn't on the router when it started,
    and never binds it later by itself."""
    from frfw import svc

    minimal_config_dict["management"] = {"ipv6": True}
    config = _config(minimal_config_dict, ula_prefix=ULA)
    dropin = tmp_path / "40-mgmt.conf"
    dropin.write_text(management.sshd_dropin(config))
    calls = []
    monkeypatch.setattr(svc, "systemctl", lambda *args, **kw: calls.append(args[:2]) or subprocess.CompletedProcess(
        args, 0, "", ""))
    monkeypatch.setattr(management, "ssh_login_users", lambda: ["admin"])
    monkeypatch.setattr(management.shutil, "which", lambda binary: "/usr/sbin/sshd")
    monkeypatch.setattr(management, "webui_listening", lambda port=443: {"127.0.0.1"})
    management.sync_sshd(config, dropin_path=dropin)
    assert ("reload-or-restart", "ssh.service") in calls
    calls.clear()
    monkeypatch.setattr(management, "webui_listening", lambda port=443: {"127.0.0.1", "fd12:3456:789a::1"})
    management.sync_sshd(config, dropin_path=dropin)
    assert ("start", "ssh.service") in calls


def test_the_webui_binds_an_ipv6_address_ipv6_only():
    from frfw.webui.server import bind_sockets

    try:
        socket_ = bind_sockets(["::1"], 0)[0]
    except OSError as exc:  # a machine (or container) without IPv6
        pytest.skip(f"no IPv6 here: {exc}")
    import socket as socket_mod
    try:
        assert socket_.family == socket_mod.AF_INET6
        assert socket_.getsockopt(socket_mod.IPPROTO_IPV6, socket_mod.IPV6_V6ONLY) == 1
    finally:
        socket_.close()


# --- the exposure view -------------------------------------------------------------


def test_the_surface_view_knows_what_ipv6_serves(dhcp_config_dict):
    _resolver(dhcp_config_dict)
    dhcp_config_dict["rules"].append({"name": "webui", "action": "accept", "from_zone": "lan", "to_zone": "self",
                                      "proto": "tcp", "dst_port": 443})
    config = _config(dhcp_config_dict)
    assert surface.ipv6_verdict(config, "lan", "udp", 53).state == surface.OPEN
    assert surface.ipv6_verdict(config, "lan", "tcp", 443).state == surface.CLOSED  # management.ipv6 off
    dhcp_config_dict["management"] = {"ipv6": True}
    verdict = surface.ipv6_verdict(_config(dhcp_config_dict), "lan", "tcp", 443)
    assert (verdict.state, verdict.why) == (surface.OPEN, "rule 'webui'")
    assert surface.ipv6_verdict(_config(dhcp_config_dict), "wan", "tcp", 443).state == surface.CLOSED


# --- the boot test's own pieces ----------------------------------------------


@pytest.fixture
def boot_test():
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "qemu_boot_test", Path(__file__).resolve().parents[1] / "installer" / "qemu-boot-test.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_boot_tests_pinhole_is_a_valid_config_with_ipv6_off_and_on(boot_test):
    """The boot test writes PINHOLE_YAML into first boot's config.yaml by
    hand: the router must load it while IPv6 is off (boot 3's start), and
    with IPv6 on as the webUI's switch saves it."""
    import yaml

    from frfw.skeleton import build_skeleton_config

    text = build_skeleton_config("ens3", "ens4").rstrip("\n") + "\n" + boot_test.PINHOLE_YAML
    raw = yaml.safe_load(text)
    off = parse_config(raw)
    assert not off.ipv6.enabled and off.ipv6.pinholes[0].is_suffix
    raw["ipv6"]["enabled"] = True
    pinhole = parse_config(raw).ipv6.pinholes[0]
    assert (pinhole.zone, pinhole.host, pinhole.port) == ("lan", boot_test.PINHOLE_IID, str(boot_test.PINHOLE_PORT))


def test_the_boot_test_reads_the_ras_prefixes_and_dns_servers(boot_test):
    """parse_router_advert, on an RA as RFC 4861/8106 lay it out: a
    Prefix Information option per prefix, one RDNSS option with two
    servers, and an option it doesn't know (MTU) in between."""
    ra = bytes([134, 0, 0, 0, 64, 0, 0x07, 0x08]) + bytes(8)
    for prefix in ("2001:db8:100::/64", "fd12:3456:789a::/64"):
        network = ipaddress.IPv6Network(prefix)
        ra += bytes([3, 4, 64, 0xC0]) + bytes(12) + network.network_address.packed
    ra += bytes([5, 1, 0, 0]) + (1280).to_bytes(4, "big")
    ra += bytes([25, 5, 0, 0]) + (600).to_bytes(4, "big")
    ra += ipaddress.IPv6Address("fd12:3456:789a::1").packed + ipaddress.IPv6Address("fd12:3456:789a:1::1").packed
    prefixes, servers = boot_test.parse_router_advert(ra)
    assert prefixes == [ipaddress.IPv6Network("2001:db8:100::/64"), ipaddress.IPv6Network("fd12:3456:789a::/64")]
    assert servers == ["fd12:3456:789a::1", "fd12:3456:789a:1::1"]
    assert boot_test.parse_router_advert(ra[:16]) == ([], [])
