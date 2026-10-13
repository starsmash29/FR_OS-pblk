"""IPv6 (ROADMAP FND-1): on the WAN for the router itself (FND-1a), and on
the LAN (FND-1b).

The config, dhcpcd's and the RA instance's generated configs, the kernel
settings written to a fake /proc/sys/net tree, the apply step, the status
read from `ip`'s JSON for every outcome a provider can give, and the
ruleset: what the WAN and the LAN need is accepted, every other IPv6
packet to the router is dropped ahead of the rules written for IPv4, and
IPv6 is routed only between the WAN and the LAN zones, out only. The real
thing -- a provider with RA, DHCPv6 and prefix delegation, and a LAN host
behind the router -- runs in the boot test (installer/qemu-boot-test.py).
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from frfw import integrity, ipv6, paths
from frfw.config import ConfigError, parse_config
from frfw.nft.builder import build_ruleset

requires_nft = pytest.mark.skipif(shutil.which("nft") is None, reason="nft binary not installed")


_DEFAULT = object()


def _config(minimal_config_dict, enabled=True, lan_zones=_DEFAULT, **extra):
    """IPv6 on; `lan_zones=[]` is the router alone (FND-1a), the default
    every LAN zone (FND-1b)."""
    raw = dict(minimal_config_dict)
    raw["ipv6"] = {"enabled": enabled}
    if lan_zones is not _DEFAULT:
        raw["ipv6"]["lan_zones"] = lan_zones
    raw.update(extra)
    return parse_config(raw)


def _router_only(minimal_config_dict, **extra):
    return _config(minimal_config_dict, lan_zones=[], **extra)


@pytest.fixture
def proc(monkeypatch, tmp_path):
    """A /proc/sys/net with eth0 and eth1, every value as a fresh kernel
    has it: RAs accepted, forwarding off."""
    root = tmp_path / "proc_sys_net"
    for device in ("all", "default", "eth0", "eth1"):
        conf = root / "ipv6" / "conf" / device
        conf.mkdir(parents=True)
        for key, value in (("accept_ra", "1"), ("accept_redirects", "1"), ("accept_source_route", "0"),
                           ("autoconf", "1"), ("disable_ipv6", "0"), ("forwarding", "0"),
                           ("keep_addr_on_down", "0")):
            (conf / key).write_text(value + "\n")
        (root / "ipv4" / "conf" / device).mkdir(parents=True)
        (root / "ipv4" / "conf" / device / "promote_secondaries").write_text("0\n")
    monkeypatch.setattr(ipv6, "PROC_NET", root)
    return root


@pytest.fixture
def systemctl(monkeypatch):
    """What was asked of fr-dhcp6 ("restart") and fr-ra ("restart fr-ra"),
    and whether they run. dnsmasq's check of the RA config passes; the
    real one is tested on its own. `ip -6` calls (the ULA addresses,
    FND-1c) are recorded in state["ip"] and succeed."""
    calls: list[str] = []
    state = {"active": False, "ra_active": False, "ip": []}
    monkeypatch.setattr(ipv6, "_systemctl",
                        lambda action, unit=None: calls.append(f"{action} {unit}" if unit else action))
    monkeypatch.setattr(ipv6, "service_active",
                        lambda unit=None: state["ra_active" if unit == paths.IPV6_RA_SERVICE_NAME else "active"])
    monkeypatch.setattr(ipv6, "_test_ra_conf", lambda text, path: None)

    def run_ip(args):
        state["ip"].append(" ".join(args))
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(ipv6, "_run_ip", run_ip)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    return calls, state


# --- the config ----------------------------------------------------------------


def test_off_is_the_default(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    assert config.ipv6.enabled is False


@pytest.mark.parametrize("raw, message", [
    ({"enabled": "yes"}, "must be true or false"),
    ({"enabled": True, "prefix_hint": 56}, "unknown key"),
    (["enabled"], "must be a mapping"),
    ({"enabled": True, "lan_zones": "lan"}, "must be a list of zone names"),
    ({"enabled": True, "lan_zones": ["lan", "lan"]}, "more than once"),
    ({"enabled": True, "lan_zones": ["dmz"]}, "unknown zone 'dmz'"),
    ({"enabled": True, "lan_zones": ["wan"]}, "faces the internet"),
])
def test_bad_sections_are_refused(minimal_config_dict, raw, message):
    minimal_config_dict["ipv6"] = raw
    with pytest.raises(ConfigError, match=message):
        parse_config(minimal_config_dict)


def test_enabled_needs_an_internet_facing_interface(minimal_config_dict):
    minimal_config_dict["interfaces"] = {"lan": {"device": "eth1", "zone": "lan"}}
    minimal_config_dict["rules"] = []
    minimal_config_dict["nat"] = {}
    minimal_config_dict["zones"] = {"lan": {}}
    with pytest.raises(ConfigError, match="needs an internet-facing interface"):
        _config(minimal_config_dict)
    assert _config(minimal_config_dict, enabled=False).ipv6.enabled is False


def test_wan_devices_are_the_internet_facing_ones(minimal_config_dict):
    minimal_config_dict["interfaces"]["wan2"] = {"device": "eth2", "zone": "wan"}
    assert ipv6.wan_devices(_config(minimal_config_dict)) == ["eth0", "eth2"]


# --- dhcpcd's config -------------------------------------------------------------


def test_dhcpcd_runs_ipv6_only_on_the_wan_and_writes_nothing_of_the_routers(minimal_config_dict):
    text = ipv6.render_dhcpcd_conf(_router_only(minimal_config_dict))
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    assert lines == [
        "ipv6only", "noipv4", "noipv4ll", "noipv6rs",
        "fqdn disable",
        "script /bin/true",
        "slaac private",
        "allowinterfaces eth0",
        # The prefix is delegated to no interface: "-" (dhcpcd.conf(5)).
        "interface eth0", "ipv6rs", "ia_na 1", "ia_pd 101 -",
    ]
    # Not on the LAN while no LAN zone gets IPv6; and with no hook and no
    # `hostname` option, dhcpcd sends no name and writes none of the
    # router's files.
    assert "eth1" not in text


@pytest.mark.skipif(shutil.which("dhcpcd") is None, reason="dhcpcd not installed")
@pytest.mark.parametrize("lan_zones", [[], _DEFAULT])
def test_real_dhcpcd_reads_the_config(minimal_config_dict, tmp_path, lan_zones):
    """dhcpcd has no config check of its own; printing a lease file it
    doesn't have still parses the whole config first, and an unknown
    option is reported there."""
    conf = tmp_path / "dhcpcd6.conf"
    conf.write_text(ipv6.render_dhcpcd_conf(_config(minimal_config_dict, lan_zones=lan_zones)))
    proc = subprocess.run(["dhcpcd", "--config", str(conf), "--dumplease", "eth0"],
                          capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
    # All it may say: that there is no running dhcpcd to ask.
    assert (proc.stdout + proc.stderr).strip() == "dhcpcd is not running"


# --- the kernel's settings ---------------------------------------------------------


def test_the_kernel_takes_no_ra_and_routes_nothing(minimal_config_dict):
    settings = ipv6.sysctl_settings(_router_only(minimal_config_dict))
    assert settings["ipv6/conf/all/forwarding"] == "0"
    for device in ("all", "default", "eth0", "eth1"):
        assert settings[f"ipv6/conf/{device}/accept_ra"] == "0"
        assert settings[f"ipv6/conf/{device}/accept_redirects"] == "0"
        assert settings[f"ipv6/conf/{device}/accept_source_route"] == "0"
        # dhcpcd does the WAN's SLAAC; the kernel does none anywhere.
        assert settings[f"ipv6/conf/{device}/autoconf"] == "0"
    assert settings["ipv6/conf/eth0/disable_ipv6"] == "0"
    assert "ipv6/conf/eth1/disable_ipv6" not in settings
    # What dhcpcd would write itself, on the WAN only: its sandbox keeps
    # /proc/sys read-only.
    assert settings["ipv4/conf/eth0/promote_secondaries"] == "1"
    assert not any(key.startswith("ipv4/") and "/eth0/" not in key for key in settings)


def test_settings_are_written_read_back_and_a_missing_device_is_skipped(proc):
    ipv6.write_sysctls({"ipv6/conf/eth0/accept_ra": "0", "ipv6/conf/eth9/accept_ra": "0",
                        "ipv6/conf/eth1/autoconf": None})
    assert (proc / "ipv6/conf/eth0/accept_ra").read_text() == "0\n"
    assert not (proc / "ipv6/conf/eth9").exists()
    assert (proc / "ipv6/conf/eth1/autoconf").read_text() == "1\n"
    assert ipv6.read_sysctls(["ipv6/conf/eth0/accept_ra", "ipv6/conf/eth9/accept_ra"]) == {
        "ipv6/conf/eth0/accept_ra": "0", "ipv6/conf/eth9/accept_ra": None}


def test_a_setting_that_cant_be_written_is_an_error(proc):
    (proc / "ipv6/conf/eth0/accept_ra").unlink()
    (proc / "ipv6/conf/eth0/accept_ra").mkdir()
    with pytest.raises(ipv6.Ipv6Error, match="net.ipv6.conf.eth0.accept_ra"):
        ipv6.write_sysctls({"ipv6/conf/eth0/accept_ra": "0"})


def test_preflight_needs_kernel_ipv6_and_dhcpcd(proc, tmp_path, monkeypatch):
    monkeypatch.setattr(ipv6, "DNSMASQ_BINARY", str(tmp_path / "no-dnsmasq"))
    binary = tmp_path / "dhcpcd"
    with pytest.raises(ipv6.Ipv6Error, match="is not installed"):
        ipv6.check_available(dhcpcd_binary=str(binary))
    binary.write_text("")
    ipv6.check_available(dhcpcd_binary=str(binary))
    with pytest.raises(ipv6.Ipv6Error, match="ipv6.disable=1"):
        ipv6.check_available(proc_root=tmp_path / "none", dhcpcd_binary=str(binary))


# --- the apply step ----------------------------------------------------------------


def test_off_and_never_on_touches_nothing(minimal_config_dict, systemctl):
    calls, _ = systemctl
    result = ipv6.sync(parse_config(minimal_config_dict))
    assert result.message == "IPv6 off"
    assert calls == []
    assert not paths.IPV6_DHCPCD_CONF_PATH.exists()


def test_on_writes_the_settings_and_config_then_restarts_dhcpcd(minimal_config_dict, proc, systemctl):
    calls, _ = systemctl
    result = ipv6.sync(_router_only(minimal_config_dict))
    assert result.active
    assert "eth0" in result.message and "no LAN zone gets IPv6" in result.message
    assert calls == ["restart"]
    assert paths.IPV6_DHCPCD_CONF_PATH.read_text() == ipv6.render_dhcpcd_conf(_router_only(minimal_config_dict))
    assert not paths.IPV6_RA_CONF_PATH.exists()
    assert (proc / "ipv6/conf/all/accept_ra").read_text() == "0\n"
    assert (proc / "ipv6/conf/eth0/accept_ra").read_text() == "0\n"
    assert (proc / "ipv6/conf/eth1/autoconf").read_text() == "0\n"
    assert (proc / "ipv4/conf/eth0/promote_secondaries").read_text() == "1\n"


def test_an_unchanged_config_doesnt_restart_dhcpcd(minimal_config_dict, proc, systemctl):
    """Every apply runs the step; a restart would drop the WAN's IPv6
    addresses and ask the provider again each time."""
    calls, _ = systemctl
    ipv6.sync(_router_only(minimal_config_dict))
    ipv6.sync(_router_only(minimal_config_dict))
    assert calls == ["restart", "start"]


def test_dry_run_changes_nothing(minimal_config_dict, proc, systemctl):
    calls, _ = systemctl
    assert "dry-run" in ipv6.sync(_config(minimal_config_dict), dry_run=True).message
    assert calls == []
    assert not paths.IPV6_DHCPCD_CONF_PATH.exists()
    assert (proc / "ipv6/conf/eth0/accept_ra").read_text() == "1\n"


def test_turning_it_off_stops_dhcpcd_and_removes_its_config(minimal_config_dict, proc, systemctl):
    calls, state = systemctl
    ipv6.sync(_router_only(minimal_config_dict))
    state["active"] = True
    result = ipv6.sync(_router_only(minimal_config_dict, ipv6={"enabled": False}))
    assert result.message == "IPv6 turned off"
    assert calls == ["restart", "stop"]
    assert not paths.IPV6_DHCPCD_CONF_PATH.exists()


def test_on_without_kernel_ipv6_is_an_error(minimal_config_dict, systemctl):
    with pytest.raises(ipv6.Ipv6Error, match="ipv6.disable=1"):
        ipv6.sync(_config(minimal_config_dict))
    assert systemctl[0] == []


def test_the_apply_runs_the_step_and_undoes_it(minimal_config_dict, proc, systemctl, monkeypatch, tmp_path):
    """frfw.provision's step: the settings it changed are written back
    when a later step fails."""
    from frfw import apply as apply_mod
    from frfw import provision
    from frfw.adblock import AdblockError
    from frfw.adblock import dns_service

    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: None)
    monkeypatch.setattr(apply_mod, "capture_running_ruleset", lambda: "")
    monkeypatch.setattr(ipv6, "check_available", lambda **kwargs: None)

    def fail(*args, **kwargs):
        raise AdblockError("boom")

    monkeypatch.setattr(dns_service, "sync_dns_resolver", fail)
    with pytest.raises(Exception, match="boom"):
        provision.apply_all(_config(minimal_config_dict), backup_dir=tmp_path / "b",
                            kea_config_path=tmp_path / "kea.json", xdp_state_path=tmp_path / "x.json",
                            pqc_conf_path=tmp_path / "pqc.cnf", ssh_kex_dropin_path=tmp_path / "kex.conf",
                            adblock_hosts_path=tmp_path / "h", adblock_dnsmasq_conf_path=tmp_path / "d.conf")
    assert systemctl[0][:2] == ["restart", "restart fr-ra"]
    # Written back as they were: routing off again.
    assert (proc / "ipv6/conf/all/forwarding").read_text() == "0\n"
    assert (proc / "ipv6/conf/eth0/accept_ra").read_text() == "1\n"
    assert (proc / "ipv6/conf/eth1/autoconf").read_text() == "1\n"
    assert (proc / "ipv4/conf/eth0/promote_secondaries").read_text() == "0\n"
    assert (proc / "ipv4/conf/eth1/promote_secondaries").read_text() == "0\n"
    assert not paths.IPV6_DHCPCD_CONF_PATH.exists()
    assert not paths.IPV6_RA_CONF_PATH.exists()


def test_dhcpcds_state_is_expected_on_the_persistence_partition():
    """Its DUID, RFC 7217 secret and leases (security-lessons, SEC-22)."""
    assert "/var/lib/dhcpcd/**" in integrity.PERSISTENCE_EXPECTED


# --- what the provider gave ----------------------------------------------------------


def _addr(device, *addresses):
    return {"ifname": device, "addr_info": [
        {"family": "inet6", "local": a.split("/")[0], "prefixlen": int(a.split("/")[1]),
         "scope": "link" if a.startswith("fe80") else "global"} for a in addresses]}


def _ip(addrs, routes):
    return lambda *args: addrs if args[0] == "addr" else routes


DEFAULT = {"dst": "default", "gateway": "fe80::1", "dev": "eth0", "protocol": "ra"}


def test_status_off_and_without_kernel(minimal_config_dict, tmp_path):
    assert ipv6.status(parse_config(minimal_config_dict)).state == ipv6.OFF
    state = ipv6.status(_config(minimal_config_dict), proc_root=tmp_path / "none")
    assert state.state == ipv6.NO_KERNEL
    assert "without IPv6" in state.summary


def test_status_nothing_from_the_provider(minimal_config_dict, proc, systemctl):
    state = ipv6.status(_router_only(minimal_config_dict), ip_json=_ip([_addr("eth0", "fe80::2/64")], []))
    assert state.state == ipv6.NOTHING
    assert state.addresses == []
    assert "keeps using IPv4" in state.summary


def test_status_address_only(minimal_config_dict, proc, systemctl):
    addrs = [_addr("eth0", "fe80::2/64", "2001:db8:1::5/64", "2001:db8:1::99/128"),
             _addr("eth1", "2001:db8:9::1/64")]  # not the WAN: not counted
    state = ipv6.status(_router_only(minimal_config_dict), ip_json=_ip(addrs, [DEFAULT]))
    assert state.state == ipv6.ADDRESS_ONLY
    assert state.addresses == [("eth0", "2001:db8:1::5/64", "SLAAC"), ("eth0", "2001:db8:1::99/128", "DHCPv6")]
    assert state.default_routes == [("eth0", "fe80::1")]
    assert "no prefix was delegated" in state.summary


def test_status_prefix_delegated(minimal_config_dict, proc, systemctl):
    systemctl[1]["active"] = True
    routes = [
        DEFAULT,
        {"dst": "2001:db8:100::/56", "type": "unreachable", "dev": "lo", "protocol": "dhcp"},
        # Not a delegated prefix: someone else's unreachable route, a /128, link-local.
        {"dst": "2001:db8:200::/48", "type": "unreachable", "dev": "lo", "protocol": "static"},
        {"dst": "2001:db8:300::1", "type": "unreachable", "dev": "lo", "protocol": "dhcp"},
        {"dst": "fe80::/64", "type": "unreachable", "dev": "lo", "protocol": "dhcp"},
    ]
    state = ipv6.status(_router_only(minimal_config_dict),
                        ip_json=_ip([_addr("eth0", "2001:db8:1::5/64")], routes))
    assert state.state == ipv6.PREFIX
    assert state.prefixes == ["2001:db8:100::/56"]
    assert "2001:db8:100::/56 (256 LAN networks)" in state.summary
    assert "only the router uses it" in state.summary
    assert state.as_dict()["service_active"] is True
    assert state.as_dict()["addresses"] == [["eth0", "2001:db8:1::5/64", "SLAAC"]]


@pytest.mark.parametrize("prefix, networks", [("2001:db8::/48", 65536), ("2001:db8::/56", 256),
                                              ("2001:db8::/60", 16), ("2001:db8::/64", 1)])
def test_lan_networks(prefix, networks):
    assert ipv6.lan_networks(prefix) == networks


def test_the_cli_reports_the_state(minimal_config_dict, tmp_path, capsys):
    import yaml

    from frfw.cli import main

    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(minimal_config_dict))
    assert main(["ipv6-status", str(path)]) == 0
    assert capsys.readouterr().out == "IPv6: IPv6 is off.\n"


# --- the ruleset ----------------------------------------------------------------------


def _chain(ruleset: str, name: str) -> list[str]:
    body = ruleset.split(f"chain {name} {{", 1)[1].split("\n\t}", 1)[0]
    return [line.strip() for line in body.splitlines() if line.strip()]


def test_off_drops_all_ipv6_ahead_of_every_service(minimal_config_dict):
    ruleset = build_ruleset(parse_config(minimal_config_dict))
    rules = _chain(ruleset, "input")
    drop = rules.index('meta nfproto ipv6 drop comment "ipv6-off"')
    assert rules[drop - 1] == "ct state invalid drop"
    assert "icmpv6" not in ruleset
    assert _chain(ruleset, "forward")[1] == 'meta nfproto ipv6 drop comment "ipv6-no-routing"'


def test_on_accepts_what_the_wan_needs_and_drops_the_rest(minimal_config_dict):
    minimal_config_dict["management"] = {"zones": ["lan"]}
    ruleset = build_ruleset(_router_only(minimal_config_dict))
    rules = _chain(ruleset, "input")
    wan = 'iifname { "eth0" }'
    expected = [
        f'{wan} icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} ip6 hoplimit 255 accept '
        'comment "ipv6-nd"',
        f'{wan} ip6 saddr fe80::/10 icmpv6 type nd-router-advert ip6 hoplimit 255 accept comment "ipv6-ra"',
        f'{wan} ip6 saddr fe80::/10 icmpv6 type mld-listener-query ip6 hoplimit 1 accept comment "ipv6-mld"',
        f'{wan} icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem }} '
        'accept comment "ipv6-errors"',
        f'{wan} icmpv6 type echo-request limit rate 5/second burst 10 packets accept comment "ipv6-ping"',
        f'{wan} ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept comment "ipv6-dhcpv6-client"',
    ]
    start = rules.index('iifname "lo" accept') + 1
    assert rules[start:start + len(expected)] == expected
    # Ahead of the established accept (ND isn't a tracked connection),
    # and nothing for the LAN.
    assert rules.index("ct state established,related accept") > start + len(expected) - 1
    assert "eth1" not in "\n".join(expected)
    # Everything else to the router goes through the IPv6 chain before any
    # IPv4-era rule (FND-1c), which drops it -- the router alone serves
    # nothing over IPv6.
    jump = rules.index("meta nfproto ipv6 jump ipv6_input")
    assert rules[jump - 1] == "ct state invalid drop"
    assert any("dport" in r for r in rules[jump + 1:])  # the management and service rules come later
    # (The jail's drops on 22/443 are the exception: drops, at the top.)
    assert not any("dport" in r for r in rules[:jump]
                   if "547" not in r and "bruteforce-jail6" not in r and "bruteforce-jail-mac" not in r)
    assert _chain(ruleset, "ipv6_input") == [
        'meta nfproto ipv6 meta pkttype != host drop comment "ipv6-not-for-the-router"',
        'meta nfproto ipv6 limit rate 10/minute burst 10 packets log prefix "fr_os/drop/input: " '
        'comment "log-ipv6-drop"',
        'meta nfproto ipv6 drop comment "ipv6-default-drop"',
    ]
    assert _chain(ruleset, "forward")[1] == 'meta nfproto ipv6 drop comment "ipv6-no-routing"'


def test_on_logs_unicast_drops_only_when_drops_are_logged(minimal_config_dict):
    rules = _chain(build_ruleset(_config(minimal_config_dict, logging={"drops": False})), "ipv6_input")
    assert not any("log-ipv6-drop" in r for r in rules)
    rules = _chain(build_ruleset(_config(minimal_config_dict, logging={"drops": True})), "ipv6_input")
    log = next(i for i, r in enumerate(rules) if "log-ipv6-drop" in r)
    assert "ipv6-not-for-the-router" in rules[log - 1]  # multicast never reaches the log
    assert "ipv6-default-drop" in rules[log + 1]


@requires_nft
@pytest.mark.parametrize("enabled", [False, True])
def test_nft_accepts_the_ruleset(minimal_config_dict, enabled):
    ruleset = build_ruleset(_config(minimal_config_dict, enabled=enabled, logging={"drops": True}))
    proc = subprocess.run(["nft", "-c", "-f", "-"], input=ruleset, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


# --- FND-1b: the LAN ------------------------------------------------------------------


def _three_zones(minimal_config_dict):
    """wan, lan, and a guest zone with a port and a VLAN of its own."""
    minimal_config_dict["interfaces"]["guest"] = {"device": "eth2", "zone": "guest"}
    minimal_config_dict["interfaces"]["guest-vlan"] = {"device": "eth2.40", "zone": "guest",
                                                       "vlan": {"parent": "eth2", "id": 40}}
    minimal_config_dict["zones"]["guest"] = {}
    return minimal_config_dict


def test_every_lan_zone_gets_ipv6_by_default_in_config_order(minimal_config_dict):
    config = _config(_three_zones(minimal_config_dict))
    assert ipv6.lan_devices(config) == [("lan", "eth1"), ("guest", "eth2"), ("guest", "eth2.40")]
    assert ipv6.excluded_zones(config) == []
    # Off: none.
    assert ipv6.lan_devices(_config(minimal_config_dict, enabled=False)) == []


def test_lan_zones_chooses_the_zones_and_their_order(minimal_config_dict):
    config = _config(_three_zones(minimal_config_dict), lan_zones=["guest", "lan"])
    assert ipv6.lan_devices(config) == [("guest", "eth2"), ("guest", "eth2.40"), ("lan", "eth1")]
    assert ipv6.lan_devices(_config(minimal_config_dict, lan_zones=[])) == []


def test_lan_zones_needs_a_zone_with_an_interface(minimal_config_dict):
    """The VPN's zone has the tunnel only: its clients are IPv4-only."""
    minimal_config_dict["zones"]["vpn"] = {}
    minimal_config_dict["wireguard"] = {"enabled": True, "address": "10.99.0.1/24"}
    with pytest.raises(ConfigError, match="no interface"):
        _config(minimal_config_dict, lan_zones=["vpn"])
    # ...and the default leaves such a zone out: nothing to hand it to.
    assert ipv6.lan_devices(_config(minimal_config_dict)) == [("lan", "eth1")]


DROP_BY_ADDRESS = {"name": "no-nas-to-wan", "action": "drop", "from_zone": "lan", "to_zone": "wan",
                   "src_address": "192.168.1.50/32"}


def test_a_drop_rule_by_ipv4_address_keeps_its_zone_off_ipv6(minimal_config_dict):
    """The host blocked by its IPv4 address would reach the same place
    over IPv6: the zone is left out of the default, with the reason, and
    refused in an explicit list."""
    minimal_config_dict["rules"].insert(0, DROP_BY_ADDRESS)
    config = _config(minimal_config_dict)
    assert ipv6.lan_devices(config) == []
    [(zone, why)] = ipv6.excluded_zones(config)
    assert zone == "lan" and "no-nas-to-wan" in why and "src_mac" in why
    with pytest.raises(ConfigError, match="zone 'lan' can't have IPv6: rule 'no-nas-to-wan'"):
        _config(minimal_config_dict, lan_zones=["lan"])


@pytest.mark.parametrize("rule", [
    # An accept by address only opens less over IPv6, never more.
    {**DROP_BY_ADDRESS, "action": "accept"},
    # From the internet: nothing new comes in over IPv6 at all.
    {**DROP_BY_ADDRESS, "from_zone": "wan", "to_zone": "lan", "src_address": "203.0.113.0/24"},
    # To the router: the router drops IPv6 from the LAN ahead of it.
    {**DROP_BY_ADDRESS, "to_zone": "self"},
    # By MAC: the same over both.
    {"name": "no-nas", "action": "drop", "from_zone": "lan", "to_zone": "wan", "src_mac": "aa:bb:cc:dd:ee:ff"},
])
def test_what_ipv6_cant_get_around_keeps_the_zone_on(minimal_config_dict, rule):
    minimal_config_dict["rules"].insert(0, rule)
    assert ipv6.lan_devices(_config(minimal_config_dict)) == [("lan", "eth1")]


def test_a_drop_rule_by_address_without_a_zone_touches_every_lan(minimal_config_dict):
    minimal_config_dict["rules"].insert(0, {**DROP_BY_ADDRESS, "from_zone": None, "to_zone": None,
                                            "dst_address": "198.51.100.0/24", "src_address": None})
    config = _config(_three_zones(minimal_config_dict))
    assert ipv6.lan_devices(config) == []
    assert [zone for zone, _ in ipv6.excluded_zones(config)] == ["lan", "guest"]


def test_the_sni_filter_no_longer_keeps_its_zones_off_ipv6(minimal_config_dict):
    """Until FND-1d the XDP SNI filter read IPv4 only, and its zones were
    kept off IPv6 (a blocked site would have stayed reachable over it).
    It reads IPv6 now: the port and its VLANs get IPv6 like any LAN, and
    an explicit lan_zones may name them."""
    minimal_config_dict["interfaces"]["iot"] = {"device": "eth1.30", "zone": "iot",
                                                "vlan": {"parent": "eth1", "id": 30}}
    minimal_config_dict["zones"]["iot"] = {}
    minimal_config_dict["xdp_sni_filter"] = {"enabled": True, "interfaces": ["lan"], "blocklist": ["x.test"]}
    config = _config(_three_zones(minimal_config_dict))
    assert ("lan", "eth1") in ipv6.lan_devices(config) and ("iot", "eth1.30") in ipv6.lan_devices(config)
    assert ipv6.excluded_zones(config) == []
    assert list(_config(minimal_config_dict, lan_zones=["lan"]).ipv6.lan_zones) == ["lan"]


def test_dhcpcd_hands_a_64_of_the_prefix_to_each_lan_device(minimal_config_dict):
    minimal_config_dict["interfaces"]["wan2"] = {"device": "eth3", "zone": "wan"}
    text = ipv6.render_dhcpcd_conf(_config(_three_zones(minimal_config_dict)))
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    # dhcpcd runs on the LAN devices (it only assigns a prefix to one it
    # runs on), reads no RA there (noipv6rs, global) and asks for nothing.
    assert "allowinterfaces eth0 eth3 eth1 eth2 eth2.40" in lines
    assert lines[lines.index("interface eth0"):] == [
        "interface eth0", "ipv6rs", "ia_na 1",
        # sla_id 0 first: a provider's /64 still serves the first LAN.
        "ia_pd 101 eth1/0/64 eth2/1/64 eth2.40/2/64",
        # A second WAN delegates nowhere: one LAN, one provider's prefix.
        "interface eth3", "ipv6rs", "ia_na 2", "ia_pd 102 -",
    ]
    assert "interface eth1" not in lines


def test_the_kernel_routes_ipv6_once_a_lan_has_it(minimal_config_dict):
    settings = ipv6.sysctl_settings(_config(minimal_config_dict))
    assert settings["ipv6/conf/all/forwarding"] == "1"
    # Still no RA taken anywhere -- a LAN must never configure the router.
    assert settings["ipv6/conf/eth1/accept_ra"] == "0" and settings["ipv6/conf/eth1/autoconf"] == "0"
    assert settings["ipv6/conf/eth1/disable_ipv6"] == "0"
    # dhcpcd runs on the LAN device too, and wants this there as well.
    assert settings["ipv4/conf/eth1/promote_secondaries"] == "1"


def test_router_advertisements_only_slaac_no_dns_no_dhcp(minimal_config_dict):
    text = ipv6.render_ra_conf(_config(_three_zones(minimal_config_dict)))
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert lines == [
        "port=0", "no-resolv", "no-hosts", "pid-file=", "leasefile-ro", "quiet-ra", "enable-ra",
        "interface=eth1", "dhcp-range=::,constructor:eth1,ra-only",
        "interface=eth2", "dhcp-range=::,constructor:eth2,ra-only",
        "interface=eth2.40", "dhcp-range=::,constructor:eth2.40,ra-only",
    ]


@pytest.mark.skipif(shutil.which("dnsmasq") is None, reason="dnsmasq not installed")
def test_real_dnsmasq_accepts_the_ra_config(minimal_config_dict, tmp_path, monkeypatch):
    monkeypatch.setattr(ipv6, "DNSMASQ_BINARY", shutil.which("dnsmasq"))
    ipv6._test_ra_conf(ipv6.render_ra_conf(_config(minimal_config_dict)), tmp_path / "ra.conf")
    with pytest.raises(ipv6.Ipv6Error, match="dnsmasq rejected"):
        ipv6._test_ra_conf("enable-ra\ndhcp-range=::,constructor:eth1,no-such-mode\n", tmp_path / "ra.conf")
    assert not list(tmp_path.iterdir())  # the candidate is gone either way


def test_preflight_needs_dnsmasq_for_the_lan(minimal_config_dict, proc, tmp_path):
    dhcpcd = tmp_path / "dhcpcd"
    dhcpcd.write_text("")
    with pytest.raises(ipv6.Ipv6Error, match="Router Advertisements need it"):
        ipv6.check_available(dhcpcd_binary=str(dhcpcd), dnsmasq_binary=str(tmp_path / "none"),
                             config=_config(minimal_config_dict))
    ipv6.check_available(dhcpcd_binary=str(dhcpcd), dnsmasq_binary=str(tmp_path / "none"),
                         config=_router_only(minimal_config_dict))


def test_on_with_a_lan_starts_the_router_advertisements(minimal_config_dict, proc, systemctl):
    calls, state = systemctl
    config = _config(minimal_config_dict)
    result = ipv6.sync(config)
    assert "the LAN gets a /64 each on eth1" in result.message
    assert calls == ["restart", "restart fr-ra"]
    assert paths.IPV6_RA_CONF_PATH.read_text() == ipv6.render_ra_conf(config)
    assert paths.IPV6_RA_CONF_PATH.stat().st_mode & 0o777 == 0o644  # fr-ra's dynamic account reads it
    assert (proc / "ipv6/conf/all/forwarding").read_text() == "1\n"
    assert (proc / "ipv4/conf/eth1/promote_secondaries").read_text() == "1\n"
    # Unchanged: neither is restarted.
    ipv6.sync(config)
    assert calls[2:] == ["start", "start fr-ra"]
    # The LAN taken off: fr-ra stops, its config goes, dhcpcd gets the new one.
    state["ra_active"] = True
    ipv6.sync(_router_only(minimal_config_dict))
    assert calls[4:] == ["restart", "stop fr-ra"]
    assert not paths.IPV6_RA_CONF_PATH.exists()
    assert (proc / "ipv6/conf/all/forwarding").read_text() == "0\n"


def test_turning_it_off_stops_both_and_routing(minimal_config_dict, proc, systemctl):
    calls, state = systemctl
    ipv6.sync(_config(minimal_config_dict))
    state["active"] = state["ra_active"] = True
    assert ipv6.sync(_config(minimal_config_dict, enabled=False)).message == "IPv6 turned off"
    assert calls[2:] == ["stop fr-ra", "stop"]
    assert not paths.IPV6_RA_CONF_PATH.exists() and not paths.IPV6_DHCPCD_CONF_PATH.exists()
    assert (proc / "ipv6/conf/all/forwarding").read_text() == "0\n"


def test_an_ra_config_dnsmasq_refuses_changes_nothing(minimal_config_dict, proc, systemctl, monkeypatch):
    def refuse(text, path):
        raise ipv6.Ipv6Error("dnsmasq rejected the Router Advertisement config: bad")

    monkeypatch.setattr(ipv6, "_test_ra_conf", refuse)
    with pytest.raises(ipv6.Ipv6Error, match="dnsmasq rejected"):
        ipv6.sync(_config(minimal_config_dict))
    assert systemctl[0] == []
    assert not paths.IPV6_DHCPCD_CONF_PATH.exists()
    assert (proc / "ipv6/conf/all/forwarding").read_text() == "0\n"


UNREACHABLE_56 = {"dst": "2001:db8:100::/56", "type": "unreachable", "dev": "lo", "protocol": "dhcp"}


def test_status_shows_the_lan_networks(minimal_config_dict, proc, systemctl):
    systemctl[1]["ra_active"] = True
    addrs = [_addr("eth0", "2001:db8:1::5/64"), _addr("eth1", "fe80::1/64", "2001:db8:100::1/64"),
             _addr("eth2", "2001:db8:100:1::1/64")]
    state = ipv6.status(_config(_three_zones(minimal_config_dict)), ip_json=_ip(addrs, [DEFAULT, UNREACHABLE_56]))
    assert state.state == ipv6.PREFIX
    assert state.lan == [("lan", "eth1", "2001:db8:100::/64"), ("guest", "eth2", "2001:db8:100:1::/64"),
                         ("guest", "eth2.40", "")]
    assert "The LAN has IPv6: lan (eth1) 2001:db8:100::/64, guest (eth2) 2001:db8:100:1::/64." in state.summary
    assert "No network on guest (eth2.40) yet." in state.summary
    # The LAN's addresses are not the WAN's.
    assert [a for _, a, _ in state.addresses] == ["2001:db8:1::5/64"]
    assert state.as_dict()["ra_active"] is True


def test_status_a_whole_64_delegated_serves_the_first_lan(minimal_config_dict, proc, systemctl):
    """dhcpcd installs no unreachable route for a /64 given whole to the
    first device (sla_id 0); the others can't have one, and are told why."""
    addrs = [_addr("eth0", "2001:db8:1::5/64"), _addr("eth1", "2001:db8:7::1/64")]
    state = ipv6.status(_config(_three_zones(minimal_config_dict)), ip_json=_ip(addrs, [DEFAULT]))
    assert state.state == ipv6.PREFIX and state.prefixes == ["2001:db8:7::/64"]
    assert "the prefix holds 1 LAN network(s) and 3 are needed" in state.summary
    assert "a /56 or /60" in state.summary


def test_status_says_why_a_zone_has_no_ipv6(minimal_config_dict, proc, systemctl):
    minimal_config_dict["rules"].insert(0, DROP_BY_ADDRESS)
    state = ipv6.status(_config(minimal_config_dict), ip_json=_ip([_addr("eth0", "2001:db8:1::5/64")],
                                                                    [DEFAULT, UNREACHABLE_56]))
    assert state.lan == []
    assert "Zone lan gets no IPv6: rule 'no-nas-to-wan' blocks by IPv4 address" in state.summary


def test_the_cli_lists_the_lan(minimal_config_dict, proc, systemctl, monkeypatch, tmp_path, capsys):
    import yaml

    from frfw.cli import main

    minimal_config_dict["ipv6"] = {"enabled": True}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(minimal_config_dict))
    monkeypatch.setattr(ipv6, "_ip_json", _ip([_addr("eth1", "2001:db8:100::1/64")], [UNREACHABLE_56]))
    assert main(["ipv6-status", str(path)]) == 0
    out = capsys.readouterr().out
    assert "  LAN lan (eth1): 2001:db8:100::/64\n" in out
    assert "  Router Advertisements (fr-ra): not running\n" in out


# --- FND-1b: the ruleset -----------------------------------------------------------


def test_the_lan_may_ask_the_router_for_its_ra_and_ping_it(minimal_config_dict):
    rules = _chain(build_ruleset(_config(minimal_config_dict)), "input")
    lan = 'iifname { "eth1" }'
    start = rules.index('iifname "lo" accept') + 7  # after the WAN's six
    assert rules[start:start + 2] == [
        f'{lan} icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit }} ip6 hoplimit 255 '
        'accept comment "ipv6-lan-nd"',
        f'{lan} icmpv6 type echo-request limit rate 5/second burst 10 packets accept comment "ipv6-lan-ping"',
    ]
    # No RA from the LAN, and every other IPv6 packet to the router goes
    # through the IPv6 chain ahead of the services (FND-1c).
    assert not any("nd-router-advert" in r and "eth1" in r for r in rules)
    assert rules.index("meta nfproto ipv6 jump ipv6_input") < next(
        i for i, r in enumerate(rules) if "dport" in r and "547" not in r and "bruteforce-jail" not in r)


def test_ipv6_is_routed_only_between_the_wan_and_the_lan_zones(minimal_config_dict):
    _three_zones(minimal_config_dict)
    minimal_config_dict["zones"]["lab"] = {}
    minimal_config_dict["interfaces"]["lab"] = {"device": "eth4", "zone": "lab"}
    rules = _chain(build_ruleset(_config(minimal_config_dict, lan_zones=["lan", "guest"])), "forward")
    routed = '{ "eth0", "eth1", "eth2", "eth2.40" }'
    assert rules[1:4] == [
        f'meta nfproto ipv6 iifname != {routed} drop comment "ipv6-not-routed-here"',
        f'meta nfproto ipv6 oifname != {routed} drop comment "ipv6-not-routed-here"',
        # BCP 38: a LAN host sends only from an address routed back to it.
        'meta nfproto ipv6 iifname { "eth1", "eth2", "eth2.40" } fib saddr . iif oif missing drop '
        'comment "ipv6-lan-spoofed"',
    ]
    assert "ipv6-no-routing" not in "\n".join(rules)


def test_nothing_new_comes_in_from_the_internet_over_ipv6(minimal_config_dict):
    """Not even what an admin rule written next to a port forward allows:
    over IPv6 it would open the port on every host of the zone."""
    minimal_config_dict["rules"].append({"name": "wan-to-lan-https", "action": "accept", "from_zone": "wan",
                                         "to_zone": "lan", "proto": "tcp", "dst_port": 443})
    rules = _chain(build_ruleset(_config(minimal_config_dict, logging={"drops": True})), "forward")
    inbound = rules.index('meta nfproto ipv6 iifname { "eth0" } drop comment "ipv6-no-inbound"')
    assert rules[inbound - 2] == "ct state invalid drop"
    assert "log-ipv6-inbound" in rules[inbound - 1]
    assert inbound < next(i for i, r in enumerate(rules) if "rule:wan-to-lan-https" in r)
    assert inbound < next(i for i, r in enumerate(rules) if "rule:lan-to-wan" in r)


def test_router_only_routes_nothing(minimal_config_dict):
    rules = _chain(build_ruleset(_router_only(minimal_config_dict)), "forward")
    assert rules[1] == 'meta nfproto ipv6 drop comment "ipv6-no-routing"'
    assert not any("ipv6-no-inbound" in r or "fib" in r for r in rules)


def test_force_dns_redirects_plain_dns_over_ipv6_too(dhcp_config_dict):
    """FND-1c: the resolver serves IPv6, so plain DNS from the LAN over
    IPv6 is redirected to it as over IPv4 -- not refused any more (1b)."""
    dhcp_config_dict["adblocker"] = {"enabled": True, "serve_lan": True, "force_dns": True,
                                     "source_urls": ["https://lists.example/hosts"]}
    ruleset = build_ruleset(_config(dhcp_config_dict))
    forward = _chain(ruleset, "forward")
    prerouting = _chain(ruleset, "prerouting")
    for family in ("ipv4", "ipv6"):
        for proto in ("udp", "tcp"):
            assert (f'meta nfproto {family} iifname @lan_ifaces {proto} dport 53 redirect to :53 '
                    'comment "force-dns"') in prerouting
    assert "force-dns-ipv6" not in ruleset
    # DoT/DoQ were already refused for both.
    assert 'iifname @lan_ifaces tcp dport 853 reject comment "force-dns-block-dot"' in forward
    # Router only: no LAN zone has IPv6, nothing to redirect.
    assert "meta nfproto ipv6 iifname @lan_ifaces" not in build_ruleset(_router_only(dhcp_config_dict))


def test_a_quarantined_host_is_held_by_its_mac_over_ipv6(minimal_config_dict):
    from frfw.nft.builder import RuntimeSets

    ruleset = build_ruleset(_config(minimal_config_dict),
                            runtime=RuntimeSets(ids_quarantine_mac=(("aa:bb:cc:dd:ee:01", 600),
                                                                    ("aa:bb:cc:dd:ee:02", 0),
                                                                    ("not-a-mac", 600))))
    assert ("\tset ids_quarantine_mac {\n\t\ttype ether_addr\n\t\tflags timeout\n"
            "\t\telements = { aa:bb:cc:dd:ee:01 timeout 600s }\n\t}") in ruleset
    forward = _chain(ruleset, "forward")
    rule = forward.index('meta nfproto ipv6 ether saddr @ids_quarantine_mac drop comment "ids-quarantine-ipv6"')
    assert rule < forward.index("ct state established,related accept")


@pytest.mark.parametrize("proto, match", [("tcp", "meta l4proto tcp"), ("udp", "meta l4proto udp"),
                                          ("icmp", "meta l4proto { icmp, ipv6-icmp }")])
def test_a_rule_by_protocol_matches_ipv6_too(minimal_config_dict, proto, match):
    """`ip protocol` matched IPv4 only: "drop udp from lan" would have let
    IPv6 through."""
    minimal_config_dict["rules"].insert(0, {"name": "no-proto", "action": "drop", "from_zone": "lan",
                                            "to_zone": "wan", "proto": proto})
    rule = next(r for r in _chain(build_ruleset(_config(minimal_config_dict)), "forward") if "rule:no-proto" in r)
    assert f"oifname @wan_ifaces {match} counter drop" in rule


@requires_nft
@pytest.mark.parametrize("logging", [True, False])
def test_nft_accepts_the_lan_ruleset(dhcp_config_dict, logging):
    from frfw.nft.builder import RuntimeSets

    _three_zones(dhcp_config_dict)
    dhcp_config_dict["adblocker"] = {"enabled": True, "serve_lan": True, "force_dns": True,
                                     "source_urls": ["https://lists.example/hosts"]}
    dhcp_config_dict["rules"].append({"name": "icmp-out", "action": "accept", "from_zone": "guest",
                                      "to_zone": "wan", "proto": "icmp"})
    ruleset = build_ruleset(_config(dhcp_config_dict, logging={"drops": logging}),
                            runtime=RuntimeSets(ids_quarantine_mac=(("aa:bb:cc:dd:ee:01", 600),)))
    proc = subprocess.run(["nft", "-c", "-f", "-"], input=ruleset, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
