"""IPv6 on the WAN, for the router itself (ROADMAP FND-1a).

The config, dhcpcd's generated config, the kernel settings written to a
fake /proc/sys/net/ipv6 tree, the apply step, the status read from `ip`'s
JSON for every outcome a provider can give, and the ruleset: what the
WAN needs is accepted, every other IPv6 packet is dropped ahead of the
rules written for IPv4, and nothing is routed. The real thing -- a
provider with RA, DHCPv6 and prefix delegation -- runs in the boot test
(installer/qemu-boot-test.py).
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from frfw import integrity, ipv6, paths
from frfw.config import ConfigError, parse_config
from frfw.nft.builder import build_ruleset

requires_nft = pytest.mark.skipif(shutil.which("nft") is None, reason="nft binary not installed")


def _config(minimal_config_dict, enabled=True, **extra):
    raw = dict(minimal_config_dict)
    raw["ipv6"] = {"enabled": enabled}
    raw.update(extra)
    return parse_config(raw)


@pytest.fixture
def proc(monkeypatch, tmp_path):
    """A /proc/sys/net with eth0 and eth1, every value as a fresh kernel
    has it: RAs accepted, forwarding off."""
    root = tmp_path / "proc_sys_net"
    for device in ("all", "default", "eth0", "eth1"):
        conf = root / "ipv6" / "conf" / device
        conf.mkdir(parents=True)
        for key, value in (("accept_ra", "1"), ("accept_redirects", "1"), ("accept_source_route", "0"),
                           ("autoconf", "1"), ("disable_ipv6", "0"), ("forwarding", "0")):
            (conf / key).write_text(value + "\n")
        (root / "ipv4" / "conf" / device).mkdir(parents=True)
        (root / "ipv4" / "conf" / device / "promote_secondaries").write_text("0\n")
    monkeypatch.setattr(ipv6, "PROC_NET", root)
    return root


@pytest.fixture
def systemctl(monkeypatch):
    """What was asked of fr-dhcp6, and whether it runs."""
    calls: list[str] = []
    state = {"active": False}
    monkeypatch.setattr(ipv6, "_systemctl", calls.append)
    monkeypatch.setattr(ipv6, "service_active", lambda: state["active"])
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
    text = ipv6.render_dhcpcd_conf(_config(minimal_config_dict))
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
    # Never on the LAN; and with no hook and no `hostname` option, dhcpcd
    # sends no name and writes none of the router's files.
    assert "eth1" not in text


@pytest.mark.skipif(shutil.which("dhcpcd") is None, reason="dhcpcd not installed")
def test_real_dhcpcd_reads_the_config(minimal_config_dict, tmp_path):
    """dhcpcd has no config check of its own; printing a lease file it
    doesn't have still parses the whole config first, and an unknown
    option is reported there."""
    conf = tmp_path / "dhcpcd6.conf"
    conf.write_text(ipv6.render_dhcpcd_conf(_config(minimal_config_dict)))
    proc = subprocess.run(["dhcpcd", "--config", str(conf), "--dumplease", "eth0"],
                          capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
    # All it may say: that there is no running dhcpcd to ask.
    assert (proc.stdout + proc.stderr).strip() == "dhcpcd is not running"


# --- the kernel's settings ---------------------------------------------------------


def test_the_kernel_takes_no_ra_and_routes_nothing(minimal_config_dict):
    settings = ipv6.sysctl_settings(_config(minimal_config_dict))
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


def test_preflight_needs_kernel_ipv6_and_dhcpcd(proc, tmp_path):
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
    result = ipv6.sync(_config(minimal_config_dict))
    assert result.active
    assert "eth0" in result.message
    assert calls == ["restart"]
    assert paths.IPV6_DHCPCD_CONF_PATH.read_text() == ipv6.render_dhcpcd_conf(_config(minimal_config_dict))
    assert (proc / "ipv6/conf/all/accept_ra").read_text() == "0\n"
    assert (proc / "ipv6/conf/eth0/accept_ra").read_text() == "0\n"
    assert (proc / "ipv6/conf/eth1/autoconf").read_text() == "0\n"
    assert (proc / "ipv4/conf/eth0/promote_secondaries").read_text() == "1\n"


def test_an_unchanged_config_doesnt_restart_dhcpcd(minimal_config_dict, proc, systemctl):
    """Every apply runs the step; a restart would drop the WAN's IPv6
    addresses and ask the provider again each time."""
    calls, _ = systemctl
    ipv6.sync(_config(minimal_config_dict))
    ipv6.sync(_config(minimal_config_dict))
    assert calls == ["restart", "start"]


def test_dry_run_changes_nothing(minimal_config_dict, proc, systemctl):
    calls, _ = systemctl
    assert "dry-run" in ipv6.sync(_config(minimal_config_dict), dry_run=True).message
    assert calls == []
    assert not paths.IPV6_DHCPCD_CONF_PATH.exists()
    assert (proc / "ipv6/conf/eth0/accept_ra").read_text() == "1\n"


def test_turning_it_off_stops_dhcpcd_and_removes_its_config(minimal_config_dict, proc, systemctl):
    calls, state = systemctl
    ipv6.sync(_config(minimal_config_dict))
    state["active"] = True
    result = ipv6.sync(_config(minimal_config_dict, enabled=False))
    assert result.message == "IPv6 on the WAN turned off"
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
    monkeypatch.setattr(ipv6, "check_available", lambda: None)

    def fail(*args, **kwargs):
        raise AdblockError("boom")

    monkeypatch.setattr(dns_service, "sync_dns_resolver", fail)
    with pytest.raises(Exception, match="boom"):
        provision.apply_all(_config(minimal_config_dict), backup_dir=tmp_path / "b",
                            kea_config_path=tmp_path / "kea.json", xdp_state_path=tmp_path / "x.json",
                            pqc_conf_path=tmp_path / "pqc.cnf", ssh_kex_dropin_path=tmp_path / "kex.conf",
                            adblock_hosts_path=tmp_path / "h", adblock_dnsmasq_conf_path=tmp_path / "d.conf")
    assert systemctl[0][0] == "restart"
    # Written back as they were.
    assert (proc / "ipv6/conf/eth0/accept_ra").read_text() == "1\n"
    assert (proc / "ipv6/conf/eth1/autoconf").read_text() == "1\n"
    assert (proc / "ipv4/conf/eth0/promote_secondaries").read_text() == "0\n"
    assert not paths.IPV6_DHCPCD_CONF_PATH.exists()


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
    state = ipv6.status(_config(minimal_config_dict), ip_json=_ip([_addr("eth0", "fe80::2/64")], []))
    assert state.state == ipv6.NOTHING
    assert state.addresses == []
    assert "keeps using IPv4" in state.summary


def test_status_address_only(minimal_config_dict, proc, systemctl):
    addrs = [_addr("eth0", "fe80::2/64", "2001:db8:1::5/64", "2001:db8:1::99/128"),
             _addr("eth1", "2001:db8:9::1/64")]  # not the WAN: not counted
    state = ipv6.status(_config(minimal_config_dict), ip_json=_ip(addrs, [DEFAULT]))
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
    state = ipv6.status(_config(minimal_config_dict),
                        ip_json=_ip([_addr("eth0", "2001:db8:1::5/64")], routes))
    assert state.state == ipv6.PREFIX
    assert state.prefixes == ["2001:db8:100::/56"]
    assert "2001:db8:100::/56 (256 LAN networks)" in state.summary
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
    ruleset = build_ruleset(_config(minimal_config_dict))
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
    # Everything else to the router: dropped before any IPv4-era rule.
    drop = rules.index('meta nfproto ipv6 drop comment "ipv6-default-drop"')
    assert rules[drop - 1].startswith("meta nfproto ipv6 limit rate") or \
        rules[drop - 1] == 'meta nfproto ipv6 meta pkttype != host drop comment "ipv6-not-for-the-router"'
    assert rules.index("ct state invalid drop") < drop
    after = rules[drop + 1:]
    assert any("dport" in r for r in after)  # the management and service rules come later
    assert not any("dport" in r for r in rules[:drop] if "547" not in r)
    assert _chain(ruleset, "forward")[1] == 'meta nfproto ipv6 drop comment "ipv6-no-routing"'


def test_on_logs_unicast_drops_only_when_drops_are_logged(minimal_config_dict):
    rules = _chain(build_ruleset(_config(minimal_config_dict, logging={"drops": False})), "input")
    assert not any("log-ipv6-drop" in r for r in rules)
    rules = _chain(build_ruleset(_config(minimal_config_dict, logging={"drops": True})), "input")
    log = next(i for i, r in enumerate(rules) if "log-ipv6-drop" in r)
    assert "ipv6-not-for-the-router" in rules[log - 1]  # multicast never reaches the log
    assert "ipv6-default-drop" in rules[log + 1]


@requires_nft
@pytest.mark.parametrize("enabled", [False, True])
def test_nft_accepts_the_ruleset(minimal_config_dict, enabled):
    ruleset = build_ruleset(_config(minimal_config_dict, enabled=enabled, logging={"drops": True}))
    proc = subprocess.run(["nft", "-c", "-f", "-"], input=ruleset, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
