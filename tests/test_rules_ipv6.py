"""Address rules over IPv6 (ROADMAP FND-1d): `src_address`/`dst_address`
take networks of either family, one or a list, and a rule is rendered
once per family it names (`ip saddr` / `ip6 saddr`). A drop rule by IPv4
address only still keeps its zone off IPv6 (FND-1b); one that names the
IPv6 networks too doesn't. The rendered rules are checked against the
real `nft` where it is installed."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from frfw import ipv6, rule_lint, surface
from frfw.config import ConfigError, parse_config
from frfw.nft.builder import build_ruleset

requires_nft = pytest.mark.skipif(shutil.which("nft") is None, reason="nft binary not installed")


def _config(raw, *rules, ipv6_on=True, **ipv6_extra):
    raw["rules"] = [*rules, *raw["rules"]]
    if ipv6_on:
        raw["ipv6"] = {"enabled": True, **ipv6_extra}
    return parse_config(raw)


def _lines(config, name):
    return [line.strip() for line in build_ruleset(config).splitlines() if f'"rule:{name}"' in line]


def _drop(name="no-nas", **kw):
    return {"name": name, "action": "drop", "from_zone": "lan", "to_zone": "wan", **kw}


def test_one_network_or_a_list_of_either_family(minimal_config_dict):
    config = _config(minimal_config_dict, _drop(src_address=["10.0.0.5", "2001:DB8:5::/48", "10.0.0.5/32"],
                                                dst_address="198.51.100.7/24"), ipv6_on=False)
    rule = config.rules[0]
    # Normalized, without repeats, in the order given.
    assert rule.src_address == ("10.0.0.5/32", "2001:db8:5::/48")
    assert rule.dst_address == ("198.51.100.0/24",)
    assert rule.families == {4}


@pytest.mark.parametrize("value, match", [
    ([], "empty list"),
    (["10.0.0.0/24", 5], "expected an address/network string"),
    ("2001:db8::zz", "invalid IPv4 or IPv6"),
    ("fe80::1%eth1", "invalid IPv4 or IPv6"),
])
def test_bad_addresses_are_refused(minimal_config_dict, value, match):
    with pytest.raises(ConfigError, match=match):
        _config(minimal_config_dict, _drop(src_address=value), ipv6_on=False)


def test_a_rule_whose_fields_share_no_family_is_refused(minimal_config_dict):
    """IPv4 sources to IPv6 destinations: it could never match."""
    with pytest.raises(ConfigError, match="no address family in common"):
        _config(minimal_config_dict, _drop(src_address="10.0.0.5", dst_address="2001:db8::/32"), ipv6_on=False)


def test_a_mixed_rule_is_rendered_once_per_family(minimal_config_dict):
    config = _config(minimal_config_dict, _drop(src_address=["10.0.0.5/32", "10.0.0.6/32", "2001:db8:5::/48"]))
    assert _lines(config, "no-nas") == [
        'iifname @lan_ifaces oifname @wan_ifaces ip saddr { 10.0.0.5/32, 10.0.0.6/32 } counter drop '
        'comment "rule:no-nas"',
        'iifname @lan_ifaces oifname @wan_ifaces ip6 saddr 2001:db8:5::/48 counter drop comment "rule:no-nas"',
    ]


def test_each_family_line_has_only_that_familys_networks(minimal_config_dict):
    """A family the source names but the destination doesn't gets no line."""
    config = _config(minimal_config_dict, _drop(src_address=["10.0.0.0/24", "2001:db8:5::/48"],
                                                dst_address="198.51.100.0/24"))
    assert _lines(config, "no-nas") == [
        'iifname @lan_ifaces oifname @wan_ifaces ip saddr 10.0.0.0/24 ip daddr 198.51.100.0/24 counter drop '
        'comment "rule:no-nas"',
    ]
    assert config.rules[0].families == {4} and config.rules[0].ipv4_addresses_only


def test_a_ztna_rule_by_ipv6_address_needs_an_ipv6_sign_in(minimal_config_dict):
    minimal_config_dict["ztna"] = {"enabled": True, "users": [{"username": "a", "password_hash": "x"}]}
    config = _config(minimal_config_dict, {"name": "gated", "action": "accept", "from_zone": "lan",
                                           "to_zone": "wan", "dst_address": "2001:db8:9::/48",
                                           "require_ztna": True})
    lines = _lines(config, "gated")
    assert len(lines) == 2
    assert "ip6 saddr . ether saddr @authenticated_ztna_users6 ip6 daddr 2001:db8:9::/48" in lines[0]
    assert 'iifname "wg0" ip6 saddr @authenticated_ztna_tunnel6 ip6 daddr 2001:db8:9::/48' in lines[1]


@requires_nft
def test_the_rendered_rules_load(minimal_config_dict):
    minimal_config_dict["ztna"] = {"enabled": True, "users": [{"username": "a", "password_hash": "x"}]}
    config = _config(minimal_config_dict,
                     _drop(src_address=["10.0.0.5/32", "2001:db8:5::/48", "fd00:1::/64"]),
                     _drop("to-v6", dst_address="2001:db8:9::1"),
                     {"name": "gated", "action": "accept", "from_zone": "lan", "to_zone": "self",
                      "proto": "tcp", "dst_port": 8443, "src_address": ["10.0.0.0/24", "fd00:1::/64"],
                      "require_ztna": True})
    proc = subprocess.run(["nft", "-c", "-f", "-"], input=build_ruleset(config), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_a_drop_rule_naming_ipv6_too_leaves_its_zone_its_ipv6(minimal_config_dict):
    """The admin covered the other family: the zone keeps IPv6, and may be
    listed. By IPv4 only, it is still kept off (FND-1b), and the reason
    says how to cover IPv6."""
    config = _config(minimal_config_dict, _drop(src_address=["192.168.1.50/32", "2001:db8:1::50/128"]),
                     lan_zones=["lan"])
    assert ipv6.lan_devices(config) == [("lan", "eth1")]
    minimal_config_dict["rules"] = minimal_config_dict["rules"][1:]
    config = _config(minimal_config_dict, _drop(src_address="192.168.1.50/32"))
    [(zone, why)] = ipv6.excluded_zones(config)
    assert zone == "lan" and "IPv4 address only" in why and "src_mac" in why and "IPv6 networks" in why


def test_management_over_ipv6_takes_a_rule_that_names_ipv6_too(minimal_config_dict):
    raw = dict(minimal_config_dict, management={"ipv6": True})
    config = _config(raw, {"name": "no-admin", "action": "drop", "from_zone": "lan", "to_zone": "self",
                           "proto": "tcp", "dst_port": 443, "src_address": ["192.168.1.66/32", "fd00:1::66"]})
    assert config.management.ipv6
    raw["rules"] = raw["rules"][1:]
    raw["rules"][0] = {**raw["rules"][0]}
    with pytest.raises(ConfigError, match="IPv4 address only"):
        _config(raw, {"name": "no-admin", "action": "drop", "from_zone": "lan", "to_zone": "self",
                      "proto": "tcp", "dst_port": 443, "src_address": "192.168.1.66/32"})


def test_a_drop_rule_by_ipv6_address_is_taken_to_meet_a_pinhole(minimal_config_dict):
    """A pinhole's host has whatever address its prefix gives it, so a
    drop from the internet by IPv6 address to its zone is a conflict (by
    IPv4 address it never matches IPv6)."""
    pinhole = {"name": "nas-https", "zone": "lan", "proto": "tcp", "port": 443, "host": "::f00d:1"}
    rule = {"name": "no-bad-net", "action": "drop", "from_zone": "wan", "to_zone": "lan",
            "src_address": "2001:db8:bad::/48"}
    with pytest.raises(ConfigError, match="no-bad-net"):
        _config(minimal_config_dict, rule, pinholes=[pinhole])


def test_the_surface_reads_a_rule_by_family(minimal_config_dict):
    config = _config(minimal_config_dict, {"name": "admin-v6", "action": "accept", "from_zone": "wan",
                                           "to_zone": "self", "proto": "tcp", "dst_port": 8443,
                                           "src_address": "2001:db8:a::/48"})
    rule = config.rules[0]
    assert surface._rule_matches(rule, "wan", "tcp", 8443, 6)
    assert not surface._rule_matches(rule, "wan", "tcp", 8443, 4)
    assert surface._conditions(rule) == ["from 2001:db8:a::/48"]


def test_the_rule_check_compares_lists_of_both_families(minimal_config_dict):
    config = _config(minimal_config_dict,
                     _drop("wide", src_address=["10.0.0.0/24", "2001:db8:1::/48"]),
                     _drop("narrow", src_address=["10.0.0.5", "2001:db8:1:2::/64"]),
                     _drop("other", src_address=["10.0.0.5", "2001:db8:2::/64"]), ipv6_on=False)
    wide, narrow, other = config.rules[:3]
    assert rule_lint.covers(wide, narrow)
    assert not rule_lint.covers(wide, other)
    assert not rule_lint.covers(narrow, wide)


# -- an IPv6 scope is text of anyone's choosing (security-lessons F1) ---------------------

#: Python's ipaddress takes whatever follows a `%` as the scope, and
#: str() gives it back: into the nft script, unchecked, until FND-1d.
SCOPED = 'fe80::1%x" ; flush ruleset ; #'


@pytest.mark.parametrize("key, value", [
    ("rule", SCOPED),
    ("rule", "2001:db8::%eth1/64"),
    ("pinhole-host", "::5%a } accept"),
    ("pinhole-from", "2001:db8:42::%x/48"),
    ("ula", "fd12:3456:789a::%x/48"),
])
def test_a_scoped_ipv6_address_is_refused_everywhere_in_the_config(minimal_config_dict, key, value):
    pinhole = {"name": "nas", "zone": "lan", "proto": "tcp", "port": 443, "host": "::f00d:1"}
    extra = {}
    rules = []
    if key == "rule":
        rules = [_drop(src_address=value)]
    elif key == "pinhole-host":
        extra["pinholes"] = [{**pinhole, "host": value}]
    elif key == "pinhole-from":
        extra["pinholes"] = [{**pinhole, "from": value}]
    else:
        extra["ula_prefix"] = value
    with pytest.raises(ConfigError):
        _config(minimal_config_dict, *rules, **extra)


def test_validate_and_the_privileged_paths_refuse_a_scope():
    from frfw import bruteforce, ids_quarantine, validate
    with pytest.raises(validate.ArgumentError):
        validate.ipv6("fe80::1%eth1")
    with pytest.raises(ids_quarantine.IdsQuarantineError, match="no scope"):
        ids_quarantine.check_target(SCOPED)
    with pytest.raises(ValueError):
        bruteforce.jail_key(SCOPED)
    with pytest.raises(bruteforce.BruteforceError):
        bruteforce.ban_ip(SCOPED, 60)
