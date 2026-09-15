import shutil
import subprocess

import pytest

from frfw.config import parse_config
from frfw.nft import build_ruleset

requires_nft = pytest.mark.skipif(shutil.which("nft") is None, reason="nft binary not installed")


def test_build_ruleset_contains_expected_rules(example_config_path):
    from frfw.config import load_config

    config = load_config(example_config_path)
    ruleset = build_ruleset(config)

    assert "table inet fr_os" in ruleset
    assert 'set wan_ifaces' in ruleset
    assert 'elements = { "eth0" }' in ruleset
    assert "policy drop;" in ruleset  # input/forward default-deny
    assert 'iifname @lan_ifaces tcp dport 22 accept comment "rule:allow-ssh-from-lan-to-router"' in ruleset
    assert "oifname @wan_ifaces masquerade" in ruleset
    assert "dnat ip to 10.0.2.10:443" in ruleset


def test_self_zone_rule_goes_to_input_not_forward(minimal_config_dict):
    minimal_config_dict["rules"].append(
        {"name": "ssh-to-router", "action": "accept", "from_zone": "lan", "to_zone": "self", "proto": "tcp", "dst_port": 22}
    )
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)

    input_chain = ruleset.split("chain input {")[1].split("chain forward {")[0]
    forward_chain = ruleset.split("chain forward {")[1]

    assert "dport 22" in input_chain
    assert "oifname" not in input_chain.split("dport 22")[0].split("\n")[-1]
    assert "dport 22" not in forward_chain


@requires_nft
def test_generated_ruleset_passes_nft_syntax_check(example_config_path):
    from frfw.config import load_config

    config = load_config(example_config_path)
    ruleset = build_ruleset(config)

    proc = subprocess.run(
        ["nft", "-c", "-f", "-"], input=ruleset, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr


@requires_nft
def test_minimal_ruleset_passes_nft_syntax_check(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)

    proc = subprocess.run(
        ["nft", "-c", "-f", "-"], input=ruleset, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr


def test_ztna_set_only_rendered_when_enabled(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    assert "authenticated_ztna_users" not in build_ruleset(config)

    minimal_config_dict["ztna"] = {"enabled": True, "users": [{"username": "a", "password_hash": "x"}]}
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)
    assert "set authenticated_ztna_users" in ruleset
    assert "flags dynamic,timeout" in ruleset
    assert "timeout 28800s" in ruleset  # default 8h


def test_ztna_set_uses_configured_ttl(minimal_config_dict):
    minimal_config_dict["ztna"] = {
        "enabled": True,
        "session_ttl_seconds": 900,
        "users": [{"username": "a", "password_hash": "x"}],
    }
    config = parse_config(minimal_config_dict)
    assert "timeout 900s" in build_ruleset(config)


def test_require_ztna_rule_adds_saddr_match(minimal_config_dict):
    minimal_config_dict["ztna"] = {"enabled": True, "users": [{"username": "a", "password_hash": "x"}]}
    minimal_config_dict["rules"].append(
        {
            "name": "gated",
            "action": "accept",
            "from_zone": "lan",
            "to_zone": "wan",
            "require_ztna": True,
        }
    )
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)

    gated_line = next(line for line in ruleset.splitlines() if "rule:gated" in line)
    assert "ip saddr @authenticated_ztna_users" in gated_line


def test_rule_without_require_ztna_has_no_saddr_match(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)
    rule_line = next(line for line in ruleset.splitlines() if "rule:lan-to-wan" in line)
    assert "authenticated_ztna_users" not in rule_line


def test_bruteforce_jail_set_always_rendered(minimal_config_dict):
    # Unlike the ZTNA set (conditional on config), the jail set is a
    # kernel-level defense that must exist regardless of what the user
    # configured -- there is no "off" switch for brute-force protection.
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)

    assert "set bruteforce_jail {" in ruleset
    assert "type ipv4_addr" in ruleset
    assert "flags timeout" in ruleset


def test_bruteforce_jail_drop_rule_is_first_rule_in_input_chain(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)

    input_chain = ruleset.split("chain input {")[1].split("chain forward {")[0]
    rule_lines = [
        line.strip()
        for line in input_chain.splitlines()
        if line.strip() and not line.strip().startswith(("policy", "type", "hook", "}"))
    ]

    assert rule_lines[0] == 'ip saddr @bruteforce_jail drop comment "bruteforce-jail"'
    assert rule_lines[1] == 'ip saddr @ids_quarantine drop comment "ids-quarantine"'
    # Must come before even the loopback accept, which is otherwise the
    # first rule in the chain.
    assert rule_lines[2] == 'iifname "lo" accept'


def test_ids_quarantine_set_always_rendered(minimal_config_dict):
    # Like the brute-force jail (and unlike the ZTNA set), the IDS
    # quarantine set is a kernel-level defense with no "off" switch --
    # it must exist regardless of whether ai_ids.enabled, since a
    # detection engine turned off later should not silently amnesty
    # already-quarantined hosts (see frfw.provision's own comment).
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)

    assert "set ids_quarantine {" in ruleset
    assert "type ipv4_addr" in ruleset
    assert "flags timeout" in ruleset


@requires_nft
def test_ztna_enabled_ruleset_passes_nft_syntax_check(minimal_config_dict):
    minimal_config_dict["ztna"] = {"enabled": True, "users": [{"username": "a", "password_hash": "x"}]}
    minimal_config_dict["rules"].append(
        {
            "name": "gated",
            "action": "accept",
            "from_zone": "lan",
            "to_zone": "wan",
            "require_ztna": True,
        }
    )
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)

    proc = subprocess.run(
        ["nft", "-c", "-f", "-"], input=ruleset, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
