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
