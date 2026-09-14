import yaml

from frfw.config import parse_config
from frfw.skeleton import build_skeleton_config


def test_skeleton_with_opt_zone_is_valid_and_complete():
    text = build_skeleton_config("eth0", "eth1", {"dmz": "eth2"}, hostname="myrouter")
    config = parse_config(yaml.safe_load(text))

    assert config.hostname == "myrouter"
    assert config.interfaces["wan"].device == "eth0"
    assert config.interfaces["wan"].zone == "wan"
    assert config.interfaces["lan"].device == "eth1"
    assert config.interfaces["dmz"].device == "eth2"
    assert config.interfaces["dmz"].zone == "dmz"
    assert {r.name for r in config.rules} == {"allow-mgmt-from-lan", "lan-to-wan"}
    assert config.nat.masquerade[0].out_zone == "wan"


def test_skeleton_without_opt_zones():
    text = build_skeleton_config("eth0", "eth1")
    config = parse_config(yaml.safe_load(text))
    assert set(config.interfaces) == {"wan", "lan"}
    assert set(config.zones) == {"wan", "lan"}


def test_skeleton_default_rules_do_not_expose_anything_from_wan():
    text = build_skeleton_config("eth0", "eth1")
    config = parse_config(yaml.safe_load(text))
    assert all(rule.from_zone != "wan" for rule in config.rules)
