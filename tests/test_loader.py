import copy

import pytest

from frfw.config import ConfigError, load_config, parse_config
from frfw.config.schema import SELF_ZONE, Action, Protocol


def test_parses_example_config(example_config_path):
    config = load_config(example_config_path)
    assert config.hostname == "fr-router"
    assert set(config.interfaces) == {"wan", "lan", "dmz"}
    assert config.interfaces["wan"].device == "eth0"
    assert config.interfaces["wan"].zone == "wan"
    assert len(config.rules) == 5
    assert config.nat.masquerade[0].out_zone == "wan"
    assert config.nat.port_forwards[0].to_address == "10.0.2.10"


def test_missing_file_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "does-not-exist.yaml")


def test_minimal_config_round_trips(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    assert config.rules[0].action == Action.ACCEPT
    assert config.rules[0].proto == Protocol.ANY


@pytest.mark.parametrize(
    "mutate,expected_message_fragment",
    [
        (lambda d: d.pop("hostname"), "hostname"),
        (lambda d: d.update(version=2), "version"),
        (lambda d: d["interfaces"]["wan"].update(zone="nonexistent"), "undefined zone"),
        (lambda d: d["interfaces"]["lan"].update(device="eth0"), "assigned to both"),
        (
            lambda d: d["rules"].append({"name": "bad", "action": "nope"}),
            "invalid action",
        ),
        (
            lambda d: d["rules"].append(
                {"name": "bad-port", "action": "accept", "proto": "tcp", "dst_port": 70000}
            ),
            "out of range",
        ),
        (
            lambda d: d["rules"].append(
                {"name": "bad-proto-port", "action": "accept", "proto": "icmp", "dst_port": 53}
            ),
            "requires proto tcp or udp",
        ),
        (
            lambda d: d.update(zones={**d["zones"], "unused": {}}),
            "not used by any interface",
        ),
        (
            lambda d: d["nat"].update(
                port_forwards=[
                    {
                        "name": "bad-fwd",
                        "in_zone": "wan",
                        "proto": "tcp",
                        "dst_port": 443,
                        "to_address": "not-an-ip",
                    }
                ]
            ),
            "invalid IPv4 address",
        ),
    ],
)
def test_invalid_configs_raise_config_error(minimal_config_dict, mutate, expected_message_fragment):
    broken = copy.deepcopy(minimal_config_dict)
    mutate(broken)
    with pytest.raises(ConfigError, match=expected_message_fragment):
        parse_config(broken)


def test_self_zone_cannot_be_declared(minimal_config_dict):
    broken = copy.deepcopy(minimal_config_dict)
    broken["zones"][SELF_ZONE] = {}
    with pytest.raises(ConfigError, match="reserved"):
        parse_config(broken)


def test_duplicate_rule_names_rejected(minimal_config_dict):
    broken = copy.deepcopy(minimal_config_dict)
    broken["rules"].append(dict(broken["rules"][0]))
    with pytest.raises(ConfigError, match="Duplicate rule name"):
        parse_config(broken)
