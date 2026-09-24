"""Config validation for the `iot` section (phase 14)."""

from __future__ import annotations

import pytest

from frfw.config import ConfigError, parse_config
from frfw.config.schema import IotIsolationMode


def _with_iot(base: dict, **iot) -> dict:
    cfg = dict(base)
    cfg["iot"] = iot
    return cfg


def test_iot_defaults_to_disabled(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    assert config.iot.enabled is False
    assert config.iot.zones == []
    assert config.iot.auto_isolate is False
    assert config.iot.isolation_mode == IotIsolationMode.INTERNET_ONLY


def test_iot_full_section_parses_and_normalizes_macs(minimal_config_dict):
    config = parse_config(
        _with_iot(
            minimal_config_dict,
            enabled=True,
            zones=["lan", "lan"],
            auto_isolate=True,
            isolation_mode="block",
            trusted_macs=["AA:BB:CC:DD:EE:01"],
            isolated_macs=["aa:bb:cc:dd:ee:02", "AA:BB:CC:DD:EE:02"],
        )
    )
    assert config.iot.zones == ["lan"]
    assert config.iot.isolation_mode == IotIsolationMode.BLOCK
    assert config.iot.trusted_macs == ["aa:bb:cc:dd:ee:01"]
    assert config.iot.isolated_macs == ["aa:bb:cc:dd:ee:02"]


def test_enabled_requires_at_least_one_zone(minimal_config_dict):
    with pytest.raises(ConfigError, match="iot.zones is empty"):
        parse_config(_with_iot(minimal_config_dict, enabled=True, zones=[]))


def test_unknown_zone_rejected(minimal_config_dict):
    with pytest.raises(ConfigError, match="undefined zone 'dmz'"):
        parse_config(_with_iot(minimal_config_dict, enabled=True, zones=["dmz"]))


def test_internet_facing_zone_rejected(minimal_config_dict):
    with pytest.raises(ConfigError, match="internet-facing"):
        parse_config(_with_iot(minimal_config_dict, enabled=True, zones=["wan"]))


def test_invalid_isolation_mode_rejected(minimal_config_dict):
    with pytest.raises(ConfigError, match="isolation_mode"):
        parse_config(_with_iot(minimal_config_dict, enabled=True, zones=["lan"], isolation_mode="vlan"))


def test_internet_only_needs_a_masquerade_zone(minimal_config_dict):
    minimal_config_dict["nat"] = {}
    with pytest.raises(ConfigError, match="needs at least one nat.masquerade"):
        parse_config(_with_iot(minimal_config_dict, enabled=True, zones=["lan"]))


def test_block_mode_works_without_masquerade(minimal_config_dict):
    minimal_config_dict["nat"] = {}
    config = parse_config(_with_iot(minimal_config_dict, enabled=True, zones=["lan"], isolation_mode="block"))
    assert config.iot.enabled


def test_invalid_mac_rejected(minimal_config_dict):
    with pytest.raises(ConfigError, match=r"iot.trusted_macs\[0\]: invalid MAC"):
        parse_config(_with_iot(minimal_config_dict, trusted_macs=["not-a-mac"]))


def test_mac_both_trusted_and_isolated_rejected(minimal_config_dict):
    with pytest.raises(ConfigError, match="both trusted and isolated"):
        parse_config(
            _with_iot(
                minimal_config_dict,
                trusted_macs=["aa:bb:cc:dd:ee:01"],
                isolated_macs=["AA:BB:CC:DD:EE:01"],
            )
        )


def test_non_boolean_flags_rejected(minimal_config_dict):
    with pytest.raises(ConfigError, match="iot.enabled must be a boolean"):
        parse_config(_with_iot(minimal_config_dict, enabled="yes"))
    with pytest.raises(ConfigError, match="iot.auto_isolate must be a boolean"):
        parse_config(_with_iot(minimal_config_dict, auto_isolate=1))
