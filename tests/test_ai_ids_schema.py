import copy

import pytest

from frfw.config import ConfigError, parse_config


def test_ai_ids_defaults_when_absent(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    assert config.ai_ids.enabled is False
    assert config.ai_ids.excluded_macs == []
    assert config.ai_ids.quarantine_duration_seconds == 2 * 3600


def test_ai_ids_round_trips(minimal_config_dict):
    minimal_config_dict["ai_ids"] = {
        "enabled": True,
        "excluded_macs": ["AA:BB:CC:DD:EE:FF"],
        "quarantine_duration_seconds": 900,
    }
    config = parse_config(minimal_config_dict)
    assert config.ai_ids.enabled is True
    assert config.ai_ids.excluded_macs == ["aa:bb:cc:dd:ee:ff"]  # normalized lowercase
    assert config.ai_ids.quarantine_duration_seconds == 900


@pytest.mark.parametrize(
    "mutate,expected_message_fragment",
    [
        (lambda d: d["ai_ids"].update(enabled="yes"), "boolean"),
        (lambda d: d["ai_ids"].update(excluded_macs="aa:bb:cc:dd:ee:ff"), "must be a list"),
        (lambda d: d["ai_ids"].update(excluded_macs=["not-a-mac"]), "invalid MAC address"),
        (lambda d: d["ai_ids"].update(quarantine_duration_seconds=0), "positive integer"),
        (lambda d: d["ai_ids"].update(quarantine_duration_seconds=-1), "positive integer"),
        (lambda d: d["ai_ids"].update(quarantine_duration_seconds=True), "positive integer"),
        (lambda d: d["ai_ids"].update(quarantine_duration_seconds="3600"), "positive integer"),
        (lambda d: d.update(ai_ids="not-a-mapping"), "must be a mapping"),
    ],
)
def test_invalid_ai_ids_configs_raise_config_error(
    minimal_config_dict, mutate, expected_message_fragment
):
    broken = copy.deepcopy(minimal_config_dict)
    broken["ai_ids"] = {}
    mutate(broken)
    with pytest.raises(ConfigError, match=expected_message_fragment):
        parse_config(broken)
