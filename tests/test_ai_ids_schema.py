import copy

import pytest

from frfw.config import ConfigError, parse_config


def test_ai_ids_defaults_when_absent(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    assert config.ai_ids.enabled is False
    assert config.ai_ids.learning_days == 7
    assert config.ai_ids.retrain_time == "03:30"
    assert config.ai_ids.excluded_macs == []


def test_ai_ids_round_trips(minimal_config_dict):
    minimal_config_dict["ai_ids"] = {
        "enabled": True,
        "learning_days": 3,
        "retrain_time": "23:59",
        "excluded_macs": ["AA:BB:CC:DD:EE:FF"],
    }
    config = parse_config(minimal_config_dict)
    assert config.ai_ids.enabled is True
    assert config.ai_ids.learning_days == 3
    assert config.ai_ids.retrain_time == "23:59"
    assert config.ai_ids.excluded_macs == ["aa:bb:cc:dd:ee:ff"]  # normalized lowercase


@pytest.mark.parametrize(
    "mutate,expected_message_fragment",
    [
        (lambda d: d["ai_ids"].update(enabled="yes"), "boolean"),
        (lambda d: d["ai_ids"].update(learning_days=0), "positive integer"),
        (lambda d: d["ai_ids"].update(learning_days=True), "positive integer"),
        (lambda d: d["ai_ids"].update(learning_days="7"), "positive integer"),
        (lambda d: d["ai_ids"].update(retrain_time="3:30"), "HH:MM"),
        (lambda d: d["ai_ids"].update(retrain_time="25:00"), "HH:MM"),
        (lambda d: d["ai_ids"].update(retrain_time="03:60"), "HH:MM"),
        (lambda d: d["ai_ids"].update(excluded_macs="aa:bb:cc:dd:ee:ff"), "must be a list"),
        (lambda d: d["ai_ids"].update(excluded_macs=["not-a-mac"]), "invalid MAC address"),
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
