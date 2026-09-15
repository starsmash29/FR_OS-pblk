from __future__ import annotations

import pytest

from frfw.config import ConfigError, parse_config


def test_pqc_defaults_when_absent(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    assert config.pqc.enabled is False


def test_pqc_round_trips(minimal_config_dict):
    minimal_config_dict["pqc"] = {"enabled": True}
    config = parse_config(minimal_config_dict)
    assert config.pqc.enabled is True


def test_pqc_rejects_non_mapping(minimal_config_dict):
    minimal_config_dict["pqc"] = "nope"
    with pytest.raises(ConfigError, match="mapping"):
        parse_config(minimal_config_dict)


def test_pqc_rejects_non_bool_enabled(minimal_config_dict):
    minimal_config_dict["pqc"] = {"enabled": "yes"}
    with pytest.raises(ConfigError, match="boolean"):
        parse_config(minimal_config_dict)
