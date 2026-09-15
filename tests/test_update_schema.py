from __future__ import annotations

import pytest

from frfw.config import ConfigError, parse_config


def test_update_defaults_when_absent(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    assert config.update.repo == ""


def test_update_repo_round_trips(minimal_config_dict):
    minimal_config_dict["update"] = {"repo": "someone/fork"}
    config = parse_config(minimal_config_dict)
    assert config.update.repo == "someone/fork"


def test_update_rejects_non_mapping(minimal_config_dict):
    minimal_config_dict["update"] = "nope"
    with pytest.raises(ConfigError, match="mapping"):
        parse_config(minimal_config_dict)


def test_update_rejects_non_string_repo(minimal_config_dict):
    minimal_config_dict["update"] = {"repo": 123}
    with pytest.raises(ConfigError, match="string"):
        parse_config(minimal_config_dict)
