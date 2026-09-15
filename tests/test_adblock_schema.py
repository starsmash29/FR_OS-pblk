from __future__ import annotations

import pytest

from frfw.config import ConfigError, parse_config


def test_adblocker_defaults_when_absent(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    assert config.adblocker.enabled is False
    assert config.adblocker.source_urls == []
    assert config.adblocker.xdp_critical_limit == 0


def test_adblocker_round_trips(minimal_config_dict):
    minimal_config_dict["adblocker"] = {
        "enabled": True,
        "source_urls": ["https://example.com/hosts"],
        "xdp_critical_limit": 50,
    }
    config = parse_config(minimal_config_dict)
    assert config.adblocker.enabled is True
    assert config.adblocker.source_urls == ["https://example.com/hosts"]
    assert config.adblocker.xdp_critical_limit == 50


def test_adblocker_rejects_non_mapping(minimal_config_dict):
    minimal_config_dict["adblocker"] = "nope"
    with pytest.raises(ConfigError, match="mapping"):
        parse_config(minimal_config_dict)


def test_adblocker_rejects_non_bool_enabled(minimal_config_dict):
    minimal_config_dict["adblocker"] = {"enabled": "yes"}
    with pytest.raises(ConfigError, match="boolean"):
        parse_config(minimal_config_dict)


def test_adblocker_rejects_non_list_source_urls(minimal_config_dict):
    minimal_config_dict["adblocker"] = {"source_urls": "https://example.com/hosts"}
    with pytest.raises(ConfigError, match="list"):
        parse_config(minimal_config_dict)


@pytest.mark.parametrize("url", ["not-a-url", "ftp://example.com/hosts", ""])
def test_adblocker_rejects_invalid_url(minimal_config_dict, url):
    minimal_config_dict["adblocker"] = {"source_urls": [url]}
    with pytest.raises(ConfigError, match="invalid URL"):
        parse_config(minimal_config_dict)


def test_adblocker_enabled_requires_at_least_one_source_url(minimal_config_dict):
    minimal_config_dict["adblocker"] = {"enabled": True, "source_urls": []}
    with pytest.raises(ConfigError, match="source_urls is empty"):
        parse_config(minimal_config_dict)


def test_adblocker_rejects_non_int_xdp_critical_limit(minimal_config_dict):
    minimal_config_dict["adblocker"] = {"xdp_critical_limit": "50"}
    with pytest.raises(ConfigError, match="integer"):
        parse_config(minimal_config_dict)


def test_adblocker_rejects_bool_xdp_critical_limit(minimal_config_dict):
    # isinstance(True, int) is True in Python -- must be explicitly excluded,
    # same as every other numeric field in this loader.
    minimal_config_dict["adblocker"] = {"xdp_critical_limit": True}
    with pytest.raises(ConfigError, match="integer"):
        parse_config(minimal_config_dict)


def test_adblocker_rejects_negative_xdp_critical_limit(minimal_config_dict):
    minimal_config_dict["adblocker"] = {"xdp_critical_limit": -1}
    with pytest.raises(ConfigError, match=">= 0"):
        parse_config(minimal_config_dict)


def test_adblocker_accepts_zero_xdp_critical_limit(minimal_config_dict):
    minimal_config_dict["adblocker"] = {"xdp_critical_limit": 0}
    config = parse_config(minimal_config_dict)
    assert config.adblocker.xdp_critical_limit == 0
