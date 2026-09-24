from __future__ import annotations

import pytest

from frfw.config import ConfigError, parse_config


def test_xdp_sni_filter_defaults_when_absent(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    assert config.xdp_sni_filter.enabled is False
    assert config.xdp_sni_filter.interfaces == []
    assert config.xdp_sni_filter.blocklist == []


def test_xdp_sni_filter_round_trips(minimal_config_dict):
    minimal_config_dict["xdp_sni_filter"] = {
        "enabled": True,
        "interfaces": ["wan"],
        "blocklist": ["Ads.Example.com", "tracker.example.net"],
    }
    config = parse_config(minimal_config_dict)
    assert config.xdp_sni_filter.enabled is True
    assert config.xdp_sni_filter.interfaces == ["wan"]
    # lowercased, matching the kernel program's case-sensitive byte match
    assert config.xdp_sni_filter.blocklist == ["ads.example.com", "tracker.example.net"]


def test_xdp_sni_filter_rejects_non_mapping(minimal_config_dict):
    minimal_config_dict["xdp_sni_filter"] = "nope"
    with pytest.raises(ConfigError, match="mapping"):
        parse_config(minimal_config_dict)


def test_xdp_sni_filter_rejects_non_bool_enabled(minimal_config_dict):
    minimal_config_dict["xdp_sni_filter"] = {"enabled": "yes"}
    with pytest.raises(ConfigError, match="boolean"):
        parse_config(minimal_config_dict)


def test_xdp_sni_filter_rejects_unknown_interface(minimal_config_dict):
    minimal_config_dict["xdp_sni_filter"] = {"enabled": True, "interfaces": ["dmz"]}
    with pytest.raises(ConfigError, match="not a defined interface"):
        parse_config(minimal_config_dict)


def test_xdp_sni_filter_enabled_requires_interfaces(minimal_config_dict):
    minimal_config_dict["xdp_sni_filter"] = {"enabled": True, "interfaces": []}
    with pytest.raises(ConfigError, match="interfaces is empty"):
        parse_config(minimal_config_dict)


def test_xdp_sni_filter_rejects_invalid_hostname(minimal_config_dict):
    minimal_config_dict["xdp_sni_filter"] = {"blocklist": ["not a hostname!"]}
    with pytest.raises(ConfigError, match="invalid hostname"):
        parse_config(minimal_config_dict)


def test_xdp_sni_filter_rejects_hostname_too_long_for_kernel_program(minimal_config_dict):
    # MAX_SNI_LEN in bpf/xdp_sni_filter.c is 32; this is 32 bytes exactly,
    # which the kernel program's own `sni_len >= MAX_SNI_LEN` check
    # already refuses to ever match (fails open instead), so rejecting it
    # here gives an immediate, clear error instead of a silently
    # never-matching blocklist entry.
    too_long = "a" * 28 + ".com"  # 32 bytes
    assert len(too_long) == 32
    minimal_config_dict["xdp_sni_filter"] = {"blocklist": [too_long]}
    with pytest.raises(ConfigError, match="must be under 32"):
        parse_config(minimal_config_dict)


def test_xdp_sni_filter_accepts_hostname_just_under_the_limit(minimal_config_dict):
    just_fits = "a" * 27 + ".com"  # 31 bytes
    assert len(just_fits) == 31
    minimal_config_dict["xdp_sni_filter"] = {"blocklist": [just_fits]}
    config = parse_config(minimal_config_dict)
    assert config.xdp_sni_filter.blocklist == [just_fits]
