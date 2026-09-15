from __future__ import annotations

import pytest

from frfw.config import ConfigError, parse_config


def test_ztna_defaults_when_absent(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    assert config.ztna.enabled is False
    assert config.ztna.session_ttl_seconds == 8 * 3600
    assert config.ztna.users == []


def test_ztna_round_trips(minimal_config_dict):
    minimal_config_dict["ztna"] = {
        "enabled": True,
        "session_ttl_seconds": 3600,
        "users": [{"username": "alice", "password_hash": "pbkdf2_sha256$1$deadbeef$cafebabe"}],
    }
    config = parse_config(minimal_config_dict)
    assert config.ztna.enabled is True
    assert config.ztna.session_ttl_seconds == 3600
    assert config.ztna.users[0].username == "alice"
    assert config.ztna.users[0].password_hash == "pbkdf2_sha256$1$deadbeef$cafebabe"


def test_ztna_rejects_non_mapping(minimal_config_dict):
    minimal_config_dict["ztna"] = "nope"
    with pytest.raises(ConfigError, match="mapping"):
        parse_config(minimal_config_dict)


def test_ztna_rejects_non_bool_enabled(minimal_config_dict):
    minimal_config_dict["ztna"] = {"enabled": "yes"}
    with pytest.raises(ConfigError, match="boolean"):
        parse_config(minimal_config_dict)


@pytest.mark.parametrize("ttl", [0, 59, 30 * 24 * 3600 + 1, -100])
def test_ztna_rejects_out_of_range_ttl(minimal_config_dict, ttl):
    minimal_config_dict["ztna"] = {"session_ttl_seconds": ttl}
    with pytest.raises(ConfigError, match="session_ttl_seconds"):
        parse_config(minimal_config_dict)


@pytest.mark.parametrize("ttl", [60, 3600, 30 * 24 * 3600])
def test_ztna_accepts_boundary_ttl(minimal_config_dict, ttl):
    minimal_config_dict["ztna"] = {"session_ttl_seconds": ttl}
    config = parse_config(minimal_config_dict)
    assert config.ztna.session_ttl_seconds == ttl


def test_ztna_enabled_requires_at_least_one_user(minimal_config_dict):
    minimal_config_dict["ztna"] = {"enabled": True, "users": []}
    with pytest.raises(ConfigError, match="no users"):
        parse_config(minimal_config_dict)


def test_ztna_rejects_duplicate_usernames(minimal_config_dict):
    minimal_config_dict["ztna"] = {
        "users": [
            {"username": "alice", "password_hash": "x"},
            {"username": "alice", "password_hash": "y"},
        ]
    }
    with pytest.raises(ConfigError, match="duplicate username"):
        parse_config(minimal_config_dict)


def test_ztna_rejects_invalid_username(minimal_config_dict):
    minimal_config_dict["ztna"] = {"users": [{"username": "bad user!", "password_hash": "x"}]}
    with pytest.raises(ConfigError, match="invalid username"):
        parse_config(minimal_config_dict)


def test_ztna_rejects_missing_password_hash(minimal_config_dict):
    minimal_config_dict["ztna"] = {"users": [{"username": "alice"}]}
    with pytest.raises(ConfigError, match="password_hash"):
        parse_config(minimal_config_dict)


def test_rule_require_ztna_defaults_false(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    assert all(r.require_ztna is False for r in config.rules)


def test_rule_require_ztna_round_trips(minimal_config_dict):
    minimal_config_dict["rules"].append(
        {
            "name": "servers-need-ztna",
            "action": "accept",
            "from_zone": "lan",
            "to_zone": "wan",
            "require_ztna": True,
        }
    )
    config = parse_config(minimal_config_dict)
    gated = [r for r in config.rules if r.name == "servers-need-ztna"]
    assert gated[0].require_ztna is True
