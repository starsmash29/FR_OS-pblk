"""Validation tests for the phase-3 additions to the config schema:
Interface.address and the `dhcp` section (frfw.config.loader._parse_dhcp)."""

import copy

import pytest

from frfw.config import ConfigError, parse_config


def test_interface_address_round_trips(minimal_config_dict):
    minimal_config_dict["interfaces"]["lan"]["address"] = "10.0.0.1/24"
    config = parse_config(minimal_config_dict)
    assert config.interfaces["lan"].address == "10.0.0.1/24"
    assert config.interfaces["wan"].address is None


def test_interface_address_without_prefix_defaults_to_slash_32(minimal_config_dict):
    # ipaddress.IPv4Interface treats a bare address as an implicit /32 --
    # syntactically valid, if a degenerate choice for a real subnet (a
    # DHCP pool on such a zone would then fail subnet validation instead).
    minimal_config_dict["interfaces"]["lan"]["address"] = "10.0.0.1"
    config = parse_config(minimal_config_dict)
    assert config.interfaces["lan"].address == "10.0.0.1/32"


def test_interface_address_garbage_rejected(minimal_config_dict):
    minimal_config_dict["interfaces"]["lan"]["address"] = "not-an-address/24"
    with pytest.raises(ConfigError, match="prefix length"):
        parse_config(minimal_config_dict)


def test_dhcp_pool_round_trips(dhcp_config_dict):
    config = parse_config(dhcp_config_dict)
    pool = config.dhcp.zones["lan"]
    assert pool.range_start == "10.0.0.100"
    assert pool.range_end == "10.0.0.200"
    assert pool.dns_servers == ["1.1.1.1"]
    assert pool.lease_time == 3600
    assert pool.reservations[0].mac_address == "aa:bb:cc:dd:ee:ff"
    assert pool.reservations[0].address == "10.0.0.50"


def test_dhcp_mac_is_lowercased(dhcp_config_dict):
    dhcp_config_dict["dhcp"]["lan"]["reservations"][0]["mac"] = "AA:BB:CC:DD:EE:FF"
    config = parse_config(dhcp_config_dict)
    assert config.dhcp.zones["lan"].reservations[0].mac_address == "aa:bb:cc:dd:ee:ff"


@pytest.mark.parametrize(
    "mutate,expected_message_fragment",
    [
        (lambda d: d["dhcp"].update(wan={"range_start": "1", "range_end": "2", "dns_servers": ["1.1.1.1"]}), "needs a static"),
        (lambda d: d["dhcp"]["lan"].update(range_start="10.0.1.100"), "not inside subnet"),
        (lambda d: d["dhcp"]["lan"].update(range_start="10.0.0.200", range_end="10.0.0.100"), "must not be after"),
        (lambda d: d["dhcp"]["lan"].update(range_start="10.0.0.1"), "gateway address"),
        (lambda d: d["dhcp"]["lan"].update(dns_servers=[]), "non-empty list"),
        (lambda d: d["dhcp"]["lan"].update(dns_servers=["not-an-ip"]), "invalid IPv4 address"),
        (lambda d: d["dhcp"]["lan"].update(lease_time=0), "positive integer"),
        (
            lambda d: d["dhcp"]["lan"]["reservations"].append(
                {"mac": "not-a-mac", "address": "10.0.0.60"}
            ),
            "invalid MAC address",
        ),
        (
            lambda d: d["dhcp"]["lan"]["reservations"].append(
                {"mac": "aa:bb:cc:dd:ee:ff", "address": "10.0.0.60"}
            ),
            "duplicate MAC",
        ),
        (
            lambda d: d["dhcp"]["lan"]["reservations"].append(
                {"mac": "11:22:33:44:55:66", "address": "10.0.0.50"}
            ),
            "duplicate address",
        ),
        (lambda d: d["dhcp"].update(unknown_zone={}), "undefined zone"),
    ],
)
def test_invalid_dhcp_configs_raise_config_error(
    dhcp_config_dict, mutate, expected_message_fragment
):
    broken = copy.deepcopy(dhcp_config_dict)
    mutate(broken)
    with pytest.raises(ConfigError, match=expected_message_fragment):
        parse_config(broken)


def test_dhcp_requires_single_interface_in_zone(dhcp_config_dict):
    broken = copy.deepcopy(dhcp_config_dict)
    broken["interfaces"]["lan2"] = {"device": "eth9", "zone": "lan"}
    with pytest.raises(ConfigError, match="exactly one interface"):
        parse_config(broken)


def test_dhcp_reservation_outside_range_but_in_subnet_is_allowed(dhcp_config_dict):
    dhcp_config_dict["dhcp"]["lan"]["reservations"].append(
        {"mac": "11:22:33:44:55:66", "address": "10.0.0.5"}
    )
    config = parse_config(dhcp_config_dict)
    assert len(config.dhcp.zones["lan"].reservations) == 2
