"""Tests for frfw.kea. Uses the real `kea-dhcp4 -t` config tester where
available -- it validates that listed interfaces actually exist on the
machine running the check, which is why `dhcp_config_dict` (conftest.py)
uses "lo" as the LAN device rather than a made-up name like "eth1"."""

from __future__ import annotations

import shutil

import pytest

from frfw.config import parse_config
from frfw.kea import KeaError, apply_dhcp_config, build_kea_config, render_kea_config

requires_kea = pytest.mark.skipif(
    shutil.which("kea-dhcp4") is None, reason="kea-dhcp4 binary not installed"
)


def test_build_kea_config_structure(dhcp_config_dict):
    config = parse_config(dhcp_config_dict)
    kea_config = build_kea_config(config)

    dhcp4 = kea_config["Dhcp4"]
    assert dhcp4["interfaces-config"]["interfaces"] == ["lo"]
    subnet = dhcp4["subnet4"][0]
    assert subnet["subnet"] == "10.0.0.0/24"
    assert subnet["pools"] == [{"pool": "10.0.0.100 - 10.0.0.200"}]
    option_names = {o["name"]: o["data"] for o in subnet["option-data"]}
    assert option_names["routers"] == "10.0.0.1"
    assert option_names["domain-name-servers"] == "1.1.1.1"
    assert subnet["reservations"] == [
        {"hw-address": "aa:bb:cc:dd:ee:ff", "ip-address": "10.0.0.50", "hostname": "nas"}
    ]


def test_build_kea_config_omits_hostname_when_absent(dhcp_config_dict):
    dhcp_config_dict["dhcp"]["lan"]["reservations"][0].pop("hostname")
    config = parse_config(dhcp_config_dict)
    reservation = build_kea_config(config)["Dhcp4"]["subnet4"][0]["reservations"][0]
    assert "hostname" not in reservation


def test_no_dhcp_zones_is_a_noop(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    result = apply_dhcp_config(config)
    assert not result.applied
    assert "No DHCP zones" in result.message


@requires_kea
def test_render_kea_config_passes_real_syntax_check(dhcp_config_dict):
    config = parse_config(dhcp_config_dict)
    text = render_kea_config(config)
    from frfw.kea import check_syntax

    check_syntax(text)  # raises KeaError on failure


@requires_kea
def test_dry_run_apply_validates_without_writing(dhcp_config_dict, tmp_path):
    config = parse_config(dhcp_config_dict)
    kea_path = tmp_path / "kea-dhcp4.conf"

    result = apply_dhcp_config(config, dry_run=True, config_path=kea_path)

    assert not result.applied
    assert not kea_path.exists()


@requires_kea
def test_syntax_check_rejects_nonexistent_interface(minimal_config_dict):
    import dataclasses

    from frfw.config.schema import DhcpConfig, DhcpPool

    # Real (nonexistent-on-this-box) "eth1" device, bypassing the
    # dhcp_config_dict fixture's "lo" substitution, to prove check_syntax
    # actually calls the real validator rather than a stub.
    minimal_config_dict["interfaces"]["lan"]["address"] = "10.0.0.1/24"
    config = parse_config(minimal_config_dict)
    config = dataclasses.replace(
        config,
        dhcp=DhcpConfig(
            zones={
                "lan": DhcpPool(
                    zone="lan",
                    range_start="10.0.0.100",
                    range_end="10.0.0.200",
                    dns_servers=["1.1.1.1"],
                )
            }
        ),
    )
    with pytest.raises(KeaError, match="eth1"):
        apply_dhcp_config(config, dry_run=True)
