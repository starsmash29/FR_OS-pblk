import os
from pathlib import Path

import pytest

from frfw.netdetect import list_interfaces


@pytest.fixture
def net_dir(tmp_path) -> Path:
    net = tmp_path / "class_net"
    net.mkdir()
    return net


def _make_iface(
    net_dir: Path,
    name: str,
    *,
    address: str | None = None,
    carrier: int | None = None,
    speed: int | None = None,
    driver: str | None = None,
) -> None:
    # Support scaffolding (fake driver/device dirs) lives as a *sibling* of
    # net_dir, not inside it -- list_interfaces() treats every entry of
    # net_dir as an interface, so nesting scaffolding there would make it
    # show up as a bogus interface too.
    support_dir = net_dir.parent / "sys_support"

    iface_dir = net_dir / name
    iface_dir.mkdir()
    if address is not None:
        (iface_dir / "address").write_text(address + "\n")
    if carrier is not None:
        (iface_dir / "carrier").write_text(f"{carrier}\n")
    if speed is not None:
        (iface_dir / "speed").write_text(f"{speed}\n")
    if driver is not None:
        driver_dir = support_dir / "drivers" / driver
        driver_dir.mkdir(parents=True, exist_ok=True)
        device_dir = support_dir / "devices" / name
        device_dir.mkdir(parents=True, exist_ok=True)
        os.symlink(driver_dir, device_dir / "driver")
        os.symlink(device_dir, iface_dir / "device")


def test_list_interfaces_reads_expected_fields(net_dir):
    _make_iface(net_dir, "lo")
    _make_iface(
        net_dir, "eth0", address="aa:bb:cc:dd:ee:ff", carrier=1, speed=1000, driver="e1000e"
    )
    _make_iface(net_dir, "wlan0", address="11:22:33:44:55:66", carrier=0)
    _make_iface(net_dir, "docker0", address="02:00:00:00:00:01", carrier=1)

    interfaces = list_interfaces(net_dir)

    assert [i.name for i in interfaces] == ["eth0", "wlan0"]

    eth0 = interfaces[0]
    assert eth0.mac_address == "aa:bb:cc:dd:ee:ff"
    assert eth0.driver == "e1000e"
    assert eth0.link_up is True
    assert eth0.speed_mbps == 1000

    wlan0 = interfaces[1]
    assert wlan0.driver is None
    assert wlan0.link_up is False
    assert wlan0.speed_mbps is None


def test_include_virtual_shows_lo_and_docker(net_dir):
    _make_iface(net_dir, "lo")
    _make_iface(net_dir, "docker0")

    interfaces = list_interfaces(net_dir, include_virtual=True)
    assert {i.name for i in interfaces} == {"lo", "docker0"}


def test_missing_sysfs_dir_returns_empty_list(net_dir):
    assert list_interfaces(net_dir / "does-not-exist") == []


def test_negative_speed_treated_as_unknown(net_dir):
    _make_iface(net_dir, "eth1", speed=-1)
    interfaces = list_interfaces(net_dir)
    assert interfaces[0].speed_mbps is None


def test_missing_carrier_file_is_unknown_not_down(net_dir):
    _make_iface(net_dir, "eth2")
    interfaces = list_interfaces(net_dir)
    assert interfaces[0].link_up is None
