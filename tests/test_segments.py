"""Security-lessons K4: segmentation by default.

- an interface can be a VLAN on another device; apply creates it;
- `add_segments` gives the router IoT and guest segments that reach the
  internet and nothing else -- not the LAN, not the router's management;
- new installs have IoT isolation on.

The VLAN device itself is created for real in the QEMU boot test (this
sandbox's kernel has no 802.1Q support); here the `ip` calls are checked.
"""

from __future__ import annotations

import subprocess

import pytest
import yaml

from frfw import ifaddr, management, segments, skeleton
from frfw.config import ConfigError, parse_config
from frfw.nft import build_ruleset


def _raw() -> dict:
    return yaml.safe_load(skeleton.build_skeleton_config("eth0", "eth1"))


def test_a_vlan_interface():
    raw = _raw()
    raw["zones"]["cams"] = {}
    raw["interfaces"]["cams"] = {"device": "eth1.30", "zone": "cams", "address": "192.168.30.1/24",
                                 "vlan": {"parent": "eth1", "id": 30}}
    iface = parse_config(raw).interfaces["cams"]
    assert (iface.vlan_parent, iface.vlan_id) == ("eth1", 30)


@pytest.mark.parametrize("vlan, error", [
    ({"parent": "eth1", "id": 0}, "1-4094"),
    ({"parent": "eth1", "id": 5000}, "1-4094"),
    ({"parent": "-rf", "id": 30}, "vlan.parent"),
    ({"parent": "eth1.30", "id": 30}, "own parent"),
    ("eth1", "mapping"),
])
def test_bad_vlans(vlan, error):
    raw = _raw()
    raw["zones"]["cams"] = {}
    raw["interfaces"]["cams"] = {"device": "eth1.30", "zone": "cams", "vlan": vlan}
    with pytest.raises(ConfigError, match=error):
        parse_config(raw)


def test_apply_creates_a_missing_vlan(monkeypatch):
    raw = _raw()
    segments.add_segments(raw, parse_config(raw), ["iot"])
    calls = []
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(ifaddr, "_run_ip", lambda args: calls.append(args))
    monkeypatch.setattr(ifaddr.subprocess, "run",
                        lambda argv, **kw: subprocess.CompletedProcess(argv, 1))  # eth1.30 doesn't exist yet
    ifaddr.sync_addresses(parse_config(raw))
    assert calls[:3] == [["link", "add", "link", "eth1", "name", "eth1.30", "type", "vlan", "id", "30"],
                         ["link", "set", "dev", "eth1", "up"], ["link", "set", "dev", "eth1.30", "up"]]
    assert ["addr", "replace", "192.168.30.1/24", "dev", "eth1.30"] in calls


def test_the_segments():
    raw = _raw()
    added = segments.add_segments(raw, parse_config(raw), ["iot", "guest"])
    assert added == ["iot", "guest"]
    config = parse_config(raw)
    assert config.interfaces["iot"].device == "eth1.30" and config.interfaces["guest"].vlan_id == 40
    assert set(config.dhcp.zones) == {"lan", "iot", "guest"}
    assert config.iot.enabled and "iot" in config.iot.zones and config.iot.auto_isolate
    # Internet only: the one rule out of each segment goes to the WAN.
    out = {(r.from_zone, r.to_zone) for r in config.rules if r.from_zone in ("iot", "guest")}
    assert out == {("iot", "wan"), ("guest", "wan")}
    # ...and neither manages the router.
    assert management.management_zones(config) == ["lan"]
    assert {"iot", "guest"} <= set(management.blocked_zones(config))
    assert "192.168.30.1" not in management.listen_addresses(config)
    ruleset = build_ruleset(config)
    assert 'set iot_ifaces {\n\t\ttype ifname\n\t\telements = { "eth1.30" }' in ruleset
    assert "no-management-from-guest" in ruleset
    # Twice is once.
    assert segments.add_segments(raw, config, ["iot", "guest"]) == []


def test_a_clash_is_refused():
    raw = _raw()
    raw["interfaces"]["lan"]["address"] = "192.168.30.1/24"
    raw["dhcp"]["lan"].update(range_start="192.168.30.100", range_end="192.168.30.199")
    raw["management"]["addresses"] = ["192.168.30.1"]  # the webUI moved with it (ROADMAP SEC-27)
    with pytest.raises(segments.SegmentError, match="already used"):
        segments.add_segments(raw, parse_config(raw), ["iot"])


def test_new_installs_isolate_iot_devices():
    config = parse_config(_raw())
    assert config.iot.enabled and config.iot.zones == ["lan"] and config.iot.auto_isolate
