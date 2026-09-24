"""Tests for frfw.iot.scanner: merging sources, the isolation decision,
and a full run_scan with every I/O dependency injected."""

from __future__ import annotations

import json

import pytest

from frfw.config import parse_config
from frfw.helper.client import HelperError
from frfw.iot import scanner
from frfw.iot.arp import ArpEntry
from frfw.iot.classify import Classification, Observation
from frfw.iot.mdns import MdnsError

ESP_MAC = "24:0a:c4:11:22:33"
LAPTOP_MAC = "3a:11:22:33:44:55"
STATIC_MAC = "00:11:22:33:44:66"
OTHER_ZONE_MAC = "00:11:22:33:44:77"


@pytest.fixture
def iot_config(minimal_config_dict):
    minimal_config_dict["interfaces"]["lan"]["address"] = "10.0.0.1/24"
    minimal_config_dict["zones"]["guest"] = {}
    minimal_config_dict["interfaces"]["guest"] = {"device": "eth2", "zone": "guest", "address": "10.9.0.1/24"}
    minimal_config_dict["iot"] = {"enabled": True, "zones": ["lan"]}
    return minimal_config_dict


def _config(raw, **iot):
    raw["iot"].update(iot)
    return parse_config(raw)


def test_gather_merges_leases_arp_and_mdns_within_iot_zones_only(iot_config):
    config = _config(iot_config)
    observations = scanner.gather_observations(
        config,
        leases=[
            {"ip": "10.0.0.50", "mac": ESP_MAC, "hostname": "esp_112233"},
            {"ip": "10.9.0.5", "mac": OTHER_ZONE_MAC, "hostname": "guest-phone"},  # guest zone
        ],
        arp_entries=[
            ArpEntry(ip="10.0.0.60", mac=STATIC_MAC, device="eth1"),
            ArpEntry(ip="10.0.0.50", mac=ESP_MAC, device="eth1"),
            ArpEntry(ip="10.9.0.6", mac="00:11:22:33:44:88", device="eth2"),  # not an IoT zone
        ],
        vendor_db={"240AC4": "Espressif Inc."},
        mdns_results={"10.0.0.50": {"_esphomelib._tcp"}},
    )
    by_mac = {o.mac: o for o in observations}
    assert set(by_mac) == {ESP_MAC, STATIC_MAC}
    assert by_mac[ESP_MAC] == Observation(
        mac=ESP_MAC, ip="10.0.0.50", hostname="esp_112233", interface="eth1",
        vendor="Espressif Inc.", services=("_esphomelib._tcp",),
    )
    assert by_mac[STATIC_MAC].ip == "10.0.0.60"
    assert by_mac[STATIC_MAC].hostname == ""


def _classified(*items):
    return [(Observation(mac=m), Classification(category=c, score=0)) for m, c in items]


def test_decide_isolation_without_auto_isolate_only_manual(iot_config):
    config = _config(iot_config, isolated_macs=[STATIC_MAC])
    assert scanner.decide_isolation(config, _classified((ESP_MAC, "iot"))) == [STATIC_MAC]


def test_decide_isolation_auto_isolates_iot_but_trusted_wins(iot_config):
    config = _config(iot_config, auto_isolate=True, trusted_macs=[ESP_MAC])
    classified = _classified((ESP_MAC, "iot"), ("00:aa:bb:cc:dd:01", "iot"), (LAPTOP_MAC, "general"), (STATIC_MAC, "unknown"))
    assert scanner.decide_isolation(config, classified) == ["00:aa:bb:cc:dd:01"]


class _FakeHelper:
    def __init__(self, leases=None, sync_ok=True):
        self.leases = leases or []
        self.sync_ok = sync_ok
        self.synced: list[list[str]] = []

    def dhcp_leases(self):
        return {"ok": True, "leases": self.leases}

    def iot_sync_isolation(self, macs):
        self.synced.append(list(macs))
        if not self.sync_ok:
            return {"ok": False, "message": "IoT isolation is disabled in the current config"}
        return {"ok": True, "isolated": list(macs), "count": len(macs)}


def _run(config, helper, tmp_path, mdns_fn=None, arp_text=None):
    arp_path = tmp_path / "arp"
    arp_path.write_text(arp_text or "IP address HW type Flags HW address Mask Device\n")
    oui_path = tmp_path / "oui.csv"
    oui_path.write_text("Registry,Assignment,Organization Name,Organization Address\nMA-L,240AC4,Espressif Inc.,x\n")
    return scanner.run_scan(
        config,
        leases_fn=helper.dhcp_leases,
        sync_fn=helper.iot_sync_isolation,
        mdns_fn=mdns_fn or (lambda addrs: {}),
        arp_path=arp_path,
        oui_path=oui_path,
        state_path=tmp_path / "inventory.json",
        now=1_700_000_000,
    )


def test_run_scan_end_to_end_with_auto_isolate(iot_config, tmp_path):
    config = _config(iot_config, auto_isolate=True)
    helper = _FakeHelper(leases=[{"ip": "10.0.0.50", "mac": ESP_MAC, "hostname": "esp_112233"}])
    seen_addrs = []

    def fake_mdns(addrs):
        seen_addrs.append(list(addrs))
        return {"10.0.0.50": {"_esphomelib._tcp"}}

    result = _run(config, helper, tmp_path, mdns_fn=fake_mdns)

    assert seen_addrs == [["10.0.0.1"]]  # only the IoT zone's router address
    assert helper.synced == [[ESP_MAC]]
    assert result.isolated == [ESP_MAC]
    assert result.messages[0] == "1 device(s) found: 1 iot"

    state = json.loads((tmp_path / "inventory.json").read_text())
    assert state["scanned_at"] == 1_700_000_000
    (device,) = state["devices"]
    assert device["mac"] == ESP_MAC
    assert device["category"] == "iot"
    assert device["isolated"] is True
    assert device["vendor"] == "Espressif Inc."
    assert state["isolated"] == [ESP_MAC]


def test_run_scan_disabled_does_nothing(minimal_config_dict, tmp_path):
    helper = _FakeHelper()
    result = _run(parse_config(minimal_config_dict), helper, tmp_path)
    assert helper.synced == []
    assert not (tmp_path / "inventory.json").exists()
    assert "disabled" in result.messages[0]


def test_run_scan_survives_mdns_and_lease_failures(iot_config, tmp_path):
    config = _config(iot_config)

    class BrokenLeases(_FakeHelper):
        def dhcp_leases(self):
            raise HelperError("cannot reach apply-helper")

    def broken_mdns(addrs):
        raise MdnsError("cannot bind UDP port 53530")

    arp = "IP address HW type Flags HW address Mask Device\n10.0.0.60 0x1 0x2 00:11:22:33:44:66 * eth1\n"
    result = _run(config, BrokenLeases(), tmp_path, mdns_fn=broken_mdns, arp_text=arp)
    assert any("DHCP leases unavailable" in m for m in result.messages)
    assert any("mDNS discovery skipped" in m for m in result.messages)
    assert [d["mac"] for d in result.devices] == [STATIC_MAC]  # ARP still worked


def test_run_scan_reports_failed_sync_as_error(iot_config, tmp_path):
    result = _run(_config(iot_config), _FakeHelper(sync_ok=False), tmp_path)
    assert any(m.startswith("error: isolation not applied") for m in result.messages)
    assert result.isolated == []


def test_resync_from_inventory_uses_stored_categories(iot_config):
    config = _config(iot_config, auto_isolate=True, trusted_macs=[ESP_MAC])
    helper = _FakeHelper()
    inventory = {"devices": [{"mac": ESP_MAC, "category": "iot"}, {"mac": STATIC_MAC, "category": "iot"}]}
    scanner.resync_from_inventory(config, inventory, sync_fn=helper.iot_sync_isolation)
    assert helper.synced == [[STATIC_MAC]]


def test_load_inventory_handles_missing_and_corrupt(tmp_path):
    assert scanner.load_inventory(tmp_path / "nope.json") is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert scanner.load_inventory(bad) is None
