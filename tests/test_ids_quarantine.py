"""Tests for frfw.ids_quarantine.

Same split as tests/test_ztna.py (this module is a deliberate structural
mirror of frfw.ztna, see its own docstring): fast unit tests that
monkeypatch `_run_nft`, plus real, unmocked integration tests against an
actual throwaway nftables table, skipped when `nft` isn't installed or
the test process isn't root.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time

import pytest

from frfw import ids_quarantine as ids_quarantine_mod

requires_nft = pytest.mark.skipif(shutil.which("nft") is None, reason="nft binary not installed")
requires_root = pytest.mark.skipif(os.geteuid() != 0, reason="nftables state access requires root")


# --- unit tests: JSON parsing / error handling, _run_nft mocked -------------


def _fake_completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(["nft"], returncode, stdout=stdout, stderr=stderr)


def test_quarantine_ip_rejects_invalid_address(monkeypatch):
    monkeypatch.setattr(ids_quarantine_mod, "_run_nft", lambda args: pytest.fail("nft should not be invoked"))
    with pytest.raises(ids_quarantine_mod.IdsQuarantineError, match="invalid IPv4 address"):
        ids_quarantine_mod.quarantine_ip("not-an-ip", 3600)


def test_quarantine_ip_rejects_non_positive_duration(monkeypatch):
    monkeypatch.setattr(ids_quarantine_mod, "_run_nft", lambda args: pytest.fail("nft should not be invoked"))
    with pytest.raises(ids_quarantine_mod.IdsQuarantineError, match="duration_seconds must be positive"):
        ids_quarantine_mod.quarantine_ip("10.0.0.5", 0)


@pytest.mark.parametrize("ip", ["127.0.0.1", "127.1.2.3", "0.0.0.0", "224.0.0.1", "169.254.9.9",
                                "240.0.0.1", "255.255.255.255"])
def test_quarantine_ip_refuses_non_host_addresses(monkeypatch, ip):
    monkeypatch.setattr(ids_quarantine_mod, "_run_nft", lambda args: pytest.fail("nft should not be invoked"))
    with pytest.raises(ids_quarantine_mod.IdsQuarantineError, match="not a host address"):
        ids_quarantine_mod.quarantine_ip(ip, 3600)


def test_quarantine_ip_refuses_own_addresses(monkeypatch):
    monkeypatch.setattr(ids_quarantine_mod, "_run_nft", lambda args: pytest.fail("nft should not be invoked"))
    with pytest.raises(ids_quarantine_mod.IdsQuarantineError, match="router's own"):
        ids_quarantine_mod.quarantine_ip("192.168.1.1", 3600, own_addresses=frozenset({"192.168.1.1"}))


def test_quarantine_ip_caps_duration(monkeypatch):
    monkeypatch.setattr(ids_quarantine_mod, "_run_nft", lambda args: _fake_completed())
    ids_quarantine_mod.quarantine_ip("10.0.0.5", ids_quarantine_mod.MAX_DURATION_SECONDS)
    with pytest.raises(ids_quarantine_mod.IdsQuarantineError, match="at most"):
        ids_quarantine_mod.quarantine_ip("10.0.0.5", ids_quarantine_mod.MAX_DURATION_SECONDS + 1)


def test_quarantine_ip_calls_nft_add_element_with_ttl(monkeypatch):
    calls = []
    monkeypatch.setattr(ids_quarantine_mod, "_run_nft", lambda args: (calls.append(args), _fake_completed())[1])

    ids_quarantine_mod.quarantine_ip("10.0.0.5", 3600)

    assert calls == [
        ["add", "element", "inet", ids_quarantine_mod.FILTER_TABLE, ids_quarantine_mod.IDS_QUARANTINE_SET_NAME,
         "{", "10.0.0.5 timeout 3600s", "}"]
    ]


def test_quarantine_ip_holds_the_hosts_mac_for_ipv6_too(monkeypatch):
    """ROADMAP FND-1b: the host's IPv6 addresses are its own choice, so
    its MAC goes into the IPv6 set, with the same timeout."""
    calls = []
    monkeypatch.setattr(ids_quarantine_mod, "_run_nft", lambda args: (calls.append(args), _fake_completed())[1])
    looked_up = []
    mac = ids_quarantine_mod.quarantine_ip(
        "10.0.0.5", 3600, lan_devices=frozenset({"eth1"}),
        neighbour=lambda ip, devices: (looked_up.append((ip, set(devices))), "aa:bb:cc:dd:ee:01")[1])
    assert mac == "aa:bb:cc:dd:ee:01" and looked_up == [("10.0.0.5", {"eth1"})]
    assert calls[1] == ["add", "element", "inet", ids_quarantine_mod.FILTER_TABLE,
                        ids_quarantine_mod.IDS_QUARANTINE_MAC_SET_NAME, "{", "aa:bb:cc:dd:ee:01 timeout 3600s", "}"]


def test_quarantine_ip_without_a_known_mac_holds_the_address_alone(monkeypatch):
    calls = []
    monkeypatch.setattr(ids_quarantine_mod, "_run_nft", lambda args: (calls.append(args), _fake_completed())[1])
    assert ids_quarantine_mod.quarantine_ip("10.0.0.5", 3600, neighbour=lambda ip, devices: None) is None
    assert len(calls) == 1


def _neigh(monkeypatch, entries, returncode=0):
    seen = []

    def run(argv, **kwargs):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, returncode, stdout=json.dumps(entries), stderr="")

    monkeypatch.setattr(ids_quarantine_mod.subprocess, "run", run)
    return seen


def test_the_mac_comes_from_the_neighbour_table_on_a_lan_device(monkeypatch):
    seen = _neigh(monkeypatch, [{"dst": "10.0.0.5", "dev": "eth1", "lladdr": "AA:BB:CC:DD:EE:01",
                                 "state": ["STALE"]}])
    assert ids_quarantine_mod.lan_neighbour_mac("10.0.0.5", {"eth1"}) == "aa:bb:cc:dd:ee:01"
    assert seen == [["ip", "-j", "-4", "neigh", "show", "to", "10.0.0.5"]]


@pytest.mark.parametrize("entry", [
    # On the WAN: the provider's gateway, never held.
    {"dst": "10.0.0.5", "dev": "eth0", "lladdr": "aa:bb:cc:dd:ee:01", "state": ["REACHABLE"]},
    # No usable entry.
    {"dst": "10.0.0.5", "dev": "eth1", "lladdr": "aa:bb:cc:dd:ee:01", "state": ["FAILED"]},
    {"dst": "10.0.0.5", "dev": "eth1", "state": ["INCOMPLETE"]},
    {"dst": "10.0.0.5", "dev": "eth1", "lladdr": "not-a-mac", "state": ["REACHABLE"]},
    # Someone else's entry.
    {"dst": "10.0.0.6", "dev": "eth1", "lladdr": "aa:bb:cc:dd:ee:01", "state": ["REACHABLE"]},
])
def test_no_mac_for_anything_but_a_live_lan_neighbour(monkeypatch, entry):
    _neigh(monkeypatch, [entry])
    assert ids_quarantine_mod.lan_neighbour_mac("10.0.0.5", {"eth1"}) is None


def test_no_lan_devices_no_lookup(monkeypatch):
    seen = _neigh(monkeypatch, [])
    assert ids_quarantine_mod.lan_neighbour_mac("10.0.0.5", ()) is None
    assert seen == []


def test_the_macs_are_carried_over_a_reload(monkeypatch):
    listing = {"nftables": [{"set": {"name": "ids_quarantine_mac", "elem": [
        {"elem": {"val": "aa:bb:cc:dd:ee:01", "timeout": 3600, "expires": 1200}}]}}]}
    calls = []
    monkeypatch.setattr(ids_quarantine_mod, "_run_nft",
                        lambda args: (calls.append(args), _fake_completed(stdout=json.dumps(listing)))[1])
    assert ids_quarantine_mod.snapshot_macs_before_reload() == [("aa:bb:cc:dd:ee:01", 1200)]
    assert calls == [["-j", "list", "set", "inet", "fr_os", "ids_quarantine_mac"]]


def test_quarantine_ip_raises_on_nft_failure(monkeypatch):
    monkeypatch.setattr(ids_quarantine_mod, "_run_nft", lambda args: _fake_completed(1, stderr="boom"))
    with pytest.raises(ids_quarantine_mod.IdsQuarantineError, match="boom"):
        ids_quarantine_mod.quarantine_ip("10.0.0.5", 3600)


def test_snapshot_before_reload_returns_empty_when_set_missing(monkeypatch):
    monkeypatch.setattr(
        ids_quarantine_mod, "_run_nft",
        lambda args: _fake_completed(1, stderr="Error: No such file or directory"),
    )
    assert ids_quarantine_mod.snapshot_before_reload() == []


def test_snapshot_before_reload_raises_on_unexpected_error(monkeypatch):
    monkeypatch.setattr(ids_quarantine_mod, "_run_nft", lambda args: _fake_completed(1, stderr="some other error"))
    # Review FR-002: an unreadable set stops the apply instead of releasing everyone.
    with pytest.raises(ids_quarantine_mod.IdsQuarantineError, match="some other error"):
        ids_quarantine_mod.snapshot_before_reload()


# --- real integration tests: actual kernel nftables state -------------------


@pytest.fixture
def real_jail_table(monkeypatch):
    """Points frfw.ids_quarantine at a real, throwaway `inet` table/set
    instead of the production `fr_os` one, and tears it down after."""
    table = "fr_os_ids_quarantine_test"
    monkeypatch.setattr(ids_quarantine_mod, "FILTER_TABLE", table)
    monkeypatch.setattr(ids_quarantine_mod, "IDS_QUARANTINE_SET_NAME", "quarantine_test")

    subprocess.run(["nft", "add", "table", "inet", table], check=True)
    subprocess.run(
        ["nft", "add", "set", "inet", table, "quarantine_test", "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}"],
        check=True,
    )
    yield table
    subprocess.run(["nft", "delete", "table", "inet", table], check=False)


@requires_nft
@requires_root
def test_real_quarantine_ip_adds_element_with_expected_ttl(real_jail_table):
    ids_quarantine_mod.quarantine_ip("10.98.0.1", 3600)

    snapshot = ids_quarantine_mod.snapshot_before_reload()
    matches = [remaining for ip, remaining in snapshot if ip == "10.98.0.1"]
    assert matches and 3590 <= matches[0] <= 3600


@requires_nft
@requires_root
def test_real_quarantine_ip_holds_the_mac_with_the_same_ttl(real_jail_table, monkeypatch):
    """ROADMAP FND-1b: the MAC set, against the real kernel."""
    monkeypatch.setattr(ids_quarantine_mod, "IDS_QUARANTINE_MAC_SET_NAME", "quarantine_mac_test")
    subprocess.run(["nft", "add", "set", "inet", real_jail_table, "quarantine_mac_test",
                    "{", "type", "ether_addr", ";", "flags", "timeout", ";", "}"], check=True)
    ids_quarantine_mod.quarantine_ip("10.98.0.4", 3600, lan_devices={"eth1"},
                                     neighbour=lambda ip, devices: "aa:bb:cc:dd:ee:04")
    [(mac, remaining)] = ids_quarantine_mod.snapshot_macs_before_reload()
    assert mac == "aa:bb:cc:dd:ee:04" and 3590 <= remaining <= 3600


@requires_nft
@requires_root
def test_real_kernel_evicts_expired_ban_on_its_own(real_jail_table):
    ids_quarantine_mod.quarantine_ip("10.98.0.2", 2)
    assert any(ip == "10.98.0.2" for ip, _ in ids_quarantine_mod.snapshot_before_reload())

    time.sleep(3)

    # No cron job, no polling loop, nothing on the Python side ran in
    # between -- purely the kernel's own timeout eviction.
    assert not any(ip == "10.98.0.2" for ip, _ in ids_quarantine_mod.snapshot_before_reload())


@requires_nft
@requires_root
def test_real_snapshot_reads_remaining_time(real_jail_table):
    ids_quarantine_mod.quarantine_ip("10.98.0.3", 3600)
    matches = [left for ip, left in ids_quarantine_mod.snapshot_before_reload() if ip == "10.98.0.3"]
    assert matches and 3500 < matches[0] <= 3600


@requires_nft
@requires_root
def test_real_snapshot_before_reload_empty_for_nonexistent_table(monkeypatch):
    monkeypatch.setattr(ids_quarantine_mod, "FILTER_TABLE", "fr_os_definitely_does_not_exist")
    monkeypatch.setattr(ids_quarantine_mod, "IDS_QUARANTINE_SET_NAME", "nope")
    assert ids_quarantine_mod.snapshot_before_reload() == []


@requires_nft
@requires_root
def test_real_generated_ruleset_puts_quarantine_drop_rule_near_the_top_of_input_chain():
    """End-to-end proof this actually wires together, not just that each
    half works in isolation: load the *real* generated ruleset
    (frfw.nft.build_ruleset) against the real `fr_os` table/chain names
    frfw.ids_quarantine itself targets, and confirm the quarantine-drop
    rule is the second rule nft reports in the input chain -- right
    after the brute-force jail's own drop rule, both before even the
    loopback accept -- verified directly against `nft`'s own JSON
    listing, not just the Python source that generated it."""
    import json as _json

    from frfw.config import parse_config
    from frfw.nft import build_ruleset

    config = parse_config(
        {
            "version": 1,
            "hostname": "test-router",
            "zones": {"wan": {}},
            "interfaces": {"wan": {"device": "lo", "zone": "wan"}},
            "rules": [],
            "nat": {},
        }
    )
    ruleset = build_ruleset(config)
    try:
        subprocess.run(["nft", "-f", "-"], input=ruleset, text=True, check=True)

        proc = subprocess.run(
            ["nft", "-j", "list", "chain", "inet", "fr_os", "input"],
            capture_output=True, text=True, check=True,
        )
        data = _json.loads(proc.stdout)
        rules = [obj["rule"] for obj in data["nftables"] if "rule" in obj]

        assert len(rules) >= 2, "expected at least two rules in the input chain"
        assert rules[0].get("comment") == "bruteforce-jail"
        assert rules[1].get("comment") == "ids-quarantine"
    finally:
        subprocess.run(["nft", "flush", "ruleset"], check=False)
