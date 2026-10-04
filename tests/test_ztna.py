"""Tests for frfw.ztna.

Split in two: fast unit tests that monkeypatch `_run_nft` (exercising
JSON parsing and error handling without touching the kernel), and a
small set of real, unmocked integration tests against an actual
throwaway nftables table -- the same "verify it for real, not just in
review" approach used for bpf/xdp_sni_filter.c and frfw.xdp. The real
tests are skipped when `nft` isn't installed or the test process isn't
root (modifying/reading nftables state needs CAP_NET_ADMIN even for a
read-only `nft list` -- confirmed directly: `runuser -u nobody -- nft
list ruleset` fails with "Operation not permitted" even though it
changes nothing).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time

import pytest

from frfw import ztna as ztna_mod

requires_nft = pytest.mark.skipif(shutil.which("nft") is None, reason="nft binary not installed")
requires_root = pytest.mark.skipif(os.geteuid() != 0, reason="nftables state access requires root")


# --- unit tests: JSON parsing / error handling, _run_nft mocked -------------

MAC = "aa:bb:cc:00:11:22"


def _fake_completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(["nft"], returncode, stdout=stdout, stderr=stderr)


def _sets(device=(), tunnel=()):
    """`nft -j list set` output for the device set (address . MAC) or the
    tunnel set (address), chosen by the set the call names."""
    def run(args):
        name = args[-1]
        if name == ztna_mod.ZTNA_SET_NAME:
            elems = [{"elem": {"val": {"concat": [ip, mac]}, "expires": left}} for ip, mac, left in device]
        else:
            elems = [{"elem": {"val": ip, "expires": left}} for ip, left in tunnel]
        return _fake_completed(stdout=json.dumps({"nftables": [{"set": {"elem": elems}}]}))
    return run


def test_authorize_client_rejects_invalid_address_and_mac(monkeypatch):
    monkeypatch.setattr(ztna_mod, "_run_nft", lambda args: pytest.fail("nft should not be invoked"))
    with pytest.raises(ztna_mod.ZtnaError, match="invalid IPv4 address"):
        ztna_mod.authorize_client("not-an-ip", MAC, 3600, "alice")
    with pytest.raises(ztna_mod.ZtnaError, match="invalid MAC"):
        ztna_mod.authorize_client("10.0.0.5", "aa:bb", 3600, "alice")


def test_a_device_is_authorized_by_address_and_mac_together(monkeypatch, tmp_path):
    """ROADMAP SEC-6: the pair names the device -- not the address alone."""
    calls = []
    monkeypatch.setattr(ztna_mod, "_run_nft", lambda args: (calls.append(args), _fake_completed())[1])
    ztna_mod.authorize_client("10.0.0.5", MAC.upper(), 3600, "alice", state_path=tmp_path / "state.json")
    assert calls == [["add", "element", "inet", ztna_mod.FILTER_TABLE, ztna_mod.ZTNA_SET_NAME,
                      "{", f"10.0.0.5 . {MAC} timeout 3600s", "}"]]


def test_a_wireguard_client_is_authorized_by_its_tunnel_address(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(ztna_mod, "_run_nft", lambda args: (calls.append(args), _fake_completed())[1])
    ztna_mod.authorize_client("10.99.0.2", "", 3600, "alice", state_path=tmp_path / "state.json")
    assert calls == [["add", "element", "inet", ztna_mod.FILTER_TABLE, ztna_mod.ZTNA_TUNNEL_SET_NAME,
                      "{", "10.99.0.2 timeout 3600s", "}"]]


def test_authorize_client_records_username_and_mac_for_status_display(tmp_path, monkeypatch):
    monkeypatch.setattr(ztna_mod, "_run_nft", lambda args: _fake_completed())
    state_path = tmp_path / "state.json"
    ztna_mod.authorize_client("10.0.0.5", MAC, 3600, "alice", state_path=state_path)
    state = json.loads(state_path.read_text())
    assert state["10.0.0.5"]["username"] == "alice" and state["10.0.0.5"]["mac"] == MAC


def test_authorize_client_raises_on_nft_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(ztna_mod, "_run_nft", lambda args: _fake_completed(1, stderr="boom"))
    with pytest.raises(ztna_mod.ZtnaError, match="boom"):
        ztna_mod.authorize_client("10.0.0.5", MAC, 3600, "alice", state_path=tmp_path / "state.json")


def test_get_authorization_returns_none_when_not_in_set(monkeypatch, tmp_path):
    monkeypatch.setattr(ztna_mod, "_run_nft", _sets())
    assert ztna_mod.get_authorization("10.0.0.9", MAC, state_path=tmp_path / "state.json") is None


def test_get_authorization_needs_the_same_device_not_just_the_address(monkeypatch, tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({"10.0.0.5": {"username": "alice", "authorized_at": 1.0}}))
    monkeypatch.setattr(ztna_mod, "_run_nft", _sets(device=[("10.0.0.5", MAC, 1234)], tunnel=[("10.99.0.2", 99)]))

    auth = ztna_mod.get_authorization("10.0.0.5", MAC, state_path=state_path)
    assert auth is not None and auth.username == "alice" and auth.expires_in_seconds == 1234 and auth.mac == MAC
    # The same address from another device -- or with no device -- is not it.
    assert ztna_mod.get_authorization("10.0.0.5", "aa:bb:cc:00:11:99", state_path=state_path) is None
    assert ztna_mod.get_authorization("10.0.0.5", "", state_path=state_path) is None
    # The tunnel client is found by its address alone.
    assert ztna_mod.get_authorization("10.99.0.2", "", state_path=state_path).expires_in_seconds == 99


def test_list_and_snapshot_cover_both_sets(monkeypatch):
    monkeypatch.setattr(ztna_mod, "_run_nft", _sets(device=[("10.0.0.5", MAC, 10)], tunnel=[("10.99.0.2", 20)]))
    assert ztna_mod.list_authorized() == [("10.0.0.5", MAC, 10), ("10.99.0.2", "", 20)]
    assert ztna_mod.snapshot_before_reload() == ztna_mod.list_authorized()


def test_snapshot_before_reload_returns_empty_when_set_missing(monkeypatch):
    monkeypatch.setattr(
        ztna_mod, "_run_nft",
        lambda args: _fake_completed(1, stderr="Error: No such file or directory"),
    )
    assert ztna_mod.snapshot_before_reload() == []


def test_snapshot_before_reload_raises_on_unexpected_error(monkeypatch):
    monkeypatch.setattr(ztna_mod, "_run_nft", lambda args: _fake_completed(1, stderr="some other error"))
    # Review FR-002: an unreadable set stops the apply instead of releasing everyone.
    with pytest.raises(ztna_mod.ZtnaError, match="some other error"):
        ztna_mod.snapshot_before_reload()


def _neigh(monkeypatch, entries, returncode=0):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, returncode, stdout=json.dumps(entries), stderr="")

    monkeypatch.setattr(ztna_mod.subprocess, "run", run)
    return calls


def test_client_link_reads_the_routers_own_neighbour_table(monkeypatch):
    calls = _neigh(monkeypatch, [{"dst": "10.0.0.5", "dev": "eth1", "lladdr": MAC.upper(), "state": ["REACHABLE"]}])
    assert ztna_mod.client_link("10.0.0.5") == ztna_mod.ClientLink(mac=MAC, device="eth1")
    assert calls == [["ip", "-j", "neigh", "show", "to", "10.0.0.5"]]


@pytest.mark.parametrize("entries", [
    [],                                                                                   # not a neighbour
    [{"dst": "10.0.0.5", "dev": "eth1", "state": ["INCOMPLETE"]}],                        # no answer
    [{"dst": "10.0.0.5", "dev": "eth1", "lladdr": MAC, "state": ["FAILED"]}],
    [{"dst": "10.0.0.6", "dev": "eth1", "lladdr": MAC, "state": ["REACHABLE"]}],          # someone else
    [{"dst": "10.0.0.5", "dev": "eth1", "lladdr": "not-a-mac", "state": ["REACHABLE"]}],
])
def test_client_link_is_none_without_a_usable_entry(monkeypatch, entries):
    _neigh(monkeypatch, entries)
    assert ztna_mod.client_link("10.0.0.5") is None


def test_client_link_validates_the_address_before_running_anything(monkeypatch):
    monkeypatch.setattr(ztna_mod.subprocess, "run", lambda *a, **k: pytest.fail("ran ip"))
    with pytest.raises(Exception, match="invalid IPv4"):
        ztna_mod.client_link("10.0.0.5; reboot")


# --- real integration tests: actual kernel nftables state -------------------


@pytest.fixture
def real_ztna_table(monkeypatch):
    """Points frfw.ztna at real, throwaway `inet` table/sets of the
    production types instead of the `fr_os` ones, and tears them down."""
    table = "fr_os_ztna_test"
    monkeypatch.setattr(ztna_mod, "FILTER_TABLE", table)
    monkeypatch.setattr(ztna_mod, "ZTNA_SET_NAME", "authed_test")
    monkeypatch.setattr(ztna_mod, "ZTNA_TUNNEL_SET_NAME", "authed_tunnel_test")

    subprocess.run(["nft", "add", "table", "inet", table], check=True)
    for name, kind in (("authed_test", "ipv4_addr . ether_addr"), ("authed_tunnel_test", "ipv4_addr")):
        subprocess.run(["nft", f"add set inet {table} {name} {{ type {kind}; flags dynamic,timeout; }}"], check=True)
    yield table
    subprocess.run(["nft", "delete", "table", "inet", table], check=False)


@requires_nft
@requires_root
def test_real_authorize_and_get_authorization_round_trip(real_ztna_table, tmp_path):
    state_path = tmp_path / "state.json"
    ztna_mod.authorize_client("10.98.0.1", MAC, 3600, "alice", state_path=state_path)
    ztna_mod.authorize_client("10.99.0.1", "", 3600, "bob", state_path=state_path)

    auth = ztna_mod.get_authorization("10.98.0.1", MAC, state_path=state_path)
    assert auth is not None and auth.username == "alice" and 3590 <= auth.expires_in_seconds <= 3600
    assert ztna_mod.get_authorization("10.98.0.1", "aa:bb:cc:00:11:99", state_path=state_path) is None
    assert ztna_mod.get_authorization("10.99.0.1", "", state_path=state_path).username == "bob"


@requires_nft
@requires_root
def test_real_kernel_evicts_expired_element_on_its_own(real_ztna_table, tmp_path):
    ztna_mod.authorize_client("10.98.0.2", MAC, 2, "bob", state_path=tmp_path / "state.json")
    assert ztna_mod.get_authorization("10.98.0.2", MAC) is not None

    time.sleep(3)

    # No cron job, no polling loop, nothing on the Python side ran in
    # between -- purely the kernel's own timeout eviction.
    assert ztna_mod.get_authorization("10.98.0.2", MAC) is None


@requires_nft
@requires_root
def test_real_snapshot_reads_remaining_time(real_ztna_table, tmp_path):
    ztna_mod.authorize_client("10.98.0.3", MAC, 3600, "carol", state_path=tmp_path / "state.json")
    matches = [left for ip, mac, left in ztna_mod.snapshot_before_reload() if (ip, mac) == ("10.98.0.3", MAC)]
    assert matches and 3500 < matches[0] <= 3600


@requires_nft
@requires_root
def test_real_snapshot_before_reload_empty_for_nonexistent_table(monkeypatch):
    monkeypatch.setattr(ztna_mod, "FILTER_TABLE", "fr_os_definitely_does_not_exist")
    assert ztna_mod.snapshot_before_reload() == []


@requires_nft
@requires_root
def test_real_snapshot_carries_nothing_from_the_address_only_set_of_before(monkeypatch):
    """Upgrading from a version before SEC-6: the loaded ZTNA_SET_NAME is
    still the old address-only set. Its sessions name no device, so none
    is carried over -- above all not into the tunnel set, which would let
    them in again by address alone."""
    table = "fr_os_ztna_old"
    monkeypatch.setattr(ztna_mod, "FILTER_TABLE", table)
    subprocess.run(["nft", "add", "table", "inet", table], check=True)
    try:
        subprocess.run(["nft", f"add set inet {table} {ztna_mod.ZTNA_SET_NAME} "
                               "{ type ipv4_addr; flags dynamic,timeout; }"], check=True)
        subprocess.run(["nft", "add", "element", "inet", table, ztna_mod.ZTNA_SET_NAME,
                        "{ 10.0.0.20 timeout 600s }"], check=True)
        assert ztna_mod.snapshot_before_reload() == []
    finally:
        subprocess.run(["nft", "delete", "table", "inet", table], check=False)
