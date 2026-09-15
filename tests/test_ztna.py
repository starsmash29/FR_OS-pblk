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


def _fake_completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(["nft"], returncode, stdout=stdout, stderr=stderr)


def test_authorize_ip_rejects_invalid_address(monkeypatch):
    monkeypatch.setattr(ztna_mod, "_run_nft", lambda args: pytest.fail("nft should not be invoked"))
    with pytest.raises(ztna_mod.ZtnaError, match="invalid IPv4 address"):
        ztna_mod.authorize_ip("not-an-ip", 3600, "alice")


def test_authorize_ip_calls_nft_add_element_with_ttl(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(ztna_mod, "_run_nft", lambda args: (calls.append(args), _fake_completed())[1])

    ztna_mod.authorize_ip("10.0.0.5", 3600, "alice", state_path=tmp_path / "state.json")

    assert calls == [
        ["add", "element", "inet", ztna_mod.FILTER_TABLE, ztna_mod.ZTNA_SET_NAME,
         "{", "10.0.0.5 timeout 3600s", "}"]
    ]


def test_authorize_ip_records_username_for_status_display(tmp_path, monkeypatch):
    monkeypatch.setattr(ztna_mod, "_run_nft", lambda args: _fake_completed())
    state_path = tmp_path / "state.json"

    ztna_mod.authorize_ip("10.0.0.5", 3600, "alice", state_path=state_path)

    state = json.loads(state_path.read_text())
    assert state["10.0.0.5"]["username"] == "alice"


def test_authorize_ip_raises_on_nft_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(ztna_mod, "_run_nft", lambda args: _fake_completed(1, stderr="boom"))
    with pytest.raises(ztna_mod.ZtnaError, match="boom"):
        ztna_mod.authorize_ip("10.0.0.5", 3600, "alice", state_path=tmp_path / "state.json")


def test_get_authorization_returns_none_when_not_in_set(monkeypatch, tmp_path):
    monkeypatch.setattr(
        ztna_mod, "_run_nft",
        lambda args: _fake_completed(stdout=json.dumps({"nftables": [{"set": {"elem": []}}]})),
    )
    assert ztna_mod.get_authorization("10.0.0.9", state_path=tmp_path / "state.json") is None


def test_get_authorization_finds_matching_ip_with_username(monkeypatch, tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({"10.0.0.5": {"username": "alice", "authorized_at": 1.0}}))

    nft_json = {
        "nftables": [
            {"set": {"elem": [
                {"elem": {"val": "10.0.0.5", "expires": 1234}},
            ]}}
        ]
    }
    monkeypatch.setattr(ztna_mod, "_run_nft", lambda args: _fake_completed(stdout=json.dumps(nft_json)))

    auth = ztna_mod.get_authorization("10.0.0.5", state_path=state_path)
    assert auth is not None
    assert auth.username == "alice"
    assert auth.expires_in_seconds == 1234


def test_snapshot_before_reload_returns_empty_when_set_missing(monkeypatch):
    monkeypatch.setattr(
        ztna_mod, "_run_nft",
        lambda args: _fake_completed(1, stderr="Error: No such file or directory"),
    )
    assert ztna_mod.snapshot_before_reload() == []


def test_snapshot_before_reload_never_raises_on_unexpected_error(monkeypatch):
    monkeypatch.setattr(ztna_mod, "_run_nft", lambda args: _fake_completed(1, stderr="some other error"))
    assert ztna_mod.snapshot_before_reload() == []


def test_restore_after_reload_skips_expired_and_continues_past_failures(monkeypatch):
    calls = []

    def fake_run_nft(args):
        calls.append(args)
        if "1.2.3.4" in " ".join(args):
            return _fake_completed(1, stderr="no such set")
        return _fake_completed()

    monkeypatch.setattr(ztna_mod, "_run_nft", fake_run_nft)

    # (ip, remaining): one already-expired (skipped without an nft call),
    # one that fails (swallowed), one that succeeds.
    ztna_mod.restore_after_reload([("10.0.0.1", 0), ("1.2.3.4", 100), ("10.0.0.2", 50)])

    assert len(calls) == 2  # the expired one never even calls nft
    assert any("10.0.0.2 timeout 50s" in " ".join(c) for c in calls)


# --- real integration tests: actual kernel nftables state -------------------


@pytest.fixture
def real_ztna_table(monkeypatch):
    """Points frfw.ztna at a real, throwaway `inet` table/set instead of
    the production `fr_os` one, and tears it down afterward."""
    table = "fr_os_ztna_test"
    monkeypatch.setattr(ztna_mod, "FILTER_TABLE", table)
    monkeypatch.setattr(ztna_mod, "ZTNA_SET_NAME", "authed_test")

    subprocess.run(["nft", "add", "table", "inet", table], check=True)
    subprocess.run(
        [
            "nft", "add", "set", "inet", table, "authed_test",
            "{", "type", "ipv4_addr", ";", "flags", "dynamic,timeout", ";", "}",
        ],
        check=True,
    )
    yield table
    subprocess.run(["nft", "delete", "table", "inet", table], check=False)


@requires_nft
@requires_root
def test_real_authorize_and_get_authorization_round_trip(real_ztna_table, tmp_path):
    state_path = tmp_path / "state.json"

    ztna_mod.authorize_ip("10.99.0.1", 3600, "alice", state_path=state_path)
    auth = ztna_mod.get_authorization("10.99.0.1", state_path=state_path)

    assert auth is not None
    assert auth.username == "alice"
    assert 3590 <= auth.expires_in_seconds <= 3600


@requires_nft
@requires_root
def test_real_kernel_evicts_expired_element_on_its_own(real_ztna_table, tmp_path):
    ztna_mod.authorize_ip("10.99.0.2", 2, "bob", state_path=tmp_path / "state.json")
    assert ztna_mod.get_authorization("10.99.0.2") is not None

    time.sleep(3)

    # No cron job, no polling loop, nothing on the Python side ran in
    # between -- purely the kernel's own timeout eviction.
    assert ztna_mod.get_authorization("10.99.0.2") is None


@requires_nft
@requires_root
def test_real_snapshot_and_restore_preserves_remaining_time(real_ztna_table, tmp_path):
    ztna_mod.authorize_ip("10.99.0.3", 3600, "carol", state_path=tmp_path / "state.json")

    snapshot = ztna_mod.snapshot_before_reload()
    assert any(ip == "10.99.0.3" for ip, _ in snapshot)

    # Simulate the ruleset reload wiping the set (frfw.nft.builder's
    # `flush ruleset` would do this to the *whole* kernel state; deleting
    # just our test set's contents is the equivalent for this test).
    subprocess.run(
        ["nft", "flush", "set", "inet", real_ztna_table, "authed_test"], check=True
    )
    assert ztna_mod.get_authorization("10.99.0.3") is None

    ztna_mod.restore_after_reload(snapshot)

    auth = ztna_mod.get_authorization("10.99.0.3")
    assert auth is not None
    assert auth.expires_in_seconds > 0


@requires_nft
@requires_root
def test_real_snapshot_before_reload_empty_for_nonexistent_table(monkeypatch):
    monkeypatch.setattr(ztna_mod, "FILTER_TABLE", "fr_os_definitely_does_not_exist")
    monkeypatch.setattr(ztna_mod, "ZTNA_SET_NAME", "nope")
    assert ztna_mod.snapshot_before_reload() == []
