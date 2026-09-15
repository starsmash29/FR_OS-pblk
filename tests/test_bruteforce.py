"""Tests for frfw.bruteforce.

Same split as tests/test_ztna.py (this module is a deliberate structural
mirror of frfw.ztna, see its own docstring): fast unit tests that
monkeypatch `_run_nft`, plus real, unmocked integration tests against an
actual throwaway nftables table, skipped when `nft` isn't installed or
the test process isn't root.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time

import pytest

from frfw import bruteforce as bruteforce_mod

requires_nft = pytest.mark.skipif(shutil.which("nft") is None, reason="nft binary not installed")
requires_root = pytest.mark.skipif(os.geteuid() != 0, reason="nftables state access requires root")


# --- unit tests: JSON parsing / error handling, _run_nft mocked -------------


def _fake_completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(["nft"], returncode, stdout=stdout, stderr=stderr)


def test_ban_ip_rejects_invalid_address(monkeypatch):
    monkeypatch.setattr(bruteforce_mod, "_run_nft", lambda args: pytest.fail("nft should not be invoked"))
    with pytest.raises(bruteforce_mod.BruteforceError, match="invalid IPv4 address"):
        bruteforce_mod.ban_ip("not-an-ip", 3600)


def test_ban_ip_rejects_non_positive_duration(monkeypatch):
    monkeypatch.setattr(bruteforce_mod, "_run_nft", lambda args: pytest.fail("nft should not be invoked"))
    with pytest.raises(bruteforce_mod.BruteforceError, match="duration_seconds must be positive"):
        bruteforce_mod.ban_ip("10.0.0.5", 0)


def test_ban_ip_calls_nft_add_element_with_ttl(monkeypatch):
    calls = []
    monkeypatch.setattr(bruteforce_mod, "_run_nft", lambda args: (calls.append(args), _fake_completed())[1])

    bruteforce_mod.ban_ip("10.0.0.5", 3600)

    assert calls == [
        ["add", "element", "inet", bruteforce_mod.FILTER_TABLE, bruteforce_mod.BRUTEFORCE_JAIL_SET_NAME,
         "{", "10.0.0.5 timeout 3600s", "}"]
    ]


def test_ban_ip_raises_on_nft_failure(monkeypatch):
    monkeypatch.setattr(bruteforce_mod, "_run_nft", lambda args: _fake_completed(1, stderr="boom"))
    with pytest.raises(bruteforce_mod.BruteforceError, match="boom"):
        bruteforce_mod.ban_ip("10.0.0.5", 3600)


def test_snapshot_before_reload_returns_empty_when_set_missing(monkeypatch):
    monkeypatch.setattr(
        bruteforce_mod, "_run_nft",
        lambda args: _fake_completed(1, stderr="Error: No such file or directory"),
    )
    assert bruteforce_mod.snapshot_before_reload() == []


def test_snapshot_before_reload_never_raises_on_unexpected_error(monkeypatch):
    monkeypatch.setattr(bruteforce_mod, "_run_nft", lambda args: _fake_completed(1, stderr="some other error"))
    assert bruteforce_mod.snapshot_before_reload() == []


def test_restore_after_reload_skips_expired_and_continues_past_failures(monkeypatch):
    calls = []

    def fake_run_nft(args):
        calls.append(args)
        if "1.2.3.4" in " ".join(args):
            return _fake_completed(1, stderr="no such set")
        return _fake_completed()

    monkeypatch.setattr(bruteforce_mod, "_run_nft", fake_run_nft)

    bruteforce_mod.restore_after_reload([("10.0.0.1", 0), ("1.2.3.4", 100), ("10.0.0.2", 50)])

    assert len(calls) == 2  # the expired one never even calls nft
    assert any("10.0.0.2 timeout 50s" in " ".join(c) for c in calls)


# --- real integration tests: actual kernel nftables state -------------------


@pytest.fixture
def real_jail_table(monkeypatch):
    """Points frfw.bruteforce at a real, throwaway `inet` table/set
    instead of the production `fr_os` one, and tears it down after."""
    table = "fr_os_bruteforce_test"
    monkeypatch.setattr(bruteforce_mod, "FILTER_TABLE", table)
    monkeypatch.setattr(bruteforce_mod, "BRUTEFORCE_JAIL_SET_NAME", "jail_test")

    subprocess.run(["nft", "add", "table", "inet", table], check=True)
    subprocess.run(
        ["nft", "add", "set", "inet", table, "jail_test", "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}"],
        check=True,
    )
    yield table
    subprocess.run(["nft", "delete", "table", "inet", table], check=False)


@requires_nft
@requires_root
def test_real_ban_ip_adds_element_with_expected_ttl(real_jail_table):
    bruteforce_mod.ban_ip("10.98.0.1", 3600)

    snapshot = bruteforce_mod.snapshot_before_reload()
    matches = [remaining for ip, remaining in snapshot if ip == "10.98.0.1"]
    assert matches and 3590 <= matches[0] <= 3600


@requires_nft
@requires_root
def test_real_kernel_evicts_expired_ban_on_its_own(real_jail_table):
    bruteforce_mod.ban_ip("10.98.0.2", 2)
    assert any(ip == "10.98.0.2" for ip, _ in bruteforce_mod.snapshot_before_reload())

    time.sleep(3)

    # No cron job, no polling loop, nothing on the Python side ran in
    # between -- purely the kernel's own timeout eviction.
    assert not any(ip == "10.98.0.2" for ip, _ in bruteforce_mod.snapshot_before_reload())


@requires_nft
@requires_root
def test_real_snapshot_and_restore_preserves_remaining_time(real_jail_table):
    bruteforce_mod.ban_ip("10.98.0.3", 3600)

    snapshot = bruteforce_mod.snapshot_before_reload()
    assert any(ip == "10.98.0.3" for ip, _ in snapshot)

    # Simulate the ruleset reload wiping the set (frfw.nft.builder's
    # `flush ruleset` would do this to the *whole* kernel state; flushing
    # just our test set's contents is the equivalent for this test).
    subprocess.run(["nft", "flush", "set", "inet", real_jail_table, "jail_test"], check=True)
    assert bruteforce_mod.snapshot_before_reload() == []

    bruteforce_mod.restore_after_reload(snapshot)

    restored = bruteforce_mod.snapshot_before_reload()
    matches = [remaining for ip, remaining in restored if ip == "10.98.0.3"]
    assert matches and matches[0] > 0


@requires_nft
@requires_root
def test_real_snapshot_before_reload_empty_for_nonexistent_table(monkeypatch):
    monkeypatch.setattr(bruteforce_mod, "FILTER_TABLE", "fr_os_definitely_does_not_exist")
    monkeypatch.setattr(bruteforce_mod, "BRUTEFORCE_JAIL_SET_NAME", "nope")
    assert bruteforce_mod.snapshot_before_reload() == []


@requires_nft
@requires_root
def test_real_generated_ruleset_puts_jail_drop_rule_first_in_input_chain():
    """End-to-end proof this actually wires together, not just that each
    half works in isolation: load the *real* generated ruleset
    (frfw.nft.build_ruleset) against the real `fr_os` table/chain names
    frfw.bruteforce itself targets, and confirm the jail-drop rule is
    literally the first rule nft reports in the input chain -- verified
    directly against `nft`'s own JSON listing, not just the Python
    source that generated it."""
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

        assert rules, "expected at least one rule in the input chain"
        assert rules[0].get("comment") == "bruteforce-jail"
    finally:
        subprocess.run(["nft", "flush", "ruleset"], check=False)
