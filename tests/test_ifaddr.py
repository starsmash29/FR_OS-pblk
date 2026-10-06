"""Tests for frfw.ifaddr. `_run_ip` is monkeypatched so these never touch
the sandbox's real network interfaces, except the last one, which runs
in its own network namespace (root only)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid

import pytest

from frfw import ifaddr as ifaddr_mod
from frfw.config.schema import Config, Interface, NatConfig, Zone


def _config(*, lan_address: str | None = "10.0.0.1/24") -> Config:
    return Config(
        version=1,
        hostname="r",
        interfaces={
            "wan": Interface(name="wan", device="eth0", zone="wan"),
            "lan": Interface(name="lan", device="eth1", zone="lan", address=lan_address),
        },
        zones={"wan": Zone(name="wan"), "lan": Zone(name="lan")},
        rules=[],
        nat=NatConfig(),
    )


@pytest.fixture(autouse=True)
def _pretend_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)


def test_no_addressed_interfaces_is_a_noop(monkeypatch):
    calls = []
    monkeypatch.setattr(ifaddr_mod, "_run_ip", lambda args: calls.append(args))

    result = ifaddr_mod.sync_addresses(_config(lan_address=None))

    assert not result.applied
    assert calls == []


def test_dry_run_never_calls_ip_or_requires_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)  # not root
    calls = []
    monkeypatch.setattr(ifaddr_mod, "_run_ip", lambda args: calls.append(args))

    result = ifaddr_mod.sync_addresses(_config(), dry_run=True)

    assert not result.applied
    assert "10.0.0.1/24" in result.message
    assert calls == []


def test_applies_replace_then_up_for_each_addressed_interface(monkeypatch):
    calls = []
    monkeypatch.setattr(ifaddr_mod, "_run_ip", lambda args: calls.append(args))

    result = ifaddr_mod.sync_addresses(_config())

    assert result.applied
    assert calls == [
        ["addr", "replace", "10.0.0.1/24", "dev", "eth1"],
        ["link", "set", "dev", "eth1", "up"],
    ]


def test_requires_root_for_real_apply(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    monkeypatch.setattr(ifaddr_mod, "_run_ip", lambda args: None)

    with pytest.raises(ifaddr_mod.IfaddrError, match="root"):
        ifaddr_mod.sync_addresses(_config())


def test_ip_failure_raises_ifaddr_error(monkeypatch):
    import subprocess

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="Error: boom")

    monkeypatch.setattr(ifaddr_mod.subprocess, "run", fake_run)

    with pytest.raises(ifaddr_mod.IfaddrError, match="boom"):
        ifaddr_mod.sync_addresses(_config())


# --- the last applied config's stale addresses (review v0.2.1 FR-NEW-005) ---


def test_an_address_the_last_config_set_and_this_one_dropped_is_removed(monkeypatch):
    calls = []
    monkeypatch.setattr(ifaddr_mod, "_run_ip", lambda args: calls.append(args))
    monkeypatch.setattr(ifaddr_mod, "_addresses", lambda device: {"10.0.0.1/24", "203.0.113.7/24"})

    result = ifaddr_mod.sync_addresses(_config(lan_address="10.0.5.1/24"), previous=_config())

    assert calls == [
        ["addr", "del", "10.0.0.1/24", "dev", "eth1"],
        ["addr", "replace", "10.0.5.1/24", "dev", "eth1"],
        ["link", "set", "dev", "eth1", "up"],
    ]
    assert "removed: eth1=10.0.0.1/24" in result.message


def test_an_address_dropped_with_no_new_one_is_removed_too(monkeypatch):
    calls = []
    monkeypatch.setattr(ifaddr_mod, "_run_ip", lambda args: calls.append(args))
    monkeypatch.setattr(ifaddr_mod, "_addresses", lambda device: {"10.0.0.1/24"})

    result = ifaddr_mod.sync_addresses(_config(lan_address=None), previous=_config())

    assert result.applied and calls == [["addr", "del", "10.0.0.1/24", "dev", "eth1"]]


def test_an_address_already_gone_is_not_removed_again(monkeypatch):
    calls = []
    monkeypatch.setattr(ifaddr_mod, "_run_ip", lambda args: calls.append(args))
    monkeypatch.setattr(ifaddr_mod, "_addresses", lambda device: set())

    ifaddr_mod.sync_addresses(_config(lan_address=None), previous=_config())

    assert calls == []


def test_without_a_last_applied_config_nothing_is_removed(monkeypatch):
    calls = []
    monkeypatch.setattr(ifaddr_mod, "_run_ip", lambda args: calls.append(args))
    monkeypatch.setattr(ifaddr_mod, "_addresses", lambda device: pytest.fail("read addresses to remove"))

    ifaddr_mod.sync_addresses(_config(lan_address="10.0.5.1/24"))

    assert ["addr", "del", "10.0.0.1/24", "dev", "eth1"] not in calls


def test_a_kept_address_and_one_written_differently_are_not_stale():
    kept = _config(lan_address="10.0.0.1/24")
    assert ifaddr_mod.stale_addresses(kept, _config()) == []
    assert ifaddr_mod.stale_addresses(_config(lan_address="10.0.0.1/16"), _config()) == [("eth1", "10.0.0.1/24")]


def test_a_dry_run_says_what_it_would_remove(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    monkeypatch.setattr(ifaddr_mod, "_run_ip", lambda args: pytest.fail("ran ip"))

    result = ifaddr_mod.sync_addresses(_config(lan_address=None), previous=_config(), dry_run=True)

    assert not result.applied and result.message == "Would remove addresses: eth1=10.0.0.1/24"


@pytest.mark.skipif(os.geteuid() != 0 or shutil.which("ip") is None, reason="needs root and iproute2")
def test_live_only_the_stale_address_goes_and_a_rollback_brings_it_back():
    """In a real network namespace: the address the last config set goes,
    one added by hand stays, and the apply's journal puts it back."""
    ns = f"frif{uuid.uuid4().hex[:6]}"
    run = lambda *a: subprocess.run(["ip", "netns", "exec", ns, *a], check=True, capture_output=True, text=True)
    subprocess.run(["ip", "netns", "add", ns], check=True)
    try:
        script = (
            "import json, os\n"
            "os.geteuid = lambda: 0\n"
            "from frfw import ifaddr\n"
            "from frfw.config.schema import Config, Interface, NatConfig, Zone\n"
            "from frfw.transaction import LinkState\n"
            "def config(address):\n"
            "    return Config(version=1, hostname='r', rules=[], nat=NatConfig(),\n"
            "                  interfaces={'lan': Interface(name='lan', device='lan0', zone='lan', address=address)},\n"
            "                  zones={'lan': Zone(name='lan')})\n"
            "before = LinkState.capture('lan0')\n"
            "ifaddr.sync_addresses(config('10.9.2.1/24'), previous=config('10.9.1.1/24'))\n"
            "applied = sorted(LinkState.capture('lan0').addresses)\n"
            "before.restore()\n"
            "print(json.dumps([applied, sorted(LinkState.capture('lan0').addresses)]))\n"
        )
        run("ip", "link", "add", "lan0", "type", "veth", "peer", "name", "lan0p")
        run("ip", "addr", "add", "10.9.1.1/24", "dev", "lan0")
        run("ip", "addr", "add", "10.9.3.1/24", "dev", "lan0")  # not FR_OS's
        out = subprocess.run(["ip", "netns", "exec", ns, "python3", "-c", script],
                             check=True, capture_output=True, text=True).stdout
        applied, rolled_back = json.loads(out)
        assert applied == ["10.9.2.1/24", "10.9.3.1/24"]
        assert rolled_back == ["10.9.1.1/24", "10.9.3.1/24"]
    finally:
        subprocess.run(["ip", "netns", "del", ns], check=False)
