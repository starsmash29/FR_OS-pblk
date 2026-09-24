"""Tests for frfw.ifaddr. `_run_ip` is monkeypatched throughout so these
never touch the sandbox's real network interfaces (a real, non-mocked
round trip against a veth pair was done manually during development --
see the phase 3 session notes)."""

from __future__ import annotations

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
        ["link", "set", "eth1", "up"],
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
