"""Tests that frfw.provision.apply_all runs ifaddr -> nft -> kea in order
and aggregates their messages. The nft/ip subprocess calls are
monkeypatched (each is unit-tested against the real binaries elsewhere:
test_builder.py, test_kea.py, test_ifaddr.py) so this stays focused on
orchestration, not re-proving each subsystem."""

from __future__ import annotations

import pytest

from frfw import apply as apply_mod
from frfw import ifaddr as ifaddr_mod
from frfw.config import parse_config
from frfw.provision import apply_all


@pytest.fixture(autouse=True)
def _pretend_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)


@pytest.fixture(autouse=True)
def _fake_nft(monkeypatch):
    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: None)
    monkeypatch.setattr(apply_mod, "capture_running_ruleset", lambda: "")


def test_apply_all_runs_all_four_steps_in_order(minimal_config_dict, tmp_path):
    config = parse_config(minimal_config_dict)  # no address, no dhcp, no xdp
    result = apply_all(
        config,
        backup_dir=tmp_path / "backups",
        kea_config_path=tmp_path / "kea.json",
        xdp_state_path=tmp_path / "xdp_state.json",
    )

    assert len(result.messages) == 4
    assert "No interface addresses" in result.messages[0]
    assert "Ruleset applied" in result.messages[1]
    assert "No DHCP zones" in result.messages[2]
    assert "XDP SNI filter disabled" in result.messages[3]


def test_apply_all_dry_run_touches_nothing(dhcp_config_dict, tmp_path, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)  # not root -- dry-run must not care
    ip_calls = []
    monkeypatch.setattr(ifaddr_mod, "_run_ip", lambda args: ip_calls.append(args))

    config = parse_config(dhcp_config_dict)
    kea_path = tmp_path / "kea.json"

    result = apply_all(
        config,
        dry_run=True,
        backup_dir=tmp_path / "backups",
        kea_config_path=kea_path,
        xdp_state_path=tmp_path / "xdp_state.json",
    )

    assert ip_calls == []
    assert not kea_path.exists()
    # xdp_sni_filter is disabled (and was never attached) in every test
    # fixture config, which is a real no-op regardless of dry_run --
    # there is nothing to "preview" undoing state that was never applied.
    previewable = result.messages[:-1]
    assert all("dry-run" in m.lower() or "would" in m.lower() for m in previewable)
    assert "XDP SNI filter disabled" in result.messages[-1]


def test_apply_all_applies_addresses_and_dhcp_together(dhcp_config_dict, tmp_path, monkeypatch):
    ip_calls = []
    monkeypatch.setattr(ifaddr_mod, "_run_ip", lambda args: ip_calls.append(args))
    monkeypatch.setattr("frfw.kea._restart_kea_service", lambda: None)

    config = parse_config(dhcp_config_dict)
    kea_path = tmp_path / "kea.json"

    result = apply_all(
        config,
        backup_dir=tmp_path / "backups",
        kea_config_path=kea_path,
        xdp_state_path=tmp_path / "xdp_state.json",
    )

    assert ip_calls == [
        ["addr", "replace", "10.0.0.1/24", "dev", "lo"],
        ["link", "set", "lo", "up"],
    ]
    assert kea_path.exists()
    assert "Kea DHCP config applied" in result.messages[2]
