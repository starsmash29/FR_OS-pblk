"""Tests that frfw.provision.apply_all runs ifaddr -> nft -> kea in order
and aggregates their messages. The nft/ip subprocess calls are
monkeypatched (each is unit-tested against the real binaries elsewhere:
test_builder.py, test_kea.py, test_ifaddr.py) so this stays focused on
orchestration, not re-proving each subsystem."""

from __future__ import annotations

import pytest

from frfw import apply as apply_mod
from frfw import ifaddr as ifaddr_mod
from frfw import ztna as ztna_mod
from frfw.config import parse_config
from frfw.provision import apply_all


@pytest.fixture(autouse=True)
def _pretend_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)


@pytest.fixture(autouse=True)
def _fake_nft(monkeypatch):
    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: None)
    monkeypatch.setattr(apply_mod, "capture_running_ruleset", lambda: "")


def test_apply_all_runs_all_five_steps_in_order(minimal_config_dict, tmp_path):
    config = parse_config(minimal_config_dict)  # no address, no dhcp, no xdp, no ztna
    result = apply_all(
        config,
        backup_dir=tmp_path / "backups",
        kea_config_path=tmp_path / "kea.json",
        xdp_state_path=tmp_path / "xdp_state.json",
    )

    assert len(result.messages) == 5
    assert "No interface addresses" in result.messages[0]
    assert "Ruleset applied" in result.messages[1]
    assert "No DHCP zones" in result.messages[2]
    assert "XDP SNI filter disabled" in result.messages[3]
    assert "ZTNA gate disabled" in result.messages[4]


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
    # xdp_sni_filter and ztna are both disabled (and were never
    # attached/enabled) in every test fixture config, which is a real
    # no-op regardless of dry_run -- there is nothing to "preview" undoing
    # state that was never applied.
    previewable = result.messages[:-2]
    assert all("dry-run" in m.lower() or "would" in m.lower() for m in previewable)
    assert "XDP SNI filter disabled" in result.messages[-2]
    assert "ZTNA gate disabled" in result.messages[-1]


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


def test_apply_all_skips_ztna_snapshot_restore_when_disabled(minimal_config_dict, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(ztna_mod, "snapshot_before_reload", lambda: calls.append("snapshot") or [])
    monkeypatch.setattr(ztna_mod, "restore_after_reload", lambda snap: calls.append("restore"))

    config = parse_config(minimal_config_dict)  # ztna disabled by default
    apply_all(config, backup_dir=tmp_path / "backups", kea_config_path=tmp_path / "kea.json")

    assert calls == []


def test_apply_all_skips_ztna_snapshot_restore_on_dry_run(minimal_config_dict, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(ztna_mod, "snapshot_before_reload", lambda: calls.append("snapshot") or [])
    monkeypatch.setattr(ztna_mod, "restore_after_reload", lambda snap: calls.append("restore"))

    minimal_config_dict["ztna"] = {
        "enabled": True,
        "users": [{"username": "a", "password_hash": "x"}],
    }
    config = parse_config(minimal_config_dict)
    result = apply_all(
        config, dry_run=True, backup_dir=tmp_path / "backups", kea_config_path=tmp_path / "kea.json"
    )

    assert calls == []
    assert "would preserve" in result.messages[-1].lower()


def test_apply_all_snapshots_and_restores_ztna_sessions_when_enabled(
    minimal_config_dict, tmp_path, monkeypatch
):
    calls = []
    fake_snapshot = [("10.0.0.5", 1800), ("10.0.0.6", 900)]
    monkeypatch.setattr(
        ztna_mod, "snapshot_before_reload", lambda: calls.append("snapshot") or fake_snapshot
    )
    monkeypatch.setattr(
        ztna_mod, "restore_after_reload", lambda snap: calls.append(("restore", snap))
    )

    minimal_config_dict["ztna"] = {
        "enabled": True,
        "users": [{"username": "a", "password_hash": "x"}],
    }
    config = parse_config(minimal_config_dict)
    result = apply_all(config, backup_dir=tmp_path / "backups", kea_config_path=tmp_path / "kea.json")

    # snapshot must happen before the restore, and restore must receive
    # exactly what the snapshot returned.
    assert calls == ["snapshot", ("restore", fake_snapshot)]
    assert "2 active session(s) preserved" in result.messages[-1]
