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


def test_apply_all_runs_all_seven_steps_in_order(minimal_config_dict, tmp_path):
    config = parse_config(minimal_config_dict)  # no address, no dhcp, no xdp, no ztna, no pqc
    result = apply_all(
        config,
        backup_dir=tmp_path / "backups",
        kea_config_path=tmp_path / "kea.json",
        xdp_state_path=tmp_path / "xdp_state.json",
        pqc_conf_path=tmp_path / "pqc_openssl.cnf",
        ssh_kex_dropin_path=tmp_path / "50-fr_os-pqc-kex.conf",
    )

    assert len(result.messages) == 7
    assert "No interface addresses" in result.messages[0]
    assert "Ruleset applied" in result.messages[1]
    assert "No DHCP zones" in result.messages[2]
    assert "XDP SNI filter disabled" in result.messages[3]
    assert "ZTNA gate disabled" in result.messages[4]
    assert "PQC hybrid TLS disabled" in result.messages[5]
    # This sandbox has no sshd installed at all, which is itself a real,
    # correctly-detected state (see frfw.pqc.sync_ssh_kex) rather than a
    # mock -- there is nothing to fake here.
    assert "sshd not installed" in result.messages[6] or "PQC hybrid SSH KEX disabled" in result.messages[6]


def test_apply_all_dry_run_touches_nothing(dhcp_config_dict, tmp_path, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)  # not root -- dry-run must not care
    ip_calls = []
    monkeypatch.setattr(ifaddr_mod, "_run_ip", lambda args: ip_calls.append(args))

    config = parse_config(dhcp_config_dict)
    kea_path = tmp_path / "kea.json"

    pqc_conf_path = tmp_path / "pqc_openssl.cnf"
    ssh_dropin_path = tmp_path / "50-fr_os-pqc-kex.conf"
    result = apply_all(
        config,
        dry_run=True,
        backup_dir=tmp_path / "backups",
        kea_config_path=kea_path,
        xdp_state_path=tmp_path / "xdp_state.json",
        pqc_conf_path=pqc_conf_path,
        ssh_kex_dropin_path=ssh_dropin_path,
    )

    assert ip_calls == []
    assert not kea_path.exists()
    assert not pqc_conf_path.exists()
    assert not ssh_dropin_path.exists()
    # xdp_sni_filter, ztna and pqc are all disabled (and were never
    # attached/enabled/applied) in every test fixture config, which is a
    # real no-op regardless of dry_run -- there is nothing to "preview"
    # undoing state that was never applied. Everything else (addresses,
    # nftables, DHCP) genuinely would change something, hence the
    # dry-run/"would" wording.
    always_off_substrings = (
        "XDP SNI filter disabled",
        "ZTNA gate disabled",
        "PQC hybrid TLS disabled",
        "sshd not installed",
    )
    for message in result.messages:
        is_always_off = any(s in message for s in always_off_substrings)
        assert is_always_off or "dry-run" in message.lower() or "would" in message.lower(), message


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
    assert any("would preserve" in m.lower() for m in result.messages)


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
    assert any("2 active session(s) preserved" in m for m in result.messages)
