"""Tests that frfw.provision.apply_all runs ifaddr -> nft -> kea in order
and aggregates their messages. The nft/ip subprocess calls are
monkeypatched (each is unit-tested against the real binaries elsewhere:
test_builder.py, test_kea.py, test_ifaddr.py) so this stays focused on
orchestration, not re-proving each subsystem."""

from __future__ import annotations

import pytest

from frfw import apply as apply_mod
from frfw import bruteforce as bruteforce_mod
from frfw import ids_quarantine as ids_quarantine_mod
from frfw import ifaddr as ifaddr_mod
from frfw import iot_isolation as iot_isolation_mod
from frfw import xdp as xdp_mod
from frfw import ztna as ztna_mod
from frfw.adblock import dns_service as adblock_dns_mod
from frfw.adblock import write_hosts_file
from frfw.config import parse_config
from frfw.provision import apply_all


@pytest.fixture(autouse=True)
def _pretend_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)


@pytest.fixture(autouse=True)
def _fake_nft(monkeypatch):
    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: None)
    monkeypatch.setattr(apply_mod, "capture_running_ruleset", lambda: "")


def test_apply_all_runs_all_eleven_steps_in_order(minimal_config_dict, tmp_path):
    config = parse_config(minimal_config_dict)  # no address, no dhcp, no xdp, no ztna, no pqc
    result = apply_all(
        config,
        backup_dir=tmp_path / "backups",
        kea_config_path=tmp_path / "kea.json",
        xdp_state_path=tmp_path / "xdp_state.json",
        pqc_conf_path=tmp_path / "pqc_openssl.cnf",
        ssh_kex_dropin_path=tmp_path / "50-fr_os-pqc-kex.conf",
        adblock_hosts_path=tmp_path / "adblock.hosts",
        adblock_dnsmasq_conf_path=tmp_path / "dnsmasq_adblock.conf",
    )

    assert len(result.messages) == 11
    assert "No interface addresses" in result.messages[0]
    assert "Ruleset applied" in result.messages[1]
    assert "No DHCP zones" in result.messages[2]
    assert "Ad-block DNS resolver disabled" in result.messages[3]
    assert "XDP SNI filter disabled" in result.messages[4]
    assert "Brute-force jail" in result.messages[5]
    assert "0 active ban(s) preserved" in result.messages[5]
    assert "AI IDS quarantine" in result.messages[6]
    assert "0 active quarantine(s) preserved" in result.messages[6]
    assert "ZTNA gate disabled" in result.messages[7]
    assert "IoT isolation disabled" in result.messages[8]
    assert "PQC hybrid TLS disabled" in result.messages[9]
    # This sandbox has no sshd installed at all, which is itself a real,
    # correctly-detected state (see frfw.pqc.sync_ssh_kex) rather than a
    # mock -- there is nothing to fake here.
    assert "sshd not installed" in result.messages[10] or "PQC hybrid SSH KEX disabled" in result.messages[10]


def _iot_config_dict(base: dict) -> dict:
    cfg = dict(base)
    cfg["iot"] = {"enabled": True, "zones": ["lan"], "isolation_mode": "block"}
    return cfg


def test_apply_all_skips_iot_snapshot_restore_when_disabled(minimal_config_dict, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(iot_isolation_mod, "snapshot_before_reload", lambda: calls.append("snap") or [])
    monkeypatch.setattr(iot_isolation_mod, "restore_after_reload", lambda s: calls.append("restore"))
    apply_all(
        parse_config(minimal_config_dict),
        backup_dir=tmp_path / "backups",
        kea_config_path=tmp_path / "kea.json",
        xdp_state_path=tmp_path / "xdp_state.json",
        pqc_conf_path=tmp_path / "pqc_openssl.cnf",
        ssh_kex_dropin_path=tmp_path / "50-fr_os-pqc-kex.conf",
        adblock_hosts_path=tmp_path / "adblock.hosts",
        adblock_dnsmasq_conf_path=tmp_path / "dnsmasq_adblock.conf",
    )
    assert calls == []


def test_apply_all_snapshots_and_restores_iot_isolation_when_enabled(
    minimal_config_dict, tmp_path, monkeypatch
):
    restored = []
    monkeypatch.setattr(
        iot_isolation_mod, "snapshot_before_reload", lambda: ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
    )
    monkeypatch.setattr(iot_isolation_mod, "restore_after_reload", lambda s: restored.append(list(s)))
    result = apply_all(
        parse_config(_iot_config_dict(minimal_config_dict)),
        backup_dir=tmp_path / "backups",
        kea_config_path=tmp_path / "kea.json",
        xdp_state_path=tmp_path / "xdp_state.json",
        pqc_conf_path=tmp_path / "pqc_openssl.cnf",
        ssh_kex_dropin_path=tmp_path / "50-fr_os-pqc-kex.conf",
        adblock_hosts_path=tmp_path / "adblock.hosts",
        adblock_dnsmasq_conf_path=tmp_path / "dnsmasq_adblock.conf",
    )
    assert restored == [["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]]
    assert "IoT isolation: 2 isolated device(s) preserved across reload" in result.messages


def test_apply_all_skips_iot_snapshot_restore_on_dry_run(minimal_config_dict, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(iot_isolation_mod, "snapshot_before_reload", lambda: calls.append("snap") or [])
    monkeypatch.setattr(iot_isolation_mod, "restore_after_reload", lambda s: calls.append("restore"))
    result = apply_all(
        parse_config(_iot_config_dict(minimal_config_dict)),
        dry_run=True,
        backup_dir=tmp_path / "backups",
        kea_config_path=tmp_path / "kea.json",
        xdp_state_path=tmp_path / "xdp_state.json",
        pqc_conf_path=tmp_path / "pqc_openssl.cnf",
        ssh_kex_dropin_path=tmp_path / "50-fr_os-pqc-kex.conf",
        adblock_hosts_path=tmp_path / "adblock.hosts",
        adblock_dnsmasq_conf_path=tmp_path / "dnsmasq_adblock.conf",
    )
    assert calls == []
    assert any("IoT isolation: would preserve" in m for m in result.messages)


def test_apply_all_dry_run_touches_nothing(dhcp_config_dict, tmp_path, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)  # not root -- dry-run must not care
    ip_calls = []
    monkeypatch.setattr(ifaddr_mod, "_run_ip", lambda args: ip_calls.append(args))

    config = parse_config(dhcp_config_dict)
    kea_path = tmp_path / "kea.json"

    pqc_conf_path = tmp_path / "pqc_openssl.cnf"
    ssh_dropin_path = tmp_path / "50-fr_os-pqc-kex.conf"
    adblock_hosts_path = tmp_path / "adblock.hosts"
    adblock_conf_path = tmp_path / "dnsmasq_adblock.conf"
    result = apply_all(
        config,
        dry_run=True,
        backup_dir=tmp_path / "backups",
        kea_config_path=kea_path,
        xdp_state_path=tmp_path / "xdp_state.json",
        pqc_conf_path=pqc_conf_path,
        ssh_kex_dropin_path=ssh_dropin_path,
        adblock_hosts_path=adblock_hosts_path,
        adblock_dnsmasq_conf_path=adblock_conf_path,
    )

    assert ip_calls == []
    assert not kea_path.exists()
    assert not pqc_conf_path.exists()
    assert not ssh_dropin_path.exists()
    assert not adblock_conf_path.exists()
    # xdp_sni_filter, ztna, pqc and adblocker are all disabled (and were
    # never attached/enabled/applied) in every test fixture config, which
    # is a real no-op regardless of dry_run -- there is nothing to
    # "preview" undoing state that was never applied. Everything else
    # (addresses, nftables, DHCP) genuinely would change something,
    # hence the dry-run/"would" wording.
    always_off_substrings = (
        "XDP SNI filter disabled",
        "ZTNA gate disabled",
        "IoT isolation disabled",
        "PQC hybrid TLS disabled",
        "sshd not installed",
        "Ad-block DNS resolver disabled",
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


def test_apply_all_skips_bruteforce_snapshot_restore_on_dry_run(minimal_config_dict, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(bruteforce_mod, "snapshot_before_reload", lambda: calls.append("snapshot") or [])
    monkeypatch.setattr(bruteforce_mod, "restore_after_reload", lambda snap: calls.append("restore"))

    config = parse_config(minimal_config_dict)
    result = apply_all(
        config, dry_run=True, backup_dir=tmp_path / "backups", kea_config_path=tmp_path / "kea.json"
    )

    # Unlike ZTNA, the jail set is always declared, but a dry run reloads
    # nothing, so there is still nothing to snapshot or restore.
    assert calls == []
    assert any("would preserve active bans" in m.lower() for m in result.messages)


def test_apply_all_snapshots_and_restores_bruteforce_bans(minimal_config_dict, tmp_path, monkeypatch):
    calls = []
    fake_snapshot = [("10.0.0.9", 1200)]
    monkeypatch.setattr(
        bruteforce_mod, "snapshot_before_reload", lambda: calls.append("snapshot") or fake_snapshot
    )
    monkeypatch.setattr(
        bruteforce_mod, "restore_after_reload", lambda snap: calls.append(("restore", snap))
    )

    config = parse_config(minimal_config_dict)
    result = apply_all(config, backup_dir=tmp_path / "backups", kea_config_path=tmp_path / "kea.json")

    assert calls == ["snapshot", ("restore", fake_snapshot)]
    assert any("1 active ban(s) preserved" in m for m in result.messages)


def test_apply_all_does_not_call_restore_when_nothing_was_banned(minimal_config_dict, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(bruteforce_mod, "snapshot_before_reload", lambda: calls.append("snapshot") or [])
    monkeypatch.setattr(
        bruteforce_mod, "restore_after_reload", lambda snap: calls.append("restore")
    )

    config = parse_config(minimal_config_dict)
    result = apply_all(config, backup_dir=tmp_path / "backups", kea_config_path=tmp_path / "kea.json")

    # No point calling nft to restore an empty set of bans.
    assert calls == ["snapshot"]
    assert any("0 active ban(s) preserved" in m for m in result.messages)


def test_apply_all_skips_ids_quarantine_snapshot_restore_on_dry_run(minimal_config_dict, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(ids_quarantine_mod, "snapshot_before_reload", lambda: calls.append("snapshot") or [])
    monkeypatch.setattr(ids_quarantine_mod, "restore_after_reload", lambda snap: calls.append("restore"))

    config = parse_config(minimal_config_dict)
    result = apply_all(
        config, dry_run=True, backup_dir=tmp_path / "backups", kea_config_path=tmp_path / "kea.json"
    )

    # Like the brute-force jail, the quarantine set is always declared,
    # but a dry run reloads nothing, so there is still nothing to
    # snapshot or restore.
    assert calls == []
    assert any("would preserve active quarantines" in m.lower() for m in result.messages)


def test_apply_all_snapshots_and_restores_ids_quarantines(minimal_config_dict, tmp_path, monkeypatch):
    calls = []
    fake_snapshot = [("10.0.0.9", 1200)]
    monkeypatch.setattr(
        ids_quarantine_mod, "snapshot_before_reload", lambda: calls.append("snapshot") or fake_snapshot
    )
    monkeypatch.setattr(
        ids_quarantine_mod, "restore_after_reload", lambda snap: calls.append(("restore", snap))
    )

    config = parse_config(minimal_config_dict)
    result = apply_all(config, backup_dir=tmp_path / "backups", kea_config_path=tmp_path / "kea.json")

    assert calls == ["snapshot", ("restore", fake_snapshot)]
    assert any("1 active quarantine(s) preserved" in m for m in result.messages)


def test_apply_all_does_not_call_restore_when_nothing_was_quarantined(minimal_config_dict, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(ids_quarantine_mod, "snapshot_before_reload", lambda: calls.append("snapshot") or [])
    monkeypatch.setattr(
        ids_quarantine_mod, "restore_after_reload", lambda snap: calls.append("restore")
    )

    config = parse_config(minimal_config_dict)
    result = apply_all(config, backup_dir=tmp_path / "backups", kea_config_path=tmp_path / "kea.json")

    # No point calling nft to restore an empty set of quarantines.
    assert calls == ["snapshot"]
    assert any("0 active quarantine(s) preserved" in m for m in result.messages)


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


def test_apply_all_merges_adblock_critical_domains_into_xdp_blocklist_without_persisting(
    minimal_config_dict, tmp_path, monkeypatch
):
    """The adblock-XDP tie-in: config.adblocker.xdp_critical_limit
    domains get unioned into what frfw.xdp.sync_sni_filter actually
    receives, but the original `Config` object passed into apply_all
    (i.e. what would be persisted to config.yaml) must come back
    completely unchanged -- see provision.py's own comment on why."""
    monkeypatch.setattr(
        adblock_dns_mod, "sync_dns_resolver", lambda *a, **kw: adblock_dns_mod.DnsSyncResult(False, "fake")
    )

    captured = {}

    def fake_sync_sni_filter(config, *, dry_run=False, state_path):
        captured["config"] = config
        return xdp_mod.SyncResult(applied=False, message="fake xdp sync")

    monkeypatch.setattr(xdp_mod, "sync_sni_filter", fake_sync_sni_filter)

    minimal_config_dict["xdp_sni_filter"] = {
        "enabled": True,
        "interfaces": ["wan"],
        "blocklist": ["manual.example.com"],
    }
    minimal_config_dict["adblocker"] = {
        "enabled": True,
        "source_urls": ["https://a.example/hosts"],
        "xdp_critical_limit": 2,
    }
    config = parse_config(minimal_config_dict)

    hosts_path = tmp_path / "adblock.hosts"
    write_hosts_file({"zzz.example.com", "aaa.example.com", "mmm.example.com"}, hosts_path)

    apply_all(
        config,
        backup_dir=tmp_path / "backups",
        kea_config_path=tmp_path / "kea.json",
        adblock_hosts_path=hosts_path,
        adblock_dnsmasq_conf_path=tmp_path / "dnsmasq_adblock.conf",
    )

    merged = captured["config"]
    assert merged.xdp_sni_filter.blocklist == ["aaa.example.com", "manual.example.com", "mmm.example.com"]
    # The Config object apply_all was actually given (what a caller
    # would go on to persist) must be untouched by the merge.
    assert config.xdp_sni_filter.blocklist == ["manual.example.com"]


def test_apply_all_does_not_touch_xdp_blocklist_when_critical_limit_is_zero(
    minimal_config_dict, tmp_path, monkeypatch
):
    monkeypatch.setattr(
        adblock_dns_mod, "sync_dns_resolver", lambda *a, **kw: adblock_dns_mod.DnsSyncResult(False, "fake")
    )

    captured = {}

    def fake_sync_sni_filter(config, *, dry_run=False, state_path):
        captured["config"] = config
        return xdp_mod.SyncResult(applied=False, message="fake xdp sync")

    monkeypatch.setattr(xdp_mod, "sync_sni_filter", fake_sync_sni_filter)

    minimal_config_dict["xdp_sni_filter"] = {
        "enabled": True,
        "interfaces": ["wan"],
        "blocklist": ["manual.example.com"],
    }
    minimal_config_dict["adblocker"] = {
        "enabled": True,
        "source_urls": ["https://a.example/hosts"],
        "xdp_critical_limit": 0,  # off -- the default
    }
    config = parse_config(minimal_config_dict)

    hosts_path = tmp_path / "adblock.hosts"
    write_hosts_file({"zzz.example.com"}, hosts_path)

    apply_all(
        config,
        backup_dir=tmp_path / "backups",
        kea_config_path=tmp_path / "kea.json",
        adblock_hosts_path=hosts_path,
        adblock_dnsmasq_conf_path=tmp_path / "dnsmasq_adblock.conf",
    )

    assert captured["config"].xdp_sni_filter.blocklist == ["manual.example.com"]
