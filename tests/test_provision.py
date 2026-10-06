"""Tests that frfw.provision.apply_all runs nft -> ifaddr -> kea in order
and aggregates their messages. The nft/ip subprocess calls are
monkeypatched (each is unit-tested against the real binaries elsewhere:
test_builder.py, test_kea.py, test_ifaddr.py) so this stays focused on
orchestration, not re-proving each subsystem."""

from __future__ import annotations

import dataclasses

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
from frfw.config.schema import AppControlConfig
from frfw.provision import apply_all
from frfw.transaction import ApplyError

#: Taken before tests/conftest.py stands it in for every test.
_REAL_DEVICE_EXISTS = ifaddr_mod.device_exists


@pytest.fixture(autouse=True)
def _pretend_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)


@pytest.fixture(autouse=True)
def _fake_nft(monkeypatch):
    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: None)
    monkeypatch.setattr(apply_mod, "capture_running_ruleset", lambda: "")


def test_apply_all_runs_every_step_in_order(minimal_config_dict, tmp_path):
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

    assert len(result.messages) == 15
    assert "Ruleset applied" in result.messages[0]
    assert result.messages[1] == "IPv4 forwarding turned on"  # only after the ruleset
    assert result.messages.pop(2) == "WireGuard off"  # security-lessons G8, also behind the ruleset
    assert "No interface addresses" in result.messages[2]
    assert "No DHCP zones" in result.messages[3]
    assert "Ad-block DNS resolver disabled" in result.messages[4]
    assert "XDP SNI filter disabled" in result.messages[5]
    assert "Brute-force jail" in result.messages[6]
    assert "0 active ban(s) preserved" in result.messages[6]
    assert "AI IDS quarantine" in result.messages[7]
    assert "0 active quarantine(s) preserved" in result.messages[7]
    assert "ZTNA gate disabled" in result.messages[8]
    assert "IoT isolation disabled" in result.messages[9]
    assert "PQC hybrid TLS disabled" in result.messages[10]
    # This sandbox has no sshd installed at all, which is itself a real,
    # correctly-detected state (see frfw.pqc.sync_ssh_kex) rather than a
    # mock -- there is nothing to fake here.
    assert "sshd not installed" in result.messages[11] or "PQC hybrid SSH KEX disabled" in result.messages[11]
    assert "sshd not installed" in result.messages[12] or "sshd listens on" in result.messages[12]
    assert result.messages[13].startswith("webUI listens on")


def _iot_config_dict(base: dict) -> dict:
    cfg = dict(base)
    cfg["iot"] = {"enabled": True, "zones": ["lan"], "isolation_mode": "block"}
    return cfg


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
        "PQC hybrid SSH KEX disabled",  # sshd installed, PQC never enabled
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
        ["link", "set", "dev", "lo", "up"],
    ]
    assert kea_path.exists()
    assert "Kea DHCP config applied" in result.messages[4]


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


def test_apply_all_reports_names_it_could_not_put_in_the_xdp_blocklist(
    minimal_config_dict, tmp_path, monkeypatch
):
    """B3 (review triage): a merged-in name of MAX_SNI_LEN bytes or more
    can never match in the kernel filter, so it is left out of the trie --
    but it used to be left out *silently*, and app-level DNS blocking is a
    completely different (and much later) layer. The operator has to be
    told which names are covered by that layer only."""
    monkeypatch.setattr(
        adblock_dns_mod, "sync_dns_resolver", lambda *a, **kw: adblock_dns_mod.DnsSyncResult(False, "fake")
    )
    too_long = "a" * 28 + ".com"  # exactly 32 bytes
    assert len(too_long) == xdp_mod.MAX_SNI_LEN
    monkeypatch.setattr(
        adblock_dns_mod,
        "blocked_app_names",
        lambda config: ["short.example.com", too_long],
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
    config = parse_config(minimal_config_dict)
    # Set on the parsed object rather than through the raw dict: the
    # config loader (rightly) demands a DNS resolver with a DHCP pool
    # before it accepts blocked_apps, and none of that is what this test
    # is about -- the merge and the report in apply_all are.
    config = dataclasses.replace(
        config,
        app_control=AppControlConfig(
            enabled=True, blocked_apps=["tiktok"], block_via_xdp=True
        ),
    )

    result = apply_all(config, **_apply_kwargs(tmp_path))

    # Dropped from the trie's input (it could never match there)...
    assert captured["config"].xdp_sni_filter.blocklist == [
        "manual.example.com",
        "short.example.com",
    ]
    # ...and named in apply's own output, so "not blocked" is never silent.
    reported = [m for m in result.messages if "NOT blocked in XDP" in m]
    assert len(reported) == 1
    assert too_long in reported[0]


def test_a_missing_interface_still_loads_the_ruleset_in_the_boots_last_resort(minimal_config_dict, tmp_path,
                                                                              monkeypatch):
    """A2 (review triage): addresses used to be synced first, so a device
    name the machine doesn't have (e.g. the example config's eth0 on a box
    with enp1s0) aborted the apply before any ruleset was loaded. At boot,
    when neither config.yaml nor the last applied config can be applied
    (ROADMAP SEC-5, firewall-cli apply --fail-closed), the last resort
    still loads the ruleset first, and nothing rolls it back."""
    loaded = []
    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: loaded.append(args))

    def missing_device(config, previous=None, dry_run=False):
        raise ifaddr_mod.IfaddrError("Cannot find device \"eth9\"")

    monkeypatch.setattr(ifaddr_mod, "sync_addresses", missing_device)
    with pytest.raises(ApplyError, match="eth9") as raised:
        apply_all(parse_config(minimal_config_dict), transactional=False, **_apply_kwargs(tmp_path))
    assert loaded.count(["-f", "-"]) == 1
    assert raised.value.step == "interface addresses" and raised.value.rolled_back == ()


def test_a_missing_device_changes_nothing_on_a_running_router(dhcp_config_dict, tmp_path, monkeypatch):
    """ROADMAP SEC-5: the preflight finds a device the steps would act on
    missing before anything is touched -- the firewall included."""
    sysfs = tmp_path / "class_net"
    (sysfs / "eth0").mkdir(parents=True)  # lo, which the config addresses, is not there
    monkeypatch.setattr(ifaddr_mod, "NET_CLASS_DIR", sysfs)
    monkeypatch.setattr(ifaddr_mod, "device_exists", _REAL_DEVICE_EXISTS)
    loaded = []
    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: loaded.append(args))
    with pytest.raises(ApplyError, match="no such network device on this machine: lo") as raised:
        apply_all(parse_config(dhcp_config_dict), **_apply_kwargs(tmp_path))
    assert raised.value.changed is False and "Nothing was applied" in str(raised.value)
    assert ["-f", "-"] not in loaded


def test_forwarding_is_turned_on_only_after_the_ruleset_loads(minimal_config_dict, tmp_path, monkeypatch):
    """Found in review: nothing turned IPv4 forwarding on, so the router
    didn't route. It must come after the ruleset (never a moment of
    unfiltered routing), and a failed ruleset load must leave it off."""
    from frfw import forwarding

    order = []
    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: order.append("nft"))
    real_enable = forwarding.enable
    monkeypatch.setattr(forwarding, "enable", lambda **kw: order.append("forwarding") or real_enable(**kw))
    apply_all(parse_config(minimal_config_dict), backup_dir=tmp_path / "b", kea_config_path=tmp_path / "k.json",
              xdp_state_path=tmp_path / "x.json")
    assert order.index("forwarding") > order.index("nft")
    assert forwarding.IP_FORWARD_PATH.read_text().strip() == "1"

    forwarding.IP_FORWARD_PATH.write_text("0\n")

    def nft_fails(args, stdin):
        raise apply_mod.NftError("syntax error")

    monkeypatch.setattr(apply_mod, "_run_nft", nft_fails)
    with pytest.raises(ApplyError, match="syntax error"):
        apply_all(parse_config(minimal_config_dict), backup_dir=tmp_path / "b", kea_config_path=tmp_path / "k.json",
                  xdp_state_path=tmp_path / "x.json")
    assert forwarding.IP_FORWARD_PATH.read_text().strip() == "0"


def test_the_vpn_comes_up_only_behind_the_ruleset(minimal_config_dict, tmp_path, monkeypatch):
    """Security-lessons G8: like forwarding, the tunnel is synced after the
    ruleset is loaded, and not at all when loading it fails."""
    from frfw import wireguard

    order = []
    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: order.append("nft"))
    monkeypatch.setattr(wireguard, "sync", lambda config, **kw: order.append("wireguard") or
                        wireguard.SyncResult("WireGuard off"))
    apply_all(parse_config(minimal_config_dict), backup_dir=tmp_path / "b", kea_config_path=tmp_path / "k.json",
              xdp_state_path=tmp_path / "x.json")
    assert "nft" in order and order[-1] == "wireguard" and order.count("wireguard") == 1

    order.clear()

    def nft_fails(args, stdin):
        raise apply_mod.NftError("syntax error")

    monkeypatch.setattr(apply_mod, "_run_nft", nft_fails)
    with pytest.raises(ApplyError, match="syntax error"):
        apply_all(parse_config(minimal_config_dict), backup_dir=tmp_path / "b", kea_config_path=tmp_path / "k.json",
                  xdp_state_path=tmp_path / "x.json")
    assert "wireguard" not in order


# --- runtime sets across the reload (review FR-002) ---------------------------


def _apply_kwargs(tmp_path):
    return dict(
        backup_dir=tmp_path / "backups",
        kea_config_path=tmp_path / "kea.json",
        xdp_state_path=tmp_path / "xdp_state.json",
        pqc_conf_path=tmp_path / "pqc_openssl.cnf",
        ssh_kex_dropin_path=tmp_path / "50-fr_os-pqc-kex.conf",
        adblock_hosts_path=tmp_path / "adblock.hosts",
        adblock_dnsmasq_conf_path=tmp_path / "dnsmasq_adblock.conf",
    )


@pytest.fixture
def loaded_rulesets(monkeypatch):
    """Every nft script the apply loads, and every other nft call."""
    loaded, other = [], []

    def run_nft(args, stdin):
        (loaded.append(stdin) if args == ["-f", "-"] else other.append(args))

    monkeypatch.setattr(apply_mod, "_run_nft", run_nft)
    return loaded, other


def _runtime_readers(monkeypatch, calls, **values):
    for name, mod in (("bruteforce", bruteforce_mod), ("ids_quarantine", ids_quarantine_mod),
                      ("ztna", ztna_mod), ("iot", iot_isolation_mod)):
        monkeypatch.setattr(mod, "snapshot_before_reload",
                            lambda name=name: calls.append(name) or list(values.get(name, [])))


@pytest.mark.reads_runtime_sets
def test_runtime_sets_come_back_in_the_same_ruleset(minimal_config_dict, tmp_path, monkeypatch, loaded_rulesets):
    raw = _iot_config_dict(minimal_config_dict)
    raw["ztna"] = {"enabled": True, "users": [{"username": "a", "password_hash": "x"}]}
    calls = []
    _runtime_readers(monkeypatch, calls, bruteforce=[("203.0.113.5", 300), ("203.0.113.6", 0)],
                     ids_quarantine=[("10.0.0.9", 7000)],
                     ztna=[("10.0.0.20", "aa:bb:cc:dd:ee:0f", 100), ("10.99.0.2", "", 90), ("10.0.0.21", "aa:bb:cc:dd:ee:0e", 0)],
                     iot=["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"])

    result = apply_all(parse_config(raw), **_apply_kwargs(tmp_path))

    loaded, other = loaded_rulesets
    assert len(loaded) == 1 and loaded[0].startswith("flush ruleset")
    ruleset = loaded[0]
    assert "elements = { 203.0.113.5 timeout 300s }" in ruleset   # the expired ban is dropped
    assert "elements = { 10.0.0.9 timeout 7000s }" in ruleset
    assert "elements = { 10.0.0.20 . aa:bb:cc:dd:ee:0f timeout 100s }" in ruleset
    assert "elements = { 10.99.0.2 timeout 90s }" in ruleset
    assert "10.0.0.21" not in ruleset   # the expired session is dropped
    assert "elements = { aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:02 }" in ruleset
    # Nothing is re-added after the load: there is no window, and no step to fail.
    assert not [a for a in other if a[:2] == ["add", "element"]]
    assert sorted(calls) == ["bruteforce", "ids_quarantine", "iot", "ztna"]
    assert "Brute-force jail: 1 active ban(s) preserved across reload" in result.messages
    assert "AI IDS quarantine: 1 active quarantine(s) preserved across reload" in result.messages
    assert "ZTNA gate: 2 active session(s) preserved across reload" in result.messages
    assert "IoT isolation: 2 isolated device(s) preserved across reload" in result.messages


@pytest.mark.reads_runtime_sets
def test_ztna_and_iot_sets_are_read_only_while_on(minimal_config_dict, tmp_path, monkeypatch, loaded_rulesets):
    calls = []
    _runtime_readers(monkeypatch, calls, ztna=[("10.0.0.20", "aa:bb:cc:dd:ee:0f", 100)], iot=["aa:bb:cc:dd:ee:01"])
    apply_all(parse_config(minimal_config_dict), **_apply_kwargs(tmp_path))
    assert sorted(calls) == ["bruteforce", "ids_quarantine"]
    assert "10.0.0.20" not in loaded_rulesets[0][0]


@pytest.mark.reads_runtime_sets
def test_dry_run_reads_no_runtime_sets(minimal_config_dict, tmp_path, monkeypatch):
    calls = []
    _runtime_readers(monkeypatch, calls)
    result = apply_all(parse_config(_iot_config_dict(minimal_config_dict)), dry_run=True, **_apply_kwargs(tmp_path))
    assert calls == []
    assert any("Brute-force jail: would preserve" in m for m in result.messages)
    assert any("IoT isolation: would preserve" in m for m in result.messages)


@pytest.mark.reads_runtime_sets
def test_an_unreadable_set_stops_the_apply_before_the_reload(minimal_config_dict, tmp_path, monkeypatch,
                                                             loaded_rulesets):
    # Review FR-002: reloading anyway would release every quarantined host.
    def broken():
        raise ids_quarantine_mod.IdsQuarantineError("netlink: Error: Could not process rule")

    monkeypatch.setattr(ids_quarantine_mod, "snapshot_before_reload", broken)
    with pytest.raises(ApplyError, match="could not read the AI IDS quarantine .* nothing was changed") as raised:
        apply_all(parse_config(minimal_config_dict), **_apply_kwargs(tmp_path))
    assert loaded_rulesets[0] == []
    assert raised.value.changed is False
