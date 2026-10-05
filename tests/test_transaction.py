"""The transaction machinery of an apply (ROADMAP SEC-5, frfw.transaction).

tests/test_apply_rollback_live.py shows the whole thing on a real kernel;
here are its parts and its edges: the journal's order and its reports,
the snapshots of files, services and network devices, the record of the
applied config, the preflight, and the boot's fallback.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import uuid

import pytest
import yaml

from frfw import apply as apply_mod
from frfw import cli, ifaddr, kea, paths, provision, xdp
from frfw import transaction as tx
from frfw.config import parse_config
from frfw.provision import apply_all
from frfw.transaction import ApplyError, FileState, LinkState, ServiceState, Transaction


@pytest.fixture(autouse=True)
def _pretend_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)


@pytest.fixture
def loaded(monkeypatch):
    """Every ruleset loaded, as text; nothing reaches the kernel."""
    scripts = []
    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: scripts.append(stdin) if args == ["-f", "-"] else None)
    monkeypatch.setattr(apply_mod, "capture_running_ruleset", lambda: "")
    return scripts


def _kwargs(tmp_path):
    return dict(backup_dir=tmp_path / "backups", kea_config_path=tmp_path / "kea.json",
                xdp_state_path=tmp_path / "xdp.json", pqc_conf_path=tmp_path / "pqc.cnf",
                ssh_kex_dropin_path=tmp_path / "kex.conf", adblock_hosts_path=tmp_path / "adblock.hosts",
                adblock_dnsmasq_conf_path=tmp_path / "dnsmasq.conf", schedule_state_path=tmp_path / "schedule.json")


# --- the journal ----------------------------------------------------------------


def test_the_journal_is_undone_last_first_and_reports_what_it_could_not_undo():
    done = []
    journal = Transaction()
    journal.begin("first", lambda: done.append("first"))
    journal.begin("second", None, why_not="nothing to go back to")
    journal.begin("third", lambda: (_ for _ in ()).throw(RuntimeError("device busy")))
    journal.begin("fourth", lambda: done.append("fourth"))
    rolled_back, not_rolled_back = journal.roll_back()
    assert done == ["fourth", "first"], "an undo that failed stopped the ones after it"
    assert rolled_back == ("fourth", "first")
    assert not_rolled_back == ("third (device busy)", "second (nothing to go back to)")
    assert journal.roll_back() == ((), ())  # a journal is undone once


def test_the_error_says_what_failed_and_what_was_and_was_not_put_back():
    before = ApplyError("network devices", ValueError("no eth9"), changed=False)
    assert str(before) == "Nothing was applied -- network devices: no eth9. The running system is unchanged."
    after = ApplyError("DHCP (Kea)", RuntimeError("kea failed"), changed=True,
                       rolled_back=("interface addresses", "the firewall"), not_rolled_back=("WireGuard (gone)",))
    assert str(after) == ("Apply failed at DHCP (Kea): kea failed. Rolled back to the previous state: "
                          "interface addresses, the firewall. NOT rolled back: WireGuard (gone).")
    clean = ApplyError("DHCP (Kea)", RuntimeError("kea failed"), changed=True, rolled_back=("the firewall",))
    assert str(clean).endswith("Nothing else was changed.")


# --- snapshots ------------------------------------------------------------------


def test_a_file_comes_back_byte_for_byte_with_its_mode_or_goes_away(tmp_path):
    path = tmp_path / "kea.json"
    absent = FileState.capture(path)
    path.write_text("new")
    assert absent.differs()
    absent.restore()
    assert not path.exists()

    path.write_bytes(b"old\x00bytes")
    os.chmod(path, 0o640)
    old = FileState.capture(path)
    path.write_text("new")
    os.chmod(path, 0o644)
    old.restore()
    assert path.read_bytes() == b"old\x00bytes" and stat.S_IMODE(path.stat().st_mode) == 0o640
    assert not old.differs()
    assert not list(tmp_path.glob(".kea.json.*")), "a temporary file was left behind"


def test_the_record_of_the_applied_config_is_roots_alone(tmp_path):
    tx.write_private(tmp_path / "applied-config.yaml", "version: 1\n")
    assert stat.S_IMODE((tmp_path / "applied-config.yaml").stat().st_mode) == 0o600


@pytest.mark.parametrize("was, now, changed, expected", [
    (True, True, True, ["restart"]),
    (True, True, False, ["start"]),
    (False, True, True, ["stop"]),
    (False, False, True, []),
])
def test_a_service_is_put_back_running_or_stopped(monkeypatch, was, now, changed, expected):
    calls = []

    def systemctl(action, unit, timeout=None):
        calls.append(action)
        out = ("active" if now else "inactive") if action == "is-active" else ""
        return subprocess.CompletedProcess([], 0, out, "")

    monkeypatch.setattr(tx.svc, "systemctl", systemctl)
    ServiceState("kea-dhcp4-server", was).restore(config_changed=changed)
    assert [c for c in calls if c != "is-active"] == expected


def test_a_service_whose_state_could_not_be_read_is_left_alone(monkeypatch):
    monkeypatch.setattr(tx.svc, "systemctl", lambda *a, **k: pytest.fail("touched a service of unknown state"))
    ServiceState("kea-dhcp4-server", None).restore(config_changed=True)


@pytest.mark.skipif(os.geteuid() != 0 or shutil.which("ip") is None, reason="needs root and iproute2")
def test_a_device_loses_what_an_apply_added_and_one_it_created_goes_away():
    ns = f"frtx{uuid.uuid4().hex[:6]}"
    run = lambda *a: subprocess.run(["ip", "netns", "exec", ns, *a], check=True, capture_output=True, text=True)
    subprocess.run(["ip", "netns", "add", ns], check=True)
    try:
        # LinkState runs `ip` in the namespace of the process: run it there.
        script = (
            "import json\n"
            "from frfw.transaction import LinkState, _ip\n"
            "before = [LinkState.capture(d) for d in ('lan0', 'new0')]\n"
            "_ip(['addr', 'add', '10.9.2.1/24', 'dev', 'lan0'])\n"
            "_ip(['link', 'set', 'dev', 'lan0', 'up'])\n"
            "_ip(['link', 'add', 'new0', 'type', 'veth', 'peer', 'name', 'new0p'])\n"
            "for link in before: link.restore()\n"
            "after = LinkState.capture('lan0')\n"
            "print(json.dumps([sorted(after.addresses), after.up, LinkState.capture('new0').exists]))\n"
        )
        run("ip", "link", "add", "lan0", "type", "veth", "peer", "name", "lan0p")
        run("ip", "addr", "add", "10.9.1.1/24", "dev", "lan0")
        out = subprocess.run(["ip", "netns", "exec", ns, "python3", "-c", script],
                             check=True, capture_output=True, text=True).stdout
        assert json.loads(out) == [["10.9.1.1/24"], False, False]
    finally:
        subprocess.run(["ip", "netns", "del", ns], check=False)


# --- apply_all: the record, the preflight, the rollback's reports ----------------


def test_a_successful_apply_records_its_text_and_a_failed_one_does_not(minimal_config_dict, tmp_path, loaded,
                                                                       monkeypatch):
    text = yaml.safe_dump(minimal_config_dict)
    apply_all(parse_config(minimal_config_dict), source_text=text, **_kwargs(tmp_path))
    assert paths.APPLIED_CONFIG_PATH.read_text() == text
    assert stat.S_IMODE(paths.APPLIED_CONFIG_PATH.stat().st_mode) == 0o600
    assert provision.load_applied_config() == parse_config(minimal_config_dict)
    apply_all(parse_config(minimal_config_dict), dry_run=True, source_text="dry: run\n", **_kwargs(tmp_path))
    assert paths.APPLIED_CONFIG_PATH.read_text() == text

    def broken(*a, **k):
        raise RuntimeError("tunnel driver missing")

    monkeypatch.setattr(provision.wireguard, "sync", broken)
    changed = dict(minimal_config_dict, hostname="other")
    with pytest.raises(ApplyError):
        apply_all(parse_config(changed), source_text=yaml.safe_dump(changed), **_kwargs(tmp_path))
    assert paths.APPLIED_CONFIG_PATH.read_text() == text


def test_an_unreadable_record_means_no_previous_config(tmp_path):
    paths.APPLIED_CONFIG_PATH.write_text("version: 99\n")
    assert provision.load_applied_config() is None


def test_the_firewall_goes_back_to_the_recorded_config(minimal_config_dict, tmp_path, loaded, monkeypatch):
    previous = dict(minimal_config_dict)
    previous["rules"] = previous["rules"] + [{"name": "was-here", "action": "accept", "from_zone": "lan",
                                              "to_zone": "self", "proto": "tcp", "dst_port": 8443}]
    apply_all(parse_config(previous), source_text=yaml.safe_dump(previous), **_kwargs(tmp_path))
    loaded.clear()

    def broken(*a, **k):
        raise RuntimeError("dnsmasq: failed to start")

    monkeypatch.setattr(provision.adblock_dns, "sync_dns_resolver", broken)
    with pytest.raises(ApplyError, match="the ad-block DNS resolver: dnsmasq: failed to start") as raised:
        apply_all(parse_config(minimal_config_dict), **_kwargs(tmp_path))
    assert len(loaded) == 2 and "was-here" not in loaded[0] and "was-here" in loaded[1]
    assert raised.value.rolled_back[-1] == "the firewall"
    assert raised.value.not_rolled_back == ()


def test_with_nothing_loaded_before_the_new_ruleset_stays_and_says_so(minimal_config_dict, tmp_path, loaded,
                                                                       monkeypatch):
    def broken(*a, **k):
        raise RuntimeError("no such device")

    monkeypatch.setattr(provision.ifaddr, "sync_addresses", broken)
    with pytest.raises(ApplyError) as raised:
        apply_all(parse_config(minimal_config_dict), **_kwargs(tmp_path))
    assert len(loaded) == 1, "the router was left without a ruleset"
    assert raised.value.not_rolled_back == (
        "the firewall (nothing was loaded before it, so the new ruleset stays: the router is never left unfiltered)",)


@pytest.mark.parametrize("step, breaker", [
    ("DHCP (Kea)", lambda m: m.setattr(kea, "check_syntax", lambda text: (_ for _ in ()).throw(
        kea.KeaError("subnet overlaps")))),
    ("the XDP SNI filter", lambda m: m.setattr(xdp, "BLOCKLIST_MAX_ENTRIES", 0)),
    ("network devices", lambda m: m.setattr(ifaddr, "device_exists", lambda device: False)),
])
def test_the_preflight_refuses_before_anything_changes(dhcp_config_dict, tmp_path, loaded, monkeypatch,
                                                       step, breaker):
    dhcp_config_dict["xdp_sni_filter"] = {"enabled": True, "interfaces": ["lan"], "blocklist": ["blocked.example"]}
    breaker(monkeypatch)
    with pytest.raises(ApplyError) as raised:
        apply_all(parse_config(dhcp_config_dict), **_kwargs(tmp_path))
    assert raised.value.step == step and raised.value.changed is False
    assert loaded == [] and not (tmp_path / "kea.json").exists()


@pytest.mark.skipif(shutil.which("kea-dhcp4") is None, reason="needs kea-dhcp4")
def test_the_preflight_takes_a_vlan_the_apply_will_create(dhcp_config_dict, tmp_path, loaded, monkeypatch):
    """Found by the boot test: Kea's own check refuses a device that isn't
    there, and the segments' VLAN devices (security-lessons K4) are only
    created by the apply's address step -- so the real kea-dhcp4 -t
    refused every config with a segment before anything ran."""
    dhcp_config_dict["zones"]["iot"] = {}
    dhcp_config_dict["interfaces"]["iot"] = {"device": "lo.30", "zone": "iot", "address": "10.0.30.1/24",
                                             "vlan": {"parent": "lo", "id": 30}}
    dhcp_config_dict["dhcp"]["iot"] = {"range_start": "10.0.30.100", "range_end": "10.0.30.200",
                                       "dns_servers": ["1.1.1.1"]}
    monkeypatch.setattr(ifaddr, "device_exists", lambda device: device != "lo.30")
    provision.preflight(parse_config(dhcp_config_dict))  # real kea-dhcp4 -t; raises if refused


# --- the boot's fallback (firewall-cli apply --fail-closed) ----------------------


@pytest.fixture
def boot(tmp_path, monkeypatch, minimal_config_dict):
    """config.yaml on disk; apply_all stood in, failing for what `fails` names."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(minimal_config_dict))
    calls, alerts = [], []
    fails = set()

    def fake_apply(config, *, dry_run=False, source_text=None, transactional=True, **kw):
        which = "last" if config.hostname == "last-good" else "yaml"
        calls.append((which, transactional))
        if (which, transactional) in fails:
            raise ApplyError("DHCP (Kea)", RuntimeError(f"{which} failed"), changed=True)
        return provision.ProvisionResult(messages=[f"{which} applied"])

    monkeypatch.setattr(cli, "apply_all", fake_apply)
    monkeypatch.setattr(cli, "_console_alert", lambda message, **kw: alerts.append(message))
    return {"path": config_path, "calls": calls, "alerts": alerts, "fails": fails, "raw": minimal_config_dict}


def _record(raw, hostname):
    paths.APPLIED_CONFIG_PATH.write_text(yaml.safe_dump(dict(raw, hostname=hostname)))


def test_boot_falls_back_to_the_last_applied_config(boot, capsys):
    _record(boot["raw"], "last-good")
    boot["fails"].add(("yaml", True))
    assert cli.main(["apply", "--fail-closed", str(boot["path"])]) == 0
    assert boot["calls"] == [("yaml", True), ("last", True)]
    out = capsys.readouterr()
    assert "WARNING: config.yaml could not be applied at boot" in out.out and "last applied" in out.out
    assert len(boot["alerts"]) == 1 and "runs the last config that was applied in full" in boot["alerts"][0]


def test_boot_applies_config_yaml_as_far_as_it_goes_when_there_is_nothing_else(boot):
    boot["fails"].add(("yaml", True))
    assert cli.main(["apply", "--fail-closed", str(boot["path"])]) == 0
    assert boot["calls"] == [("yaml", True), ("yaml", False)]
    assert "applied as far as it goes" in boot["alerts"][0]


def test_boot_does_not_fall_back_to_the_same_config(boot):
    _record(boot["raw"], boot["raw"]["hostname"])
    boot["fails"].add(("yaml", True))
    cli.main(["apply", "--fail-closed", str(boot["path"])])
    assert boot["calls"] == [("yaml", True), ("yaml", False)]


def test_boot_still_loads_config_yaml_when_the_last_applied_one_fails_too(boot):
    _record(boot["raw"], "last-good")
    boot["fails"].update({("yaml", True), ("last", True), ("yaml", False)})
    assert cli.main(["apply", "--fail-closed", str(boot["path"])]) == 1
    assert boot["calls"] == [("yaml", True), ("last", True), ("yaml", False)]


def test_an_apply_from_the_console_never_falls_back(boot):
    """Only the boot does: an admin applying by hand sees the failure."""
    _record(boot["raw"], "last-good")
    boot["fails"].add(("yaml", True))
    assert cli.main(["apply", str(boot["path"])]) == 1
    assert boot["calls"] == [("yaml", True)] and boot["alerts"] == []
