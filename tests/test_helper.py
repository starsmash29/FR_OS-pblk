"""Tests for the apply-helper Unix socket protocol.

Runs a real ApplyHelperServer in manual-bind mode (no systemd) against a
throwaway socket, config and backup dir, and talks to it with the real
client -- this exercises the actual wire protocol. `frfw.apply._run_nft`
is monkeypatched so a "real apply" request never touches the sandbox's
kernel nftables state.
"""

from __future__ import annotations

import subprocess
import threading
from pathlib import Path

import pytest

from frfw import adblock as adblock_mod
from frfw import apply as apply_mod
from frfw import bruteforce as bruteforce_mod
from frfw import conntrack as conntrack_mod
from frfw import hwinfo as hwinfo_mod
from frfw import ids_quarantine as ids_quarantine_mod
from frfw import iot_isolation as iot_isolation_mod
from frfw import ztna as ztna_mod
from frfw.admin_account import hash_password
from frfw.helper import client
from frfw.helper.server import ApplyHelperServer

EXAMPLE_CONFIG = Path(__file__).resolve().parent.parent / "examples" / "config.yaml"


@pytest.fixture
def running_server(tmp_path, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)

    # Simulate "a ruleset becomes loaded after the first real apply", so a
    # second apply exercises the backup path and rollback has something to
    # roll back to -- without ever calling the real `nft` binary.
    state = {"applied": False}

    def fake_run_nft(args, stdin):
        if args == ["-f", "-"]:
            state["applied"] = True

    def fake_capture():
        return "table inet fr_os {}\n" if state["applied"] else ""

    monkeypatch.setattr(apply_mod, "_run_nft", fake_run_nft)
    monkeypatch.setattr(apply_mod, "capture_running_ruleset", fake_capture)

    # frfw.ztna's own real-nft behavior is exercised directly in
    # test_ztna.py; here we only care about this socket protocol's
    # request/response mapping (bad IP, unknown user, disabled gate,
    # ...), so a tiny in-memory fake stands in for the kernel set --
    # same reasoning as apply_mod._run_nft being faked above.
    ztna_set: dict[str, tuple[str, int]] = {}

    def fake_ztna_run_nft(args):
        if args[:2] == ["add", "element"]:
            ip, ttl = args[-2].split(" timeout ")
            ztna_set[ip] = (None, int(ttl.rstrip("s")))
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if args[:2] == ["-j", "list"]:
            import json as _json
            elems = [{"elem": {"val": ip, "expires": ttl}} for ip, (_u, ttl) in ztna_set.items()]
            return subprocess.CompletedProcess(
                args, 0, stdout=_json.dumps({"nftables": [{"set": {"elem": elems}}]}), stderr=""
            )
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="unsupported in fake")

    monkeypatch.setattr(ztna_mod, "_run_nft", fake_ztna_run_nft)

    # Same fakery, for the same reason, as ztna_set above -- this socket
    # protocol test only cares that "ban_ip" maps to a correctly-formed
    # nft add-element call, not that the real kernel set exists.
    jail_set: dict[str, int] = {}

    def fake_bruteforce_run_nft(args):
        if args[:2] == ["add", "element"]:
            ip, ttl = args[-2].split(" timeout ")
            jail_set[ip] = int(ttl.rstrip("s"))
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if args[:2] == ["-j", "list"]:
            import json as _json
            elems = [{"elem": {"val": ip, "expires": ttl}} for ip, ttl in jail_set.items()]
            return subprocess.CompletedProcess(
                args, 0, stdout=_json.dumps({"nftables": [{"set": {"elem": elems}}]}), stderr=""
            )
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="unsupported in fake")

    monkeypatch.setattr(bruteforce_mod, "_run_nft", fake_bruteforce_run_nft)

    # Same fakery, for the same reason, as jail_set above -- this socket
    # protocol test only cares that "quarantine_ip" maps to a
    # correctly-formed nft add-element call.
    quarantine_set: dict[str, int] = {}

    def fake_ids_quarantine_run_nft(args):
        if args[:2] == ["add", "element"]:
            ip, ttl = args[-2].split(" timeout ")
            quarantine_set[ip] = int(ttl.rstrip("s"))
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if args[:2] == ["-j", "list"]:
            import json as _json
            elems = [{"elem": {"val": ip, "expires": ttl}} for ip, ttl in quarantine_set.items()]
            return subprocess.CompletedProcess(
                args, 0, stdout=_json.dumps({"nftables": [{"set": {"elem": elems}}]}), stderr=""
            )
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="unsupported in fake")

    monkeypatch.setattr(ids_quarantine_mod, "_run_nft", fake_ids_quarantine_run_nft)

    # frfw.conntrack's own /proc/net/nf_conntrack parsing is exercised
    # directly in test_conntrack.py; here we only care that the
    # "conntrack_sample" command relays whatever read_snapshot() returns.
    monkeypatch.setattr(conntrack_mod, "read_snapshot", lambda: [])

    # frfw.hwinfo's own dmidecode-output parsing is exercised directly
    # in test_hwinfo.py; here we only care that "hw_ram_info" relays
    # whatever read_ram_modules() returns. Empty by default (as if
    # dmidecode weren't installed, the common case).
    monkeypatch.setattr(hwinfo_mod, "read_ram_modules", lambda: [])

    socket_path = tmp_path / "apply.sock"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(EXAMPLE_CONFIG.read_text())
    backup_dir = tmp_path / "backups"
    ztna_state_path = tmp_path / "ztna_state.json"
    adblock_hosts_path = tmp_path / "adblock.hosts"

    # frfw.iot_isolation's real-nft behavior (and the real packet-level
    # effect) is exercised in test_iot_isolation.py; here an in-memory
    # list stands in for the kernel set, same reasoning as the fakes above.
    iot_set: list[str] = []

    def fake_sync_isolated(macs):
        macs = iot_isolation_mod.normalize_macs(macs)
        iot_set[:] = macs
        return macs

    monkeypatch.setattr(iot_isolation_mod, "sync_isolated", fake_sync_isolated)
    monkeypatch.setattr(iot_isolation_mod, "list_isolated", lambda: list(iot_set))

    server = ApplyHelperServer(
        socket_path,
        config_path,
        backup_dir=backup_dir,
        ztna_state_path=ztna_state_path,
        adblock_hosts_path=adblock_hosts_path,
        kea_leases_path=tmp_path / "kea-leases4.csv",
        adblock_category_dir=tmp_path / "adblock.d",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield socket_path
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _enable_ztna(config_path: Path, username: str = "alice", password: str = "hunter22") -> None:
    text = config_path.read_text()
    text += (
        "\nztna:\n"
        "  enabled: true\n"
        "  session_ttl_seconds: 3600\n"
        "  users:\n"
        f"    - username: {username}\n"
        f"      password_hash: \"{hash_password(password)}\"\n"
    )
    config_path.write_text(text)


def test_ping(running_server):
    assert client.ping(running_server) == {"ok": True, "message": "pong"}


def test_apply_dry_run(running_server):
    response = client.apply_config(dry_run=True, socket_path=running_server)
    assert response["ok"] is True
    assert "dry-run" in response["message"].lower()


def test_apply_real_then_rollback_roundtrip(running_server):
    first = client.apply_config(dry_run=False, socket_path=running_server)
    assert first["ok"] is True
    assert "Ruleset applied" in first["message"]

    second = client.apply_config(dry_run=False, socket_path=running_server)
    assert second["ok"] is True
    assert "backed up" in second["message"]

    rolled_back = client.rollback(running_server)
    assert rolled_back["ok"] is True
    assert "Rolled back to" in rolled_back["message"]


def test_rollback_without_prior_apply_reports_error(running_server):
    response = client.rollback(running_server)
    assert response["ok"] is False
    assert "backup" in response["message"].lower()


def test_unknown_command_returns_error(running_server):
    response = client.send_command({"cmd": "nope"}, running_server)
    assert response["ok"] is False
    assert "unknown command" in response["message"]


def test_malformed_request_returns_error(running_server):
    import socket as socket_mod

    with socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM) as sock:
        sock.connect(str(running_server))
        sock.sendall(b"not json\n")
        sock.shutdown(socket_mod.SHUT_WR)
        raw = sock.recv(4096)
    assert b'"ok": false' in raw.lower()


def test_client_reports_error_when_socket_missing(tmp_path):
    with pytest.raises(client.HelperError):
        client.ping(tmp_path / "no-such.sock")


# --- ZTNA commands -----------------------------------------------------------


def test_authorize_ztna_fails_when_gate_disabled(running_server):
    response = client.authorize_ztna("10.0.0.5", "alice", running_server)
    assert response["ok"] is False
    assert "disabled" in response["message"].lower()


def test_authorize_ztna_fails_for_unknown_user(running_server, tmp_path):
    _enable_ztna(tmp_path / "config.yaml")
    response = client.authorize_ztna("10.0.0.5", "mallory", running_server)
    assert response["ok"] is False
    assert "no such ztna user" in response["message"].lower()


def test_authorize_ztna_fails_for_invalid_ip(running_server, tmp_path):
    _enable_ztna(tmp_path / "config.yaml")
    response = client.authorize_ztna("not-an-ip", "alice", running_server)
    assert response["ok"] is False
    assert "invalid" in response["message"].lower()


def test_authorize_ztna_success_then_status_round_trip(running_server, tmp_path):
    _enable_ztna(tmp_path / "config.yaml")

    authorize = client.authorize_ztna("10.0.0.5", "alice", running_server)
    assert authorize["ok"] is True
    assert authorize["expires_in"] == 3600

    status = client.ztna_status("10.0.0.5", running_server)
    assert status["ok"] is True
    assert status["authorized"] is True
    assert status["username"] == "alice"
    assert status["expires_in"] == 3600


def test_ztna_status_reports_unauthorized_for_unknown_ip(running_server, tmp_path):
    _enable_ztna(tmp_path / "config.yaml")
    status = client.ztna_status("10.0.0.99", running_server)
    assert status == {"ok": True, "authorized": False}


# --- ad-block refresh command --------------------------------------------------


def test_refresh_adblock_fails_with_no_source_urls(running_server):
    # examples/config.yaml has no `adblocker` section at all --
    # source_urls defaults to empty.
    response = client.refresh_adblock(running_server)
    assert response["ok"] is False
    assert "source_urls and adblocker.categories are both empty" in response["message"]


def test_refresh_adblock_success(running_server, tmp_path, monkeypatch):
    monkeypatch.setattr(
        adblock_mod, "_fetch_url", lambda url, timeout: "0.0.0.0 ads.example.com\n"
    )
    text = tmp_path / "config.yaml"
    text.write_text(
        text.read_text()
        + "\nadblocker:\n  enabled: true\n  source_urls: [\"https://a.example/hosts\"]\n"
    )

    response = client.refresh_adblock(running_server)

    assert response["ok"] is True
    assert response["domain_count"] == 1
    assert response["failed_urls"] == []
    assert adblock_mod.count_blocked_domains(tmp_path / "adblock.hosts") == 1


# --- brute-force jail (ban_ip) command ------------------------------------


def test_ban_ip_rejects_invalid_address(running_server):
    response = client.ban_ip("not-an-ip", 3600, running_server)
    assert response["ok"] is False
    assert "invalid ipv4 address" in response["message"].lower()


def test_ban_ip_rejects_missing_ip(running_server):
    response = client.send_command({"cmd": "ban_ip", "duration_seconds": 3600}, running_server)
    assert response["ok"] is False
    assert "'ip' is required" in response["message"]


def test_ban_ip_rejects_non_integer_duration(running_server):
    response = client.send_command(
        {"cmd": "ban_ip", "ip": "10.0.0.5", "duration_seconds": "soon"}, running_server
    )
    assert response["ok"] is False
    assert "duration_seconds" in response["message"]


def test_ban_ip_success_calls_nft_add_element(running_server):
    response = client.ban_ip("10.0.0.5", 3600, running_server)
    assert response == {"ok": True, "message": "10.0.0.5 jailed for 3600s"}


def test_ban_ip_defaults_to_one_hour(running_server):
    response = client.send_command({"cmd": "ban_ip", "ip": "10.0.0.6"}, running_server)
    assert response == {"ok": True, "message": "10.0.0.6 jailed for 3600s"}


# --- AI IDS quarantine (quarantine_ip / ids_quarantine_status) commands -----


def test_quarantine_ip_rejects_invalid_address(running_server):
    response = client.quarantine_ip("not-an-ip", 7200, running_server)
    assert response["ok"] is False
    assert "invalid ipv4 address" in response["message"].lower()


def test_quarantine_ip_rejects_missing_ip(running_server):
    response = client.send_command({"cmd": "quarantine_ip", "duration_seconds": 7200}, running_server)
    assert response["ok"] is False
    assert "'ip' is required" in response["message"]


def test_quarantine_ip_rejects_non_integer_duration(running_server):
    response = client.send_command(
        {"cmd": "quarantine_ip", "ip": "10.0.0.9", "duration_seconds": "soon"}, running_server
    )
    assert response["ok"] is False
    assert "duration_seconds" in response["message"]


def test_quarantine_ip_success_calls_nft_add_element(running_server):
    response = client.quarantine_ip("10.0.0.9", 7200, running_server)
    assert response == {"ok": True, "message": "10.0.0.9 quarantined for 7200s"}


def test_quarantine_ip_defaults_to_two_hours(running_server):
    response = client.send_command({"cmd": "quarantine_ip", "ip": "10.0.0.10"}, running_server)
    assert response == {"ok": True, "message": "10.0.0.10 quarantined for 7200s"}


def test_ids_quarantine_status_empty_when_nothing_quarantined(running_server):
    response = client.ids_quarantine_status(running_server)
    assert response == {"ok": True, "quarantined": [], "count": 0}


def test_ids_quarantine_status_reflects_kernel_state_after_quarantine(running_server):
    client.quarantine_ip("10.0.0.11", 100, running_server)
    response = client.ids_quarantine_status(running_server)
    assert response["ok"] is True
    assert response["count"] == 1
    assert response["quarantined"][0]["ip"] == "10.0.0.11"


# --- conntrack sample command ------------------------------------------------


def test_conntrack_sample_relays_flows(running_server, monkeypatch):
    from frfw.conntrack import ConntrackFlow

    monkeypatch.setattr(
        conntrack_mod,
        "read_snapshot",
        lambda: [ConntrackFlow(proto="tcp", src="10.0.0.5", sport=1234, dst="1.1.1.1", dport=443)],
    )
    response = client.conntrack_sample(running_server)
    assert response == {
        "ok": True,
        "flows": [{"proto": "tcp", "src": "10.0.0.5", "sport": 1234, "dst": "1.1.1.1", "dport": 443}],
    }


def test_conntrack_sample_empty_by_default(running_server):
    response = client.conntrack_sample(running_server)
    assert response == {"ok": True, "flows": []}


# --- metrics-support status commands (bruteforce_status / ztna_sessions_status / hw_ram_info) ---


def test_bruteforce_status_empty_by_default(running_server):
    response = client.bruteforce_status(running_server)
    assert response == {"ok": True, "banned": [], "count": 0}


def test_bruteforce_status_reflects_kernel_state_after_ban(running_server):
    client.ban_ip("10.0.0.5", 100, running_server)
    response = client.bruteforce_status(running_server)
    assert response["ok"] is True
    assert response["count"] == 1
    assert response["banned"][0]["ip"] == "10.0.0.5"


def test_ztna_sessions_status_empty_when_gate_disabled(running_server):
    response = client.ztna_sessions_status(running_server)
    assert response == {"ok": True, "sessions": [], "count": 0}


def test_ztna_sessions_status_reflects_kernel_state_after_authorization(running_server, tmp_path):
    _enable_ztna(tmp_path / "config.yaml")
    client.authorize_ztna("10.0.0.6", "alice", running_server)

    response = client.ztna_sessions_status(running_server)
    assert response["ok"] is True
    assert response["count"] == 1
    assert response["sessions"][0]["ip"] == "10.0.0.6"


def test_hw_ram_info_empty_when_dmidecode_unavailable(running_server):
    response = client.hw_ram_info(running_server)
    assert response == {"ok": True, "modules": []}


def test_hw_ram_info_relays_parsed_modules(running_server, monkeypatch):
    from frfw.hwinfo import RamModule

    monkeypatch.setattr(
        hwinfo_mod, "read_ram_modules", lambda: [RamModule(part_number="M471A1K43CB1-CTD", speed_mhz=2667)]
    )
    response = client.hw_ram_info(running_server)
    assert response == {
        "ok": True,
        "modules": [{"part_number": "M471A1K43CB1-CTD", "speed_mhz": 2667}],
    }


def _enable_iot(config_path: Path, trusted: list[str] | None = None) -> None:
    text = config_path.read_text()
    text += "\niot:\n  enabled: true\n  zones: [lan]\n"
    if trusted:
        text += "  trusted_macs: [" + ", ".join(trusted) + "]\n"
    config_path.write_text(text)


def test_dhcp_leases_empty_without_lease_file(running_server):
    assert client.dhcp_leases(running_server) == {"ok": True, "leases": [], "count": 0}


def test_dhcp_leases_relays_active_leases(running_server, tmp_path):
    import time as _time

    expire = int(_time.time()) + 600
    (tmp_path / "kea-leases4.csv").write_text(
        "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context\n"
        f"10.0.1.50,24:0A:C4:11:22:33,,3600,{expire},1,0,0,esp_112233,0,\n"
    )
    response = client.dhcp_leases(running_server)
    assert response["ok"] is True
    assert response["leases"] == [
        {"ip": "10.0.1.50", "mac": "24:0a:c4:11:22:33", "hostname": "esp_112233", "expire": expire}
    ]


def test_iot_sync_isolation_refused_when_disabled(running_server):
    response = client.iot_sync_isolation(["aa:bb:cc:dd:ee:01"], running_server)
    assert response == {"ok": False, "message": "IoT isolation is disabled in the current config"}


def test_iot_sync_isolation_drops_trusted_macs(running_server, tmp_path):
    _enable_iot(tmp_path / "config.yaml", trusted=["aa:bb:cc:dd:ee:02"])
    response = client.iot_sync_isolation(["AA:BB:CC:DD:EE:01", "aa:bb:cc:dd:ee:02"], running_server)
    assert response["ok"] is True
    assert response["isolated"] == ["aa:bb:cc:dd:ee:01"]
    assert response["skipped_trusted"] == ["aa:bb:cc:dd:ee:02"]

    status = client.iot_isolation_status(running_server)
    assert status == {"ok": True, "isolated": ["aa:bb:cc:dd:ee:01"], "count": 1}


def test_iot_sync_isolation_rejects_malformed_input(running_server, tmp_path):
    _enable_iot(tmp_path / "config.yaml")
    bad = client.iot_sync_isolation(["not-a-mac"], running_server)
    assert bad["ok"] is False and "invalid MAC" in bad["message"]
    not_list = client.send_command({"cmd": "iot_sync_isolation", "macs": "aa:bb:cc:dd:ee:01"}, running_server)
    assert not_list == {"ok": False, "message": "'macs' must be a list"}


def test_refresh_adblock_writes_categories_and_reports_counts(running_server, tmp_path, monkeypatch):
    pages = {
        "https://lists.example/ads": "0.0.0.0 ads.example\n",
        "https://lists.example/malware": "127.0.0.1\tbad.example\n",
    }
    monkeypatch.setattr(adblock_mod, "_fetch_url", lambda url, timeout: pages[url])
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        config_path.read_text()
        + "\nadblocker:\n  enabled: true\n  source_urls: [https://lists.example/ads]\n"
        + "  categories:\n    malware: [https://lists.example/malware]\n"
    )
    response = client.refresh_adblock(running_server)
    assert response["ok"] is True, response
    assert response["category_counts"] == {"ads": 1, "malware": 1}
    assert (tmp_path / "adblock.d" / "malware.hosts").read_text().endswith("0.0.0.0 bad.example\n")
