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

from frfw import apply as apply_mod
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

    socket_path = tmp_path / "apply.sock"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(EXAMPLE_CONFIG.read_text())
    backup_dir = tmp_path / "backups"
    ztna_state_path = tmp_path / "ztna_state.json"

    server = ApplyHelperServer(
        socket_path, config_path, backup_dir=backup_dir, ztna_state_path=ztna_state_path
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
