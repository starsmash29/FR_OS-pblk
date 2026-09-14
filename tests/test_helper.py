"""Tests for the apply-helper Unix socket protocol.

Runs a real ApplyHelperServer in manual-bind mode (no systemd) against a
throwaway socket, config and backup dir, and talks to it with the real
client -- this exercises the actual wire protocol. `frfw.apply._run_nft`
is monkeypatched so a "real apply" request never touches the sandbox's
kernel nftables state.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from frfw import apply as apply_mod
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

    socket_path = tmp_path / "apply.sock"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(EXAMPLE_CONFIG.read_text())
    backup_dir = tmp_path / "backups"

    server = ApplyHelperServer(socket_path, config_path, backup_dir=backup_dir)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield socket_path
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


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
