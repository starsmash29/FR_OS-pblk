"""Tests for the update-helper Unix socket protocol (frfw.helper.update_server).

Mirrors test_helper.py's approach for the firewall apply-helper: a real
UpdateHelperServer against a throwaway socket, talked to with the real
client -- exercising the actual wire protocol -- with `frfw.update`'s own
apply/rollback functions monkeypatched so no real pip/systemctl/network
call ever happens.
"""

from __future__ import annotations

import threading

import pytest

from frfw import update as update_mod
from frfw.helper import update_client as client
from frfw.helper.update_server import UpdateHelperServer


@pytest.fixture
def running_server(tmp_path, monkeypatch):
    calls = {"apply": [], "rollback": 0}

    def fake_apply(version, *, repo, state_path, releases_dir):
        calls["apply"].append(version)
        if version == "bad":
            raise update_mod.UpdateError("simulated failure")
        return version

    def fake_rollback(*, repo, state_path, releases_dir):
        calls["rollback"] += 1
        return "0.1.0"

    monkeypatch.setattr(update_mod, "apply_update", fake_apply)
    monkeypatch.setattr(update_mod, "rollback_update", fake_rollback)

    socket_path = tmp_path / "update.sock"
    server = UpdateHelperServer(
        socket_path,
        repo="x/y",
        state_path=tmp_path / "state.json",
        releases_dir=tmp_path / "releases",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield socket_path, calls
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_ping(running_server):
    socket_path, _ = running_server
    assert client.ping(socket_path) == {"ok": True, "message": "pong"}


def test_apply_success(running_server):
    socket_path, calls = running_server
    response = client.apply("0.2.0", socket_path=socket_path)
    assert response == {"ok": True, "message": "Updated to 0.2.0"}
    assert calls["apply"] == ["0.2.0"]


def test_apply_failure_is_reported_not_raised(running_server):
    socket_path, _ = running_server
    response = client.apply("bad", socket_path=socket_path)
    assert response["ok"] is False
    assert "simulated failure" in response["message"]


def test_apply_requires_version_string(running_server):
    socket_path, _ = running_server
    response = client.send_command({"cmd": "apply"}, socket_path)
    assert response["ok"] is False
    assert "version" in response["message"]


def test_rollback(running_server):
    socket_path, calls = running_server
    response = client.rollback(socket_path=socket_path)
    assert response == {"ok": True, "message": "Rolled back to 0.1.0"}
    assert calls["rollback"] == 1


def test_unknown_command_returns_error(running_server):
    socket_path, _ = running_server
    response = client.send_command({"cmd": "nope"}, socket_path)
    assert response["ok"] is False
    assert "unknown command" in response["message"]


def test_client_reports_error_when_socket_missing(tmp_path):
    with pytest.raises(client.HelperError):
        client.ping(tmp_path / "no-such.sock")
