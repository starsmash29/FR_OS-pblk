"""Root-run update-helper daemon: the privileged side of the webUI's
update mechanism (phase 6, see frfw.update and ARCHITECTURE.md).

Deliberately a separate daemon/socket from frfw.helper.server (the
firewall apply-helper) -- see frfw.helper.update_protocol's module
docstring for why. Structurally this mirrors that module closely
(systemd socket activation, one-JSON-object-per-line, StreamRequestHandler
per connection); the duplication is small and keeping the two daemons
fully independent (no shared base class) means a change to one's
request handling can never accidentally affect the other's.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import socketserver
import sys
from pathlib import Path

from frfw import paths
from frfw import update as update_mod
from frfw.helper.update_protocol import MAX_LINE_BYTES

_SD_LISTEN_FDS_START = 3


def _systemd_provided_socket() -> socket.socket | None:
    """Return the socket systemd handed us via socket activation, if any."""
    listen_pid = os.environ.get("LISTEN_PID")
    listen_fds = os.environ.get("LISTEN_FDS")
    if not listen_pid or not listen_fds:
        return None
    if int(listen_pid) != os.getpid() or int(listen_fds) < 1:
        return None
    return socket.fromfd(_SD_LISTEN_FDS_START, socket.AF_UNIX, socket.SOCK_STREAM)


def _handle_request(request: dict, server: "UpdateHelperServer") -> dict:
    cmd = request.get("cmd")
    try:
        if cmd == "ping":
            return {"ok": True, "message": "pong"}

        if cmd == "apply":
            version = request.get("version")
            if not isinstance(version, str) or not version:
                return {"ok": False, "message": "'version' must be a non-empty string"}
            new_version = update_mod.apply_update(
                version,
                repo=server.repo,
                state_path=server.state_path,
                releases_dir=server.releases_dir,
            )
            return {"ok": True, "message": f"Updated to {new_version}"}

        if cmd == "rollback":
            restored = update_mod.rollback_update(
                repo=server.repo,
                state_path=server.state_path,
                releases_dir=server.releases_dir,
            )
            return {"ok": True, "message": f"Rolled back to {restored}"}

        return {"ok": False, "message": f"unknown command {cmd!r}"}
    except update_mod.UpdateError as exc:
        return {"ok": False, "message": str(exc)}


class _Handler(socketserver.StreamRequestHandler):
    server: "UpdateHelperServer"

    def handle(self) -> None:
        line = self.rfile.readline(MAX_LINE_BYTES)
        if not line:
            return
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("request must be a JSON object")
            response = _handle_request(request, self.server)
        except (ValueError, TypeError) as exc:
            response = {"ok": False, "message": f"invalid request: {exc}"}
        self.wfile.write(json.dumps(response).encode() + b"\n")


class UpdateHelperServer(socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(
        self,
        socket_path: Path = paths.UPDATE_SOCKET_PATH,
        *,
        repo: str = update_mod.DEFAULT_REPO,
        state_path: Path = paths.UPDATE_STATE_PATH,
        releases_dir: Path = paths.RELEASES_DIR,
        systemd_socket: socket.socket | None = None,
    ) -> None:
        self.repo = repo
        self.state_path = state_path
        self.releases_dir = releases_dir
        self._owns_socket_file = systemd_socket is None

        if systemd_socket is not None:
            super().__init__(str(socket_path), _Handler, bind_and_activate=False)
            self.socket.close()
            self.socket = systemd_socket
        else:
            socket_path = Path(socket_path)
            socket_path.parent.mkdir(parents=True, exist_ok=True)
            socket_path.unlink(missing_ok=True)
            super().__init__(str(socket_path), _Handler)

    def server_close(self) -> None:
        super().server_close()
        if self._owns_socket_file:
            Path(self.server_address).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="firewall-update-helper")
    parser.add_argument("--socket", default=str(paths.UPDATE_SOCKET_PATH))
    parser.add_argument("--repo", default=update_mod.DEFAULT_REPO)
    parser.add_argument("--state-path", default=str(paths.UPDATE_STATE_PATH))
    parser.add_argument("--releases-dir", default=str(paths.RELEASES_DIR))
    args = parser.parse_args(argv)

    server = UpdateHelperServer(
        Path(args.socket),
        repo=args.repo,
        state_path=Path(args.state_path),
        releases_dir=Path(args.releases_dir),
        systemd_socket=_systemd_provided_socket(),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
