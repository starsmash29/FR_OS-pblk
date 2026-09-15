"""Root-run apply-helper daemon: the privileged side of the webUI's
Unix-socket interface (see ARCHITECTURE.md's security model).

The webUI (phase 3) will run unprivileged and never touch nftables or
/etc/fr_os directly; instead it sends a one-line JSON request here and
gets a one-line JSON response back. Access control is left to the
socket's filesystem permissions (see systemd/fr-apply-helper.socket,
which sets SocketGroup= so only a dedicated group can connect) rather
than anything in this protocol -- deliberately, since Unix socket
permissions are a well-understood primitive and this daemon has no
concept of "users" of its own.

Supports systemd socket activation (LISTEN_FDS/LISTEN_PID) so systemd can
own the socket file's permissions; falls back to binding the socket
itself for local development/testing.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import socketserver
import sys
from pathlib import Path

import yaml

from frfw import kea, paths, ztna
from frfw.apply import NftError, rollback_last
from frfw.config import ConfigError, load_config, parse_config
from frfw.helper.protocol import MAX_LINE_BYTES
from frfw.ifaddr import IfaddrError
from frfw.kea import KeaError
from frfw.provision import apply_all
from frfw.ztna import ZtnaError

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


def _handle_request(request: dict, server: "ApplyHelperServer") -> dict:
    cmd = request.get("cmd")
    try:
        if cmd == "ping":
            return {"ok": True, "message": "pong"}

        if cmd == "apply":
            config = load_config(server.config_path)
            result = apply_all(
                config,
                dry_run=bool(request.get("dry_run", False)),
                backup_dir=server.backup_dir,
                kea_config_path=server.kea_config_path,
            )
            return {"ok": True, "message": "; ".join(result.messages)}

        if cmd == "rollback":
            restored = rollback_last(server.backup_dir)
            return {"ok": True, "message": f"Rolled back to {restored}"}

        if cmd == "save_config":
            text = request.get("yaml")
            if not isinstance(text, str):
                return {"ok": False, "message": "'yaml' must be a string"}
            parse_config(yaml.safe_load(text))  # validate before writing anything
            _write_atomic(server.config_path, text)
            return {"ok": True, "message": f"Config saved to {server.config_path}"}

        if cmd == "authorize_ztna":
            return _handle_authorize_ztna(request, server)

        if cmd == "ztna_status":
            return _handle_ztna_status(request, server)

        return {"ok": False, "message": f"unknown command {cmd!r}"}
    except (
        ConfigError, NftError, IfaddrError, KeaError, ZtnaError,
        FileNotFoundError, yaml.YAMLError,
    ) as exc:
        return {"ok": False, "message": str(exc)}


def _handle_authorize_ztna(request: dict, server: "ApplyHelperServer") -> dict:
    ip = request.get("ip")
    username = request.get("username")
    if not isinstance(ip, str) or not ip:
        return {"ok": False, "message": "'ip' is required"}
    if not isinstance(username, str) or not username:
        return {"ok": False, "message": "'username' is required"}
    try:
        ipaddress.IPv4Address(ip)
    except ValueError as exc:
        return {"ok": False, "message": f"invalid IPv4 address {ip!r}: {exc}"}

    config = load_config(server.config_path)
    if not config.ztna.enabled:
        return {"ok": False, "message": "ZTNA gate is disabled in the current config"}
    if not any(u.username == username for u in config.ztna.users):
        # Authentication itself already happened in the (unprivileged)
        # webUI process before it ever sent this command (see
        # frfw.webui.routes.ztna) -- this is a defense-in-depth check
        # against a stale/forged request naming a user that no longer
        # exists, not a second authentication step.
        return {"ok": False, "message": f"no such ZTNA user {username!r}"}

    ztna.authorize_ip(ip, config.ztna.session_ttl_seconds, username, state_path=server.ztna_state_path)
    return {
        "ok": True,
        "message": f"{ip} authorized as {username!r} for {config.ztna.session_ttl_seconds}s",
        "expires_in": config.ztna.session_ttl_seconds,
    }


def _handle_ztna_status(request: dict, server: "ApplyHelperServer") -> dict:
    ip = request.get("ip")
    if not isinstance(ip, str) or not ip:
        return {"ok": False, "message": "'ip' is required"}

    auth = ztna.get_authorization(ip, state_path=server.ztna_state_path)
    if auth is None:
        return {"ok": True, "authorized": False}
    return {
        "ok": True,
        "authorized": True,
        "username": auth.username,
        "expires_in": auth.expires_in_seconds,
    }


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(text)
    tmp_path.replace(path)


class _Handler(socketserver.StreamRequestHandler):
    server: "ApplyHelperServer"

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


class ApplyHelperServer(socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(
        self,
        socket_path: Path = paths.APPLY_SOCKET_PATH,
        config_path: Path = paths.CONFIG_PATH,
        *,
        backup_dir: Path = paths.BACKUP_DIR,
        kea_config_path: Path = kea.KEA_CONFIG_PATH,
        ztna_state_path: Path = paths.ZTNA_STATE_PATH,
        systemd_socket: socket.socket | None = None,
    ) -> None:
        self.config_path = config_path
        self.backup_dir = backup_dir
        self.kea_config_path = kea_config_path
        self.ztna_state_path = ztna_state_path
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
    parser = argparse.ArgumentParser(prog="firewall-helper")
    parser.add_argument("--socket", default=str(paths.APPLY_SOCKET_PATH))
    parser.add_argument("--config", default=str(paths.CONFIG_PATH))
    parser.add_argument("--backup-dir", default=str(paths.BACKUP_DIR))
    parser.add_argument("--kea-config", default=str(kea.KEA_CONFIG_PATH))
    parser.add_argument("--ztna-state", default=str(paths.ZTNA_STATE_PATH))
    args = parser.parse_args(argv)

    server = ApplyHelperServer(
        Path(args.socket),
        Path(args.config),
        backup_dir=Path(args.backup_dir),
        kea_config_path=Path(args.kea_config),
        ztna_state_path=Path(args.ztna_state),
        systemd_socket=_systemd_provided_socket(),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
