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

from frfw import bruteforce, conntrack, hwinfo, ids_quarantine, iot_isolation, kea, paths, ztna
from frfw.adblock import AdblockError
from frfw.iot import leases as iot_leases
from frfw.iot_isolation import IotIsolationError
from frfw.adblock import refresh as adblock_refresh
from frfw.apply import NftError, rollback_last
from frfw.bruteforce import BruteforceError
from frfw.config import ConfigError, load_config, parse_config
from frfw.conntrack import ConntrackError
from frfw.helper.protocol import MAX_LINE_BYTES
from frfw.hwinfo import HwInfoError
from frfw.ids_quarantine import IdsQuarantineError
from frfw.ifaddr import IfaddrError
from frfw.kea import KeaError
from frfw.pqc import PqcError
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

        if cmd == "refresh_adblock":
            return _handle_refresh_adblock(server)

        if cmd == "ban_ip":
            return _handle_ban_ip(request)

        if cmd == "quarantine_ip":
            return _handle_quarantine_ip(request)

        if cmd == "ids_quarantine_status":
            return _handle_ids_quarantine_status()

        if cmd == "conntrack_sample":
            return _handle_conntrack_sample()

        if cmd == "bruteforce_status":
            return _handle_bruteforce_status()

        if cmd == "ztna_sessions_status":
            return _handle_ztna_sessions_status()

        if cmd == "hw_ram_info":
            return _handle_hw_ram_info()

        if cmd == "dhcp_leases":
            return _handle_dhcp_leases(server)

        if cmd == "iot_sync_isolation":
            return _handle_iot_sync_isolation(request, server)

        if cmd == "iot_isolation_status":
            return _handle_iot_isolation_status()

        return {"ok": False, "message": f"unknown command {cmd!r}"}
    except (
        ConfigError, NftError, IfaddrError, KeaError, ZtnaError, PqcError, AdblockError,
        BruteforceError, IdsQuarantineError, ConntrackError, HwInfoError, IotIsolationError,
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


def _handle_refresh_adblock(server: "ApplyHelperServer") -> dict:
    config = load_config(server.config_path)
    result = adblock_refresh(
        config.adblocker.source_urls,
        hosts_path=server.adblock_hosts_path,
        categories=config.adblocker.categories,
        category_dir=server.adblock_category_dir,
        allowlist=config.adblocker.allowlist,
    )
    return {
        "ok": True,
        "message": result.message,
        "domain_count": result.domain_count,
        "failed_urls": result.failed_urls,
        "category_counts": result.category_counts or {},
    }


def _handle_ban_ip(request: dict) -> dict:
    ip = request.get("ip")
    duration_seconds = request.get("duration_seconds", 3600)
    if not isinstance(ip, str) or not ip:
        return {"ok": False, "message": "'ip' is required"}
    if not isinstance(duration_seconds, int) or isinstance(duration_seconds, bool):
        return {"ok": False, "message": "'duration_seconds' must be an integer"}

    bruteforce.ban_ip(ip, duration_seconds)
    return {"ok": True, "message": f"{ip} jailed for {duration_seconds}s"}


def _handle_quarantine_ip(request: dict) -> dict:
    ip = request.get("ip")
    duration_seconds = request.get("duration_seconds", 7200)
    if not isinstance(ip, str) or not ip:
        return {"ok": False, "message": "'ip' is required"}
    if not isinstance(duration_seconds, int) or isinstance(duration_seconds, bool):
        return {"ok": False, "message": "'duration_seconds' must be an integer"}

    ids_quarantine.quarantine_ip(ip, duration_seconds)
    return {"ok": True, "message": f"{ip} quarantined for {duration_seconds}s"}


def _handle_ids_quarantine_status() -> dict:
    quarantined = [
        {"ip": ip, "expires_in": remaining}
        for ip, remaining in ids_quarantine.list_quarantined()
    ]
    return {"ok": True, "quarantined": quarantined, "count": len(quarantined)}


def _handle_conntrack_sample() -> dict:
    flows = conntrack.read_snapshot()
    return {
        "ok": True,
        "flows": [
            {"proto": f.proto, "src": f.src, "sport": f.sport, "dst": f.dst, "dport": f.dport}
            for f in flows
        ],
    }


def _handle_bruteforce_status() -> dict:
    banned = [{"ip": ip, "expires_in": remaining} for ip, remaining in bruteforce.list_banned()]
    return {"ok": True, "banned": banned, "count": len(banned)}


def _handle_ztna_sessions_status() -> dict:
    sessions = [{"ip": ip, "expires_in": remaining} for ip, remaining in ztna.list_authorized()]
    return {"ok": True, "sessions": sessions, "count": len(sessions)}


def _handle_hw_ram_info() -> dict:
    modules = [
        {"part_number": m.part_number, "speed_mhz": m.speed_mhz}
        for m in hwinfo.read_ram_modules()
    ]
    return {"ok": True, "modules": modules}


def _handle_dhcp_leases(server: "ApplyHelperServer") -> dict:
    leases = [
        {"ip": l.ip, "mac": l.mac, "hostname": l.hostname, "expire": l.expire}
        for l in iot_leases.read_leases(server.kea_leases_path)
    ]
    return {"ok": True, "leases": leases, "count": len(leases)}


def _handle_iot_sync_isolation(request: dict, server: "ApplyHelperServer") -> dict:
    macs = request.get("macs")
    if not isinstance(macs, list):
        return {"ok": False, "message": "'macs' must be a list"}
    normalized = iot_isolation.normalize_macs(macs)

    config = load_config(server.config_path)
    if not config.iot.enabled:
        return {"ok": False, "message": "IoT isolation is disabled in the current config"}
    trusted = set(config.iot.trusted_macs)
    skipped = [m for m in normalized if m in trusted]
    written = iot_isolation.sync_isolated([m for m in normalized if m not in trusted])
    return {
        "ok": True,
        "message": f"{len(written)} device(s) isolated",
        "isolated": written,
        "count": len(written),
        "skipped_trusted": skipped,
    }


def _handle_iot_isolation_status() -> dict:
    isolated = iot_isolation.list_isolated()
    return {"ok": True, "isolated": isolated, "count": len(isolated)}


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
        adblock_hosts_path: Path = paths.ADBLOCK_HOSTS_PATH,
        kea_leases_path: Path = iot_leases.KEA_LEASES_PATH,
        adblock_category_dir: Path = paths.ADBLOCK_CATEGORY_DIR,
        systemd_socket: socket.socket | None = None,
    ) -> None:
        self.adblock_category_dir = adblock_category_dir
        self.config_path = config_path
        self.backup_dir = backup_dir
        self.kea_config_path = kea_config_path
        self.ztna_state_path = ztna_state_path
        self.adblock_hosts_path = adblock_hosts_path
        self.kea_leases_path = kea_leases_path
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
    parser.add_argument("--adblock-hosts", default=str(paths.ADBLOCK_HOSTS_PATH))
    args = parser.parse_args(argv)

    server = ApplyHelperServer(
        Path(args.socket),
        Path(args.config),
        backup_dir=Path(args.backup_dir),
        kea_config_path=Path(args.kea_config),
        ztna_state_path=Path(args.ztna_state),
        adblock_hosts_path=Path(args.adblock_hosts),
        systemd_socket=_systemd_provided_socket(),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
