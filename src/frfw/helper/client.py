"""Client for the apply-helper Unix socket, for use by the future webUI.

Not exercised by the CLI (which talks to frfw.apply directly, since it
already runs with whatever privileges the operator invoked it with) --
this exists for phase 3, where the webUI runs unprivileged and must go
through the socket instead.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

from frfw import paths
from frfw.helper.protocol import MAX_LINE_BYTES


class HelperError(Exception):
    """Raised on a transport failure talking to the apply-helper."""


def send_command(
    cmd: dict, socket_path: Path = paths.APPLY_SOCKET_PATH, timeout: float = 10.0
) -> dict:
    """Send one JSON request and return the decoded JSON response.

    Note this only reports transport-level failures as `HelperError`; an
    application-level failure (bad config, nft rejecting the ruleset) comes
    back as a normal `{"ok": False, "message": ...}` response.
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(socket_path))
            sock.sendall(json.dumps(cmd).encode() + b"\n")
            sock.shutdown(socket.SHUT_WR)

            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(len(c) for c in chunks) > MAX_LINE_BYTES:
                    raise HelperError("response from apply-helper exceeded size limit")
    except OSError as exc:
        raise HelperError(f"cannot reach apply-helper at {socket_path}: {exc}") from exc

    raw = b"".join(chunks).strip()
    if not raw:
        raise HelperError("apply-helper closed the connection without a response")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HelperError(f"invalid response from apply-helper: {raw!r}") from exc


def ping(socket_path: Path = paths.APPLY_SOCKET_PATH) -> dict:
    return send_command({"cmd": "ping"}, socket_path)


def apply_config(dry_run: bool = False, socket_path: Path = paths.APPLY_SOCKET_PATH) -> dict:
    return send_command({"cmd": "apply", "dry_run": dry_run}, socket_path)


def rollback(socket_path: Path = paths.APPLY_SOCKET_PATH) -> dict:
    return send_command({"cmd": "rollback"}, socket_path)


def save_config(yaml_text: str, socket_path: Path = paths.APPLY_SOCKET_PATH) -> dict:
    return send_command({"cmd": "save_config", "yaml": yaml_text}, socket_path)


def authorize_ztna(
    ip: str, username: str, socket_path: Path = paths.APPLY_SOCKET_PATH
) -> dict:
    return send_command({"cmd": "authorize_ztna", "ip": ip, "username": username}, socket_path)


def ztna_status(ip: str, socket_path: Path = paths.APPLY_SOCKET_PATH) -> dict:
    return send_command({"cmd": "ztna_status", "ip": ip}, socket_path)


def refresh_adblock(socket_path: Path = paths.APPLY_SOCKET_PATH, timeout: float = 60.0) -> dict:
    """Longer default timeout than every other command here -- this one
    downloads potentially several megabytes from third-party URLs before
    it can respond, unlike everything else on this socket."""
    return send_command({"cmd": "refresh_adblock"}, socket_path, timeout=timeout)


def ban_ip(
    ip: str, duration_seconds: int = 3600, socket_path: Path = paths.APPLY_SOCKET_PATH
) -> dict:
    return send_command(
        {"cmd": "ban_ip", "ip": ip, "duration_seconds": duration_seconds}, socket_path
    )


def quarantine_ip(
    ip: str, duration_seconds: int = 7200, socket_path: Path = paths.APPLY_SOCKET_PATH
) -> dict:
    return send_command(
        {"cmd": "quarantine_ip", "ip": ip, "duration_seconds": duration_seconds}, socket_path
    )


def ids_quarantine_status(socket_path: Path = paths.APPLY_SOCKET_PATH) -> dict:
    return send_command({"cmd": "ids_quarantine_status"}, socket_path)


def conntrack_sample(socket_path: Path = paths.APPLY_SOCKET_PATH) -> dict:
    return send_command({"cmd": "conntrack_sample"}, socket_path)


def bruteforce_status(socket_path: Path = paths.APPLY_SOCKET_PATH) -> dict:
    return send_command({"cmd": "bruteforce_status"}, socket_path)


def ztna_sessions_status(socket_path: Path = paths.APPLY_SOCKET_PATH) -> dict:
    return send_command({"cmd": "ztna_sessions_status"}, socket_path)


def hw_ram_info(socket_path: Path = paths.APPLY_SOCKET_PATH) -> dict:
    return send_command({"cmd": "hw_ram_info"}, socket_path)


def dhcp_leases(socket_path: Path = paths.APPLY_SOCKET_PATH) -> dict:
    return send_command({"cmd": "dhcp_leases"}, socket_path)


def iot_sync_isolation(macs: list[str], socket_path: Path = paths.APPLY_SOCKET_PATH) -> dict:
    return send_command({"cmd": "iot_sync_isolation", "macs": macs}, socket_path)


def iot_isolation_status(socket_path: Path = paths.APPLY_SOCKET_PATH) -> dict:
    return send_command({"cmd": "iot_isolation_status"}, socket_path)
