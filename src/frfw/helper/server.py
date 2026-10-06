"""Root-run apply-helper daemon: the privileged side of the webUI's
Unix-socket interface (see ARCHITECTURE.md's security model).

The webUI (phase 3) will run unprivileged and never touch nftables or
/etc/fr_os directly; instead it sends a one-line JSON request here and
gets a one-line JSON response back. Two layers of access control: the
socket file's permissions (systemd/fr-apply-helper.socket: 0660
root:fr_os-feeds, the one group the webUI and the sensors share --
ROADMAP SEC-11) decide who can connect at all, and the kernel-reported
peer uid (SO_PEERCRED) decides which commands that connection may send
-- everything for the webUI, a short list for the network-parsing
daemons, nothing for anyone else (see frfw.helper.peer).

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
import subprocess
import sys
from pathlib import Path

import yaml

from frfw import apply_confirm, bruteforce, conntrack, firewall_log, hwinfo, ids_quarantine, iot_isolation, kea, paths, surface, svc, wireguard, xdp, ztna
from frfw.adblock import AdblockError
from frfw.iot import leases as iot_leases
from frfw.iot_isolation import IotIsolationError
from frfw.adblock import refresh as adblock_refresh
from frfw.apply import NftError, rollback_last
from frfw.bruteforce import BruteforceError
from frfw.config import ConfigError, load_config, parse_config, read_config
from frfw.config.export import refresh_sensor_copy, write_sensor_copy
from frfw.conntrack import ConntrackError
from frfw.helper.peer import PeerPolicy, peer_credentials
from frfw.helper.protocol import MAX_LINE_BYTES
from frfw.hwinfo import HwInfoError
from frfw.ids_quarantine import IdsQuarantineError
from frfw.ifaddr import IfaddrError
from frfw.kea import KeaError
from frfw.pqc import PqcError
from frfw.management import LOOPBACK, listen_addresses, moves_management
from frfw.provision import apply_all, applied_config_text, load_applied_config
from frfw.transaction import ApplyError, write_keeping_owner
from frfw.surface import SurfaceError
from frfw.webui import audit as webui_audit
from frfw.forwarding import ForwardingError
from frfw.wireguard import WireguardError
from frfw.ztna import ZtnaError

_SD_LISTEN_FDS_START = 3

#: The IoT scan, run on demand by the "iot_scan" command.
IOT_SCAN_SERVICE = "fr-iot-scan.service"


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
            return _handle_apply(request, server)

        if cmd == "set_management_addresses":
            return _handle_set_management_addresses(request, server)

        if cmd == "apply_status":
            return _handle_apply_status()

        if cmd == "apply_confirm":
            with apply_confirm.locked():
                apply_confirm.confirm(str(request.get("id") or ""))
            return {"ok": True, "message": "Apply confirmed: the router keeps this config"}

        if cmd == "apply_revert":
            with apply_confirm.locked():
                messages = apply_confirm.revert("the admin went back", config_path=server.config_path)
            return {"ok": True, "message": messages[0]}

        if cmd == "restore_rejected":
            with apply_confirm.locked():
                message = apply_confirm.restore_rejected(config_path=server.config_path)
            return {"ok": True, "message": message}

        if cmd == "rollback":
            restored = rollback_last(server.backup_dir)
            return {"ok": True, "message": f"Rolled back to {restored}"}

        if cmd == "save_config":
            text = request.get("yaml")
            if not isinstance(text, str):
                return {"ok": False, "message": "'yaml' must be a string"}
            raw = yaml.safe_load(text)
            parse_config(raw)  # validate before writing anything
            _write_atomic(server.config_path, text)
            # ROADMAP SEC-11: the parser daemons' copy, without secrets --
            # they re-read it, so a change reaches them without an apply.
            message = f"Config saved to {server.config_path}"
            try:
                write_sensor_copy(raw, server.sensor_config_path)
            except OSError as exc:
                message += f"; could not refresh the sensors' config copy: {exc}"
            return {"ok": True, "message": message}

        if cmd == "authorize_ztna":
            return _handle_authorize_ztna(request, server)

        if cmd == "ztna_status":
            return _handle_ztna_status(request, server)

        if cmd == "refresh_adblock":
            return _handle_refresh_adblock(server)

        if cmd == "ban_ip":
            return _handle_ban_ip(request)

        if cmd == "quarantine_ip":
            return _handle_quarantine_ip(request, server)

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

        if cmd == "iot_scan":
            return _handle_iot_scan()

        if cmd == "listening_sockets":
            return _handle_listening_sockets()

        if cmd == "audit_append":
            return _handle_audit_append(request, server)

        if cmd == "wireguard_status":
            return {"ok": True, **wireguard.status()}

        if cmd == "firewall_drops":
            return {"ok": True, "drops": firewall_log.recent_drops()}

        if cmd == "xdp_stats":
            return {"ok": True, "stats": xdp.get_stats()}

        return {"ok": False, "message": f"unknown command {cmd!r}"}
    except (
        ConfigError, NftError, IfaddrError, KeaError, ZtnaError, PqcError, AdblockError,
        BruteforceError, IdsQuarantineError, ConntrackError, HwInfoError, IotIsolationError,
        SurfaceError, ForwardingError, WireguardError, xdp.XdpError, FileNotFoundError, yaml.YAMLError,
        ApplyError, apply_confirm.PendingError,
    ) as exc:
        return {"ok": False, "message": str(exc)}


def _handle_apply(request: dict, server: "ApplyHelperServer") -> dict:
    """Apply config.yaml. Asked with `confirm` (the webUI's Apply), a
    successful apply is held until the admin confirms it, and the router
    goes back by itself otherwise (ROADMAP SEC-26, frfw.apply_confirm)."""
    config, text = read_config(server.config_path)
    if request.get("dry_run", False):
        _refuse_moving_management(config)
        result = apply_all(config, dry_run=True, backup_dir=server.backup_dir,
                           kea_config_path=server.kea_config_path, source_text=text)
        return {"ok": True, "message": "; ".join(result.messages)}
    with apply_confirm.locked():
        return _apply_locked(server, config, text, confirm=bool(request.get("confirm")),
                             user=str(request.get("user") or "")[:64])


def _refuse_moving_management(config) -> None:
    """ROADMAP SEC-27: only the webUI address setting moves the webUI and
    SSH -- never the side effect of another change."""
    moved = moves_management(config, load_applied_config())
    if moved:
        raise ApplyError("the webUI address", ValueError(moved), changed=False)


def _apply_locked(server: "ApplyHelperServer", config, text: str, *, confirm: bool, user: str) -> dict:
    """An apply, with `apply_confirm.locked()` held."""
    waiting = apply_confirm.read()
    if waiting is not None:
        return {"ok": False, "message": (
            f"The last apply is waiting for confirmation ({waiting.remaining()} s left): "
            "confirm it or go back before applying again")}
    _refuse_moving_management(config)
    previous = applied_config_text()
    result = apply_all(config, backup_dir=server.backup_dir, kea_config_path=server.kea_config_path,
                       source_text=text)
    messages = list(result.messages)
    held = None
    if confirm and apply_confirm.needs_confirmation(config, text, previous):
        seconds = config.management.confirm_apply_seconds
        try:
            # Where the admin can reach the webUI now -- loopback is no
            # one's way in.
            reachable = [a for a in listen_addresses(config) if a != LOOPBACK]
            held = apply_confirm.begin(previous, seconds, by=user, addresses=reachable)
        except apply_confirm.PendingError as exc:
            messages.insert(0, f"Applied, but not held for confirmation: {exc}")
        else:
            messages.insert(0, f"Applied -- confirm it within {seconds} s, or the router goes back to "
                               "the config applied before it")
    problem = refresh_sensor_copy(server.config_path, server.sensor_config_path)
    if problem:
        messages.append(problem)
    reply = {"ok": True, "message": "; ".join(messages)}
    if held is not None:
        reply["pending"] = held.public()
    return reply


def _handle_set_management_addresses(request: dict, server: "ApplyHelperServer") -> dict:
    """ROADMAP SEC-27: the one way to move the webUI and SSH -- the admin's
    own action. Only that changes: config.yaml must hold nothing else
    unapplied. Applied at once and held until it is confirmed from the
    new address (SEC-26); config.yaml is left as it was if it fails."""
    addresses = request.get("addresses")
    if not isinstance(addresses, list) or not addresses or not all(isinstance(a, str) for a in addresses):
        return {"ok": False, "message": "'addresses' must be a non-empty list of IPv4 addresses"}
    with apply_confirm.locked():
        text = server.config_path.read_text()
        if apply_confirm.read() is not None:
            return {"ok": False, "message": "The last apply is waiting for confirmation: confirm it or go back first"}
        recorded = applied_config_text()
        if recorded is not None and recorded != text:
            return {"ok": False, "message": (
                "The config has changes that aren't applied yet: apply them (or undo them) first, so that "
                "moving the webUI changes nothing else")}
        raw = yaml.safe_load(text) or {}
        raw["management"] = {**(raw.get("management") or {}), "addresses": list(addresses)}
        new_text = yaml.safe_dump(raw, sort_keys=False)
        config = parse_config(yaml.safe_load(new_text))  # every address must be on the router
        _write_atomic(server.config_path, new_text)
        try:
            reply = _apply_locked(server, config, new_text, confirm=True, user=str(request.get("user") or "")[:64])
        except BaseException:
            _write_atomic(server.config_path, text)
            raise
        if not reply.get("ok"):
            _write_atomic(server.config_path, text)
        return reply


def _handle_apply_status() -> dict:
    """What the webUI shows on every page while an apply waits (ROADMAP
    SEC-26) -- never the previous config's text, which stays root's."""
    waiting = apply_confirm.read()
    return {"ok": True, "pending": None if waiting is None else waiting.public(),
            "rejected": apply_confirm.has_rejected()}


def _ztna_client_mac(ip: str, config) -> str:
    """Which client `ip` is, for the ZTNA gate (ROADMAP SEC-6): "" for a
    WireGuard client -- an address in the tunnel's network, bound to its
    key by WireGuard, and only ever matched on the tunnel (a TCP
    connection from such an address can't complete from anywhere else:
    the router's replies go into the tunnel) -- else the MAC the router
    sees `ip` at in its own neighbour table. A client not directly
    attached -- behind another router or NAT -- raises ztna.ClientNotDirect."""
    address = ipaddress.IPv4Address(ip)
    if config.wireguard.enabled and config.wireguard.address:
        if address in ipaddress.IPv4Interface(config.wireguard.address).network:
            return ""
    link = ztna.client_link(ip)
    if link is None:
        raise ztna.ClientNotDirect(
            f"{ip} is not on a network the router is attached to -- it came through another router or "
            "NAT, so the router can't tell its devices apart and won't sign them all in at once. "
            "From outside, connect through the router's WireGuard VPN and sign in there."
        )
    return link.mac


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

    # ROADMAP SEC-6: the device, not just its address. Decided here, by
    # root, from the router's own view -- never from the request.
    try:
        mac = _ztna_client_mac(ip, config)
    except ztna.ClientNotDirect as exc:
        return {"ok": False, "message": str(exc)}
    ztna.authorize_client(ip, mac, config.ztna.session_ttl_seconds, username, state_path=server.ztna_state_path)
    basis = f"this device ({mac})" if mac else "your WireGuard key"
    return {
        "ok": True,
        "message": f"{ip} authorized as {username!r} for {config.ztna.session_ttl_seconds}s, bound to {basis}",
        "expires_in": config.ztna.session_ttl_seconds,
        "mac": mac,
    }


def _handle_ztna_status(request: dict, server: "ApplyHelperServer") -> dict:
    ip = request.get("ip")
    if not isinstance(ip, str) or not ip:
        return {"ok": False, "message": "'ip' is required"}
    try:
        ipaddress.IPv4Address(ip)
    except ValueError as exc:
        return {"ok": False, "message": f"invalid IPv4 address {ip!r}: {exc}"}
    try:
        mac = _ztna_client_mac(ip, load_config(server.config_path))
    except ztna.ClientNotDirect:
        return {"ok": True, "authorized": False, "direct": False}

    auth = ztna.get_authorization(ip, mac, state_path=server.ztna_state_path)
    if auth is None:
        return {"ok": True, "authorized": False}
    return {
        "ok": True,
        "authorized": True,
        "username": auth.username,
        "expires_in": auth.expires_in_seconds,
        "mac": auth.mac,
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


def _router_addresses(server: "ApplyHelperServer") -> frozenset[str]:
    """The router's own IPv4 addresses per the saved config (never
    quarantined). An unreadable config gives none: loopback and the other
    non-host addresses are still refused by ids_quarantine itself."""
    try:
        config = load_config(server.config_path)
    except (ConfigError, OSError, yaml.YAMLError):
        return frozenset()
    own = {str(ipaddress.IPv4Interface(i.address).ip) for i in config.interfaces.values() if i.address}
    if config.wireguard.enabled and config.wireguard.address:
        own.add(str(ipaddress.IPv4Interface(config.wireguard.address).ip))
    return frozenset(own)


def _handle_quarantine_ip(request: dict, server: "ApplyHelperServer") -> dict:
    ip = request.get("ip")
    duration_seconds = request.get("duration_seconds", 7200)
    if not isinstance(ip, str) or not ip:
        return {"ok": False, "message": "'ip' is required"}
    if not isinstance(duration_seconds, int) or isinstance(duration_seconds, bool):
        return {"ok": False, "message": "'duration_seconds' must be an integer"}

    ids_quarantine.quarantine_ip(ip, duration_seconds, own_addresses=_router_addresses(server))
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
    sessions = [{"ip": ip, "mac": mac, "expires_in": remaining} for ip, mac, remaining in ztna.list_authorized()]
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


#: What an audit entry from the webUI may carry (security-lessons G9/E6).
_AUDIT_MAX_FIELDS = 20
_AUDIT_MAX_TEXT = 500
_AUDIT_RESERVED = frozenset({"ts", "via"})


def _handle_audit_append(request: dict, server: "ApplyHelperServer") -> dict:
    """Append the webUI's audit entry to the root-owned log. The webUI can
    only add: it can't write the file, so it can't rewrite or remove what
    is already there. The time and the origin are set here, not taken
    from the request."""
    entry = request.get("entry")
    if not isinstance(entry, dict) or len(entry) > _AUDIT_MAX_FIELDS:
        return {"ok": False, "message": "'entry' must be a small mapping"}
    clean: dict = {}
    for key, value in entry.items():
        if not isinstance(key, str) or not key.isidentifier() or len(key) > 40 or key in _AUDIT_RESERVED:
            return {"ok": False, "message": f"invalid audit field {key!r}"}
        if isinstance(value, str):
            clean[key] = value[:_AUDIT_MAX_TEXT]
        elif value is None or isinstance(value, (bool, int, float)):
            clean[key] = value
        else:
            return {"ok": False, "message": f"invalid value for audit field {key!r}"}
    webui_audit.prepare(server.audit_log_path)
    webui_audit.append(server.audit_log_path, {**clean, "via": "webui"})
    return {"ok": True}


def _handle_listening_sockets() -> dict:
    """Security-lessons I3: every listening socket and the interfaces'
    addresses, read as root so `ss` can name the processes it may."""
    listeners, addresses = surface.collect()
    return {
        "ok": True,
        "listeners": [{"proto": l.proto, "address": l.address, "port": l.port, "device": l.device,
                       "process": l.process} for l in listeners],
        "addresses": addresses,
    }


def _handle_iot_scan() -> dict:
    """The webUI's "Scan now": run the scan in fr-iot-scan.service (as
    fr_os-sensor) rather than in the webUI process, which must never
    parse LAN traffic itself."""
    try:
        proc = svc.systemctl("start", IOT_SCAN_SERVICE, timeout=120)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "message": f"could not run {IOT_SCAN_SERVICE}: {exc}"}
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        return {"ok": False, "message": f"{IOT_SCAN_SERVICE} failed: {detail} (see journalctl -u {IOT_SCAN_SERVICE})"}
    return {"ok": True, "message": f"{IOT_SCAN_SERVICE} finished"}


#: config.yaml's writer -- it keeps the file's owner and mode -- lives in
#: frfw.transaction, which the revert of an unconfirmed apply (ROADMAP
#: SEC-26) shares.
_write_atomic = write_keeping_owner


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
            pid, uid, _gid = peer_credentials(self.connection)
            if self.server.peer_policy.allows(uid, request.get("cmd")):
                response = _handle_request(request, self.server)
            else:
                print(f"firewall-helper: refused {request.get('cmd')!r} from pid {pid} uid {uid}",
                      file=sys.stderr, flush=True)
                response = {"ok": False, "message": f"command {request.get('cmd')!r} is not allowed for uid {uid}"}
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
        audit_log_path: Path = paths.AUDIT_LOG_PATH,
        systemd_socket: socket.socket | None = None,
        peer_policy: PeerPolicy | None = None,
        sensor_config_path: Path | None = None,
    ) -> None:
        self._peer_policy = peer_policy
        # Resolved now, not at import: tests point paths at a temporary one.
        self.sensor_config_path = sensor_config_path or paths.SENSOR_CONFIG_PATH
        self.audit_log_path = audit_log_path
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

    @property
    def peer_policy(self) -> PeerPolicy:
        # Looked up per connection, not once at start: fr-accounts.service
        # may create fr_os-sensor after this daemon is already running
        # (the first boot after an update).
        return self._peer_policy or PeerPolicy.from_system()

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
