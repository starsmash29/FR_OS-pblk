"""Keeping the management plane off the internet (security-lessons F2/G4).

The big firewall compromises of 2026 all started at an admin interface
reachable from the internet. FR_OS's management plane is the webUI
(:443) and, when installed, sshd (:22). Unless `management.allow_wan`
is set, they are reachable only from the management zones -- by default
every zone that doesn't face the internet -- in three independent ways:

1. nft: the input chain drops :22/:443 from every other zone, ahead of
   any admin-written rule (frfw.nft.builder), so a rule "allow 443 from
   wan" can't open it by accident;
2. the webUI listens only on the static addresses of the management
   zones' interfaces and on loopback, not 0.0.0.0 (frfw.webui.server);
3. sshd gets a `ListenAddress` drop-in with the same addresses.

With `allow_wan` both listen on every address and the nft drop is left
out; the webUI and `apply` warn while that is on.
"""

from __future__ import annotations

import grp
import json
import ipaddress
import os
import pwd
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from frfw import paths, svc
from frfw.config.loader import internet_facing_zones
from frfw.config.schema import Config

#: The management services' ports: sshd, the webUI.
SSH_PORT = 22
WEBUI_PORT = 443
MANAGEMENT_PORTS = (SSH_PORT, WEBUI_PORT)

#: The sshd binary to validate the drop-in with (tests point it elsewhere).
SSHD_BINARY = "sshd"

LOOPBACK = "127.0.0.1"
ANY = "0.0.0.0"

WAN_WARNING = (
    "management.allow_wan is on: the webUI and SSH are reachable from the internet. "
    "Use the WireGuard VPN (VPN screen) for remote management instead and turn this off."
)


def internet_zones(config: Config) -> set[str]:
    return internet_facing_zones(config.zones, config.nat)


def management_zones(config: Config) -> list[str]:
    """The zones management is reachable from."""
    if config.management.zones:
        return list(config.management.zones)
    if config.management.allow_wan:
        return sorted(config.zones)
    internet = internet_zones(config)
    return sorted(z for z in config.zones if z not in internet)


def blocked_zones(config: Config) -> list[str]:
    """Zones whose management traffic the input chain drops."""
    allowed = set(management_zones(config))
    return sorted(z for z in config.zones if z not in allowed)


def listen_addresses(config: Config) -> list[str]:
    """Where the webUI and sshd listen: loopback plus the static address
    of every interface in a management zone -- or everything, with
    allow_wan. Just loopback if no management interface has a static
    address (then only the console can reach them, which is the point)."""
    if config.management.allow_wan:
        return [ANY]
    zones = set(management_zones(config))
    addresses = [LOOPBACK]
    for iface in sorted(config.interfaces.values(), key=lambda i: i.name):
        if iface.zone in zones and iface.address:
            ip = str(ipaddress.IPv4Interface(iface.address).ip)
            if ip not in addresses:
                addresses.append(ip)
    wg = config.wireguard
    if wg.enabled and wg.zone in zones:
        # Security-lessons K5: manage the router through the VPN.
        addresses.append(str(ipaddress.IPv4Interface(wg.address).ip))
    return addresses


# -- sshd ------------------------------------------------------------------------

_SSHD_DROPIN_HEADER = """\
# Managed by FR_OS (frfw.management) -- regenerated on every `apply`, do
# not edit by hand. Where sshd listens -- the management zones only
# (management.* in /etc/fr_os/config.yaml) -- and how it authenticates:
# keys only, members of the SSH group only (security-lessons F2/F3).
"""


class ManagementError(Exception):
    pass


@dataclass(frozen=True)
class SyncResult:
    message: str


#: Security-lessons F3: keys only, no root, only members of the SSH
#: group, few tries, a short grace time. sshd uses the first value it
#: reads, and this file sorts before distribution drop-ins such as
#: 50-cloud-init.conf, so these win.
SSHD_HARDENING = (
    "PermitRootLogin no",
    "PasswordAuthentication no",
    "KbdInteractiveAuthentication no",
    "PermitEmptyPasswords no",
    "PubkeyAuthentication yes",
    "AuthenticationMethods publickey",
    f"AllowGroups {paths.SSH_GROUP}",
    "MaxAuthTries 3",
    "LoginGraceTime 30",
    "X11Forwarding no",
)


#: Security-lessons H3: no downgrade in negotiated crypto -- only strong
#: key exchange, ciphers and MACs (all in OpenSSH >= 8.5, so Debian
#: bookworm's 9.2 knows every name). No SHA-1, no CBC, no MD5, no
#: encrypt-and-MAC; the DH groups are there for older clients only.
SSHD_KEX = (
    "sntrup761x25519-sha512@openssh.com",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group16-sha512",
)
SSHD_CIPHERS = (
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
)
SSHD_MACS = (
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "umac-128-etm@openssh.com",
)


def sshd_dropin(config: Config) -> str:
    lines = [_SSHD_DROPIN_HEADER.rstrip("\n")]
    lines += [f"ListenAddress {address}" for address in listen_addresses(config)]
    lines += list(SSHD_HARDENING)
    if not config.pqc.enabled:
        # With PQC on, frfw.pqc's drop-in owns KexAlgorithms (ML-KEM hybrid
        # first); sshd keeps the first value it reads, so ours must not
        # set it then.
        lines.append("KexAlgorithms " + ",".join(SSHD_KEX))
    lines.append("Ciphers " + ",".join(SSHD_CIPHERS))
    lines.append("MACs " + ",".join(SSHD_MACS))
    return "\n".join(lines) + "\n"


def ssh_login_users() -> list[str]:
    """Members of the SSH group that have an authorized_keys file -- the
    people who can actually log in with the drop-in above."""
    try:
        members = grp.getgrnam(paths.SSH_GROUP).gr_mem
    except KeyError:
        return []
    users = []
    for name in members:
        try:
            home = Path(pwd.getpwnam(name).pw_dir)
        except KeyError:
            continue
        if (home / ".ssh" / "authorized_keys").is_file():
            users.append(name)
    return sorted(users)


def sync_sshd(
    config: Config,
    *,
    dry_run: bool = False,
    dropin_path: Path | None = None,
    sshd_binary: str | None = None,
) -> SyncResult:
    """Write the ListenAddress drop-in, check it with `sshd -t` (restoring
    the previous one if sshd rejects it) and reload sshd -- a reload keeps
    open sessions. sshd runs only while someone can log in (a member of
    the SSH group with authorized_keys); otherwise it is stopped and
    disabled (security-lessons I1). A no-op without sshd."""
    dropin_path = paths.SSHD_MANAGEMENT_DROPIN_PATH if dropin_path is None else dropin_path
    sshd_binary = SSHD_BINARY if sshd_binary is None else sshd_binary
    if shutil.which(sshd_binary) is None:
        return SyncResult("sshd not installed; nothing to bind")
    content = sshd_dropin(config)
    where = ", ".join(listen_addresses(config))
    users = ssh_login_users()
    if dry_run:
        if not users:
            return SyncResult(f"Would turn SSH off: {NOBODY_CAN_LOG_IN} (dry-run)")
        return SyncResult(f"Would make sshd listen on {where} (dry-run)")
    previous = dropin_path.read_text() if dropin_path.exists() else None

    def restore() -> None:
        if previous is None:
            dropin_path.unlink(missing_ok=True)
        else:
            dropin_path.write_text(previous)

    if previous != content:
        if os.geteuid() != 0:
            raise ManagementError("writing the sshd drop-in needs root")
        dropin_path.parent.mkdir(parents=True, exist_ok=True)
        dropin_path.write_text(content)
        # `sshd -t` needs the privilege-separation directory, which exists
        # only while ssh.service runs. When it doesn't, Debian's unit runs
        # the same check (ExecStartPre=sshd -t) as it starts, below.
        if paths.SSHD_PRIVSEP_DIR.is_dir():
            proc = subprocess.run([sshd_binary, "-t"], capture_output=True, text=True)
            if proc.returncode != 0:
                restore()
                raise ManagementError(proc.stderr.strip() or "sshd -t rejected the ListenAddress drop-in")
    if not users:
        # Security-lessons I1: a listening service is attack surface; one
        # nobody can log in to is nothing else. Off until someone can.
        for unit in SSH_UNITS:
            svc.systemctl("disable", unit, timeout=60)
            svc.systemctl("stop", unit, timeout=60)
        return SyncResult(f"SSH is off: {NOBODY_CAN_LOG_IN}")
    svc.systemctl("enable", SSH_UNITS[0], timeout=60)
    if previous != content:
        reload = svc.systemctl("reload-or-restart", SSH_UNITS[0], timeout=60)
    else:
        reload = svc.systemctl("start", SSH_UNITS[0], timeout=60)
    if reload.returncode != 0:
        if previous != content:
            restore()
        raise ManagementError(reload.stderr.strip() or "failed to start or reload the ssh service")
    return SyncResult(f"sshd listens on {where}; key login for {', '.join(users)}")


#: Debian's OpenSSH units (the socket one exists but is off by default).
SSH_UNITS = ("ssh.service", "ssh.socket")

NOBODY_CAN_LOG_IN = (
    f"nobody can log in with a key yet. Add a user to the {paths.SSH_GROUP} group, give them "
    "~/.ssh/authorized_keys, then apply -- SSH starts once someone can use it"
)


# -- the webUI ---------------------------------------------------------------------

def webui_listening(port: int = WEBUI_PORT) -> set[str] | None:
    """The addresses something listens on at TCP `port` (`ss`), or None
    when that can't be told."""
    try:
        proc = subprocess.run(["ss", "-Hltn", f"sport = :{port}"], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    found = set()
    for line in proc.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            found.add(fields[3].rsplit(":", 1)[0].strip("[]"))
    return found


def record_webui_listen(addresses: list[str], path: Path | None = None) -> None:
    path = paths.WEBUI_LISTEN_PATH if path is None else path
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps({"addresses": addresses}) + "\n")
    os.chmod(tmp, 0o644)
    tmp.replace(path)


def recorded_webui_listen(path: Path | None = None) -> list[str] | None:
    """The addresses the last applied config has the webUI listen on, or
    None when none are recorded (or the record is not one)."""
    path = paths.WEBUI_LISTEN_PATH if path is None else path
    try:
        addresses = json.loads(path.read_text())["addresses"]
        if not isinstance(addresses, list) or not addresses:
            return None
        return [str(ipaddress.IPv4Address(a)) for a in addresses]
    except (OSError, ValueError, KeyError, TypeError):
        return None


def sync_webui(config: Config, *, dry_run: bool = False, listen_path: Path | None = None) -> SyncResult:
    """The webUI binds its addresses at start; when they should change
    (a new LAN address, allow_wan toggled), restart it -- a few seconds
    later, so the request that triggered this apply still gets its
    answer. The addresses are recorded for it first (paths.WEBUI_LISTEN_PATH):
    it binds those, the applied config's, rather than config.yaml's
    (ROADMAP SEC-5)."""
    wanted = set(listen_addresses(config))
    if dry_run:
        return SyncResult("Would make the webUI listen on " + ", ".join(sorted(wanted)) + " (dry-run)")
    record_webui_listen(listen_addresses(config), listen_path)
    running = webui_listening()
    if not running or running == wanted:
        return SyncResult("webUI listens on " + ", ".join(sorted(wanted)))
    try:
        subprocess.run(
            ["systemd-run", "--quiet", "--on-active=3", "--unit=fr-webui-rebind",
             "systemctl", "try-restart", "fr-webui.service"],
            capture_output=True, text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return SyncResult("webUI listen addresses changed; restart fr-webui to apply them")
    return SyncResult("webUI restarting to listen on " + ", ".join(sorted(wanted)))
