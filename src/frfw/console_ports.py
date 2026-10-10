"""The router's ports on the console's login screen, kept current.

First boot used to put one line into /etc/issue -- the webUI's address
and the LAN port it picked (ROADMAP NET-13) -- and nothing ever updated
it: after the admin moved a port to another role in the webUI, or a cable
to another port, the console still showed the first boot's picture, with
no way to see which port had a link. The owner's first hardware test
(docs/hardware.md) was debugged from exactly that screen.

`render` builds a short summary instead: every physical port with its
link (and speed), the role the applied config gives it, and its IPv4
addresses; the webUI's address; and a warning when the LAN port has no
link while a port no role uses has one -- the LAN cable is likely in the
wrong port. Roles are never changed here (the owner's decision: a cable in
the wrong port must not move the LAN, and the webUI with it, onto the
upstream network); the admin moves the role in the webUI or the cable.

`write` puts it into ISSUE_PATH, which agetty prints with the other
/etc/issue.d files before every login prompt, and asks the running gettys
to redraw. `watch` (fr-console-ports.service) rewrites it at start, on
every link or address change the kernel reports (rtnetlink), and when the
applied config or the webUI's addresses change. It also takes first
boot's old one-off line out of /etc/issue.

Not secret: the file is 0644, like /etc/issue. Every value written is
escaped for agetty, which reads backslash sequences in issue files.
"""

from __future__ import annotations

import json
import os
import select
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

from frfw import management, netdetect, paths

ISSUE_PATH = Path("/etc/issue.d/fr_os-ports.issue")
LEGACY_ISSUE_PATH = Path("/etc/issue")

#: First boot's one-off lines in /etc/issue (before this module): they
#: start with these, and are now stale copies of what ISSUE_PATH shows.
_LEGACY_PREFIXES = ("FR_OS webUI: ", "FR_OS no LAN port assigned ")

#: rtnetlink multicast groups (linux/rtnetlink.h): link up/down and
#: renamed devices, IPv4 addresses added or removed (a DHCP lease).
RTMGRP_LINK = 0x1
RTMGRP_IPV4_IFADDR = 0x10

#: How often `watch` looks at the config files between kernel events.
POLL_SECONDS = 5.0
#: A link flapping sends a burst of messages: wait this long for the
#: burst to end before redrawing.
SETTLE_SECONDS = 1.0


@dataclass(frozen=True)
class Role:
    name: str  # the interface's name in the config: wan, lan, iot, ...
    zone: str
    vlan_id: int | None = None


def roles_by_device(config_text: str | None) -> dict[str, list[Role]]:
    """Which config interfaces sit on each device: by `device`, or by
    `vlan.parent` for a VLAN of it. Read without validating -- a summary
    of a config the loader would reject is still better than none."""
    try:
        raw = yaml.safe_load(config_text) if config_text else None
    except yaml.YAMLError:
        return {}
    interfaces = raw.get("interfaces") if isinstance(raw, dict) else None
    if not isinstance(interfaces, dict):
        return {}
    roles: dict[str, list[Role]] = {}
    for name, entry in interfaces.items():
        if not isinstance(entry, dict):
            continue
        vlan = entry.get("vlan") if isinstance(entry.get("vlan"), dict) else None
        device = vlan.get("parent") if vlan else entry.get("device")
        if not isinstance(device, str):
            continue
        vlan_id = vlan.get("id") if vlan and isinstance(vlan.get("id"), int) else None
        roles.setdefault(device, []).append(Role(str(name), str(entry.get("zone", "?")), vlan_id))
    return roles


def ipv4_addresses(run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> dict[str, list[str]]:
    """Each device's IPv4 addresses, from `ip -j` (the kernel's, so a
    WAN's DHCP lease is there too)."""
    try:
        proc = run(["ip", "-j", "-4", "address", "show"], capture_output=True, text=True, timeout=10)
        entries = json.loads(proc.stdout) if proc.returncode == 0 else []
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {}
    found: dict[str, list[str]] = {}
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict) or not isinstance(entry.get("ifname"), str):
            continue
        for info in entry.get("addr_info") or []:
            if isinstance(info, dict) and info.get("local") and info.get("prefixlen") is not None:
                found.setdefault(entry["ifname"], []).append(f"{info['local']}/{info['prefixlen']}")
    return found


def _escape(text: str) -> str:
    """agetty reads `\\x` sequences in issue files; print them literally."""
    return text.replace("\\", "\\\\")


def _link(iface: netdetect.DetectedInterface) -> str:
    # A port that is down has no readable carrier (None): no link either.
    if not iface.link_up:
        return "no link"
    return f"link {iface.speed_mbps} Mbit/s" if iface.speed_mbps else "link up"


def _role_text(device_roles: list[Role]) -> str:
    if not device_roles:
        return "not assigned"
    parts = []
    for role in device_roles:
        text = role.name.upper() if role.name == role.zone else f"{role.name} (zone {role.zone})"
        parts.append(f"{text} on VLAN {role.vlan_id}" if role.vlan_id else text)
    return ", ".join(parts)


def render(
    interfaces: list[netdetect.DetectedInterface],
    roles: dict[str, list[Role]],
    addresses: dict[str, list[str]],
    webui: list[str] | None,
) -> str:
    """The summary agetty shows: a header, one line per port, the webUI's
    address, and a warning when the LAN cable looks misplaced."""
    lines = ["FR_OS ports:"]
    width = max((len(iface.name) for iface in interfaces), default=0)
    for iface in interfaces:
        device_roles = roles.get(iface.name, [])
        address = ", ".join(addresses.get(iface.name, [])) or "no address"
        lines.append(f"  {iface.name:<{width}}  {_link(iface):<18} {_role_text(device_roles):<14}  {address}")
    if not interfaces:
        lines.append("  no network ports found")

    webui = [a for a in webui or [] if a != management.LOOPBACK]
    if webui:
        lines.append("webUI: " + ", ".join(f"https://{a}/" for a in webui) + " (from the LAN)")
    elif not roles:
        lines.append("No port has a role yet: run 'firewall-cli assign-interfaces' or the first-boot setup.")

    lan_ports = [i for i in interfaces if any(r.name == "lan" or r.zone == "lan" for r in roles.get(i.name, []))]
    spare_with_link = [i.name for i in interfaces if not roles.get(i.name) and i.link_up]
    if lan_ports and not any(i.link_up for i in lan_ports) and spare_with_link:
        lan = ", ".join(i.name for i in lan_ports)
        spare = ", ".join(spare_with_link)
        lines.append(f"WARNING: the LAN port ({lan}) has no link, but {spare} (no role) has one: "
                     "is the LAN cable in the wrong port? Move it, or give that port the LAN role in the webUI.")
    return "\n".join(_escape(line) for line in lines) + "\n\n"


def current_config_text() -> str | None:
    """The config the router runs: the last one applied in full (ROADMAP
    SEC-5), else config.yaml (first boot, before any apply)."""
    for path in (paths.APPLIED_CONFIG_PATH, paths.CONFIG_PATH):
        try:
            return path.read_text()
        except OSError:
            continue
    return None


def summary() -> str:
    return render(
        netdetect.list_interfaces(),
        roles_by_device(current_config_text()),
        ipv4_addresses(),
        management.recorded_webui_listen(),
    )


def write(text: str, *, path: Path | None = None) -> bool:
    """Replace the file when its text changed; True when it did."""
    path = ISSUE_PATH if path is None else path
    try:
        if path.read_text() == text:
            return False
    except OSError:
        pass
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text)
    os.chmod(tmp, 0o644)
    tmp.replace(path)
    return True


def remove_legacy_line(path: Path | None = None) -> bool:
    """Take first boot's old one-off line (and the blank line after it)
    out of /etc/issue, in place."""
    path = LEGACY_ISSUE_PATH if path is None else path
    try:
        lines = path.read_text().splitlines(keepends=True)
    except OSError:
        return False
    kept, dropped, skip_blank = [], False, False
    for line in lines:
        if line.startswith(_LEGACY_PREFIXES):
            dropped, skip_blank = True, True
            continue
        if skip_blank and not line.strip():
            skip_blank = False
            continue
        skip_blank = False
        kept.append(line)
    if dropped:
        with path.open("w") as fh:  # in place: keep the file's mode/owner
            fh.writelines(kept)
    return dropped


def redraw_consoles(run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> None:
    """Ask the running gettys to print the login screen again."""
    try:
        run(["agetty", "--reload"], capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        pass


def refresh() -> bool:
    remove_legacy_line()
    changed = write(summary())
    if changed:
        redraw_consoles()
    return changed


def _mtimes() -> tuple:
    out = []
    for path in (paths.APPLIED_CONFIG_PATH, paths.CONFIG_PATH, paths.WEBUI_LISTEN_PATH):
        try:
            out.append(path.stat().st_mtime_ns)
        except OSError:
            out.append(None)
    return tuple(out)


def watch() -> None:  # pragma: no cover - a loop around refresh(), run by the boot test
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    sock.bind((0, RTMGRP_LINK | RTMGRP_IPV4_IFADDR))
    refresh()
    seen = _mtimes()
    while True:
        ready, _, _ = select.select([sock], [], [], POLL_SECONDS)
        if ready:
            time.sleep(SETTLE_SECONDS)
            while select.select([sock], [], [], 0)[0]:
                sock.recv(65536)
        now = _mtimes()
        if ready or now != seen:
            seen = now
            refresh()
