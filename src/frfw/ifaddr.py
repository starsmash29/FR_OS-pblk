"""Applies interface static IPv4 addresses declared in the config.

Shells out to `ip` (iproute2), already required on any Debian box that
does networking at all, rather than a netlink binding -- consistent with
frfw.apply/frfw.nft's "shell out to the standard system tool" approach.

Adds/updates the declared address (`ip addr replace` is idempotent) and
brings the link up. An address the *last applied* config set and this one
no longer has -- an interface's `address:` changed or removed, or moved
to another device -- is removed (review v0.2.1 FR-NEW-005: until then the
old address stayed, and the router kept answering on a subnet the admin
had taken away). Only those: an address FR_OS never set (a DHCP lease on
the WAN, one added by hand) is never touched. The apply's journal
(frfw.transaction.LinkState) puts a removed address back on a rollback.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from frfw import validate
from frfw.config.schema import Config, Interface


class IfaddrError(Exception):
    """Raised when the `ip` binary rejects an address or fails to apply it."""


@dataclass(frozen=True)
class SyncResult:
    applied: bool
    message: str


def sync_addresses(config: Config, *, previous: Config | None = None, dry_run: bool = False) -> SyncResult:
    """Create missing VLAN devices (security-lessons K4), remove the
    addresses `previous` (the last applied config) set that `config` no
    longer has, then apply every interface's static `address`."""
    vlans = [iface for iface in config.interfaces.values() if iface.vlan_id is not None]
    if vlans and not dry_run:
        _require_root()
        for iface in vlans:
            _ensure_vlan(iface)
    addressed = [iface for iface in config.interfaces.values() if iface.address]
    stale = stale_addresses(config, previous)
    if not addressed and not stale:
        return SyncResult(applied=False, message="No interface addresses to sync")

    summary = ", ".join(f"{iface.device}={iface.address}" for iface in addressed)
    gone = ", ".join(f"{device}={address}" for device, address in stale)

    if dry_run:
        parts = [f"Would set addresses: {summary}"] if addressed else []
        parts += [f"Would remove addresses: {gone}"] if stale else []
        return SyncResult(applied=False, message="; ".join(parts))

    _require_root()
    # Removed first: an address that moves to another device is then
    # never on two devices at once.
    for device, address in stale:
        _remove_one(device, address)
    for iface in addressed:
        _apply_one(iface)

    parts = [f"Addresses applied: {summary}"] if addressed else []
    parts += [f"Addresses removed: {gone}"] if stale else []
    return SyncResult(applied=True, message="; ".join(parts))


def stale_addresses(config: Config, previous: Config | None) -> list[tuple[str, str]]:
    """The (device, address) pairs `previous` set that `config` doesn't:
    what an apply of `config` removes (review v0.2.1 FR-NEW-005)."""
    if previous is None:
        return []
    wanted = {(iface.device, _canonical(iface.address))
              for iface in config.interfaces.values() if iface.address}
    stale: list[tuple[str, str]] = []
    for iface in previous.interfaces.values():
        if not iface.address:
            continue
        pair = (iface.device, _canonical(iface.address))
        if pair not in wanted and pair not in stale:
            stale.append(pair)
    return stale


def _canonical(address: str) -> str:
    return str(ipaddress.IPv4Interface(address))


#: Where the kernel lists this namespace's network devices.
NET_CLASS_DIR = Path("/sys/class/net")


def device_exists(device: str) -> bool:
    """Whether this machine has network device `device` (the preflight of
    an apply, ROADMAP SEC-5)."""
    return (NET_CLASS_DIR / validate.ifname(device)).exists()


def _apply_one(iface: Interface) -> None:
    # Security-lessons F1: validated again here, and always after the
    # `dev` keyword -- iproute2 has no `--`, but takes whatever follows
    # `dev` as the name, never as an option.
    try:
        device = validate.ifname(iface.device)
        address = validate.ipv4_interface(iface.address)
    except validate.ArgumentError as exc:
        raise IfaddrError(str(exc)) from exc
    _run_ip(["addr", "replace", address, "dev", device])
    _run_ip(["link", "set", "dev", device, "up"])


def _remove_one(device: str, address: str) -> None:
    # Security-lessons F1, as in _apply_one. Gone already (a reboot, by
    # hand, the device itself unplugged): nothing to remove.
    try:
        device = validate.ifname(device)
        address = validate.ipv4_interface(address)
    except validate.ArgumentError as exc:
        raise IfaddrError(str(exc)) from exc
    if address not in _addresses(device):
        return
    _run_ip(["addr", "del", address, "dev", device])


def _addresses(device: str) -> set[str]:
    """The IPv4 addresses `device` has now; none if it isn't there."""
    try:
        proc = subprocess.run(["ip", "-j", "addr", "show", "dev", device], capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise IfaddrError("'ip' binary not found; install the iproute2 package") from exc
    if proc.returncode != 0:
        return set()
    try:
        links = json.loads(proc.stdout)
    except ValueError as exc:
        raise IfaddrError(f"could not read the addresses of {device}: {exc}") from exc
    return {
        str(ipaddress.IPv4Interface(f"{a['local']}/{a['prefixlen']}"))
        for link in links for a in link.get("addr_info", []) if a.get("family") == "inet"
    }


def _ensure_vlan(iface: Interface) -> None:
    try:
        device = validate.ifname(iface.device)
        parent = validate.ifname(iface.vlan_parent)
    except validate.ArgumentError as exc:
        raise IfaddrError(str(exc)) from exc
    if subprocess.run(["ip", "link", "show", "dev", device], capture_output=True).returncode != 0:
        _run_ip(["link", "add", "link", parent, "name", device, "type", "vlan", "id", str(iface.vlan_id)])
    _run_ip(["link", "set", "dev", parent, "up"])
    _run_ip(["link", "set", "dev", device, "up"])


def _require_root() -> None:
    if os.geteuid() != 0:
        raise IfaddrError("Applying interface addresses requires root privileges.")


def _run_ip(args: list[str]) -> None:
    try:
        proc = subprocess.run(["ip", *args], capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise IfaddrError("'ip' binary not found; install the iproute2 package") from exc
    if proc.returncode != 0:
        raise IfaddrError(proc.stderr.strip() or f"ip exited with status {proc.returncode}")
