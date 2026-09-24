"""Applies interface static IPv4 addresses declared in the config.

Shells out to `ip` (iproute2), already required on any Debian box that
does networking at all, rather than a netlink binding -- consistent with
frfw.apply/frfw.nft's "shell out to the standard system tool" approach.

Only ever adds/updates the declared address (`ip addr replace` is
idempotent) and brings the link up. It does not remove addresses that
fall out of the config, since frfw does not track everything it has ever
applied -- if you remove an interface's `address:`, the old address stays
configured until removed by hand or on reboot.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

from frfw.config.schema import Config, Interface


class IfaddrError(Exception):
    """Raised when the `ip` binary rejects an address or fails to apply it."""


@dataclass(frozen=True)
class SyncResult:
    applied: bool
    message: str


def sync_addresses(config: Config, *, dry_run: bool = False) -> SyncResult:
    """Apply every interface's static `address`, if any are declared."""
    addressed = [iface for iface in config.interfaces.values() if iface.address]
    if not addressed:
        return SyncResult(applied=False, message="No interface addresses to sync")

    summary = ", ".join(f"{iface.device}={iface.address}" for iface in addressed)

    if dry_run:
        return SyncResult(applied=False, message=f"Would set addresses: {summary}")

    _require_root()
    for iface in addressed:
        _apply_one(iface)

    return SyncResult(applied=True, message=f"Addresses applied: {summary}")


def _apply_one(iface: Interface) -> None:
    _run_ip(["addr", "replace", iface.address, "dev", iface.device])
    _run_ip(["link", "set", iface.device, "up"])


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
