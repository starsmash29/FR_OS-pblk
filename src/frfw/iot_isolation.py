"""Kernel-level enforcement for IoT isolation (phase 14, see frfw.iot):
keeps the `iot_isolated` nftables set
(`frfw.nft.builder.IOT_ISOLATED_SET_NAME`) in sync with the MAC
addresses the IoT scanner decided to isolate.

A deliberate structural mirror of frfw.ids_quarantine / frfw.bruteforce /
frfw.ztna (same `_run_nft`/`_list_set_elements`/snapshot shape,
see frfw.bruteforce's docstring for why this project keeps these
separate instead of sharing a base class), with two real differences:

- elements are MAC addresses (`type ether_addr`), matched with
  `ether saddr`, so a device can't escape by getting a new DHCP lease;
- there is no per-element timeout. The whole set is replaced atomically
  on every scan (`sync_isolated`, one `nft -f` transaction: `flush set`
  plus `add element`), so a device leaves the set exactly when the next
  scan -- or an admin marking it trusted -- says it should.

The *decision* is made in the unprivileged scanner (frfw.iot.scanner,
running as fr_os-sensor, which is also the process that parses untrusted
mDNS/DHCP data); this module is only reached through the privileged
apply-helper's `iot_sync_isolation` command, which additionally drops
any MAC the current config lists as trusted before calling in here.

Every function that touches the kernel needs root (CAP_NET_ADMIN), same
as the other three set modules.
"""

from __future__ import annotations

import json
import re
import subprocess

from frfw import validate
from frfw.nft.builder import FILTER_TABLE, IOT_ISOLATED_SET_NAME

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}\Z")

#: Upper bound on one sync request -- far above any real home/small-office
#: network, low enough that a bogus request can't build a huge nft script.
MAX_ISOLATED = 4096


class IotIsolationError(Exception):
    """Raised when `nft` rejects an isolation-set operation, an input MAC
    is malformed, or the `nft` binary itself is unavailable."""


def normalize_macs(macs: list[str]) -> list[str]:
    """Lowercased, de-duplicated, validated -- raises on the first bad one
    rather than silently skipping it, so a caller bug is visible."""
    if len(macs) > MAX_ISOLATED:
        raise IotIsolationError(f"too many MACs ({len(macs)} > {MAX_ISOLATED})")
    result: list[str] = []
    for mac in macs:
        if not isinstance(mac, str):
            raise IotIsolationError(f"invalid MAC address {mac!r}")
        mac = mac.lower()
        if not _MAC_RE.match(mac):
            raise IotIsolationError(f"invalid MAC address {mac!r}")
        if mac not in result:
            result.append(mac)
    return result


def sync_isolated(macs: list[str]) -> list[str]:
    """Replace the set's contents with exactly `macs`, in one nft
    transaction (either the whole new membership lands or nothing
    changes). Returns the normalized list actually written."""
    macs = normalize_macs(macs)
    script = [f"flush set inet {FILTER_TABLE} {IOT_ISOLATED_SET_NAME}"]
    if macs:
        script.append(
            f"add element inet {FILTER_TABLE} {IOT_ISOLATED_SET_NAME} {{ {', '.join(macs)} }}"
        )
    _nft_script("\n".join(script) + "\n")
    return macs


def list_isolated() -> list[str]:
    """Live set membership -- for the webUI/metrics. Surfaces real nft
    errors instead of reporting zero, like frfw.ids_quarantine's
    status query."""
    return _list_set_elements()


def snapshot_before_reload() -> list[str]:
    """Every currently isolated device's MAC (the MACs), read just
    before a full ruleset reload: frfw.provision.apply_all passes them to
    frfw.nft.build_ruleset, which writes them into the new ruleset's set
    declaration, so they survive the reload in the same nft transaction
    (review FR-002). A set or table that isn't loaded yet means nothing
    to carry over; any other failure raises IotIsolationError -- the apply then
    stops before touching the running ruleset, rather than silently
    releasing everyone.
    """
    return _list_set_elements()


# --- kernel state (nft) -------------------------------------------------


def _list_set_elements() -> list[str]:
    proc = _run_nft(["-j", "list", "set", "inet", FILTER_TABLE, IOT_ISOLATED_SET_NAME])
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        if "No such file or directory" in stderr or "does not exist" in stderr:
            return []
        raise IotIsolationError(stderr or f"nft exited with status {proc.returncode}")

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise IotIsolationError(f"could not parse nft JSON output: {exc}") from exc

    macs: list[str] = []
    for obj in data.get("nftables", []):
        set_obj = obj.get("set")
        if not set_obj:
            continue
        for entry in set_obj.get("elem", []):
            # A set without `flags timeout` lists plain strings; keep the
            # dict form too in case an nft version wraps them anyway.
            if isinstance(entry, dict):
                entry = (entry.get("elem") or {}).get("val")
            if isinstance(entry, str):
                macs.append(entry.lower())
    return macs


def _nft_script(script: str) -> None:
    try:
        proc = subprocess.run(["nft", "-f", "-"], input=script, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise IotIsolationError("'nft' binary not found; install the nftables package") from exc
    if proc.returncode != 0:
        raise IotIsolationError(proc.stderr.strip() or f"nft exited with status {proc.returncode}")


def _run_nft(args: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(validate.nft_argv(args), capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise IotIsolationError("'nft' binary not found; install the nftables package") from exc
