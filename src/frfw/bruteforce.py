"""Kernel-level brute-force login protection: bans a source IP by adding
it to the `bruteforce_jail` nftables set (`frfw.nft.builder.
BRUTEFORCE_JAIL_SET_NAME`), which the generated ruleset's `chain input`
drops unconditionally, at the very top, before any other rule. The
*decision* to ban an IP is made entirely in the unprivileged webUI
process (`frfw.webui.auth_rate_limiter.BruteforceGuard`, counting failed
`/login`/`/ztna/login` attempts in memory); this module is only the
kernel-side enforcement action, reached exclusively through the
privileged apply-helper's `ban_ip` socket command (see
`frfw.helper.server`) -- the webUI never touches `nft` itself.

Once banned, the kernel evicts the element itself when its own element
timeout elapses -- no userspace polling, cron job, or background thread
involved, the identical mechanism `frfw.ztna.authorize_ip` already uses
and that module's docstring already verified by hand (an element added
with a short timeout was gone from `nft list set`'s output within a
second of it elapsing, no code running).

Every function here that touches the kernel requires root, for the same
reason `frfw.ztna` documents in detail: even a read-only `nft list`
needs CAP_NET_ADMIN. This module is a close structural mirror of
`frfw.ztna` (same `_nft`/`_run_nft`/`_list_set_elements`/snapshot
shape, against a different set) rather than sharing code with it --
consistent with how `frfw.pqc`'s TLS and SSH halves, or `frfw.kea` and
`frfw.xdp`'s subprocess-wrapping, also don't share a common base despite
similar shapes: each kernel-facing subsystem in this project stays a
small, independently-testable module rather than an early shared
abstraction across genuinely different kernel objects (a jail set of
banned IPs and a set of ZTNA-authorized IPs happen to look alike today,
but nothing requires them to stay that way).

IMPORTANT -- the same `flush ruleset` problem ZTNA has. Since
`BRUTEFORCE_JAIL_SET_NAME` is now declared unconditionally (see that
constant's comment in frfw.nft.builder), *every* firewall apply -- not
just ones enabling some optional feature -- would otherwise silently
un-ban every currently-jailed IP the instant an admin saves any unrelated
config change. `snapshot_before_reload()` exists to prevent exactly
that: `frfw.provision.apply_all` reads the live bans with it and the new
ruleset carries them (frfw.nft.RuntimeSets), the same way as ZTNA's.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
from typing import Callable, Iterable

from frfw import ids_quarantine, validate
from frfw.nft.builder import (
    BRUTEFORCE_JAIL6_SET_NAME,
    BRUTEFORCE_JAIL_MAC_SET_NAME,
    BRUTEFORCE_JAIL_SET_NAME,
    FILTER_TABLE,
)


class BruteforceError(Exception):
    """Raised when `nft` rejects a jail-set operation, or the `nft`
    binary itself is unavailable."""


def jail_key(ip: str) -> str:
    """What one source address is, for counting and jailing: the address
    itself (an IPv4-mapped IPv6 one as its IPv4). ROADMAP FND-1c keyed an
    IPv6 source by its /64, because a host picks its own interface
    identifier; but management over IPv6 is reachable from the LAN only
    (the router's ULA), where a /64 is every host on the segment (H3).
    The host itself is held by its MAC instead -- device_key for
    counting, ban_ip for the jail."""
    address = ipaddress.ip_address(ip)
    if address.version == 6 and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def device_key(ip: str, lan_devices: Iterable[str], *,
               neighbour: Callable[[str, Iterable[str]], str | None] | None = None) -> str | None:
    """The MAC of the LAN host behind the IPv6 source `ip`, from the
    router's neighbour table on one of `lan_devices`, or None: an IPv4
    source, or a host not on a LAN link. Whatever address the host picks,
    its MAC stays, so it counts and is jailed as one (ROADMAP FND-1d, H3).
    A LAN host can change its MAC too: that is a new link for the LAN,
    and buys five more guesses per MAC, which the per-account lock (10
    in 15 minutes, from any source) bounds anyway."""
    key = jail_key(ip)
    if ":" not in key:
        return None
    return (neighbour or ids_quarantine.lan_neighbour_mac)(key, lan_devices)


def ban_ip(ip: str, duration_seconds: int, *, lan_devices: Iterable[str] = (),
           neighbour: Callable[[str, Iterable[str]], str | None] | None = None) -> str | None:
    """Adds `ip` to the kernel's brute-force jail for `duration_seconds`
    -- the sole enforcement action: an IPv4 address to
    BRUTEFORCE_JAIL_SET_NAME; an IPv6 one by its host's MAC
    (device_key) to BRUTEFORCE_JAIL_MAC_SET_NAME, or as the address to
    BRUTEFORCE_JAIL6_SET_NAME when the neighbour table doesn't know it.
    Returns the MAC it jailed, if any. Requires root and the sets to
    already exist (i.e. at least one firewall apply must have run since
    install, same precondition `frfw.ztna.authorize_ip` has for its own
    set)."""
    try:
        key = jail_key(ip)
    except ValueError as exc:
        raise BruteforceError(f"invalid IP address {ip!r}: {exc}") from exc
    if duration_seconds <= 0:
        raise BruteforceError(f"duration_seconds must be positive, got {duration_seconds}")

    mac = device_key(key, lan_devices, neighbour=neighbour)
    if mac is not None:
        set_name, key = BRUTEFORCE_JAIL_MAC_SET_NAME, mac
    else:
        set_name = BRUTEFORCE_JAIL6_SET_NAME if ":" in key else BRUTEFORCE_JAIL_SET_NAME
    _nft(
        [
            "add", "element", "inet", FILTER_TABLE, set_name,
            "{", f"{key} timeout {duration_seconds}s", "}",
        ]
    )
    return mac


def list_banned() -> list[tuple[str, int]]:
    """Live (source, remaining_seconds) pairs for every currently jailed
    source -- an address, a jailed host's MAC, or a /64 banned before
    FND-1d as "<network>/64" -- a status query, e.g. for the metrics
    exporter's `fros_bruteforce_banned_ips` gauge (see frfw.metrics).
    Surfaces a genuine nft problem rather than silently reporting zero
    banned IPs."""
    return (_list_set_elements() + _list_set_elements(BRUTEFORCE_JAIL6_SET_NAME)
            + _list_set_elements(BRUTEFORCE_JAIL_MAC_SET_NAME))


def snapshot_before_reload() -> list[tuple[str, int]]:
    """Every currently jailed IP (ip, seconds left), read just
    before a full ruleset reload: frfw.provision.apply_all passes them to
    frfw.nft.build_ruleset, which writes them into the new ruleset's set
    declaration, so they survive the reload in the same nft transaction
    (review FR-002). A set or table that isn't loaded yet means nothing
    to carry over; any other failure raises BruteforceError -- the apply then
    stops before touching the running ruleset, rather than silently
    releasing everyone.
    """
    return _list_set_elements()


def snapshot6_before_reload() -> list[tuple[str, int]]:
    """The same for the IPv6 jail: (address or "<network>/64", seconds
    left)."""
    return _list_set_elements(BRUTEFORCE_JAIL6_SET_NAME)


def snapshot_macs_before_reload() -> list[tuple[str, int]]:
    """The same for the jail by MAC: (mac, seconds left)."""
    return _list_set_elements(BRUTEFORCE_JAIL_MAC_SET_NAME)


# --- kernel state (nft) -------------------------------------------------


def _list_set_elements(set_name: str | None = None) -> list[tuple[str, int]]:
    set_name = set_name or BRUTEFORCE_JAIL_SET_NAME
    proc = _run_nft(["-j", "list", "set", "inet", FILTER_TABLE, set_name])
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        if "No such file or directory" in stderr or "does not exist" in stderr:
            return []  # set (or the whole table) not loaded -- nobody is jailed
        raise BruteforceError(stderr or f"nft exited with status {proc.returncode}")

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise BruteforceError(f"could not parse nft JSON output: {exc}") from exc

    elements: list[tuple[str, int]] = []
    for obj in data.get("nftables", []):
        set_obj = obj.get("set")
        if not set_obj:
            continue
        for entry in set_obj.get("elem", []):
            elem = entry.get("elem") if isinstance(entry, dict) else None
            if not isinstance(elem, dict):
                continue
            ip = _element_value(elem.get("val"))
            if ip is None:
                continue
            elements.append((ip, int(elem.get("expires") or 0)))
    return elements


def _element_value(val) -> str | None:
    """An address ("192.0.2.1"), or an interval set's prefix -- `nft -j`
    gives {"prefix": {"addr": "2001:db8::", "len": 64}} -- as
    "2001:db8::/64"."""
    if isinstance(val, str):
        return val
    if isinstance(val, dict) and isinstance(val.get("prefix"), dict):
        prefix = val["prefix"]
        if isinstance(prefix.get("addr"), str) and isinstance(prefix.get("len"), int):
            return f"{prefix['addr']}/{prefix['len']}"
    return None


def _nft(args: list[str]) -> None:
    proc = _run_nft(args)
    if proc.returncode != 0:
        raise BruteforceError(proc.stderr.strip() or f"nft exited with status {proc.returncode}")


def _run_nft(args: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(validate.nft_argv(args), capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise BruteforceError("'nft' binary not found; install the nftables package") from exc
