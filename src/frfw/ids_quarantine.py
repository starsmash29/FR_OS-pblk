"""Kernel-level IPS enforcement for the AI IDS engine (frfw.ai_ids):
quarantines a source IP by adding it to the `ids_quarantine` nftables set
(`frfw.nft.builder.IDS_QUARANTINE_SET_NAME`), which the generated
ruleset drops unconditionally in both `chain input` (near the very top,
right after the brute-force jail's own drop rule) and `chain forward`
(first): a quarantined host reaches neither the router nor anything
through it (review C-01 -- it used to be the router only).

`quarantine_ip` refuses addresses no detector should ever quarantine
(loopback, unspecified, multicast, link-local, reserved, broadcast, and
the router's own addresses, which the helper passes in) and caps the
duration at MAX_DURATION_SECONDS: the command is open to the parser
daemons, so a bug in one must not be able to lock the router out of
itself for years (review C-04).

This module is a deliberate close structural mirror of frfw.bruteforce
(itself a mirror of frfw.ztna) rather than sharing code with either of
them: same `_nft`/`_run_nft`/`_list_set_elements`/snapshot shape,
against a third, independent kernel set. See frfw.bruteforce's own
docstring for why this project keeps doing this instead of factoring out
a shared "banned-IP-set" base class -- a jail set of banned IPs, a set
of ZTNA-authorized IPs, and a set of IDS-quarantined IPs happen to look
alike today, but nothing requires them to stay that way, and each stays
independently testable without an early shared abstraction.

The *decision* to quarantine an IP is made entirely in the unprivileged
`fr-ai-ids` daemon (frfw.ai_ids.engine.AnomalyEngine, scoring connection-
rate/destination-diversity/SNI-blocklist-hit features drawn from
frfw.conntrack and fr-xdp-sni-logger's journald output); this module is
only the kernel-side enforcement action, reached exclusively through the
privileged apply-helper's `quarantine_ip` socket command (see
frfw.helper.server) -- the AI IDS daemon never touches `nft` itself,
exactly like the webUI never does for `ban_ip`.

Once quarantined, the kernel evicts the element itself when its own
element timeout elapses -- no userspace polling, cron job, or background
thread involved, the identical mechanism frfw.bruteforce/frfw.ztna
already use and already verified by hand.

Every function here that touches the kernel requires root, for the same
reason frfw.ztna documents in detail: even a read-only `nft list` needs
CAP_NET_ADMIN.

IMPORTANT -- the same `flush ruleset` problem ZTNA and the brute-force
jail have. Since IDS_QUARANTINE_SET_NAME is declared unconditionally
(see that constant's comment in frfw.nft.builder), *every* firewall
apply -- not just ones enabling some optional feature -- would otherwise
silently un-quarantine every currently-quarantined IP the instant an
admin saves any unrelated config change.
`snapshot_before_reload()` exists to prevent exactly that: the live
quarantines are carried into the new ruleset (frfw.nft.RuntimeSets) by
`frfw.provision.apply_all`, like the brute-force jail's and ZTNA's.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess

from frfw import validate
from frfw.nft.builder import FILTER_TABLE, IDS_QUARANTINE_SET_NAME


class IdsQuarantineError(Exception):
    """Raised when `nft` rejects a quarantine-set operation, or the
    `nft` binary itself is unavailable."""


#: The longest quarantine a single request may ask for (7 days).
MAX_DURATION_SECONDS = 7 * 24 * 3600


def check_target(ip: str, own_addresses: frozenset[str] = frozenset()) -> ipaddress.IPv4Address:
    """`ip` as an address that may be quarantined, or IdsQuarantineError."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError as exc:
        raise IdsQuarantineError(f"invalid IPv4 address {ip!r}: {exc}") from exc
    if (addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local
            or addr.is_reserved or addr == ipaddress.IPv4Address("255.255.255.255")):
        raise IdsQuarantineError(f"refusing to quarantine {ip}: not a host address")
    if str(addr) in own_addresses:
        raise IdsQuarantineError(f"refusing to quarantine {ip}: it is one of the router's own addresses")
    return addr


def quarantine_ip(ip: str, duration_seconds: int, *, own_addresses: frozenset[str] = frozenset()) -> None:
    """Adds `ip` to the kernel's IDS quarantine set for
    `duration_seconds` -- the sole enforcement action. Requires root and
    the set to already exist (i.e. at least one firewall apply must have
    run since install, same precondition frfw.bruteforce.ban_ip has for
    its own set). `own_addresses`: the router's addresses, never
    quarantined (see this module's docstring)."""
    check_target(ip, own_addresses)
    if duration_seconds <= 0:
        raise IdsQuarantineError(f"duration_seconds must be positive, got {duration_seconds}")
    if duration_seconds > MAX_DURATION_SECONDS:
        raise IdsQuarantineError(
            f"duration_seconds may be at most {MAX_DURATION_SECONDS} (7 days), got {duration_seconds}"
        )

    _nft(
        [
            "add", "element", "inet", FILTER_TABLE, IDS_QUARANTINE_SET_NAME,
            "{", f"{ip} timeout {duration_seconds}s", "}",
        ]
    )


def list_quarantined() -> list[tuple[str, int]]:
    """Live (ip, remaining_seconds) pairs for every currently quarantined
    IP -- the webUI dashboard/AI IDS screen's status query. Surfaces a
    genuine nft problem to the admin rather than silently reporting zero
    quarantined hosts."""
    return _list_set_elements()


def snapshot_before_reload() -> list[tuple[str, int]]:
    """Every currently quarantined IP (ip, seconds left), read just
    before a full ruleset reload: frfw.provision.apply_all passes them to
    frfw.nft.build_ruleset, which writes them into the new ruleset's set
    declaration, so they survive the reload in the same nft transaction
    (review FR-002). A set or table that isn't loaded yet means nothing
    to carry over; any other failure raises IdsQuarantineError -- the apply then
    stops before touching the running ruleset, rather than silently
    releasing everyone.
    """
    return _list_set_elements()


# --- kernel state (nft) -------------------------------------------------


def _list_set_elements() -> list[tuple[str, int]]:
    proc = _run_nft(["-j", "list", "set", "inet", FILTER_TABLE, IDS_QUARANTINE_SET_NAME])
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        if "No such file or directory" in stderr or "does not exist" in stderr:
            return []  # set (or the whole table) not loaded -- nobody is quarantined
        raise IdsQuarantineError(stderr or f"nft exited with status {proc.returncode}")

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise IdsQuarantineError(f"could not parse nft JSON output: {exc}") from exc

    elements: list[tuple[str, int]] = []
    for obj in data.get("nftables", []):
        set_obj = obj.get("set")
        if not set_obj:
            continue
        for entry in set_obj.get("elem", []):
            elem = entry.get("elem") if isinstance(entry, dict) else None
            if not isinstance(elem, dict):
                continue
            ip = elem.get("val")
            if not isinstance(ip, str):
                continue
            elements.append((ip, int(elem.get("expires") or 0)))
    return elements


def _nft(args: list[str]) -> None:
    proc = _run_nft(args)
    if proc.returncode != 0:
        raise IdsQuarantineError(proc.stderr.strip() or f"nft exited with status {proc.returncode}")


def _run_nft(args: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(validate.nft_argv(args), capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise IdsQuarantineError("'nft' binary not found; install the nftables package") from exc
