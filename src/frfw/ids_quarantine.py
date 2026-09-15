"""Kernel-level IPS enforcement for the AI IDS engine (frfw.ai_ids):
quarantines a source IP by adding it to the `ids_quarantine` nftables set
(`frfw.nft.builder.IDS_QUARANTINE_SET_NAME`), which the generated
ruleset's `chain input` drops unconditionally, near the very top --
right after the brute-force jail's own drop rule, before any other rule.

This module is a deliberate close structural mirror of frfw.bruteforce
(itself a mirror of frfw.ztna) rather than sharing code with either of
them: same `_nft`/`_run_nft`/`_list_set_elements`/snapshot-restore shape,
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
`snapshot_before_reload()`/`restore_after_reload()` exist to prevent
exactly that, called from `frfw.provision.apply_all` the same way as the
brute-force jail's and ZTNA's own pairs.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess

from frfw.nft.builder import FILTER_TABLE, IDS_QUARANTINE_SET_NAME


class IdsQuarantineError(Exception):
    """Raised when `nft` rejects a quarantine-set operation, or the
    `nft` binary itself is unavailable."""


def quarantine_ip(ip: str, duration_seconds: int) -> None:
    """Adds `ip` to the kernel's IDS quarantine set for
    `duration_seconds` -- the sole enforcement action. Requires root and
    the set to already exist (i.e. at least one firewall apply must have
    run since install, same precondition frfw.bruteforce.ban_ip has for
    its own set)."""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError as exc:
        raise IdsQuarantineError(f"invalid IPv4 address {ip!r}: {exc}") from exc
    if duration_seconds <= 0:
        raise IdsQuarantineError(f"duration_seconds must be positive, got {duration_seconds}")

    _nft(
        [
            "add", "element", "inet", FILTER_TABLE, IDS_QUARANTINE_SET_NAME,
            "{", f"{ip} timeout {duration_seconds}s", "}",
        ]
    )


def list_quarantined() -> list[tuple[str, int]]:
    """Live (ip, remaining_seconds) pairs for every currently quarantined
    IP -- the webUI dashboard/AI IDS screen's status query. Unlike
    `snapshot_before_reload()` below, this does NOT swallow nft errors:
    a status query should surface a genuine problem (e.g. `nft` itself
    missing) to the admin rather than silently reporting zero
    quarantined hosts."""
    return _list_set_elements()


def snapshot_before_reload() -> list[tuple[str, int]]:
    """Best-effort (ip, remaining_seconds) pairs for every currently
    quarantined IP, to hand to `restore_after_reload()` after a full
    ruleset reload wipes the set (see this module's docstring). Never
    raises -- mirrors `frfw.bruteforce.snapshot_before_reload`'s exact
    reasoning: a fresh install, a temporarily missing `nft` binary, or
    any other failure just means "nothing to preserve", never a reason
    to fail an otherwise-valid firewall apply."""
    try:
        return _list_set_elements()
    except IdsQuarantineError:
        return []


def restore_after_reload(snapshot: list[tuple[str, int]]) -> None:
    """Re-adds every (ip, remaining_seconds) pair from a prior
    `snapshot_before_reload()` call, each with a fresh timeout set to its
    captured remaining time. Best-effort per element, and never raises --
    identical rationale to `frfw.bruteforce.restore_after_reload`."""
    for ip, remaining in snapshot:
        if remaining <= 0:
            continue
        try:
            _nft(
                [
                    "add", "element", "inet", FILTER_TABLE, IDS_QUARANTINE_SET_NAME,
                    "{", f"{ip} timeout {remaining}s", "}",
                ]
            )
        except IdsQuarantineError:
            continue


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
        return subprocess.run(["nft", *args], capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise IdsQuarantineError("'nft' binary not found; install the nftables package") from exc
