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
`frfw.ztna` (same `_nft`/`_run_nft`/`_list_set_elements`/snapshot-restore
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
config change. `snapshot_before_reload()`/`restore_after_reload()` exist
to prevent exactly that, called from `frfw.provision.apply_all` the same
way as ZTNA's pair.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess

from frfw.nft.builder import BRUTEFORCE_JAIL_SET_NAME, FILTER_TABLE


class BruteforceError(Exception):
    """Raised when `nft` rejects a jail-set operation, or the `nft`
    binary itself is unavailable."""


def ban_ip(ip: str, duration_seconds: int) -> None:
    """Adds `ip` to the kernel's brute-force jail set for
    `duration_seconds` -- the sole enforcement action. Requires root and
    the set to already exist (i.e. at least one firewall apply must have
    run since install, same precondition `frfw.ztna.authorize_ip` has for
    its own set)."""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError as exc:
        raise BruteforceError(f"invalid IPv4 address {ip!r}: {exc}") from exc
    if duration_seconds <= 0:
        raise BruteforceError(f"duration_seconds must be positive, got {duration_seconds}")

    _nft(
        [
            "add", "element", "inet", FILTER_TABLE, BRUTEFORCE_JAIL_SET_NAME,
            "{", f"{ip} timeout {duration_seconds}s", "}",
        ]
    )


def snapshot_before_reload() -> list[tuple[str, int]]:
    """Best-effort (ip, remaining_seconds) pairs for every currently
    jailed IP, to hand to `restore_after_reload()` after a full ruleset
    reload wipes the set (see this module's docstring). Never raises --
    mirrors `frfw.ztna.snapshot_before_reload`'s exact reasoning: a fresh
    install, a temporarily missing `nft` binary, or any other failure
    just means "nothing to preserve", never a reason to fail an
    otherwise-valid firewall apply."""
    try:
        return _list_set_elements()
    except BruteforceError:
        return []


def restore_after_reload(snapshot: list[tuple[str, int]]) -> None:
    """Re-adds every (ip, remaining_seconds) pair from a prior
    `snapshot_before_reload()` call, each with a fresh timeout set to its
    captured remaining time. Best-effort per element, and never raises --
    identical rationale to `frfw.ztna.restore_after_reload`."""
    for ip, remaining in snapshot:
        if remaining <= 0:
            continue
        try:
            _nft(
                [
                    "add", "element", "inet", FILTER_TABLE, BRUTEFORCE_JAIL_SET_NAME,
                    "{", f"{ip} timeout {remaining}s", "}",
                ]
            )
        except BruteforceError:
            continue


# --- kernel state (nft) -------------------------------------------------


def _list_set_elements() -> list[tuple[str, int]]:
    proc = _run_nft(["-j", "list", "set", "inet", FILTER_TABLE, BRUTEFORCE_JAIL_SET_NAME])
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
            ip = elem.get("val")
            if not isinstance(ip, str):
                continue
            elements.append((ip, int(elem.get("expires") or 0)))
    return elements


def _nft(args: list[str]) -> None:
    proc = _run_nft(args)
    if proc.returncode != 0:
        raise BruteforceError(proc.stderr.strip() or f"nft exited with status {proc.returncode}")


def _run_nft(args: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["nft", *args], capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise BruteforceError("'nft' binary not found; install the nftables package") from exc
