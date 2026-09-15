"""Zero Trust Network Access (ZTNA) gate: kernel-space, per-source-IP
authorization enforcement via an nftables dynamic timeout set.

The whole design fits in one sentence: a source IP is either currently
an element of the `authenticated_ztna_users` nftables set
(`frfw.nft.builder.ZTNA_SET_NAME`) or it isn't, and any rule with
`require_ztna: true` (see `frfw.config.schema.Rule`) only matches
traffic from an IP that is. There is no per-connection/per-request
identity check, no session token, no cloud identity provider, and no
userspace timer -- granting access means one `nft add element ... {
ip timeout Ns }` call, and the *kernel itself* evicts the element when
its own timeout elapses (confirmed by hand during development: an
element added with a 5-second timeout was gone from `nft list set`'s
output within 6 seconds, no code involved). This is what makes it cheap
enough to run on old x86 hardware at line rate -- the data plane never
leaves the kernel, and there is nothing for userspace to poll.

Every function in this module that touches the kernel (`authorize_ip`,
`get_authorization`, `snapshot_before_reload`) requires root: reading or
writing nftables state -- even a read-only `nft list` -- needs
CAP_NET_ADMIN, confirmed directly (`runuser -u nobody -- nft list
ruleset` fails with "Operation not permitted (you must be root)" even
though it changes nothing). That means, unlike frfw.xdp's
get_stats()/get_attached() (which read a plain JSON state file the
unprivileged webUI process can open directly), *nothing* in this module
is safe to call from the unprivileged webUI process -- every call, the
read-only status check included, goes through fr-apply-helper's Unix
socket (see frfw.helper.server's "authorize_ztna"/"ztna_status"
commands and frfw.webui.routes.ztna, which never imports this module
directly).

IMPORTANT -- the `flush ruleset` problem. frfw.nft.builder always
starts a generated ruleset with `flush ruleset` (see that module's
docstring), which deletes *every* table, chain and set in the kernel's
entire nftables state, this one included; the very next line in the
same reload recreates an empty set. Left alone, that means any admin
clicking "Apply" for a completely unrelated firewall change (e.g.
adding a rule for a new device) would instantly and silently log out
every currently-authorized ZTNA client. `snapshot_before_reload()` /
`restore_after_reload()` exist specifically to prevent that:
frfw.provision.apply_all calls the former immediately before
`frfw.apply.apply_ruleset()` and the latter immediately after,
re-adding every previously-authorized IP with a fresh timeout equal to
whatever time it had left. This does mean a session can gain a few
extra seconds (the time the apply itself took) on every such reload --
an explicit, harmless-in-practice tradeoff in the user's favor, not a
bug.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from frfw import paths
from frfw.nft.builder import FILTER_TABLE, ZTNA_SET_NAME


class ZtnaError(Exception):
    """Raised when `nft` rejects a ZTNA set operation, or the `nft`
    binary itself is unavailable."""


@dataclass(frozen=True)
class ZtnaAuthorization:
    ip: str
    username: str | None
    expires_in_seconds: int


def authorize_ip(
    ip: str,
    ttl_seconds: int,
    username: str,
    *,
    state_path: Path = paths.ZTNA_STATE_PATH,
) -> None:
    """Grants `ip` access for `ttl_seconds` by adding it to the kernel's
    ZTNA set -- the actual, sole enforcement action; everything else in
    this function is bookkeeping for the /ztna/status page. Requires
    root (see this module's docstring) and the set to already exist,
    i.e. `config.ztna.enabled` must be true and a firewall apply must
    have run at least once since -- the caller (frfw.helper.server) is
    expected to check `config.ztna.enabled` itself and return a clear
    error rather than let this raise a confusing nft error for that
    case.
    """
    try:
        ipaddress.IPv4Address(ip)
    except ValueError as exc:
        raise ZtnaError(f"invalid IPv4 address {ip!r}: {exc}") from exc

    _nft(["add", "element", "inet", FILTER_TABLE, ZTNA_SET_NAME, "{", f"{ip} timeout {ttl_seconds}s", "}"])
    _record_authorization(ip, username, state_path)


def get_authorization(ip: str, *, state_path: Path = paths.ZTNA_STATE_PATH) -> ZtnaAuthorization | None:
    """Live kernel-state lookup: is `ip` currently a member of the ZTNA
    set, and if so, how much time does it have left? Returns `None` if
    not authorized -- covering both "never authorized" and "was
    authorized but the kernel has already evicted it", which are
    indistinguishable and should be: there is no separate "expired but
    still remembered" state anywhere in this design.
    """
    for elem_ip, remaining in _list_set_elements():
        if elem_ip == ip:
            return ZtnaAuthorization(
                ip=ip, username=_lookup_username(ip, state_path), expires_in_seconds=remaining
            )
    return None


def snapshot_before_reload() -> list[tuple[str, int]]:
    """Best-effort (ip, remaining_seconds) pairs for every currently
    authorized client, to hand to `restore_after_reload()` after a full
    ruleset reload wipes the set (see this module's docstring). Never
    raises: a fresh install (the table/set doesn't exist yet, e.g. ZTNA
    was never enabled or this is the very first apply), a temporarily
    missing `nft` binary, or any other failure just means "nothing to
    preserve" -- none of those are reasons to fail an otherwise-valid
    firewall apply that has nothing to do with ZTNA.
    """
    try:
        return _list_set_elements()
    except ZtnaError:
        return []


def restore_after_reload(snapshot: list[tuple[str, int]]) -> None:
    """Re-adds every (ip, remaining_seconds) pair from a prior
    `snapshot_before_reload()` call, each with a fresh timeout set to
    its captured remaining time. Best-effort per element -- one stale
    or now-invalid entry (e.g. the new config disabled ZTNA, so the set
    no longer exists at all) never blocks the rest, and this function
    never raises: restoring sessions is a courtesy on top of a firewall
    apply that has already succeeded by the time this runs, never a
    reason to report that apply as failed.
    """
    for ip, remaining in snapshot:
        if remaining <= 0:
            continue
        try:
            _nft(
                [
                    "add", "element", "inet", FILTER_TABLE, ZTNA_SET_NAME,
                    "{", f"{ip} timeout {remaining}s", "}",
                ]
            )
        except ZtnaError:
            continue


# --- kernel state (nft) -------------------------------------------------


def _list_set_elements() -> list[tuple[str, int]]:
    proc = _run_nft(["-j", "list", "set", "inet", FILTER_TABLE, ZTNA_SET_NAME])
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        if "No such file or directory" in stderr or "does not exist" in stderr:
            return []  # set (or the whole table) not loaded -- nothing authorized
        raise ZtnaError(stderr or f"nft exited with status {proc.returncode}")

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ZtnaError(f"could not parse nft JSON output: {exc}") from exc

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
        raise ZtnaError(proc.stderr.strip() or f"nft exited with status {proc.returncode}")


def _run_nft(args: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["nft", *args], capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise ZtnaError("'nft' binary not found; install the nftables package") from exc


# --- display-only state (which username authorized which IP) -----------


def _load_state(state_path: Path) -> dict:
    if not state_path.is_file():
        return {}
    try:
        return json.loads(state_path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _record_authorization(ip: str, username: str, state_path: Path) -> None:
    state = _load_state(state_path)
    state[ip] = {"username": username, "authorized_at": time.time()}
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = state_path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(state))
    tmp_path.replace(state_path)


def _lookup_username(ip: str, state_path: Path) -> str | None:
    entry = _load_state(state_path).get(ip)
    return entry.get("username") if isinstance(entry, dict) else None
