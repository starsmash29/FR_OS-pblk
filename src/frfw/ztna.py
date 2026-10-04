"""Zero Trust Network Access (ZTNA) gate: kernel-space, per-client
authorization enforcement via nftables dynamic timeout sets.

The whole design fits in one sentence: a client is either currently an
element of the gate's sets or it isn't, and any rule with `require_ztna:
true` (see `frfw.config.schema.Rule`) only matches traffic from a client
that is.

**What a "client" is (ROADMAP SEC-6, review v0.2.0 R12).** It used to be
a source IP alone, so everyone behind one NAT got in once one person
signed in, and another device on the LAN could take a signed-in address
over. Now it is one device:

- on the router's own networks, the address *and* the MAC the router
  sees it at (`frfw.nft.builder.ZTNA_SET_NAME`, `ipv4_addr .
  ether_addr`). The MAC comes from the router's own neighbour table
  (`client_link`), read by root right after the client's sign-in request
  reached it -- never from anything the client says;
- through the WireGuard tunnel, the tunnel address
  (`frfw.nft.builder.ZTNA_TUNNEL_SET_NAME`): WireGuard binds it to the
  client's key;
- anything else -- a client behind another router or NAT, which the
  router can't tell apart from the others there -- is refused, and told
  to use WireGuard (`ClientNotDirect`). A NAT device *on* the LAN is
  still one device to the router: whoever is behind it shares its
  sign-in, the same limit any address-based gate has.

There is no per-connection/per-request identity check, no session token,
no cloud identity provider, and no userspace timer -- granting access
means one `nft add element ... { ip . mac timeout Ns }` call, and the
*kernel itself* evicts the element when its own timeout elapses
(confirmed by hand during development: an element added with a
5-second timeout was gone from `nft list set`'s output within 6
seconds, no code involved). This is what makes it cheap enough to run
on old x86 hardware at line rate -- the data plane never leaves the
kernel, and there is nothing for userspace to poll.

Every function in this module that touches the kernel (`authorize_client`,
`client_link`, `get_authorization`, `snapshot_before_reload`) requires root: reading or
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
every currently-authorized ZTNA client. `snapshot_before_reload()`
exists specifically to prevent that: frfw.provision.apply_all reads the
sessions with it just before the reload and the new ruleset declares
them again (frfw.nft.RuntimeSets), each with whatever time it had left,
in the same nft transaction as the flush.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from frfw import paths, validate
from frfw.nft.builder import FILTER_TABLE, ZTNA_SET_NAME, ZTNA_TUNNEL_SET_NAME


class ZtnaError(Exception):
    """Raised when `nft` rejects a ZTNA set operation, or the `nft`
    binary itself is unavailable."""


class ClientNotDirect(ZtnaError):
    """The client is not on a network the router is directly attached to
    (ROADMAP SEC-6): it reached the gate through another router or NAT,
    so the router can't tell it apart from the others behind it."""


#: Neighbour states in which the kernel holds a usable link-layer address.
_USABLE_NEIGH_STATES = frozenset({"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP"})


@dataclass(frozen=True)
class ZtnaAuthorization:
    ip: str
    username: str | None
    expires_in_seconds: int
    mac: str = ""  # "" for a WireGuard client: its tunnel address is bound to its key


@dataclass(frozen=True)
class ClientLink:
    mac: str
    device: str


def client_link(ip: str) -> ClientLink | None:
    """The MAC and device the router reaches `ip` at, from its own
    neighbour table (`ip -j neigh show to IP`), or None if `ip` is not a
    neighbour -- not on a network the router is directly attached to.
    The client has just sent the router a request, so a neighbour on the
    LAN has a fresh entry. Root only reads it; the client tells nothing."""
    validate.ipv4(ip)
    try:
        proc = subprocess.run(["ip", "-j", "neigh", "show", "to", ip], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ZtnaError(f"could not read the neighbour table: {exc}") from exc
    if proc.returncode != 0:
        raise ZtnaError(proc.stderr.strip() or f"ip neigh exited with status {proc.returncode}")
    try:
        entries = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise ZtnaError(f"could not parse ip neigh output: {exc}") from exc
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict) or entry.get("dst") != ip:
            continue
        states = set(entry.get("state") or [])
        lladdr, dev = entry.get("lladdr"), entry.get("dev")
        if not (states & _USABLE_NEIGH_STATES) or not isinstance(lladdr, str) or not isinstance(dev, str):
            continue
        try:
            return ClientLink(mac=validate.mac(lladdr), device=validate.ifname(dev))
        except validate.ArgumentError:
            continue
    return None


def authorize_client(
    ip: str,
    mac: str,
    ttl_seconds: int,
    username: str,
    *,
    state_path: Path = paths.ZTNA_STATE_PATH,
) -> None:
    """Grants the client access for `ttl_seconds` by adding it to the
    kernel's ZTNA sets -- the actual, sole enforcement action; everything
    else here is bookkeeping for the /ztna/status page. `mac` names the
    device on the router's own networks (ZTNA_SET_NAME); "" is a
    WireGuard client, by its tunnel address (ZTNA_TUNNEL_SET_NAME) --
    frfw.helper.server decides which, never the client. Requires root
    (see this module's docstring) and the sets to exist, i.e. a firewall
    apply must have run at least once.
    """
    try:
        ipaddress.IPv4Address(ip)
    except ValueError as exc:
        raise ZtnaError(f"invalid IPv4 address {ip!r}: {exc}") from exc
    if mac:
        try:
            mac = validate.mac(mac)
        except validate.ArgumentError as exc:
            raise ZtnaError(str(exc)) from exc
        _nft(["add", "element", "inet", FILTER_TABLE, ZTNA_SET_NAME, "{", f"{ip} . {mac} timeout {ttl_seconds}s", "}"])
    else:
        _nft(["add", "element", "inet", FILTER_TABLE, ZTNA_TUNNEL_SET_NAME, "{", f"{ip} timeout {ttl_seconds}s", "}"])
    _record_authorization(ip, mac, username, state_path)


def get_authorization(ip: str, mac: str = "", *, state_path: Path = paths.ZTNA_STATE_PATH) -> ZtnaAuthorization | None:
    """Live kernel-state lookup: is this client -- `ip` at `mac`, or the
    WireGuard client at `ip` when `mac` is "" -- currently authorized, and
    for how long? Returns `None` if not, covering both "never authorized"
    and "already evicted by the kernel", which are indistinguishable and
    should be: there is no separate "expired but still remembered" state.
    """
    for elem_ip, elem_mac, remaining in _list_elements():
        if elem_ip == ip and elem_mac == mac.lower():
            return ZtnaAuthorization(ip=ip, username=_lookup_username(ip, state_path),
                                     expires_in_seconds=remaining, mac=elem_mac)
    return None


def list_authorized() -> list[tuple[str, str, int]]:
    """Live (ip, mac, remaining_seconds) for every currently authorized
    ZTNA client, mac "" for a WireGuard client -- a status query, e.g. for
    the metrics exporter's `fros_ztna_active_sessions` gauge (see
    frfw.metrics). Surfaces a genuine nft problem rather than reporting
    zero sessions."""
    return _list_elements()


def snapshot_before_reload() -> list[tuple[str, str, int]]:
    """Every currently authorized ZTNA client (ip, mac, seconds left),
    read just before a full ruleset reload: frfw.provision.apply_all
    passes them to frfw.nft.build_ruleset, which writes them into the new
    ruleset's set declarations, so they survive the reload in the same
    nft transaction (review FR-002). A set or table that isn't loaded yet
    means nothing to carry over -- also the address-only set of a version
    before ROADMAP SEC-6, whose sessions name no device: those sign in
    again. Any other failure raises ZtnaError -- the apply then stops
    before touching the running ruleset, rather than silently releasing
    everyone.
    """
    return _list_elements()


# --- kernel state (nft) -------------------------------------------------


def _list_elements() -> list[tuple[str, str, int]]:
    return _list_set_elements(ZTNA_SET_NAME, paired=True) + _list_set_elements(ZTNA_TUNNEL_SET_NAME, paired=False)


def _list_set_elements(set_name: str, *, paired: bool) -> list[tuple[str, str, int]]:
    """(ip, mac, seconds left) for each element of one ZTNA set. Only the
    shape the set is meant to hold counts: `paired`, address . MAC pairs
    (mac never ""); otherwise addresses (mac ""). So the address-only
    ZTNA_SET_NAME of a version before ROADMAP SEC-6 yields nothing, and
    its sessions are never carried into the tunnel set by mistake."""
    proc = _run_nft(["-j", "list", "set", "inet", FILTER_TABLE, set_name])
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        if "No such file or directory" in stderr or "does not exist" in stderr:
            return []  # set (or the whole table) not loaded -- nothing authorized
        raise ZtnaError(stderr or f"nft exited with status {proc.returncode}")

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ZtnaError(f"could not parse nft JSON output: {exc}") from exc

    elements: list[tuple[str, str, int]] = []
    for obj in data.get("nftables", []):
        set_obj = obj.get("set")
        if not set_obj:
            continue
        for entry in set_obj.get("elem", []):
            elem = entry.get("elem") if isinstance(entry, dict) else None
            if not isinstance(elem, dict):
                continue
            val = elem.get("val")
            if not paired and isinstance(val, str):
                ip, mac = val, ""
            elif paired and isinstance(val, dict) and isinstance(val.get("concat"), list) and len(val["concat"]) == 2:
                ip, mac = val["concat"]
                if not isinstance(mac, str) or not mac:
                    continue
            else:
                continue
            if not isinstance(ip, str) or not isinstance(mac, str):
                continue
            elements.append((ip, mac.lower(), int(elem.get("expires") or 0)))
    return elements


def _nft(args: list[str]) -> None:
    proc = _run_nft(args)
    if proc.returncode != 0:
        raise ZtnaError(proc.stderr.strip() or f"nft exited with status {proc.returncode}")


def _run_nft(args: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(validate.nft_argv(args), capture_output=True, text=True)
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


def _record_authorization(ip: str, mac: str, username: str, state_path: Path) -> None:
    state = _load_state(state_path)
    state[ip] = {"username": username, "mac": mac, "authorized_at": time.time()}
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = state_path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(state))
    tmp_path.replace(state_path)


def _lookup_username(ip: str, state_path: Path) -> str | None:
    entry = _load_state(state_path).get(ip)
    return entry.get("username") if isinstance(entry, dict) else None
