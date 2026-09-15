"""Reads a lightweight per-flow snapshot from the kernel's connection
tracking table, for the AI IDS/IPS engine's connection-rate and
destination-diversity features (see frfw.ai_ids.engine).

Why this exists at all: the phase 4 XDP SNI filter (frfw.xdp,
bpf/xdp_sni_filter.c) only ever sees TCP traffic to port 443 whose
ClientHello SNI matches a *blocklisted* domain -- it never logs a pass,
and it has no notion of "connection attempts" or "destination diversity"
for arbitrary traffic. Requests for real signal on those two features
therefore cannot be satisfied from fr-xdp-sni-logger's output alone;
there is a real trust boundary to document here (see ARCHITECTURE.md's
phase 11 section for the full correction).

The only other already-active, real, kernel-native source of "which
source IP is talking to which destination IP/port, and is this a new
flow" is Linux's own connection tracker -- already running on this
router regardless of AI IDS, because `ct state established,related
accept`/`ct state invalid drop` (frfw.nft.builder's every generated
ruleset) require it. `/proc/net/nf_conntrack` exposes exactly that table
as a plain text pseudo-file, one line per tracked flow, with no new
system package needed (confirmed in this sandbox that `conntrack-tools`
isn't installed by default, and isn't a dependency of this project) --
parsing it directly in Python is lighter than shelling out to a CLI tool
that may not even be present.

IMPORTANT -- like every other kernel-state read in this project
(frfw.ztna, frfw.bruteforce, frfw.ids_quarantine all document the same
thing for `nft list`), this file is root-only: confirmed by hand in this
sandbox (`ls -la /proc/net/nf_conntrack` -> `-r--r----- root root`;
reading it as an unprivileged user raises PermissionError). This module
itself does not check privilege -- exactly like frfw.ifaddr/frfw.kea,
which leave that to their call site -- because its only caller
(frfw.helper.server's "conntrack_sample" command) already runs as root
by construction (it's the privileged apply-helper), the same way
frfw.ztna's kernel reads are only ever reached through that same
process.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

CONNTRACK_PATH = Path("/proc/net/nf_conntrack")

#: Only these two L4 protocols are meaningful for connection-rate /
#: destination-diversity scoring -- an ICMP conntrack line has no
#: sport/dport at all (type=/code=/id= instead), so it never produces a
#: flow here rather than producing one with fabricated port numbers.
_TRACKED_PROTOCOLS = frozenset({"tcp", "udp"})


class ConntrackError(Exception):
    """Raised when `/proc/net/nf_conntrack` exists but cannot be read
    (wrong permissions, module not loaded in an unexpected way) --
    distinct from the file simply not existing, which read_snapshot()
    treats as "no flows" rather than an error, since a from-scratch
    system genuinely has nothing tracked yet."""


@dataclass(frozen=True)
class ConntrackFlow:
    """The original-direction 5-tuple of one tracked flow. `sport` is
    kept only so a caller (frfw.ai_ids.daemon) can tell two genuinely
    different flows between the same src/dst/dport apart when diffing
    consecutive snapshots for "is this flow new since last time?" -- the
    anomaly engine itself never looks at it."""

    proto: str
    src: str
    sport: int
    dst: str
    dport: int


def read_snapshot(path: Path = CONNTRACK_PATH) -> list[ConntrackFlow]:
    """Parse every currently-tracked TCP/UDP flow's original-direction
    tuple. Returns an empty list if the file doesn't exist at all (no
    conntrack entries have ever been created, or the kernel wasn't built
    with connection tracking -- both mean "nothing to report", not an
    error). Raises `ConntrackError` if the file exists but can't be read
    (e.g. this process isn't actually root).

    Deliberately scans for `src=`/`dst=`/`dport=`/`sport=` tokens by
    prefix rather than a fixed field index: a TCP line has an extra TCP
    state token (e.g. "ESTABLISHED") between the timeout and the first
    `src=` that a UDP line doesn't, so the *position* of the tuple's
    fields shifts by protocol, but the *first occurrence* of each
    prefixed token is always the original-direction tuple regardless
    (the conntrack line always lists the original direction before the
    reply direction's own src=/dst=/sport=/dport= repeat).
    """
    if not path.is_file():
        return []
    try:
        text = path.read_text()
    except OSError as exc:
        raise ConntrackError(f"cannot read {path}: {exc}") from exc

    flows: list[ConntrackFlow] = []
    for line in text.splitlines():
        flow = _parse_line(line)
        if flow is not None:
            flows.append(flow)
    return flows


def _parse_line(line: str) -> ConntrackFlow | None:
    parts = line.split()
    if len(parts) < 5:
        return None
    proto = parts[2]
    if proto not in _TRACKED_PROTOCOLS:
        return None

    src = dst = None
    sport = dport = None
    for token in parts:
        if src is None and token.startswith("src="):
            src = token[4:]
        elif dst is None and token.startswith("dst="):
            dst = token[4:]
        elif sport is None and token.startswith("sport="):
            sport = _to_int(token[6:])
        elif dport is None and token.startswith("dport="):
            dport = _to_int(token[6:])
        if src is not None and dst is not None and sport is not None and dport is not None:
            break

    if src is None or dst is None or sport is None or dport is None:
        return None
    return ConntrackFlow(proto=proto, src=src, sport=sport, dst=dst, dport=dport)


def _to_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None
