"""Pure, dependency-free sliding-window anomaly scoring for the AI IDS
engine -- no scikit-learn, no pandas, no numpy, nothing beyond the
stdlib (`collections.deque`, `statistics`). This is a deliberate choice,
not a shortcut: on the "legacy x86 homelab hardware" this project
targets, per-IP counters and stdlib `mean`/`pstdev` over a few dozen
samples cost nothing worth measuring, while scikit-learn alone pulls in
numpy/scipy and a compiled BLAS -- a real burden on a low-end router
appliance for a feature whose entire input is three small numbers per
known host.

This module only ever sees data that has already been reduced to
"which source IP did what, when" -- see frfw.ai_ids.daemon for where
that data actually comes from (frfw.conntrack for connection-rate/
destination-diversity, fr-xdp-sni-logger's journald output for
SNI-blocklist-hit frequency) and ARCHITECTURE.md's phase 11 section for
why those are the real, honest sources rather than a single one, and
what a request describing "ingest fr-xdp-sni-logger for everything"
gets wrong about what that logger actually emits.

Design: for each source IP, three sliding-window counters --
connection-attempt rate, the ratio of unique destination IPs to total
connection attempts (a portscan/lateral-movement signature: a normal
host talks to a handful of destinations repeatedly, a scanning host
approaches 1.0), and SNI-blocklist-hit count (a beaconing/malware
signature: repeated attempts to reach a known-bad domain). Every
`window_seconds` tick (driven by frfw.ai_ids.daemon, not by this class
itself -- see `evaluate()`), each counter's current value is compared
against that *same IP's own* history of past window values via a
z-score (`(value - mean) / stdev`), so "anomalous" means "unusual for
this host", not an arbitrary global cutoff shared by a NAS and a laptop
alike. A brand new IP has no history yet; until it accumulates
`MIN_BASELINE_SAMPLES` windows, it is instead checked against a fixed
absolute floor -- generous enough that a normal host's first few minutes
on the network do not immediately trip a "3 standard deviations from a
sample size of zero" false positive.
"""

from __future__ import annotations

import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field

#: Sliding window used for every feature -- both "how far back do we look
#: for the current sample" and "how often does frfw.ai_ids.daemon call
#: evaluate()". Not yet configurable (see ARCHITECTURE.md's open issues
#: -- the same deliberate simplification frfw.webui.auth_rate_limiter's
#: MAX_ATTEMPTS/WINDOW_SECONDS made for phase 10's brute-force guard).
WINDOW_SECONDS = 60.0

#: How many past per-window samples make up an IP's own baseline history.
BASELINE_SAMPLES = 30

#: Below this many historical samples, an IP has no meaningful baseline
#: yet -- score it against ABS_*_FLOOR instead of a z-score.
MIN_BASELINE_SAMPLES = 5

#: How many standard deviations above an IP's own mean counts as
#: anomalous, once it has a baseline.
ZSCORE_THRESHOLD = 3.0

#: Absolute floors, used only until an IP has a baseline. Deliberately
#: generous: false-positive-on-day-one is worse than a missed detection
#: for the first half hour of a host's life on the network.
ABS_CONN_RATE_FLOOR = 5.0  # new connections/second
ABS_UNIQUE_DST_RATIO_FLOOR = 0.8  # unique destinations / total connections
ABS_SNI_BLOCK_COUNT_FLOOR = 3  # blocklist hits within one window

#: A destination-diversity *ratio* is meaningless (and trivially 1.0)
#: from a tiny handful of connections -- a single connection to a
#: single destination is not a "100% of connections went to a new
#: destination" scan signature, it is simply one connection. Below this
#: many connections in the window, the ratio feature is skipped
#: entirely for that window (neither scored nor added to the baseline
#: history), rather than recording a near-meaningless data point.
MIN_CONNS_FOR_RATIO = 5

#: Memory bounding without a dedicated cleanup thread -- same pattern as
#: frfw.webui.auth_rate_limiter.BruteforceGuard's _SWEEP_INTERVAL: every
#: this many mutating calls, the calling thread also evicts IPs that have
#: been completely silent for STALE_IP_SECONDS.
SWEEP_INTERVAL = 200
STALE_IP_SECONDS = 3600.0


@dataclass
class _IpWindow:
    new_conn_ts: deque = field(default_factory=deque)
    dst_ips_seen: dict = field(default_factory=dict)  # dst_ip -> last-seen monotonic ts
    sni_block_ts: deque = field(default_factory=deque)
    conn_rate_history: deque = field(default_factory=lambda: deque(maxlen=BASELINE_SAMPLES))
    dst_ratio_history: deque = field(default_factory=lambda: deque(maxlen=BASELINE_SAMPLES))
    sni_block_history: deque = field(default_factory=lambda: deque(maxlen=BASELINE_SAMPLES))
    last_seen: float = 0.0


@dataclass(frozen=True)
class AnomalyEvent:
    """One flagged IP, from one `evaluate()` call. `score` is the
    highest z-score among the features that tripped (or, for a
    still-baselining IP scored against the absolute floor instead,
    `value / floor`) -- a rough severity ranking for display, not a
    calibrated probability."""

    ip: str
    score: float
    reasons: tuple[str, ...]
    conn_rate: float
    unique_dst_ratio: float
    sni_block_count: int


class AnomalyEngine:
    """Thread-safe: `observe_connection`/`observe_sni_block` are called
    from frfw.ai_ids.daemon's journald-tailing thread and its
    conntrack-polling loop respectively, while `evaluate` is called from
    the same loop on a timer -- a plain `threading.Lock` around all
    three (the same primitive choice frfw.webui.auth_rate_limiter makes,
    for the same reason: this is a small, short-held critical section
    guarding plain dict/deque mutation, not something that benefits from
    asyncio)."""

    def __init__(
        self,
        *,
        window_seconds: float = WINDOW_SECONDS,
        zscore_threshold: float = ZSCORE_THRESHOLD,
    ) -> None:
        self._window_seconds = window_seconds
        self._zscore_threshold = zscore_threshold
        self._lock = threading.Lock()
        self._ips: dict[str, _IpWindow] = {}
        self._calls_since_sweep = 0

    @property
    def window_seconds(self) -> float:
        return self._window_seconds

    def observe_connection(self, src_ip: str, dst_ip: str, *, now: float | None = None) -> None:
        """Record one *new* connection attempt from `src_ip` to
        `dst_ip`. The caller (frfw.ai_ids.daemon) is responsible for
        only calling this for flows genuinely new since the last
        conntrack sample -- an established, long-lived connection must
        not be re-counted on every poll, or a single legitimate,
        long-running connection would look like an ever-climbing
        connection rate."""
        now = time.monotonic() if now is None else now
        with self._lock:
            window = self._get_locked(src_ip, now)
            window.new_conn_ts.append(now)
            window.dst_ips_seen[dst_ip] = now
            self._prune_locked(window, now)

    def observe_sni_block(self, src_ip: str, *, now: float | None = None) -> None:
        """Record one XDP SNI-blocklist drop attributed to `src_ip`."""
        now = time.monotonic() if now is None else now
        with self._lock:
            window = self._get_locked(src_ip, now)
            window.sni_block_ts.append(now)
            self._prune_locked(window, now)

    def evaluate(self, ip: str, *, now: float | None = None) -> AnomalyEvent | None:
        """Score `ip`'s current window against its own history, then
        commit the current window into that history for next time.

        Intended to be called exactly once per `window_seconds` per
        currently-tracked IP (frfw.ai_ids.daemon's job, not this
        class's) -- calling it more often than that would commit the
        same (still-filling) window into the baseline history multiple
        times and skew it; calling it less often just means coarser
        detection latency, never incorrect scoring.
        """
        now = time.monotonic() if now is None else now
        with self._lock:
            window = self._ips.get(ip)
            if window is None:
                return None
            self._prune_locked(window, now)

            conn_rate = len(window.new_conn_ts) / self._window_seconds
            total_conns = len(window.new_conn_ts)
            unique_dst_ratio = (len(window.dst_ips_seen) / total_conns) if total_conns else 0.0
            sni_block_count = len(window.sni_block_ts)

            features = [
                ("connection-rate spike", conn_rate, window.conn_rate_history, ABS_CONN_RATE_FLOOR),
                (
                    "SNI-blocklist beacon",
                    float(sni_block_count),
                    window.sni_block_history,
                    ABS_SNI_BLOCK_COUNT_FLOOR,
                ),
            ]
            # The ratio feature only means something with enough
            # connections in the window to divide by -- see
            # MIN_CONNS_FOR_RATIO's own comment.
            if total_conns >= MIN_CONNS_FOR_RATIO:
                features.append(
                    (
                        "destination-scan pattern",
                        unique_dst_ratio,
                        window.dst_ratio_history,
                        ABS_UNIQUE_DST_RATIO_FLOOR,
                    )
                )

            reasons: list[str] = []
            best_score = 0.0
            for label, value, history, floor in features:
                triggered, score = self._score_feature(value, history, floor)
                if triggered:
                    reasons.append(label)
                    best_score = max(best_score, score)
                history.append(value)

            if not reasons:
                return None
            return AnomalyEvent(
                ip=ip,
                score=round(best_score, 2),
                reasons=tuple(reasons),
                conn_rate=round(conn_rate, 3),
                unique_dst_ratio=round(unique_dst_ratio, 3),
                sni_block_count=sni_block_count,
            )

    def _score_feature(
        self, value: float, history: deque, floor: float
    ) -> tuple[bool, float]:
        if len(history) >= MIN_BASELINE_SAMPLES:
            mean = statistics.mean(history)
            stdev = statistics.pstdev(history) or 1e-6
            z = (value - mean) / stdev
            # Still require the value to clear at least half the
            # absolute floor even when statistically anomalous, so an
            # IP whose baseline is itself near-zero (e.g. a host that
            # has only ever made 0-1 connections per window) doesn't
            # get flagged the moment it makes a second one.
            if z >= self._zscore_threshold and value > floor / 2:
                return True, z
            return False, 0.0
        if value >= floor:
            return True, value / floor
        return False, 0.0

    def tracked_ips(self) -> list[str]:
        """Every IP with at least one observation still inside its
        current window or history -- what frfw.ai_ids.daemon iterates
        over to call `evaluate()`."""
        with self._lock:
            return list(self._ips)

    def _get_locked(self, ip: str, now: float) -> _IpWindow:
        self._calls_since_sweep += 1
        if self._calls_since_sweep >= SWEEP_INTERVAL:
            self._calls_since_sweep = 0
            self._sweep_locked(now)
        window = self._ips.setdefault(ip, _IpWindow())
        window.last_seen = now
        return window

    def _prune_locked(self, window: _IpWindow, now: float) -> None:
        cutoff = now - self._window_seconds
        while window.new_conn_ts and window.new_conn_ts[0] < cutoff:
            window.new_conn_ts.popleft()
        while window.sni_block_ts and window.sni_block_ts[0] < cutoff:
            window.sni_block_ts.popleft()
        stale_dsts = [dst for dst, ts in window.dst_ips_seen.items() if ts < cutoff]
        for dst in stale_dsts:
            del window.dst_ips_seen[dst]

    def _sweep_locked(self, now: float) -> None:
        stale = [ip for ip, w in self._ips.items() if now - w.last_seen > STALE_IP_SECONDS]
        for ip in stale:
            del self._ips[ip]
