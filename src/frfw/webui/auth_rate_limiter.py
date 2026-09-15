"""In-memory failed-login tracking for the webUI's two login endpoints
(`/login`, the admin account; `/ztna/login`, the ZTNA gate), escalating
to a kernel-level ban via the privileged apply-helper once a source IP
crosses the threshold (see `frfw.bruteforce` for the enforcement side
and `frfw.nft.builder.BRUTEFORCE_JAIL_SET_NAME` for the always-on
nftables set the ban lands in).

This module is deliberately *only* the counting/decision half -- it
never touches `nft`, a socket, or the filesystem. That split mirrors
every other privilege boundary in this project (frfw.webui.routes.ztna's
own docstring makes the same point about ZTNA login: "authenticate
in-process, only then ask the privileged helper to act").

**Threading model**: every route handler in this codebase is a plain
`def`, not `async def` (`grep -c "async def" src/frfw/webui/routes/*.py`
returns 0) -- FastAPI/Starlette runs sync path operations in a worker
thread pool, so concurrent requests genuinely execute on different OS
threads, not interleaved on one asyncio event loop. An `asyncio.Lock`
would not exclude those threads from each other at all (and generally
can't even be safely awaited from a plain `def` handler in the first
place) -- `threading.Lock` is the only correct choice here, not "asyncio
lock or thread-safe dict" as an either/or; a plain dict guarded by a
`threading.Lock` is exactly what this implements.

**Memory bound**: a distinct one-off failing IP (never seen again)
leaves one small list entry in `_attempts` forever if nothing ever
prunes it. Rather than a background thread (which this project avoids
everywhere -- periodic work here uses systemd timers, e.g.
fr-adblock-refresh.timer, not in-process threads/loops), `record_failure`
opportunistically sweeps the whole table for fully-expired entries
every `_SWEEP_INTERVAL`-th call. This keeps steady-state memory bounded
without a dedicated cleanup loop, at the cost of a bounded amount of
short-lived staleness -- an acceptable, homelab-scale tradeoff.
"""

from __future__ import annotations

import threading
import time

from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with

#: 5 failed attempts within 5 minutes bans the source IP -- exactly the
#: thresholds given in the phase 10 request. Not exposed in config.yaml
#: (unlike every optional subsystem elsewhere in this project): this is
#: baseline login hygiene, not a feature an admin opts into or tunes.
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 5 * 60

#: How long a jailed IP stays dropped at the firewall once banned.
#: nftables' own element timeout enforces this -- see frfw.bruteforce.
BAN_DURATION_SECONDS = 60 * 60

#: Sweep the whole table for expired entries every this-many
#: `record_failure` calls, not on every single one -- see module
#: docstring's "memory bound" note.
_SWEEP_INTERVAL = 100


class BruteforceGuard:
    """Thread-safe, in-memory, per-source-IP failed-login counter.

    One instance lives for the lifetime of the webUI process
    (`frfw.webui.app.create_app` constructs the default; tests inject
    their own via `create_app(bruteforce_guard=...)`), shared by both
    `/login` and `/ztna/login` -- five failures split across the two
    endpoints from the same IP bans it exactly as five failures on one
    endpoint would, since both routes call the same `record_failure`.
    """

    def __init__(
        self,
        *,
        max_attempts: int = MAX_ATTEMPTS,
        window_seconds: float = WINDOW_SECONDS,
    ) -> None:
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._lock = threading.Lock()
        self._attempts: dict[str, list[float]] = {}
        self._calls_since_sweep = 0

    def record_failure(self, ip: str) -> bool:
        """Records one failed attempt from `ip` "right now". Returns
        `True` exactly once per ban -- the call that makes the count
        within the current window reach `max_attempts` -- and resets
        that IP's counter immediately after, so the caller's own
        "ask the helper to ban" action happens exactly once per
        threshold crossing, not on every subsequent request before the
        kernel rule actually starts dropping them."""
        now = time.monotonic()
        with self._lock:
            self._calls_since_sweep += 1
            if self._calls_since_sweep >= _SWEEP_INTERVAL:
                self._calls_since_sweep = 0
                self._sweep_expired(now)

            timestamps = self._attempts.setdefault(ip, [])
            timestamps.append(now)
            self._prune(timestamps, now)

            if len(timestamps) >= self._max_attempts:
                del self._attempts[ip]
                return True
            return False

    def record_success(self, ip: str) -> None:
        """A successful login resets `ip`'s failure history entirely --
        an admin who mistypes their password a few times and then gets
        it right shouldn't still be one mistake away from a ban."""
        with self._lock:
            self._attempts.pop(ip, None)

    def _prune(self, timestamps: list[float], now: float) -> None:
        cutoff = now - self._window_seconds
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)

    def _sweep_expired(self, now: float) -> None:
        cutoff = now - self._window_seconds
        stale = [ip for ip, timestamps in self._attempts.items() if timestamps[-1] < cutoff]
        for ip in stale:
            del self._attempts[ip]


def reject_failed_login(
    ip: str, guard: BruteforceGuard, helper: HelperClient, *, redirect_path: str
):
    """Shared by `/login` and `/ztna/login`'s failure paths: record the
    failure, and if it just crossed the threshold, ask the privileged
    helper to jail the IP at the firewall layer and say so plainly
    (an admin who locked themselves out deserves a clear reason, not
    a generic "invalid credentials" that leaves them guessing) --
    otherwise the ordinary invalid-credentials message."""
    if guard.record_failure(ip):
        helper.ban_ip(ip, BAN_DURATION_SECONDS)
        return redirect_with(
            redirect_path,
            error="Too many failed login attempts -- this address is temporarily blocked",
        )
    return redirect_with(redirect_path, error="Invalid credentials")
