"""Failed-login tracking for the webUI's two login endpoints (`/login`,
the admin accounts; `/ztna/login`, the ZTNA gate).

Two counters (security-lessons G6):

- **per source address**: 5 failures within 5 minutes and the address is
  jailed at the firewall for an hour, through the privileged apply-helper
  (see `frfw.bruteforce` for the enforcement side and
  `frfw.nft.builder.BRUTEFORCE_JAIL_SET_NAME` for the nftables set);
- **per account**: 10 failures within 15 minutes, from any number of
  addresses, and the account's sign-in is refused for the rest of that
  window -- what stops credential stuffing spread over a botnet, which
  the per-address jail never sees. So that an attacker can't lock the
  owner out this way, an address the account signed in from successfully
  in the last 90 days (a *known source*) is not affected.

Both, and the known sources, are kept on disk (`state_path`, 0600 in the
webUI's own state directory), so restarting the webUI -- or crashing it
on purpose -- no longer resets them. Without a `state_path` (tests) they
live in memory only.

The known sources also tell a sign-in from a new address apart
(`record_success` returns whether the address is new for the account),
which the audit log records (security-lessons G9).

This module is only the counting/decision half: it never touches `nft`
or a socket. Route handlers are plain `def`s run on a thread pool, so
the state is guarded by a `threading.Lock`.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with

#: 5 failed attempts within 5 minutes bans the source IP.
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 5 * 60

#: How long a jailed IP stays dropped at the firewall once banned.
#: nftables' own element timeout enforces this -- see frfw.bruteforce.
BAN_DURATION_SECONDS = 60 * 60

#: Per-account lockout (security-lessons G6).
ACCOUNT_MAX_ATTEMPTS = 10
ACCOUNT_WINDOW_SECONDS = 15 * 60

#: A source that signed in successfully stays "known" this long.
KNOWN_SOURCE_SECONDS = 90 * 24 * 3600

#: Sweep the whole table for expired entries every this-many
#: `record_failure` calls, not on every single one.
_SWEEP_INTERVAL = 100

#: Keep the state file small whatever an attacker sends.
_MAX_TRACKED = 5000


def _now() -> float:
    return time.time()


class BruteforceGuard:
    """Thread-safe failed-login counters, per source IP and per account,
    optionally persisted to `state_path`."""

    def __init__(
        self,
        *,
        max_attempts: int = MAX_ATTEMPTS,
        window_seconds: float = WINDOW_SECONDS,
        account_max_attempts: int = ACCOUNT_MAX_ATTEMPTS,
        account_window_seconds: float = ACCOUNT_WINDOW_SECONDS,
        state_path: Path | None = None,
    ) -> None:
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._account_max_attempts = account_max_attempts
        self._account_window_seconds = account_window_seconds
        self._state_path = state_path
        self._lock = threading.Lock()
        self._attempts: dict[str, list[float]] = {}
        self._account_attempts: dict[str, list[float]] = {}
        self._known: dict[str, dict[str, float]] = {}
        self._calls_since_sweep = 0
        self._load()

    # -- per source address ----------------------------------------------------

    def record_failure(self, ip: str) -> bool:
        """Records one failed attempt from `ip` "right now". Returns
        `True` exactly once per ban -- the call that makes the count
        within the current window reach `max_attempts` -- and resets
        that IP's counter immediately after, so the caller's own
        "ask the helper to ban" action happens exactly once per
        threshold crossing."""
        now = _now()
        with self._lock:
            self._calls_since_sweep += 1
            if self._calls_since_sweep >= _SWEEP_INTERVAL:
                self._calls_since_sweep = 0
                self._sweep_expired(now)

            timestamps = self._attempts.setdefault(ip, [])
            timestamps.append(now)
            self._prune(timestamps, now, self._window_seconds)

            banned = len(timestamps) >= self._max_attempts
            if banned:
                del self._attempts[ip]
            self._save()
            return banned

    def record_success(self, ip: str, account: str | None = None) -> bool:
        """A successful sign-in resets `ip`'s failure history; with
        `account`, also the account's, and `ip` becomes (or stays) a
        known source of it. Returns True when the account has signed in
        before, but never (or not for 90 days) from `ip`."""
        now = _now()
        with self._lock:
            self._attempts.pop(ip, None)
            new_source = False
            if account is not None:
                self._account_attempts.pop(account, None)
                known = self._known.setdefault(account, {})
                seen = known.get(ip)
                # The very first sign-in to an account has nothing to
                # compare against: only a further address is "new".
                new_source = bool(known) and (seen is None or now - seen > KNOWN_SOURCE_SECONDS)
                known[ip] = now
            self._save()
            return new_source

    # -- per account -------------------------------------------------------------

    def record_account_failure(self, account: str) -> None:
        now = _now()
        with self._lock:
            if account not in self._account_attempts and len(self._account_attempts) >= _MAX_TRACKED:
                return
            timestamps = self._account_attempts.setdefault(account, [])
            timestamps.append(now)
            self._prune(timestamps, now, self._account_window_seconds)
            self._save()

    def account_locked(self, account: str, ip: str) -> int:
        """Seconds until `account` can be tried again from `ip` (0: now).
        A known source of the account is never locked out."""
        now = _now()
        with self._lock:
            seen = self._known.get(account, {}).get(ip)
            if seen is not None and now - seen <= KNOWN_SOURCE_SECONDS:
                return 0
            timestamps = self._account_attempts.get(account, [])
            self._prune(timestamps, now, self._account_window_seconds)
            if len(timestamps) < self._account_max_attempts:
                return 0
            return max(1, int(timestamps[0] + self._account_window_seconds - now))

    # -- internals ----------------------------------------------------------------

    @staticmethod
    def _prune(timestamps: list[float], now: float, window: float) -> None:
        cutoff = now - window
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)

    def _sweep_expired(self, now: float) -> None:
        cutoff = now - self._window_seconds
        for ip in [ip for ip, ts in self._attempts.items() if not ts or ts[-1] < cutoff]:
            del self._attempts[ip]
        cutoff = now - self._account_window_seconds
        for acct in [a for a, ts in self._account_attempts.items() if not ts or ts[-1] < cutoff]:
            del self._account_attempts[acct]
        if len(self._attempts) > _MAX_TRACKED:  # flooded with one-off addresses
            for ip in sorted(self._attempts, key=lambda k: self._attempts[k][-1])[: len(self._attempts) - _MAX_TRACKED]:
                del self._attempts[ip]

    def _load(self) -> None:
        if self._state_path is None:
            return
        try:
            data = json.loads(self._state_path.read_text())
        except (OSError, ValueError):
            return
        now = _now()

        def lists(raw) -> dict[str, list[float]]:
            return {str(k): sorted(float(t) for t in v if isinstance(t, (int, float)))
                    for k, v in (raw or {}).items() if isinstance(v, list)}

        self._attempts = lists(data.get("ips"))
        self._account_attempts = lists(data.get("accounts"))
        self._known = {str(a): {str(ip): float(t) for ip, t in (v or {}).items()
                                if isinstance(t, (int, float)) and now - t <= KNOWN_SOURCE_SECONDS}
                       for a, v in (data.get("known") or {}).items() if isinstance(v, dict)}
        self._sweep_expired(now)

    def _save(self) -> None:
        if self._state_path is None:
            return
        data = {"ips": self._attempts, "accounts": self._account_attempts, "known": self._known}
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._state_path.with_suffix(".tmp")
            tmp.unlink(missing_ok=True)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(json.dumps(data))
            tmp.replace(self._state_path)
        except OSError:
            # Counting must never break the sign-in it guards; the
            # in-memory counters still apply.
            pass


def reject_failed_login(
    ip: str, guard: BruteforceGuard, helper: HelperClient, *, redirect_path: str, account: str | None = None
):
    """Shared by `/login` and `/ztna/login`'s failure paths: record the
    failure (per address, and per account when one is named), and if the
    address just crossed the threshold, ask the privileged helper to jail
    it at the firewall and say so plainly -- otherwise the ordinary
    invalid-credentials message."""
    if account is not None:
        guard.record_account_failure(account)
    if guard.record_failure(ip):
        helper.ban_ip(ip, BAN_DURATION_SECONDS)
        return redirect_with(
            redirect_path,
            error="Too many failed login attempts -- this address is temporarily blocked",
        )
    return redirect_with(redirect_path, error="Invalid credentials")


def locked_message(seconds: int) -> str:
    minutes = max(1, (seconds + 59) // 60)
    return (f"Too many failed sign-ins for this account -- try again in {minutes} minute(s), "
            "or from a device that has signed in to it before")
