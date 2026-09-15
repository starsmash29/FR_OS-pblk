"""Tests for frfw.webui.auth_rate_limiter: the in-memory, thread-safe
failed-login counter, and the small shared helper both login routes
call on a failed attempt."""

from __future__ import annotations

import threading

import pytest

from frfw.webui.auth_rate_limiter import BAN_DURATION_SECONDS, BruteforceGuard, reject_failed_login


def test_below_threshold_never_triggers_a_ban():
    guard = BruteforceGuard(max_attempts=5, window_seconds=300)
    for _ in range(4):
        assert guard.record_failure("10.0.0.1") is False


def test_reaching_threshold_triggers_exactly_once():
    guard = BruteforceGuard(max_attempts=5, window_seconds=300)
    results = [guard.record_failure("10.0.0.1") for _ in range(5)]
    assert results == [False, False, False, False, True]


def test_counter_resets_after_a_ban_is_triggered():
    guard = BruteforceGuard(max_attempts=5, window_seconds=300)
    for _ in range(5):
        guard.record_failure("10.0.0.1")
    # A 6th failure right after the ban must not trip a second "just
    # banned" signal immediately -- the counter was reset by the 5th.
    assert guard.record_failure("10.0.0.1") is False


def test_different_ips_are_tracked_independently():
    guard = BruteforceGuard(max_attempts=5, window_seconds=300)
    for _ in range(4):
        guard.record_failure("10.0.0.1")
    # A different IP starts fresh, not inheriting 10.0.0.1's count.
    assert guard.record_failure("10.0.0.2") is False


def test_record_success_resets_the_counter(monkeypatch_time=None):
    guard = BruteforceGuard(max_attempts=5, window_seconds=300)
    for _ in range(4):
        guard.record_failure("10.0.0.1")
    guard.record_success("10.0.0.1")
    # Would have been the 5th (banning) failure had the counter not
    # been reset by the success in between.
    assert guard.record_failure("10.0.0.1") is False


def test_record_success_on_unknown_ip_is_a_harmless_noop():
    guard = BruteforceGuard()
    guard.record_success("10.0.0.99")  # never recorded a failure -- must not raise


def test_old_failures_outside_the_window_do_not_count(monkeypatch):
    guard = BruteforceGuard(max_attempts=5, window_seconds=300)
    clock = {"t": 1000.0}
    monkeypatch.setattr("time.monotonic", lambda: clock["t"])

    for _ in range(4):
        guard.record_failure("10.0.0.1")

    clock["t"] += 301  # past the 300s window -- those 4 failures expire
    # A single new failure should not immediately trip the threshold,
    # since the old ones have aged out.
    assert guard.record_failure("10.0.0.1") is False


def test_failures_within_window_still_count_after_partial_expiry(monkeypatch):
    guard = BruteforceGuard(max_attempts=5, window_seconds=300)
    clock = {"t": 1000.0}
    monkeypatch.setattr("time.monotonic", lambda: clock["t"])

    guard.record_failure("10.0.0.1")  # t=1000
    clock["t"] += 100  # t=1100, still within the window of the first
    for _ in range(3):
        guard.record_failure("10.0.0.1")  # t=1100 x3 -- 4 total so far
    clock["t"] += 250  # t=1350: the t=1000 failure (350s old) has expired,
    # the three t=1100 ones (250s old) have not.
    assert guard.record_failure("10.0.0.1") is False  # only 4 in-window now
    assert guard.record_failure("10.0.0.1") is True  # 5th in-window -- bans


def test_thread_safety_exactly_one_ban_under_concurrent_failures():
    """The explicit "thread-safe" requirement: hammer record_failure for
    the same IP from many threads at once and confirm the threshold is
    crossed exactly once, never zero times (a race that let two threads
    both read count=4 and both increment past 5 without either seeing
    "banned") and never more than once (both threads seeing count==5)."""
    guard = BruteforceGuard(max_attempts=5, window_seconds=300)
    ban_signals = []
    lock = threading.Lock()

    def hammer():
        result = guard.record_failure("10.0.0.1")
        if result:
            with lock:
                ban_signals.append(result)

    threads = [threading.Thread(target=hammer) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(ban_signals) == 1


def test_sweep_does_not_lose_in_window_entries(monkeypatch):
    """The periodic full-table sweep (every _SWEEP_INTERVAL calls) must
    only ever evict entries that are actually expired -- exercised here
    by driving enough distinct-IP failures to trigger at least one
    sweep, then confirming an in-window IP's count survived it."""
    import frfw.webui.auth_rate_limiter as rate_limiter_mod

    guard = BruteforceGuard(max_attempts=5, window_seconds=300)
    monkeypatch.setattr(rate_limiter_mod, "_SWEEP_INTERVAL", 10)

    for _ in range(3):
        guard.record_failure("10.0.0.1")
    # Push the call count past the sweep interval with unrelated IPs.
    for i in range(10):
        guard.record_failure(f"10.0.1.{i}")

    # 10.0.0.1's 3 in-window failures must still be there -- two more
    # failures should now trip the ban.
    guard.record_failure("10.0.0.1")
    assert guard.record_failure("10.0.0.1") is True


# --- reject_failed_login ------------------------------------------------


class _FakeHelper:
    def __init__(self):
        self.banned = []

    def ban_ip(self, ip, duration_seconds):
        self.banned.append((ip, duration_seconds))
        return {"ok": True}


def test_reject_failed_login_below_threshold_does_not_ban():
    guard = BruteforceGuard(max_attempts=5, window_seconds=300)
    helper = _FakeHelper()

    response = reject_failed_login("10.0.0.1", guard, helper, redirect_path="/login")

    assert helper.banned == []
    assert response.headers["location"] == "/login?error=Invalid+credentials"


def test_reject_failed_login_at_threshold_bans_and_reports_clearly():
    guard = BruteforceGuard(max_attempts=5, window_seconds=300)
    helper = _FakeHelper()

    for _ in range(4):
        reject_failed_login("10.0.0.1", guard, helper, redirect_path="/login")
    response = reject_failed_login("10.0.0.1", guard, helper, redirect_path="/login")

    assert helper.banned == [("10.0.0.1", BAN_DURATION_SECONDS)]
    assert "temporarily blocked" in response.headers["location"].lower().replace("+", " ")


def test_reject_failed_login_uses_given_redirect_path():
    guard = BruteforceGuard()
    helper = _FakeHelper()
    response = reject_failed_login("10.0.0.1", guard, helper, redirect_path="/ztna/login")
    assert response.headers["location"].startswith("/ztna/login?")
