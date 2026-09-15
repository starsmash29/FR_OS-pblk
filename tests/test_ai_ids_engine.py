"""Tests for frfw.ai_ids.engine.AnomalyEngine: the pure-stdlib
sliding-window scorer, exercised with a synthetic, fully controlled
clock so window ticks and baseline accumulation are deterministic --
no real conntrack/journald/wall-clock timing involved (see
tests/test_ai_ids_daemon.py for the layer that wires real-ish telemetry
into this).
"""

from __future__ import annotations

from frfw.ai_ids.engine import AnomalyEngine


def _feed_normal_window(engine: AnomalyEngine, ip: str, base: float) -> None:
    """A realistic "boring" window: 10 connections, mostly to the same
    two destinations -- low unique-destination ratio, low rate."""
    for i in range(8):
        engine.observe_connection(ip, "1.1.1.1", now=base + 0.1 * i)
    for i in range(2):
        engine.observe_connection(ip, "8.8.8.8", now=base + 0.5 + 0.1 * i)


def test_no_observations_evaluates_to_none():
    engine = AnomalyEngine(window_seconds=10.0)
    assert engine.evaluate("10.0.0.1", now=0.0) is None


def test_brand_new_ip_below_absolute_floor_is_not_flagged():
    engine = AnomalyEngine(window_seconds=10.0)
    engine.observe_connection("10.0.0.1", "1.1.1.1", now=1.0)
    assert engine.evaluate("10.0.0.1", now=10.0) is None


def test_brand_new_ip_above_absolute_floor_is_flagged():
    engine = AnomalyEngine(window_seconds=10.0)
    # 20 distinct destinations, no baseline yet -- trips the absolute
    # unique-destination-ratio floor (0.8) immediately.
    for i in range(20):
        engine.observe_connection("10.0.0.1", f"10.50.0.{i}", now=1.0)
    event = engine.evaluate("10.0.0.1", now=10.0)
    assert event is not None
    assert "destination-scan pattern" in event.reasons


def test_established_baseline_is_not_flagged_by_its_own_normal_pattern():
    engine = AnomalyEngine(window_seconds=10.0)
    for w in range(10):
        base = 1000.0 + w * 10.0
        _feed_normal_window(engine, "10.0.0.5", base)
        assert engine.evaluate("10.0.0.5", now=base + 10.0) is None


def test_scan_burst_after_normal_baseline_is_flagged():
    engine = AnomalyEngine(window_seconds=10.0)
    for w in range(10):
        base = 1000.0 + w * 10.0
        _feed_normal_window(engine, "10.0.0.5", base)
        engine.evaluate("10.0.0.5", now=base + 10.0)

    scan_base = 1000.0 + 10 * 10.0
    for i in range(20):
        engine.observe_connection("10.0.0.5", f"10.50.0.{i}", now=scan_base + 1)
    event = engine.evaluate("10.0.0.5", now=scan_base + 10.0)

    assert event is not None
    assert "destination-scan pattern" in event.reasons
    assert event.unique_dst_ratio == 1.0


def test_sni_blocklist_beacon_pattern_is_flagged():
    engine = AnomalyEngine(window_seconds=10.0)
    for _ in range(5):
        engine.observe_sni_block("10.0.0.7", now=1.0)
    event = engine.evaluate("10.0.0.7", now=10.0)
    assert event is not None
    assert "SNI-blocklist beacon" in event.reasons
    assert event.sni_block_count == 5


def test_different_ips_are_scored_independently():
    engine = AnomalyEngine(window_seconds=10.0)
    for i in range(20):
        engine.observe_connection("10.0.0.1", f"10.50.0.{i}", now=1.0)
    engine.observe_connection("10.0.0.2", "1.1.1.1", now=1.0)

    assert engine.evaluate("10.0.0.1", now=10.0) is not None
    assert engine.evaluate("10.0.0.2", now=10.0) is None


def test_observations_outside_the_window_are_pruned():
    engine = AnomalyEngine(window_seconds=10.0)
    for i in range(20):
        engine.observe_connection("10.0.0.1", f"10.50.0.{i}", now=1.0)
    # Far past the window -- all of the above should have aged out.
    event = engine.evaluate("10.0.0.1", now=1000.0)
    assert event is None


def test_tracked_ips_reflects_current_observations():
    engine = AnomalyEngine(window_seconds=10.0)
    engine.observe_connection("10.0.0.1", "1.1.1.1", now=1.0)
    engine.observe_sni_block("10.0.0.2", now=1.0)
    assert set(engine.tracked_ips()) == {"10.0.0.1", "10.0.0.2"}


def test_stale_ips_are_swept_from_memory():
    from frfw.ai_ids import engine as engine_mod

    engine = AnomalyEngine(window_seconds=10.0)
    # Trigger enough calls to force a sweep, with one IP long silent.
    engine.observe_connection("10.0.0.1", "1.1.1.1", now=0.0)
    for i in range(engine_mod.SWEEP_INTERVAL):
        engine.observe_connection(f"10.0.1.{i % 250}", "1.1.1.1", now=engine_mod.STALE_IP_SECONDS + 1)
    assert "10.0.0.1" not in engine.tracked_ips()
