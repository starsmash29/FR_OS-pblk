"""Tests for frfw.ai_ids.daemon.IDSDaemon's testable building blocks
(handle_sni_event_line / poll_conntrack_once / evaluate_and_enforce /
resolve_excluded_ips) -- everything except `run_forever`/
`_tail_journal_forever`, which are thin, real I/O loops not exercised
here (see the module docstring for why: the logic worth testing all
lives in the pieces below)."""

from __future__ import annotations

import json

import pytest

from frfw.ai_ids.daemon import IDSDaemon, resolve_excluded_ips
from frfw.ai_ids.engine import AnomalyEngine
from frfw.config import parse_config
from frfw.helper.client import HelperError


@pytest.fixture
def config_with_reservation(dhcp_config_dict):
    dhcp_config_dict["ai_ids"] = {
        "enabled": True,
        "excluded_macs": ["aa:bb:cc:dd:ee:ff"],
        "quarantine_duration_seconds": 999,
    }
    return parse_config(dhcp_config_dict)


class _Clock:
    def __init__(self, t: float = 0.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def _daemon(config, *, quarantine_fn=None, conntrack_fn=None, tmp_path, clock=None):
    return IDSDaemon(
        config,
        engine=AnomalyEngine(window_seconds=10.0),
        quarantine_fn=quarantine_fn or (lambda ip, duration: {"ok": True}),
        conntrack_fn=conntrack_fn or (lambda: {"ok": True, "flows": []}),
        events_path=tmp_path / "events.json",
        clock=clock or _Clock(),
    )


def test_resolve_excluded_ips_maps_mac_to_reservation_address(config_with_reservation):
    assert resolve_excluded_ips(config_with_reservation) == {"10.0.0.50"}


def test_resolve_excluded_ips_empty_when_no_excluded_macs(dhcp_config_dict):
    config = parse_config(dhcp_config_dict)
    assert resolve_excluded_ips(config) == set()


def test_resolve_excluded_ips_ignores_mac_with_no_matching_reservation(dhcp_config_dict):
    dhcp_config_dict["ai_ids"] = {"excluded_macs": ["11:22:33:44:55:66"]}
    config = parse_config(dhcp_config_dict)
    assert resolve_excluded_ips(config) == set()


# --- handle_sni_event_line ------------------------------------------------


def test_handle_sni_event_line_feeds_the_engine(config_with_reservation, tmp_path):
    daemon = _daemon(config_with_reservation, tmp_path=tmp_path)
    line = json.dumps({"action": "drop", "saddr": "10.0.0.7", "sni": "evil.example.com"})
    for _ in range(5):
        daemon.handle_sni_event_line(line)

    event = daemon.engine.evaluate("10.0.0.7", now=daemon._clock())
    assert event is not None
    assert "SNI-blocklist beacon" in event.reasons


def test_handle_sni_event_line_ignores_malformed_json(config_with_reservation, tmp_path):
    daemon = _daemon(config_with_reservation, tmp_path=tmp_path)
    daemon.handle_sni_event_line("not json at all")  # must not raise
    assert daemon.engine.tracked_ips() == []


def test_handle_sni_event_line_ignores_non_drop_actions(config_with_reservation, tmp_path):
    daemon = _daemon(config_with_reservation, tmp_path=tmp_path)
    daemon.handle_sni_event_line(json.dumps({"action": "pass", "saddr": "10.0.0.7"}))
    assert daemon.engine.tracked_ips() == []


# --- poll_conntrack_once ---------------------------------------------------


def test_poll_conntrack_once_observes_new_flows(config_with_reservation, tmp_path):
    flows = [
        {"proto": "tcp", "src": "10.0.0.9", "sport": 40000 + i, "dst": f"203.0.113.{i}", "dport": 443}
        for i in range(6)
    ]
    daemon = _daemon(config_with_reservation, conntrack_fn=lambda: {"ok": True, "flows": flows}, tmp_path=tmp_path)

    daemon.poll_conntrack_once()

    event = daemon.engine.evaluate("10.0.0.9", now=daemon._clock() + 10.0)
    assert event is not None
    assert "destination-scan pattern" in event.reasons


def test_poll_conntrack_once_does_not_double_count_already_seen_flows(config_with_reservation, tmp_path):
    flow = {"proto": "tcp", "src": "10.0.0.9", "sport": 1234, "dst": "1.1.1.1", "dport": 443}
    daemon = _daemon(config_with_reservation, conntrack_fn=lambda: {"ok": True, "flows": [flow]}, tmp_path=tmp_path)

    daemon.poll_conntrack_once()
    daemon.poll_conntrack_once()  # same still-open flow, sampled again
    daemon.poll_conntrack_once()

    event = daemon.engine.evaluate("10.0.0.9", now=daemon._clock() + 10.0)
    # A single long-lived connection re-sampled three times must count
    # as one connection attempt, not three.
    assert event is None


def test_poll_conntrack_once_survives_helper_error(config_with_reservation, tmp_path):
    def broken():
        raise HelperError("apply-helper unreachable")

    daemon = _daemon(config_with_reservation, conntrack_fn=broken, tmp_path=tmp_path)
    daemon.poll_conntrack_once()  # must not raise
    assert daemon.engine.tracked_ips() == []


def test_poll_conntrack_once_ignores_not_ok_response(config_with_reservation, tmp_path):
    daemon = _daemon(
        config_with_reservation, conntrack_fn=lambda: {"ok": False, "message": "boom"}, tmp_path=tmp_path
    )
    daemon.poll_conntrack_once()
    assert daemon.engine.tracked_ips() == []


# --- evaluate_and_enforce ---------------------------------------------------


def test_evaluate_and_enforce_quarantines_flagged_non_excluded_ip(config_with_reservation, tmp_path):
    quarantined = []

    def fake_quarantine(ip, duration):
        quarantined.append((ip, duration))
        return {"ok": True}

    daemon = _daemon(config_with_reservation, quarantine_fn=fake_quarantine, tmp_path=tmp_path)
    for i in range(20):
        daemon.engine.observe_connection("10.0.0.99", f"203.0.113.{i}", now=0.0)

    flagged = daemon.evaluate_and_enforce()

    assert [e.ip for e in flagged] == ["10.0.0.99"]
    assert quarantined == [("10.0.0.99", 999)]  # ai_ids.quarantine_duration_seconds


def test_evaluate_and_enforce_skips_excluded_ip(config_with_reservation, tmp_path):
    quarantined = []
    daemon = _daemon(
        config_with_reservation,
        quarantine_fn=lambda ip, d: quarantined.append((ip, d)) or {"ok": True},
        tmp_path=tmp_path,
    )
    for i in range(20):
        daemon.engine.observe_connection("10.0.0.50", f"203.0.113.{i}", now=0.0)  # excluded MAC's IP

    flagged = daemon.evaluate_and_enforce()

    assert [e.ip for e in flagged] == ["10.0.0.50"]  # still flagged...
    assert quarantined == []  # ...but never enforced


def test_evaluate_and_enforce_survives_helper_error(config_with_reservation, tmp_path):
    def broken(ip, duration):
        raise HelperError("apply-helper unreachable")

    daemon = _daemon(config_with_reservation, quarantine_fn=broken, tmp_path=tmp_path)
    for i in range(20):
        daemon.engine.observe_connection("10.0.0.99", f"203.0.113.{i}", now=0.0)

    flagged = daemon.evaluate_and_enforce()  # must not raise
    assert [e.ip for e in flagged] == ["10.0.0.99"]


def test_evaluate_and_enforce_logs_nothing_when_helper_refuses(config_with_reservation, tmp_path):
    from frfw.ai_ids.daemon import load_recent_events

    events_path = tmp_path / "events.json"
    daemon = IDSDaemon(
        config_with_reservation,
        engine=AnomalyEngine(window_seconds=10.0),
        quarantine_fn=lambda ip, d: {"ok": False, "message": "set does not exist"},
        conntrack_fn=lambda: {"ok": True, "flows": []},
        events_path=events_path,
        clock=_Clock(),
    )
    for i in range(20):
        daemon.engine.observe_connection("10.0.0.99", f"203.0.113.{i}", now=0.0)

    daemon.evaluate_and_enforce()

    assert load_recent_events(events_path) == []


# --- recent-events log -----------------------------------------------------


def test_successful_quarantine_is_appended_to_the_events_log(config_with_reservation, tmp_path):
    from frfw.ai_ids.daemon import load_recent_events

    events_path = tmp_path / "events.json"
    daemon = IDSDaemon(
        config_with_reservation,
        engine=AnomalyEngine(window_seconds=10.0),
        quarantine_fn=lambda ip, d: {"ok": True},
        conntrack_fn=lambda: {"ok": True, "flows": []},
        events_path=events_path,
        clock=_Clock(),
    )
    for i in range(20):
        daemon.engine.observe_connection("10.0.0.99", f"203.0.113.{i}", now=0.0)

    daemon.evaluate_and_enforce()

    events = load_recent_events(events_path)
    assert len(events) == 1
    assert events[0]["ip"] == "10.0.0.99"
    assert "destination-scan pattern" in events[0]["reasons"]


def test_events_log_is_capped_at_the_recent_events_limit(tmp_path):
    from frfw.ai_ids import daemon as daemon_mod

    events_path = tmp_path / "events.json"
    fake_daemon = object.__new__(daemon_mod.IDSDaemon)
    fake_daemon._events_path = events_path

    for i in range(daemon_mod.RECENT_EVENTS_LIMIT + 10):
        event = daemon_mod.AnomalyEvent(
            ip=f"10.0.0.{i % 250}", score=1.0, reasons=("x",), conn_rate=0.0,
            unique_dst_ratio=0.0, sni_block_count=0,
        )
        fake_daemon._append_event_log(event)

    events = daemon_mod.load_recent_events(events_path, limit=daemon_mod.RECENT_EVENTS_LIMIT + 100)
    assert len(events) == daemon_mod.RECENT_EVENTS_LIMIT


def test_load_recent_events_missing_file_returns_empty_list(tmp_path):
    from frfw.ai_ids.daemon import load_recent_events

    assert load_recent_events(tmp_path / "nope.json") == []


def test_load_recent_events_respects_limit(tmp_path):
    from frfw.ai_ids import daemon as daemon_mod

    events_path = tmp_path / "events.json"
    fake_daemon = object.__new__(daemon_mod.IDSDaemon)
    fake_daemon._events_path = events_path
    for i in range(5):
        event = daemon_mod.AnomalyEvent(
            ip=f"10.0.0.{i}", score=1.0, reasons=("x",), conn_rate=0.0,
            unique_dst_ratio=0.0, sni_block_count=0,
        )
        fake_daemon._append_event_log(event)

    assert len(daemon_mod.load_recent_events(events_path, limit=2)) == 2


# --- is_daemon_active --------------------------------------------------------


def test_is_daemon_active_reflects_systemctl_output(monkeypatch):
    from frfw.ai_ids import daemon as daemon_mod

    def fake_run(args, capture_output, text):
        import subprocess

        assert args == ["systemctl", "is-active", "fr-ai-ids.service"]
        return subprocess.CompletedProcess(args, 0, stdout="active\n", stderr="")

    monkeypatch.setattr(daemon_mod.subprocess, "run", fake_run)
    assert daemon_mod.is_daemon_active() is True


def test_is_daemon_active_false_when_inactive(monkeypatch):
    from frfw.ai_ids import daemon as daemon_mod
    import subprocess

    monkeypatch.setattr(
        daemon_mod.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess([], 3, stdout="inactive\n", stderr=""),
    )
    assert daemon_mod.is_daemon_active() is False


def test_is_daemon_active_false_when_systemctl_missing(monkeypatch):
    from frfw.ai_ids import daemon as daemon_mod

    def raise_not_found(*a, **kw):
        raise FileNotFoundError()

    monkeypatch.setattr(daemon_mod.subprocess, "run", raise_not_found)
    assert daemon_mod.is_daemon_active() is False

