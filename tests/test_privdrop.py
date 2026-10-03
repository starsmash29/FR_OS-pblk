"""Security-lessons I1: the BPF-reading daemons drop root right after
opening their map, before they read a byte from it."""

from __future__ import annotations

import pytest

from frfw import privdrop, xdp


def test_the_sni_event_logger_drops_root_before_the_first_poll(monkeypatch, tmp_path):
    events = []

    class FakeReader:
        def __init__(self, on_event):
            events.append("open")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def poll(self, timeout_ms):
            events.append("poll")
            raise KeyboardInterrupt  # end the endless loop

    pin = tmp_path / "events"
    pin.write_text("")
    monkeypatch.setattr(xdp, "PIN_EVENTS_PATH", pin)
    monkeypatch.setattr(xdp, "RingBufferReader", FakeReader)
    monkeypatch.setattr(xdp.os, "geteuid", lambda: 0)
    monkeypatch.setattr(privdrop, "drop_privileges", lambda: events.append("drop"))
    events_file = tmp_path / "events.jsonl"
    with pytest.raises(KeyboardInterrupt):
        xdp.run_event_logger(events_path=events_file)
    assert events == ["open", "drop", "poll"]
    # ROADMAP SEC-4: the event file was created by the process before it
    # dropped root, readable by its group only, never by others.
    assert events_file.exists() and events_file.stat().st_mode & 0o777 == 0o640


def test_drop_privileges_refuses_to_stay_root(monkeypatch):
    calls = []
    monkeypatch.setattr(privdrop.os, "setgroups", lambda groups: calls.append(("setgroups", groups)))
    monkeypatch.setattr(privdrop.os, "setgid", lambda gid: calls.append(("setgid", gid)))
    monkeypatch.setattr(privdrop.os, "setuid", lambda uid: calls.append(("setuid", uid)))
    monkeypatch.setattr(privdrop.os, "getuid", lambda: 0)
    monkeypatch.setattr(privdrop.os, "geteuid", lambda: 0)
    with pytest.raises(RuntimeError, match="failed to drop root"):
        privdrop.drop_privileges()
    # Groups first, then the group, then the user: the order that works.
    assert [c[0] for c in calls] == ["setgroups", "setgid", "setuid"]
