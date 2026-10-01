from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from frfw import xdp as xdp_mod
from frfw.config import load_config
from frfw.webui.routes import xdp as xdp_route


def _alive(pid: int) -> bool:
    """Is this pid still a process (or a not-yet-reaped zombie)?"""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _add_wan(client):
    client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )


def test_xdp_page_requires_login(client):
    response = client.get("/xdp")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_page_shows_disabled_by_default(logged_in_client):
    response = logged_in_client.get("/xdp")
    assert response.status_code == 200
    assert "Disabled" in response.text
    assert "badge-red" in response.text


def test_save_settings_persists_interfaces_and_blocklist(logged_in_client, webui_env):
    _add_wan(logged_in_client)

    response = logged_in_client.post(
        "/xdp/settings",
        data={
            "enabled": "true",
            "interfaces": ["wan"],
            "blocklist": "ads.example.com\ntracker.example.net",
        },
    )
    assert "success" in response.headers["location"]

    config = load_config(webui_env["config_path"])
    assert config.xdp_sni_filter.enabled is True
    assert config.xdp_sni_filter.interfaces == ["wan"]
    assert config.xdp_sni_filter.blocklist == ["ads.example.com", "tracker.example.net"]


def test_blocklist_textarea_accepts_commas_and_dedupes(logged_in_client, webui_env):
    _add_wan(logged_in_client)

    logged_in_client.post(
        "/xdp/settings",
        data={
            "enabled": "true",
            "interfaces": ["wan"],
            "blocklist": "a.example.com, b.example.com,\na.example.com\nc.example.com",
        },
    )

    config = load_config(webui_env["config_path"])
    assert config.xdp_sni_filter.blocklist == [
        "a.example.com",
        "b.example.com",
        "c.example.com",
    ]


def test_save_settings_rejects_unknown_interface(logged_in_client, webui_env):
    response = logged_in_client.post(
        "/xdp/settings",
        data={"enabled": "true", "interfaces": ["nonexistent"], "blocklist": ""},
    )
    assert "error" in response.headers["location"]
    assert not webui_env["config_path"].exists()


def test_enabled_page_lists_configured_domains(logged_in_client):
    _add_wan(logged_in_client)
    logged_in_client.post(
        "/xdp/settings",
        data={"enabled": "true", "interfaces": ["wan"], "blocklist": "ads.example.com"},
    )

    page = logged_in_client.get("/xdp")
    assert "ads.example.com" in page.text
    # never attached in this test (no real kernel/bpftool) -- distinct from
    # "Disabled" so an admin can tell "configured but not yet applied"
    # apart from "turned off".
    assert "Not attached yet" in page.text
    assert "badge-red" in page.text


def test_remove_domain(logged_in_client, webui_env):
    _add_wan(logged_in_client)
    logged_in_client.post(
        "/xdp/settings",
        data={
            "enabled": "true",
            "interfaces": ["wan"],
            "blocklist": "a.example.com\nb.example.com",
        },
    )

    response = logged_in_client.post("/xdp/blocklist/remove", data={"domain": "a.example.com"})
    assert "success" in response.headers["location"]

    config = load_config(webui_env["config_path"])
    assert config.xdp_sni_filter.blocklist == ["b.example.com"]


def test_native_mode_shows_green_badge(logged_in_client, webui_env, monkeypatch):
    _add_wan(logged_in_client)
    logged_in_client.post(
        "/xdp/settings",
        data={"enabled": "true", "interfaces": ["wan"], "blocklist": "a.example.com"},
    )
    webui_env["xdp_state_path"].write_text(json.dumps({"attached": {"eth0": "xdpdrv"}}))
    monkeypatch.setattr(xdp_mod, "live_attachment", lambda device: (xdp_mod.AttachMode.NATIVE, 1))

    page = logged_in_client.get("/xdp")
    assert "badge-green" in page.text
    assert "Native" in page.text


def test_generic_mode_shows_yellow_badge(logged_in_client, webui_env, monkeypatch):
    _add_wan(logged_in_client)
    logged_in_client.post(
        "/xdp/settings",
        data={"enabled": "true", "interfaces": ["wan"], "blocklist": "a.example.com"},
    )
    webui_env["xdp_state_path"].write_text(json.dumps({"attached": {"eth0": "xdpgeneric"}}))
    monkeypatch.setattr(xdp_mod, "live_attachment", lambda device: (xdp_mod.AttachMode.GENERIC, 1))

    page = logged_in_client.get("/xdp")
    assert "badge-yellow" in page.text
    assert "Generic" in page.text


def test_available_interfaces_checkboxes_only_show_defined_interfaces(logged_in_client):
    _add_wan(logged_in_client)
    page = logged_in_client.get("/xdp")
    assert 'value="wan"' in page.text
    assert 'value="lan"' not in page.text


def test_logs_stream_requires_login(client):
    response = client.get("/xdp/logs/stream")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_logs_stream_relays_valid_json_lines_and_drops_garbage(logged_in_client, monkeypatch):
    lines = [
        '{"ts": 1.0, "saddr": "1.2.3.4", "sport": 111, "daddr": "5.6.7.8", "dport": 443, "sni": "bad.example.com"}',
        "not json, should be dropped",
        "",
        '{"ts": 2.0, "saddr": "9.9.9.9", "sport": 222, "daddr": "8.8.8.8", "dport": 443, "sni": "also-bad.example.com"}',
    ]
    monkeypatch.setattr(xdp_route, "_iter_journal_lines", lambda cmd: iter(lines))

    with logged_in_client.stream("GET", "/xdp/logs/stream") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(response.iter_text())

    assert "bad.example.com" in body
    assert "also-bad.example.com" in body
    assert "not json" not in body
    assert body.count("data: ") == 2


def test_two_tabs_of_one_session_share_one_journalctl(logged_in_client, monkeypatch):
    """SEC-13: every live-log tab of a session shares one `journalctl`,
    not one child per HTTP request (docs/reviews/v0.2.0.md R19).

    The two requests run concurrently in threads: Starlette's TestClient
    drains a response body before it returns it, so an open SSE stream can
    only be observed while another request is still in flight. The fake
    source blocks on `release` after its first line, which keeps the
    first tab (and the session's stream) alive while the second one joins.
    """
    calls = []
    started = threading.Event()
    release = threading.Event()

    def fake_journal(cmd):
        calls.append(list(cmd))
        started.set()
        yield '{"ts": 1.0, "sni": "first.example.com"}'
        release.wait(10)
        yield '{"ts": 2.0, "sni": "second.example.com"}'

    monkeypatch.setattr(xdp_route, "_iter_journal_lines", fake_journal)
    monkeypatch.setattr(xdp_route, "_log_streams", {})

    bodies: dict[str, str] = {}

    def read_tab(name):
        with logged_in_client.stream("GET", "/xdp/logs/stream") as response:
            assert response.status_code == 200
            bodies[name] = "".join(response.iter_text())

    first = threading.Thread(target=read_tab, args=("first",))
    second = threading.Thread(target=read_tab, args=("second",))
    first.start()
    try:
        assert started.wait(5), "the first tab never started a journalctl"
        second.start()
        # Wait for the second tab to join the session's stream rather than
        # guessing with a sleep: the session's stream object is the one in
        # the registry, and it counts its subscribers.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            streams = list(xdp_route._log_streams.values())
            if streams and len(streams[0]._subscribers) == 2:
                break
            time.sleep(0.01)
        assert len(calls) == 1, "the second tab started its own journalctl"
    finally:
        release.set()
        first.join(20)
        second.join(20)

    assert not first.is_alive() and not second.is_alive()
    # One child for the session, both tabs fed from it: the second tab
    # joins before the last line, so it sees that line and not the first.
    assert "first.example.com" in bodies["first"]
    assert "second.example.com" in bodies["second"]
    assert len(calls) == 1, "a second journalctl was spawned for one session"


def test_stream_past_the_cap_is_an_error_frame_and_spawns_nothing(
    logged_in_client, monkeypatch
):
    """SEC-13: at `LOG_STREAM_LIMIT` live streams, the next session gets
    one clear `text/event-stream` error frame and no child process
    (R19)."""
    calls = []

    def fake_journal(cmd):
        calls.append(list(cmd))
        yield '{"ts": 1.0, "sni": "a.example.com"}'

    monkeypatch.setattr(xdp_route, "_iter_journal_lines", fake_journal)
    # Fill the process-wide registry with streams that are still live.
    monkeypatch.setattr(
        xdp_route,
        "_log_streams",
        {f"other-session-{n}": xdp_route._LogStream(f"other-session-{n}")
         for n in range(xdp_route.LOG_STREAM_LIMIT)},
    )

    with logged_in_client.stream("GET", "/xdp/logs/stream") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(response.iter_text())

    assert calls == [], "a journalctl was spawned past the cap"
    assert "error" in body
    assert str(xdp_route.LOG_STREAM_LIMIT) in body


def test_last_tab_leaving_terminates_the_journal_child(monkeypatch):
    """SEC-13: the `journalctl` child is gone once the session's last tab
    disconnects, which is what frees the registry entry and the cap slot
    (R19).

    `_iter_journal_lines` already terminates the child in its `finally`
    (see its docstring), and the sharing code closes that generator when
    the last tab goes. This drives the real function with a real child
    process that prints its own pid, so the assertion is about the
    process, not a fake's bookkeeping.

    Driven on the stream object rather than through a request: the
    TestClient drains a response body before returning it, and a
    `journalctl -f` never ends, so a live stream cannot be observed from
    outside a request."""
    monkeypatch.setattr(xdp_route, "_log_streams", {})
    real_iter = xdp_route._iter_journal_lines

    def fake_journal(cmd):
        yield from real_iter([
            sys.executable,
            "-c",
            "import json, os, time; "
            "print(json.dumps({'pid': os.getpid()}), flush=True); time.sleep(30)",
        ])

    monkeypatch.setattr(xdp_route, "_iter_journal_lines", fake_journal)

    stream = xdp_route._LogStream("session-a")
    xdp_route._log_streams["session-a"] = stream
    tab = stream.subscribe()
    try:
        frame = next(tab)
        pid = json.loads(frame.removeprefix("data: "))["pid"]
        assert _alive(pid), "the test's journal child never started"
    finally:
        tab.close()  # the browser tab disconnected

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and _alive(pid):
        time.sleep(0.05)
    assert not _alive(pid), "the journalctl child outlived its last tab"
    assert xdp_route._log_streams == {}, "the session kept its cap slot"


def _request_with_cookie(cookie: str | None) -> Request:
    """A minimal Starlette `Request` whose `cookies` contains `cookie`.

    `Request.cookies` is derived from the `Cookie` header, so callers
    only pass the value of `COOKIE_NAME`. A `None` cookie means no
    header at all: a request with no session cookie (e.g. an
    unauthenticated caller, or the edge E.D.I.T.H. flagged in PR #31).
    """
    headers: list[tuple[bytes, bytes]] = []
    if cookie is not None:
        headers.append((b"cookie", f"fr_os_session={cookie}".encode()))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/xdp/logs/stream",
            "headers": headers,
            "query_string": b"",
        }
    )


def test_session_stream_key_fails_closed_without_a_cookie():
    """E.D.I.T.H., PR #31: a missing cookie must not map to the constant
    hash of the empty string (`sha256('')`): every unauthenticated caller
    would share that `LOG_STREAM_LIMIT` slot. The route is already gated
    by `require_login`, so a 401 is unreachable here today -- but calling
    `_session_stream_key` with an absent cookie must fail rather than hand
    back a shared slot."""
    with pytest.raises(HTTPException) as exc:
        xdp_route._session_stream_key(_request_with_cookie(None))
    assert exc.value.status_code == 401


def test_session_stream_key_is_the_digest_not_the_cookie_itself():
    """The registry never keeps the raw cookie: it keeps only its
    `sha256` hex digest (`routes/xdp.py:_session_stream_key`)."""
    key = xdp_route._session_stream_key(_request_with_cookie("secret-value"))
    assert key == hashlib.sha256(b"secret-value").hexdigest()
    assert "secret-value" not in key


def test_a_broken_source_ends_the_stream_and_frees_the_cap_slot(monkeypatch):
    """E.D.I.T.H., PR #31: any driving failure (a journal read error, or
    a cancelled tab mid-read) must not leave a session's `_LogStream`
    with a dead source registered under `LOG_STREAM_LIMIT`. The whole
    session's stream must end, its child closed, and the slot released,
    rather than the next tab re-driving a broken source."""
    monkeypatch.setattr(xdp_route, "_log_streams", {})

    class JournalBoom(RuntimeError):
        pass

    def failing_journal(cmd):
        yield '{"ts": 1.0, "sni": "first.example.com"}'
        raise JournalBoom("journal read failed")

    monkeypatch.setattr(xdp_route, "_iter_journal_lines", failing_journal)

    stream = xdp_route._acquire_stream("session-boom")
    assert stream is not None
    watcher = stream.subscribe()
    driver = stream.subscribe()
    try:
        assert "first.example.com" in next(driver)
        with pytest.raises(JournalBoom):
            next(driver)
    finally:
        driver.close()
        watcher.close()

    assert xdp_route._log_streams == {}
    assert stream.finished
    assert next(watcher, None) is None

    fresh = xdp_route._acquire_stream("session-boom")
    assert fresh is not None and fresh is not stream


def test_a_finished_flag_is_read_under_the_streams_own_lock(monkeypatch):
    """E.D.I.T.H., PR #31: `_finish` writes `_finished = True` under
    `_cond`, so `_acquire_stream` must read it under the same lock --
    otherwise the CPython memory-model race lets a new tab be handed a
    dead stream. Assert deterministically: replacing `_cond` with a stub
    that counts enters proves the property actually takes it."""
    monkeypatch.setattr(xdp_route, "_log_streams", {})
    stream = xdp_route._LogStream("session-race")
    xdp_route._log_streams["session-race"] = stream

    class _CountingCondition:
        def __init__(self, inner):
            self._inner = inner
            self.count = 0

        def __enter__(self):
            self.count += 1
            return self._inner.__enter__()

        def __exit__(self, *a):
            return self._inner.__exit__(*a)

        def wait(self, *a, **kw):
            return self._inner.wait(*a, **kw)

        def notify_all(self):
            return self._inner.notify_all()

    inner = stream._cond
    counting = _CountingCondition(inner)
    stream._cond = counting

    _ = stream.finished
    assert counting.count == 1, "`finished` must take the stream's own lock"

    assert stream._finished is False  # accessed directly -- still not finished
    stream._cond = inner
    stream._finish()
    counting = _CountingCondition(inner)
    stream._cond = counting

    assert stream.finished is True
    assert counting.count == 1, "a finished flag read must be under the lock too"
