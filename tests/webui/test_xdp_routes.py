from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import sys
import threading
import time

import pytest
import uvicorn
from fastapi import HTTPException
from starlette.requests import Request

from frfw import xdp as xdp_mod
from frfw.config import load_config
from frfw.webui.auth import COOKIE_NAME
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


def _fake_journal(monkeypatch, code: str) -> None:
    """Stand a real child process in for `journalctl -f`: the stream
    code runs exactly as on a router, only the argv differs."""
    monkeypatch.setattr(xdp_route, "_JOURNALCTL_CMD", [sys.executable, "-c", code])


@pytest.fixture
def fresh_streams(monkeypatch):
    """A clean per-process registry, so no test sees another's streams."""
    streams: dict = {}
    monkeypatch.setattr(xdp_route, "_log_streams", streams)
    return streams


def test_logs_stream_relays_valid_json_lines_and_drops_garbage(
    logged_in_client, monkeypatch, fresh_streams
):
    lines = [
        '{"ts": 1.0, "saddr": "1.2.3.4", "sport": 111, "daddr": "5.6.7.8", "dport": 443, "sni": "bad.example.com"}',
        "not json, should be dropped",
        "",
        '{"ts": 2.0, "saddr": "9.9.9.9", "sport": 222, "daddr": "8.8.8.8", "dport": 443, "sni": "also-bad.example.com"}',
    ]
    _fake_journal(monkeypatch, f"print('\\n'.join({lines!r}))")

    with logged_in_client.stream("GET", "/xdp/logs/stream") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(response.iter_text())

    assert "bad.example.com" in body
    assert "also-bad.example.com" in body
    assert "not json" not in body
    assert body.count("data: ") == 2
    # The journal ended, so the session's stream ended with it and gave
    # its cap slot back (review v0.2.0 R19).
    assert fresh_streams == {}


def test_a_missing_journalctl_is_an_error_frame(logged_in_client, monkeypatch, fresh_streams):
    monkeypatch.setattr(xdp_route, "_JOURNALCTL_CMD", ["/nonexistent/journalctl", "-f"])

    with logged_in_client.stream("GET", "/xdp/logs/stream") as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())

    assert json.loads(body.removeprefix("data: "))["error"].startswith("journalctl not found")
    assert fresh_streams == {}


def test_stream_past_the_cap_is_an_error_frame_and_spawns_nothing(
    logged_in_client, monkeypatch, fresh_streams, tmp_path
):
    """SEC-13: at `LOG_STREAM_LIMIT` live streams, the next session gets
    one clear `text/event-stream` error frame and no child process
    (review v0.2.0 R19)."""
    spawned = tmp_path / "spawned"
    _fake_journal(monkeypatch, f"open({str(spawned)!r}, 'w').close()")
    # Fill the process-wide registry with other sessions' live streams.
    for n in range(xdp_route.LOG_STREAM_LIMIT):
        fresh_streams[f"other-session-{n}"] = xdp_route._LogStream(f"other-session-{n}")

    with logged_in_client.stream("GET", "/xdp/logs/stream") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(response.iter_text())

    assert not spawned.exists(), "a journalctl was spawned past the cap"
    assert "limit reached" in json.loads(body.removeprefix("data: "))["error"]
    assert str(xdp_route.LOG_STREAM_LIMIT) in body
    assert len(fresh_streams) == xdp_route.LOG_STREAM_LIMIT


def test_a_queue_that_is_not_read_drops_its_oldest_frame_not_the_end():
    """A tab that stops reading must neither block the session's stream
    nor grow without bound; the end marker always gets through."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=2)
    for frame in ("one", "two", "three", None):
        xdp_route._offer(queue, frame)
    assert [queue.get_nowait() for _ in range(queue.qsize())] == ["three", None]


def _request_with_cookie(cookie: str | None) -> Request:
    """A minimal Starlette `Request` whose `cookies` contains `cookie`.

    `Request.cookies` is derived from the `Cookie` header, so callers
    only pass the value of `COOKIE_NAME`. A `None` cookie means no
    header at all: a request with no session cookie.
    """
    headers: list[tuple[bytes, bytes]] = []
    if cookie is not None:
        headers.append((b"cookie", f"{COOKIE_NAME}={cookie}".encode()))
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
    """A missing cookie must not map to the constant hash of the empty
    string: every such caller would share one registry entry. The route
    is gated by `require_login`, so this is defence in depth."""
    with pytest.raises(HTTPException) as exc:
        xdp_route._session_stream_key(_request_with_cookie(None))
    assert exc.value.status_code == 401


def test_session_stream_key_is_the_digest_not_the_cookie_itself():
    """The registry never keeps the raw cookie, a bearer secret: it
    keeps only its sha256 hex digest."""
    key = xdp_route._session_stream_key(_request_with_cookie("secret-value"))
    assert key == hashlib.sha256(b"secret-value").hexdigest()
    assert "secret-value" not in key


# --- Against a real server ------------------------------------------------
#
# The TestClient drains a response body before it hands it over, and it
# never disconnects mid-stream, so it can't show what happens when a
# browser tab is closed on a quiet journal -- the case R19 is about. These
# tests run the app under uvicorn, as on the router, and talk to it over
# real sockets.


@pytest.fixture
def live_server(app):
    """The app under a real uvicorn, on an ephemeral loopback port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="off"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started, "uvicorn did not start"
    yield sock.getsockname()
    server.should_exit = True
    thread.join(10)
    sock.close()


def _open_tab(address, cookie: str) -> socket.socket:
    """A browser tab on the live-log page: an open SSE request."""
    tab = socket.create_connection(address, timeout=10)
    tab.sendall(
        b"GET /xdp/logs/stream HTTP/1.1\r\nHost: router\r\n"
        + f"Cookie: {COOKIE_NAME}={cookie}\r\n\r\n".encode()
    )
    return tab


def _read_until(tab: socket.socket, marker: bytes) -> bytes:
    received = b""
    while marker not in received:
        chunk = tab.recv(4096)
        assert chunk, f"the stream ended before {marker!r}: {received!r}"
        received += chunk
    return received


def _wait_for(condition, timeout: float = 10) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return condition()


#: A quiet journal: one line naming the child, then nothing for a minute.
#: Every child it starts also appends its pid to a file, so a test counts
#: the children that really ran, not a fake's bookkeeping.
_QUIET_JOURNAL = (
    "import json, os, sys, time; "
    "open(sys.argv[1], 'a').write(f'{os.getpid()}\\n'); "
    "print(json.dumps({'pid': os.getpid()}), flush=True); "
    "time.sleep(60)"
)


def _children(pids_file) -> list[int]:
    return [int(pid) for pid in pids_file.read_text().split()] if pids_file.exists() else []


def test_closing_the_last_tab_on_a_quiet_journal_ends_the_child(
    logged_in_client, live_server, monkeypatch, fresh_streams, tmp_path
):
    """SEC-13 / review v0.2.0 R19: the `journalctl` child of a closed tab
    is gone, and the session's cap slot free, even when the journal never
    writes another line -- the case where a server is never told its
    client left."""
    pids_file = tmp_path / "pids"
    monkeypatch.setattr(
        xdp_route, "_JOURNALCTL_CMD", [sys.executable, "-c", _QUIET_JOURNAL, str(pids_file)]
    )
    monkeypatch.setattr(xdp_route, "LOG_HEARTBEAT_SECONDS", 0.2)
    cookie = logged_in_client.cookies[COOKIE_NAME]

    tab = _open_tab(live_server, cookie)
    _read_until(tab, b'"pid"')
    [pid] = _children(pids_file)
    assert _alive(pid)

    tab.close()  # the browser tab is closed

    assert _wait_for(lambda: not _alive(pid)), "the journalctl child outlived its last tab"
    assert _wait_for(lambda: fresh_streams == {}), "the session kept its cap slot"


def test_tabs_of_one_session_share_one_child_until_the_last_one_leaves(
    logged_in_client, live_server, monkeypatch, fresh_streams, tmp_path
):
    """SEC-13 / review v0.2.0 R19: every live-log tab of a session reads
    one `journalctl`, not one child per request; closing one tab leaves
    the others streaming, and the last one to leave ends the child."""
    pids_file = tmp_path / "pids"
    monkeypatch.setattr(
        xdp_route, "_JOURNALCTL_CMD", [sys.executable, "-c", _QUIET_JOURNAL, str(pids_file)]
    )
    monkeypatch.setattr(xdp_route, "LOG_HEARTBEAT_SECONDS", 0.2)
    cookie = logged_in_client.cookies[COOKIE_NAME]

    first = _open_tab(live_server, cookie)
    _read_until(first, b'"pid"')
    second = _open_tab(live_server, cookie)
    # The second tab joined after the only line: it gets keep-alives.
    _read_until(second, b": keepalive")

    [pid] = _children(pids_file)
    [stream] = fresh_streams.values()
    assert len(stream.subscribers) == 2

    first.close()
    assert _wait_for(lambda: len(stream.subscribers) == 1)
    assert _alive(pid), "closing one tab ended the session's other tab"
    _read_until(second, b": keepalive")  # still streaming

    second.close()
    assert _wait_for(lambda: not _alive(pid)), "the journalctl child outlived its last tab"
    assert _wait_for(lambda: fresh_streams == {})
    assert _children(pids_file) == [pid], "a second journalctl was spawned for one session"
