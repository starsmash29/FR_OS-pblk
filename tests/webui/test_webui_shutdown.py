"""A stopping webUI must not wait for ever on an open live-log tab.

The XDP screen's live log is a Server-Sent Events request that never ends
while the browser keeps the tab open, and uvicorn's default is to wait for
every open request before it exits. So each restart of fr-webui -- `apply`
rebinding it to a new address (frfw.management.sync_webui), an update --
hung until systemd's stop timeout; the QEMU boot test caught it as the
rebind still running when the router powered off. fr-webui now gives open
requests SHUTDOWN_GRACE_SECONDS (the browser's EventSource reconnects).
"""

from __future__ import annotations

import socket
import ssl
import threading
import time

import uvicorn

from frfw.webui import server as webui_server
from frfw.webui.auth import COOKIE_NAME
from frfw.webui.routes import xdp as xdp_route
from frfw.webui.tls import ensure_self_signed_cert


def test_a_stopping_webui_does_not_wait_for_an_open_live_log_tab(app, logged_in_client, tmp_path, monkeypatch):
    monkeypatch.setattr(xdp_route, "LOG_HEARTBEAT_SECONDS", 0.2)
    monkeypatch.setattr(xdp_route, "_log_streams", {})
    monkeypatch.setattr(xdp_route, "_EVENTS_CMD", ["tail", "-n", "0", "-F", "--", str(tmp_path / "events.jsonl")])
    cert, key = tmp_path / "webui.crt", tmp_path / "webui.key"
    ensure_self_signed_cert(cert, key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    config = webui_server.server_config(app, port=sock.getsockname()[1], cert_path=cert, key_path=key)
    config.log_level = "warning"
    config.lifespan = "off"
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    tab = context.wrap_socket(socket.create_connection(sock.getsockname(), timeout=10))
    try:
        tab.sendall(b"GET /xdp/logs/stream HTTP/1.1\r\nHost: router\r\n"
                    + f"Cookie: {COOKIE_NAME}={logged_in_client.cookies[COOKIE_NAME]}\r\n\r\n".encode())
        received = b""
        while b": keepalive" not in received:  # the tab is open and streaming
            received += tab.recv(4096)

        started = time.monotonic()
        server.should_exit = True
        thread.join(webui_server.SHUTDOWN_GRACE_SECONDS + 10)
        assert not thread.is_alive(), "the webUI still waits on the open live-log tab"
        assert time.monotonic() - started < webui_server.SHUTDOWN_GRACE_SECONDS + 5
    finally:
        tab.close()
        sock.close()
