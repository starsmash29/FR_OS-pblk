"""installer/qemu-boot-test.py's webUI client against the real webUI.

The QEMU boot test drives the router's webUI like a browser: log in with
the generated password, finish first-run setup, change settings, apply.
It only runs in the *Build installer ISO* workflow, so when the webUI
started refusing state-changing requests without the session's CSRF
token (ROADMAP SEC-9), nothing here noticed that the boot test's own
client sent none -- the boot test failed with 403 on `POST /setup`.

This runs the boot test's own `get`/`post` against the real app, served
by uvicorn over TLS on loopback, so its client is checked on every run
of the test suite, not only on an ISO build.
"""

from __future__ import annotations

import importlib.util
import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn
import yaml

from frfw.admin_account import ROLE_ADMIN
from frfw.webui.tls import ensure_self_signed_cert

BOOT_TEST = Path(__file__).resolve().parents[2] / "installer" / "qemu-boot-test.py"
GENERATED = "Gen3rated-by-first-boot"


@pytest.fixture
def boot_test():
    spec = importlib.util.spec_from_file_location("qemu_boot_test", BOOT_TEST)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def router_webui(app, webui_env, tmp_path, boot_test, monkeypatch, minimal_config_dict):
    """The app as the router serves it: HTTPS, a first-boot config and
    account, the boot test's port swapped for an ephemeral one."""
    webui_env["config_path"].write_text(yaml.safe_dump(minimal_config_dict))
    webui_env["admin_store"].set_password("admin", GENERATED, ROLE_ADMIN, must_change=True)
    cert, key = tmp_path / "webui.crt", tmp_path / "webui.key"
    ensure_self_signed_cert(cert, key)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(
        app, log_level="warning", lifespan="off", ssl_certfile=str(cert), ssl_keyfile=str(key),
    ))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started, "uvicorn did not start"
    monkeypatch.setattr(boot_test, "WEBUI_HOST", "127.0.0.1")
    monkeypatch.setattr(boot_test, "WEBUI_PORT", sock.getsockname()[1])
    yield
    server.should_exit = True
    thread.join(10)
    sock.close()


def test_the_boot_tests_client_gets_through_setup_and_changes_settings(boot_test, router_webui, webui_env):
    """Boot 3's sequence, step for step: every state-changing request
    must carry the token of the session it belongs to, including the new
    session first-run setup starts."""
    opener = boot_test.webui_opener()
    assert boot_test.wait_for_webui(opener, 10) is not None

    landed = boot_test.post(opener, "/login", {"username": "admin", "password": GENERATED})
    assert landed.endswith("/setup")

    done = boot_test.post(opener, "/setup", {"username": boot_test.NEW_USERNAME,
                                             "password": boot_test.NEW_PASSWORD,
                                             "password_confirm": boot_test.NEW_PASSWORD})
    assert done.endswith("/segments?first_run=1")
    assert webui_env["admin_store"].get(boot_test.NEW_USERNAME) is not None

    assert 'id="score"' in boot_test.get(opener, "/security")
    landed = boot_test.post(opener, "/rules/timezone", {"timezone": "Europe/Budapest"})
    assert "error=" not in landed
    assert "Europe/Budapest" in webui_env["config_path"].read_text()
    applied = boot_test.post(opener, "/apply", {})
    assert "error=" not in applied


def test_the_boot_tests_stream_check_reads_the_first_line(boot_test, router_webui, monkeypatch):
    """ROADMAP SEC-4: boot 3 reads the live XDP log's first line to show
    the webUI's stream works without journal access."""
    from frfw.webui.routes import xdp as xdp_route

    monkeypatch.setattr(xdp_route, "LOG_HEARTBEAT_SECONDS", 0.2)
    opener = boot_test.webui_opener()
    boot_test.post(opener, "/login", {"username": "admin", "password": GENERATED})
    boot_test.post(opener, "/setup", {"username": boot_test.NEW_USERNAME, "password": boot_test.NEW_PASSWORD,
                                      "password_confirm": boot_test.NEW_PASSWORD})
    assert boot_test.first_stream_line(opener).startswith(":")


def test_the_boot_tests_tls_handshake_names_the_host_it_is_given(boot_test, router_webui, monkeypatch):
    """ROADMAP P4-1: boot 3 tells a dropped ClientHello from a completed
    handshake with `tls_handshake`; against the real webUI an allowed
    name completes, and a port nothing answers on doesn't."""
    assert boot_test.tls_handshake(boot_test.XDP_ALLOWED_NAME, timeout=5)
    monkeypatch.setattr(boot_test, "WEBUI_PORT", 1)
    assert not boot_test.tls_handshake(boot_test.XDP_ALLOWED_NAME, timeout=2)


def test_the_boot_tests_split_client_hello_gets_an_answer_from_the_webui(boot_test, router_webui):
    """ROADMAP SEC-17: boot 3 tells a stopped split hello from a delivered
    one by whether the webUI's TLS server answers; it must answer the
    synthetic hello once it has all of it. The hello is a well-formed
    ClientHello, its name last and wholly after the cut."""
    from frfw.tlsfp.clienthello import parse_client_hello

    record, cut = boot_test.split_client_hello(boot_test.XDP_ALLOWED_NAME)
    assert len(record) > 1460 and cut < 1460
    hello = parse_client_hello(record[5:])
    assert hello.server_name == boot_test.XDP_ALLOWED_NAME and hello.extensions[-1] == 0
    assert record.index(boot_test.XDP_ALLOWED_NAME.encode()) > cut
    assert boot_test.split_hello_answered(boot_test.XDP_ALLOWED_NAME)


def test_udp_through_router_tells_a_reject_from_silence_and_an_answer(boot_test, monkeypatch):
    """ROADMAP SEC-1's boot-test check reads a port unreachable as the
    router's reject, and nothing else as one -- here on loopback, whose
    closed ports answer with exactly that ICMP error."""
    monkeypatch.setattr(boot_test, "BEYOND_HOST", "127.0.0.1")
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.bind(("127.0.0.1", 0))
    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silent.bind(("127.0.0.1", 0))
    closed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()

    def reply():
        data, peer = echo.recvfrom(2048)
        echo.sendto(data[:1], peer)

    threading.Thread(target=reply, daemon=True).start()
    try:
        assert boot_test.udp_through_router(echo.getsockname()[1]) == "answered"
        assert boot_test.udp_through_router(silent.getsockname()[1], timeout=0.5) == "no answer"
        assert boot_test.udp_through_router(closed_port) == "refused"
    finally:
        echo.close()
        silent.close()
