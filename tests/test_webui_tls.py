"""Security-lessons H2: no legacy protocols -- the webUI states its TLS
floor (1.2) explicitly instead of relying on the Python/OpenSSL build's
default, and is TLS 1.3-only with PQC on. Checked against the real
fr-webui process with real TLS clients.
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time

import pytest
import yaml

from frfw import management, pqc
from frfw.skeleton import build_skeleton_config
from frfw.webui.server import tls_minimum_1_2_context_factory


def test_the_floor_is_set_even_where_the_build_default_is_lower():
    def permissive_default():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        return ctx

    assert tls_minimum_1_2_context_factory(None, permissive_default).minimum_version == ssl.TLSVersion.TLSv1_2
    assert pqc.tls_ssl_context_factory(None, permissive_default).minimum_version == ssl.TLSVersion.TLSv1_3


def _handshake(port: int, version: ssl.TLSVersion) -> str | None:
    """The negotiated version, or None if the server refused."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version < ssl.TLSVersion.TLSv1_2:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # let the client *try* the old protocol
    ctx.minimum_version = version
    ctx.maximum_version = version
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with ctx.wrap_socket(raw) as tls:
                return tls.version()
    except (ssl.SSLError, OSError):
        return None


@pytest.fixture
def webui(tmp_path):
    started = []

    def start(pqc_enabled: bool) -> int:
        raw = yaml.safe_load(build_skeleton_config("eth0", "eth1", lan_address="10.99.0.1/24"))
        raw["pqc"] = {"enabled": pqc_enabled}
        config = tmp_path / f"config-{pqc_enabled}.yaml"
        config.write_text(yaml.safe_dump(raw))
        port = 19000 + os.getpid() % 500 + (500 if pqc_enabled else 0)
        proc = subprocess.Popen(
            [sys.executable, "-m", "frfw.webui.server", "--config", str(config), "--port", str(port),
             "--cert", str(tmp_path / "cert.pem"), "--key", str(tmp_path / "key.pem")],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
            env={**os.environ, "OPENSSL_CONF": "/dev/null"},
        )
        started.append(proc)
        for _ in range(100):
            if management.webui_listening(port):
                return port
            if proc.poll() is not None:
                pytest.fail(proc.stderr.read())
            time.sleep(0.2)
        pytest.fail("fr-webui did not start")

    yield start
    for proc in started:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)


@pytest.mark.skipif(not shutil.which("ss") or not shutil.which("openssl"), reason="needs ss and openssl")
def test_the_real_webui_refuses_tls_below_1_2(webui):
    port = webui(pqc_enabled=False)
    assert _handshake(port, ssl.TLSVersion.TLSv1) is None
    assert _handshake(port, ssl.TLSVersion.TLSv1_1) is None
    assert _handshake(port, ssl.TLSVersion.TLSv1_2) == "TLSv1.2"
    assert _handshake(port, ssl.TLSVersion.TLSv1_3) == "TLSv1.3"


@pytest.mark.skipif(not shutil.which("ss") or not shutil.which("openssl"), reason="needs ss and openssl")
def test_with_pqc_the_real_webui_is_tls_1_3_only(webui):
    port = webui(pqc_enabled=True)
    assert _handshake(port, ssl.TLSVersion.TLSv1_2) is None
    assert _handshake(port, ssl.TLSVersion.TLSv1_3) == "TLSv1.3"
