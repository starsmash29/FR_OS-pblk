"""IPv4 forwarding (found in review: nothing ever turned it on, so FR_OS
didn't route LAN traffic at all)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from frfw import forwarding

REPO_SRC = Path(__file__).resolve().parent.parent / "src"


def test_enable_turns_the_switch_on(tmp_path):
    switch = tmp_path / "ip_forward"
    switch.write_text("0\n")
    assert forwarding.enable(path=switch) == "IPv4 forwarding turned on"
    assert switch.read_text().strip() == "1"
    assert forwarding.enable(path=switch) == "IPv4 forwarding on"  # already on: nothing to do


def test_dry_run_changes_nothing(tmp_path):
    switch = tmp_path / "ip_forward"
    switch.write_text("0\n")
    assert "dry-run" in forwarding.enable(path=switch, dry_run=True)
    assert switch.read_text().strip() == "0"


def test_a_switch_that_cannot_be_written_is_an_error(tmp_path):
    with pytest.raises(forwarding.ForwardingError, match="cannot turn IPv4 forwarding on"):
        forwarding.enable(path=tmp_path / "missing" / "ip_forward")


def _sh(*args, ns=None, check=True):
    cmd = (["ip", "netns", "exec", ns] if ns else []) + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


@pytest.mark.skipif(os.geteuid() != 0 or not shutil.which("ip"), reason="needs root and ip netns")
def test_the_router_really_routes_once_enabled():
    """client -- router -- server in three network namespaces: a TCP
    connection from the client to the server gets through only after
    forwarding.enable() ran inside the router's namespace."""
    tag = uuid.uuid4().hex[:6]
    client, router, server = f"fwc{tag}", f"fwr{tag}", f"fws{tag}"
    listener = None
    try:
        for ns in (client, router, server):
            _sh("ip", "netns", "add", ns)
            _sh("ip", "link", "set", "lo", "up", ns=ns)
        for left, left_ns, right, right_ns in ((f"c{tag}", client, f"rc{tag}", router),
                                               (f"s{tag}", server, f"rs{tag}", router)):
            _sh("ip", "link", "add", left, "type", "veth", "peer", "name", right)
            _sh("ip", "link", "set", left, "netns", left_ns)
            _sh("ip", "link", "set", right, "netns", right_ns)
        for ns, dev, addr in ((client, f"c{tag}", "10.91.1.2/24"), (router, f"rc{tag}", "10.91.1.1/24"),
                              (router, f"rs{tag}", "10.91.2.1/24"), (server, f"s{tag}", "10.91.2.2/24")):
            _sh("ip", "addr", "add", addr, "dev", dev, ns=ns)
            _sh("ip", "link", "set", dev, "up", ns=ns)
        _sh("ip", "route", "add", "default", "via", "10.91.1.1", ns=client)
        _sh("ip", "route", "add", "default", "via", "10.91.2.1", ns=server)
        _sh("sysctl", "-qw", "net.ipv4.ip_forward=0", ns=router)
        listener = subprocess.Popen(
            ["ip", "netns", "exec", server, sys.executable, "-c",
             "import socket\ns = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
             "s.bind(('10.91.2.2', 8099)); s.listen()\n"
             "while True:\n    c, _ = s.accept(); c.sendall(b'hello'); c.close()\n"])

        def reaches_server() -> bool:
            probe = ("import socket, sys\n"
                     "try:\n    c = socket.create_connection(('10.91.2.2', 8099), timeout=2)\n"
                     "    sys.exit(0 if c.recv(5) == b'hello' else 1)\n"
                     "except OSError:\n    sys.exit(1)\n")
            return _sh(sys.executable, "-c", probe, ns=client, check=False).returncode == 0

        # The server answers on its own side (so a failure below is routing).
        up = ("import socket, sys, time\n"
              "for _ in range(50):\n"
              "    try:\n        socket.create_connection(('10.91.2.2', 8099), 1); sys.exit(0)\n"
              "    except OSError:\n        time.sleep(0.1)\n"
              "sys.exit(1)\n")
        assert _sh(sys.executable, "-c", up, ns=server, check=False).returncode == 0
        assert not reaches_server()
        env = dict(os.environ, PYTHONPATH=str(REPO_SRC))
        out = subprocess.run(["ip", "netns", "exec", router, sys.executable, "-c",
                              "from frfw import forwarding; print(forwarding.enable())"],
                             capture_output=True, text=True, check=True, env=env).stdout
        assert "IPv4 forwarding turned on" in out
        assert _sh("sysctl", "-n", "net.ipv4.ip_forward", ns=router).stdout.strip() == "1"
        assert reaches_server()
    finally:
        if listener is not None:
            listener.kill()
            listener.wait()
        for ns in (client, router, server):
            _sh("ip", "netns", "del", ns, check=False)
