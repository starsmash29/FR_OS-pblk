"""The XDP SNI filter against real packets, in real network namespaces.

Three namespaces -- a LAN client, the router, an internet server -- with
the compiled bpf/xdp_sni_filter.c attached to one of the router's two
interfaces. This pins down two things unit tests with a mocked bpftool
cannot:

1. Direction. XDP only runs on packets an interface *receives*. Attached
   to the router's WAN-side interface, a LAN client's ClientHello is
   never inspected and reaches the server even when its SNI is on the
   blocklist; attached to the LAN-side interface it is dropped. (The
   phase 4 docs recommended the WAN interface; this test is what caught
   that.)
2. Phase 16's pass reporting: with `set_report_pass(True)` a
   non-matching SNI shows up on the ring buffer as action "pass".

Skipped unless running as root with clang, a working bpftool, libbpf and
bpffs -- and never run while an FR_OS XDP program is already pinned on
this machine, so it cannot disturb a real deployment.
"""

from __future__ import annotations

import ctypes.util
import glob
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from frfw import xdp

CLIENT_NS, ROUTER_NS, SERVER_NS = "frx-cli", "frx-rtr", "frx-srv"
CLIENT_IP, SERVER_IP = "10.81.1.10", "10.81.2.10"
ROUTER_LAN_DEV, ROUTER_WAN_DEV = "frx-rl", "frx-rw"

_SERVER = """
import socket, sys
log = open(sys.argv[1], "a", buffering=1)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 443)); s.listen(16)
while True:
    c, _ = s.accept(); c.settimeout(2)
    try:
        data = c.recv(4096)
        log.write(f"{len(data)} {data[:1].hex()}\\n")
    except OSError:
        log.write("0 timeout\\n")
    c.close()
"""

_CLIENT = """
import socket, ssl, sys
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
raw = socket.create_connection((sys.argv[1], 443), timeout=3)
tls = ctx.wrap_socket(raw, server_hostname=sys.argv[2], do_handshake_on_connect=False)
tls.settimeout(3)
try:
    tls.do_handshake()
except (OSError, ssl.SSLError):
    pass
"""


def _working_bpftool_dir() -> str | None:
    """The system bpftool is often a version-matching wrapper that fails
    on a kernel it has no linux-tools package for; any installed
    linux-tools bpftool works for what these tests do."""
    candidates = [""] + sorted(glob.glob("/usr/lib/linux-tools-*")) + sorted(glob.glob("/usr/lib/linux-tools/*"))
    for directory in candidates:
        binary = os.path.join(directory, "bpftool") if directory else shutil.which("bpftool")
        if not binary or not os.access(binary, os.X_OK):
            continue
        if subprocess.run([binary, "version"], capture_output=True).returncode == 0:
            return directory
    return None


def _skip_reason() -> str | None:
    if os.geteuid() != 0:
        return "needs root"
    for tool in ("clang", "ip", "nsenter"):
        if shutil.which(tool) is None:
            return f"{tool} not installed"
    if _working_bpftool_dir() is None:
        return "no working bpftool"
    if ctypes.util.find_library("bpf") is None:
        return "libbpf not installed"
    if not os.path.ismount("/sys/fs/bpf"):
        return "bpffs not mounted at /sys/fs/bpf"
    if xdp.is_loaded():
        return "an FR_OS XDP program is already pinned on this machine"
    return None


pytestmark = pytest.mark.skipif(_skip_reason() is not None, reason=str(_skip_reason()))


def _sh(*cmd: str, ns: str | None = None) -> None:
    full = (["ip", "netns", "exec", ns] if ns else []) + list(cmd)
    subprocess.run(full, check=True, capture_output=True)


def _cleanup_namespaces() -> None:
    for ns in (CLIENT_NS, ROUTER_NS, SERVER_NS):
        subprocess.run(["ip", "netns", "del", ns], capture_output=True)


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("xdp_live")
    mp = pytest.MonkeyPatch()
    tools = _working_bpftool_dir()
    if tools:
        mp.setenv("PATH", f"{tools}:{os.environ['PATH']}")

    _cleanup_namespaces()
    server = None
    try:
        for ns in (CLIENT_NS, ROUTER_NS, SERVER_NS):
            _sh("ip", "netns", "add", ns)
            _sh("ip", "link", "set", "lo", "up", ns=ns)
        _sh("ip", "link", "add", ROUTER_LAN_DEV, "netns", ROUTER_NS, "type", "veth",
            "peer", "name", "frx-c", "netns", CLIENT_NS)
        _sh("ip", "link", "add", ROUTER_WAN_DEV, "netns", ROUTER_NS, "type", "veth",
            "peer", "name", "frx-s", "netns", SERVER_NS)
        _sh("ip", "addr", "add", f"{CLIENT_IP}/24", "dev", "frx-c", ns=CLIENT_NS)
        _sh("ip", "link", "set", "frx-c", "up", ns=CLIENT_NS)
        _sh("ip", "route", "add", "default", "via", "10.81.1.1", ns=CLIENT_NS)
        _sh("ip", "addr", "add", f"{SERVER_IP}/24", "dev", "frx-s", ns=SERVER_NS)
        _sh("ip", "link", "set", "frx-s", "up", ns=SERVER_NS)
        _sh("ip", "route", "add", "default", "via", "10.81.2.1", ns=SERVER_NS)
        _sh("ip", "addr", "add", "10.81.1.1/24", "dev", ROUTER_LAN_DEV, ns=ROUTER_NS)
        _sh("ip", "addr", "add", "10.81.2.1/24", "dev", ROUTER_WAN_DEV, ns=ROUTER_NS)
        _sh("ip", "link", "set", ROUTER_LAN_DEV, "up", ns=ROUTER_NS)
        _sh("ip", "link", "set", ROUTER_WAN_DEV, "up", ns=ROUTER_NS)
        _sh("sysctl", "-qw", "net.ipv4.ip_forward=1", ns=ROUTER_NS)

        (tmp / "server.py").write_text(_SERVER)
        (tmp / "client.py").write_text(_CLIENT)
        server_log = tmp / "server.log"
        server_log.touch()
        server = subprocess.Popen(
            ["ip", "netns", "exec", SERVER_NS, sys.executable, str(tmp / "server.py"), str(server_log)]
        )
        time.sleep(0.5)

        xdp.load_and_pin(xdp.ensure_compiled(obj_path=tmp / "xdp_sni_filter.o"))
        xdp.sync_blocklist(["blocked.example"])
        yield {"tmp": tmp, "server_log": server_log}
    finally:
        if server is not None:
            server.kill()
            server.wait()
        xdp.unload()
        _cleanup_namespaces()
        mp.undo()


# `ip netns exec` / `ip -n` also give the command a fresh /sys, where the
# bpffs holding the pinned program is not mounted; nsenter switches only
# the network namespace.
_IN_ROUTER = ["nsenter", f"--net=/run/netns/{ROUTER_NS}"]


def _attach(dev: str) -> None:
    subprocess.run(
        [*_IN_ROUTER, "ip", "link", "set", "dev", dev, "xdpgeneric", "pinned", str(xdp.PIN_PROG_PATH)],
        check=True, capture_output=True,
    )


def _detach(dev: str) -> None:
    subprocess.run([*_IN_ROUTER, "ip", "link", "set", "dev", dev, "xdpgeneric", "off"],
                   check=True, capture_output=True)


def _connect(lab, sni: str) -> list[str]:
    """Open one TLS connection from the client; returns what the server
    logged for it (empty if the ClientHello never arrived)."""
    before = lab["server_log"].read_text().splitlines()
    subprocess.run(
        ["ip", "netns", "exec", CLIENT_NS, sys.executable, str(lab["tmp"] / "client.py"), SERVER_IP, sni],
        capture_output=True, timeout=20,
    )
    time.sleep(2.5)  # the server's own recv timeout
    return lab["server_log"].read_text().splitlines()[len(before):]


def _drain(reader: xdp.RingBufferReader) -> None:
    while reader.poll(50) > 0:
        pass


def test_wan_side_attachment_never_sees_lan_client_hellos(lab):
    _attach(ROUTER_WAN_DEV)
    try:
        before = xdp.get_stats()
        received = _connect(lab, "blocked.example")
        after = xdp.get_stats()
    finally:
        _detach(ROUTER_WAN_DEV)
    # The ClientHello (TLS record type 0x16) reached the server...
    assert any(line.split()[1] == "16" for line in received), received
    # ...because the program never saw a ClientHello at all.
    assert after["drop_match"] == before["drop_match"]
    assert after["pass_no_match"] == before["pass_no_match"]


def test_lan_side_attachment_drops_blocklisted_sni(lab):
    events: list[xdp.SniEvent] = []
    _attach(ROUTER_LAN_DEV)
    try:
        with xdp.RingBufferReader(events.append) as reader:
            _drain(reader)
            events.clear()
            before = xdp.get_stats()
            received = _connect(lab, "www.blocked.example")
            reader.poll(500)
            after = xdp.get_stats()
    finally:
        _detach(ROUTER_LAN_DEV)
    assert not any(line.split()[1] == "16" for line in received), received
    assert after["drop_match"] > before["drop_match"]
    drops = [e for e in events if e.action == "drop"]
    assert drops and drops[0].hostname == "www.blocked.example"
    assert drops[0].saddr == CLIENT_IP and drops[0].dport == 443


def test_pass_events_only_while_reporting_is_on(lab):
    events: list[xdp.SniEvent] = []
    _attach(ROUTER_LAN_DEV)
    try:
        with xdp.RingBufferReader(events.append) as reader:
            _drain(reader)
            xdp.set_report_pass(False)
            events.clear()
            _connect(lab, "quiet.example")
            reader.poll(500)
            assert [e for e in events if e.action == "pass"] == []

            xdp.set_report_pass(True)
            assert xdp.report_pass_enabled()
            events.clear()
            received = _connect(lab, "allowed.example")
            reader.poll(500)
    finally:
        xdp.set_report_pass(False)
        _detach(ROUTER_LAN_DEV)
    # A pass is still a pass: the connection went through.
    assert any(line.split()[1] == "16" for line in received), received
    passes = [e for e in events if e.action == "pass"]
    assert passes and passes[0].hostname == "allowed.example"
    assert passes[0].saddr == CLIENT_IP
    assert not xdp.report_pass_enabled()
