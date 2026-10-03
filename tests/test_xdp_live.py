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
import json
import os
import shutil
import socket
import struct
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


# --- phase 19: ClientHello copies for TLS fingerprinting ---------------------------

_RAW_CLIENT = """
import socket, sys, time
hello = bytes.fromhex(sys.argv[3])
s = socket.create_connection((sys.argv[1], 443), timeout=3)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
split = int(sys.argv[2])
s.sendall(hello[:split]); time.sleep(0.2); s.sendall(hello[split:]); time.sleep(0.5)
s.close()
"""

# Opens the hello ring buffer as root, drops to an unprivileged account
# exactly like fr-tls-fp, then fingerprints what arrives.
_FINGERPRINTER = """
import json, os, sys, time
from frfw import xdp
from frfw.config import parse_config
from frfw.tlsfp.daemon import TlsFingerprintDaemon, drop_privileges
holder = []
reader = xdp.RingBufferReader(lambda seg: holder[0].handle_segment(seg), xdp.PIN_HELLO_PKTS_PATH,
                              decode=xdp.HelloSegment.from_bytes)
drop_privileges()
config = parse_config({"version": 1, "hostname": "r", "zones": {"lan": {}},
                       "interfaces": {"lan": {"device": "x", "zone": "lan"}}, "rules": [], "nat": {}})
holder.append(TlsFingerprintDaemon(config, state_path=__import__("pathlib").Path("/nonexistent/x"),
                                   quarantine_fn=lambda ip, d: {"ok": True}))
print("ready", flush=True)
deadline = time.time() + float(sys.argv[1])
while time.time() < deadline:
    reader.poll(200)
d = holder[0]
print(json.dumps({"uid": os.getuid(), "stats": d.stats,
                  "clients": {c: sorted(fps) for c, fps in d.inventory.clients.items()},
                  "sni": {c: [s for fp in fps.values() for s in fp.sni] for c, fps in d.inventory.clients.items()}}))
"""


def test_split_client_hello_is_fingerprinted_after_dropping_privileges(lab):
    import tlsfp_samples as samples

    from frfw.tlsfp.clienthello import parse_client_hello
    from frfw.tlsfp.fingerprint import ja4

    message = samples.client_hello(samples.default_extensions(sni="pq.example", pq=True))
    wire = samples.tls_records(message)
    assert len(wire) > 1460  # more than one full-size segment carries on a 1500-byte MTU
    expected = ja4(parse_client_hello(message))

    (lab["tmp"] / "raw_client.py").write_text(_RAW_CLIENT)
    (lab["tmp"] / "fingerprinter.py").write_text(_FINGERPRINTER)
    env = {**os.environ, "PYTHONPATH": str(Path(xdp.__file__).resolve().parents[1])}
    _attach(ROUTER_LAN_DEV)
    xdp.set_settings(xdp.SETTING_REPORT_HELLO)
    try:
        fingerprinter = subprocess.Popen(
            [sys.executable, str(lab["tmp"] / "fingerprinter.py"), "8"],
            stdout=subprocess.PIPE, text=True, env=env,
        )
        assert fingerprinter.stdout.readline().strip() == "ready"
        subprocess.run(
            ["ip", "netns", "exec", CLIENT_NS, sys.executable, str(lab["tmp"] / "raw_client.py"),
             SERVER_IP, "900", wire.hex()],
            capture_output=True, timeout=20, check=True,
        )
        # A real TLS stack too (single segment here: OpenSSL 3.0 sends no PQ share).
        _connect(lab, "py.example")
        result = json.loads(fingerprinter.communicate(timeout=30)[0].splitlines()[-1])
    finally:
        xdp.set_settings(0)
        _detach(ROUTER_LAN_DEV)

    assert result["uid"] != 0
    assert expected in result["clients"][CLIENT_IP]
    assert {"pq.example", "py.example"} <= set(result["sni"][CLIENT_IP])
    assert result["stats"]["parse_errors"] == 0
    assert any(fp.startswith("t13d") for fp in result["clients"][CLIENT_IP] if fp != expected)


# --- SEC-16: VLAN-tagged frames (review-triage B2) ---------------------------------
#
# These go in as raw Ethernet frames from the client's side of the veth,
# so the tags are on the wire exactly as written (a VLAN device would
# hand them to the veth as offload metadata instead, which XDP never
# sees). Nothing has to be routed: the program's counters, its events and
# its hello copies show what it made of each frame.

_INJECT = """
import socket, sys
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((sys.argv[1], 0))
s.send(bytes.fromhex(sys.argv[2]))
"""

ETH_P_8021Q, ETH_P_8021AD, ETH_P_IP = 0x8100, 0x88A8, 0x0800


def _mac(dev: str, ns: str) -> bytes:
    out = subprocess.run(["ip", "-n", ns, "-j", "link", "show", dev],
                         check=True, capture_output=True, text=True).stdout
    return bytes.fromhex(json.loads(out)[0]["address"].replace(":", ""))


def _ipv4_checksum(header: bytes) -> int:
    total = sum(int.from_bytes(header[i:i + 2], "big") for i in range(0, len(header), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _tcp_frame(payload: bytes, tags: list[tuple[int, int]], dst_mac: bytes, src_mac: bytes,
               *, datagram_payload: int | None = None, sport: int = 40443) -> bytes:
    """An Ethernet frame carrying one TCP segment to SERVER_IP:443, behind
    `tags` ((TPID, VLAN id) pairs, outermost first).

    The IPv4 total length counts `datagram_payload` bytes of TCP payload
    (default: all of `payload`); whatever of `payload` lies past that is
    still on the wire, after the end of the datagram -- where Ethernet
    padding goes (SEC-7)."""
    if datagram_payload is None:
        datagram_payload = len(payload)
    tcp = struct.pack("!HHIIBBHHH", sport, 443, 1000, 0, 5 << 4, 0x18, 64240, 0, 0)
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + datagram_payload, 1, 0x4000, 64, 6, 0,
                               socket.inet_aton(CLIENT_IP), socket.inet_aton(SERVER_IP)))
    ip[10:12] = _ipv4_checksum(bytes(ip)).to_bytes(2, "big")
    ethertypes = [tpid for tpid, _ in tags] + [ETH_P_IP]
    frame = dst_mac + src_mac + ethertypes[0].to_bytes(2, "big")
    for (_, vid), inner in zip(tags, ethertypes[1:]):
        frame += vid.to_bytes(2, "big") + inner.to_bytes(2, "big")
    return frame + bytes(ip) + tcp + payload


def _tls_frame(sni: str, tags: list[tuple[int, int]], dst_mac: bytes, src_mac: bytes) -> tuple[bytes, bytes]:
    """A frame with a ClientHello for `sni` (see `_tcp_frame`). Returns the
    frame and its TCP payload (the TLS record)."""
    import tlsfp_samples as samples

    payload = samples.tls_records(samples.client_hello(samples.default_extensions(sni=sni, pq=False)))
    return _tcp_frame(payload, tags, dst_mac, src_mac), payload


def _inject(lab, frame: bytes) -> None:
    script = lab["tmp"] / "inject.py"
    if not script.exists():
        script.write_text(_INJECT)
    subprocess.run(["ip", "netns", "exec", CLIENT_NS, sys.executable, str(script), "frx-c", frame.hex()],
                   check=True, capture_output=True, timeout=10)


@pytest.fixture()
def lan_attached(lab):
    _attach(ROUTER_LAN_DEV)
    try:
        yield {"dst": _mac(ROUTER_LAN_DEV, ROUTER_NS), "src": _mac("frx-c", CLIENT_NS)}
    finally:
        _detach(ROUTER_LAN_DEV)


@pytest.mark.parametrize("tags", [
    [],
    [(ETH_P_8021Q, 30)],                         # one 802.1Q tag: FR_OS's own segments (frfw.segments)
    [(ETH_P_8021AD, 100), (ETH_P_8021Q, 30)],    # QinQ: an 802.1ad S-tag around a C-tag
    [(ETH_P_8021Q, 100), (ETH_P_8021Q, 30)],     # two 802.1Q tags
], ids=["untagged", "802.1q", "qinq-802.1ad", "double-802.1q"])
def test_blocklisted_sni_is_dropped_behind_vlan_tags(lab, lan_attached, tags):
    events: list[xdp.SniEvent] = []
    frame, _ = _tls_frame("www.blocked.example", tags, lan_attached["dst"], lan_attached["src"])
    with xdp.RingBufferReader(events.append) as reader:
        _drain(reader)
        events.clear()
        before = xdp.get_stats()
        _inject(lab, frame)
        reader.poll(500)
        after = xdp.get_stats()
    assert after["drop_match"] == before["drop_match"] + 1
    drops = [e for e in events if e.action == "drop"]
    assert drops and drops[0].hostname == "www.blocked.example"
    assert drops[0].saddr == CLIENT_IP and drops[0].dport == 443


def test_allowed_sni_behind_a_vlan_tag_is_parsed_and_passed(lab, lan_attached):
    frame, _ = _tls_frame("allowed.example", [(ETH_P_8021Q, 30)], lan_attached["dst"], lan_attached["src"])
    before = xdp.get_stats()
    _inject(lab, frame)
    after = xdp.get_stats()
    assert after["pass_no_match"] == before["pass_no_match"] + 1
    assert after["drop_match"] == before["drop_match"]


def test_hello_copy_behind_a_vlan_tag_starts_at_the_tls_record(lab, lan_attached):
    """Phase 19's hello copies address the TCP payload by packet offset,
    so the tag bytes have to be counted in it; off by 4 the copy would
    start inside the TCP header and every fingerprint would fail."""
    segments: list[xdp.HelloSegment] = []
    frame, payload = _tls_frame("fp.example", [(ETH_P_8021AD, 100), (ETH_P_8021Q, 30)],
                                lan_attached["dst"], lan_attached["src"])
    xdp.set_settings(xdp.SETTING_REPORT_HELLO)
    try:
        with xdp.RingBufferReader(segments.append, xdp.PIN_HELLO_PKTS_PATH,
                                  decode=xdp.HelloSegment.from_bytes) as reader:
            while reader.poll(50) > 0:
                pass
            segments.clear()
            _inject(lab, frame)
            reader.poll(500)
    finally:
        xdp.set_settings(0)
    assert len(segments) == 1 and segments[0].first
    assert segments[0].saddr == CLIENT_IP and segments[0].dport == 443
    assert segments[0].payload == payload[:len(segments[0].payload)]
    assert segments[0].payload[:1] == b"\x16"


def _ip_in_receives(ns: str) -> int:
    snmp = subprocess.run(["ip", "netns", "exec", ns, "cat", "/proc/net/snmp"],
                          check=True, capture_output=True, text=True).stdout.splitlines()
    names, values = [line.split() for line in snmp if line.startswith("Ip:")][:2]
    return int(values[names.index("InReceives")])


_THREE_TAGS = [(ETH_P_8021Q, 30), (ETH_P_8021Q, 31), (ETH_P_8021Q, 32)]


def test_a_tag_stack_deeper_than_the_filter_unwraps_passes_unparsed(lab, lan_attached):
    """The documented fail-open (MAX_VLAN_TAGS in bpf/xdp_sni_filter.c):
    a frame with more tags than the program unwraps is passed without
    being parsed or counted -- never dropped as malformed."""
    frame, _ = _tls_frame("www.blocked.example", _THREE_TAGS, lan_attached["dst"], lan_attached["src"])
    before = xdp.get_stats()
    _inject(lab, frame)
    assert xdp.get_stats() == before


def _vlan_devices_supported() -> bool:
    probe = "frx-probe"
    subprocess.run(["ip", "netns", "add", probe], capture_output=True)
    try:
        subprocess.run(["ip", "-n", probe, "link", "add", "frx-p0", "type", "veth", "peer", "name", "frx-p1"],
                       capture_output=True)
        return subprocess.run(["ip", "-n", probe, "link", "add", "link", "frx-p0", "name", "frx-p0.30",
                               "type", "vlan", "id", "30"], capture_output=True).returncode == 0
    finally:
        subprocess.run(["ip", "netns", "del", probe], capture_output=True)


# --- SEC-17: the name's case and a trailing dot (review-triage B3) -------------
#
# The blocklist entry here is stored the way an operator would type it, and
# the wire name is spelled the way a client happens to send it. Before
# extract_sni() normalized, every spelling below that differed from the
# stored entry's bytes built a different LPM key and reached the server.


@pytest.mark.parametrize("wire_sni", [
    "www.blocked.example",      # the stored spelling, unchanged
    "WWW.BLOCKED.EXAMPLE",      # case only
    "Www.Blocked.Example",      # mixed case
    "www.blocked.example.",     # one trailing dot (RFC 1035 3.1)
    "www.blocked.example...",   # a run of trailing dots
    "WWW.Blocked.Example...",   # both at once
], ids=["exact", "upper", "mixed", "trailing-dot", "dot-run", "case-and-dots"])
def test_a_blocklisted_name_is_dropped_whatever_case_and_dots_the_client_uses(
    lab, lan_attached, wire_sni
):
    """The kernel must build the same key for every spelling of one name,
    and that key is the one the userspace mirror installed for the blocklist
    entry 'blocked.example' (see the lab fixture)."""
    events: list[xdp.SniEvent] = []
    frame, _ = _tls_frame(wire_sni, [], lan_attached["dst"], lan_attached["src"])
    with xdp.RingBufferReader(events.append) as reader:
        _drain(reader)
        events.clear()
        before = xdp.get_stats()
        _inject(lab, frame)
        reader.poll(500)
        after = xdp.get_stats()
    assert after["drop_match"] == before["drop_match"] + 1
    assert after["pass_no_match"] == before["pass_no_match"]
    drops = [e for e in events if e.action == "drop"]
    assert drops and drops[0].hostname == xdp.normalize_sni(wire_sni)


@pytest.mark.parametrize("wire_sni", [
    "notblocked.example",       # shares the tail, not a label boundary
    "www.blocked.example.evil.test",  # the blocked name as a left-hand label
    "xblocked.example",         # the blocked name as a right-hand label
], ids=["prefix", "suffix-chain", "suffix-label"])
def test_normalization_does_not_widen_a_name_to_its_neighbours(lab, lan_attached, wire_sni):
    """Folding case and trimming dots must not turn the LPM key's label
    boundary into a plain substring match: a name that merely contains
    'blocked.example' as bytes, but not as a whole label, still passes."""
    frame, _ = _tls_frame(wire_sni, [], lan_attached["dst"], lan_attached["src"])
    before = xdp.get_stats()
    _inject(lab, frame)
    after = xdp.get_stats()
    assert after["drop_match"] == before["drop_match"]
    assert after["pass_no_match"] == before["pass_no_match"] + 1


def test_a_subdomain_of_a_blocklisted_name_is_still_dropped(lab, lan_attached):
    """Normalizing must not cost the subdomain coverage the key scheme
    exists for: reverse("." + name) blocks a parent and everything under it."""
    frame, _ = _tls_frame("deep.www.blocked.example", [], lan_attached["dst"], lan_attached["src"])
    before = xdp.get_stats()
    _inject(lab, frame)
    assert xdp.get_stats()["drop_match"] == before["drop_match"] + 1


def test_a_name_at_the_kernel_limit_is_counted_as_a_pass_not_dropped(lab, lan_attached):
    """The third B3 bypass, made explicit: a wire name of MAX_SNI_LEN or
    more is refused by parse_sni_body() before normalization, so it cannot
    match -- it is passed and *counted*, not dropped and not silently lost.
    parse_sni_body() rejecting the over-long name leaves found_len == 0, which
    the caller buckets as pass_no_sni (a server_name was present but no usable
    name came out of it), so that is the counter that moves. sync_blocklist()
    refuses such an entry at configuration time (tests/test_xdp.py), so an
    operator never gets one into the trie either."""
    wire_sni = "a" * 40 + ".example"
    frame, _ = _tls_frame(wire_sni, [], lan_attached["dst"], lan_attached["src"])
    before = xdp.get_stats()
    _inject(lab, frame)
    after = xdp.get_stats()
    # The security property: the over-long name is never dropped (so it can
    # never be made to match a blocklist entry) ...
    assert after["drop_match"] == before["drop_match"]
    # ... and it is accounted for, not silently dropped on the floor.
    assert after["pass_no_sni"] == before["pass_no_sni"] + 1


def _ip_in_receives(ns: str) -> int:
    snmp = subprocess.run(["ip", "netns", "exec", ns, "cat", "/proc/net/snmp"],
                          check=True, capture_output=True, text=True).stdout.splitlines()
    names, values = [line.split() for line in snmp if line.startswith("Ip:")][:2]
    return int(values[names.index("InReceives")])


def test_a_tag_stack_deeper_than_the_filter_unwraps_is_not_routed_either(lab, lan_attached):
    """Why that fail-open is safe: the router's IP layer never sees such a
    frame. The kernel strips one tag per VLAN device configured for it,
    and the router has no device for the extra tags. Shown with the
    router's own VLAN 30 device present: the frame with one tag reaches
    IP, the frame with three tags never does."""
    if not _vlan_devices_supported():
        pytest.skip("this kernel has no 802.1Q VLAN devices (8021q)")
    _sh("ip", "link", "add", "link", ROUTER_LAN_DEV, "name", "frx-rl.30", "type", "vlan", "id", "30", ns=ROUTER_NS)
    _sh("ip", "addr", "add", "10.81.30.1/24", "dev", "frx-rl.30", ns=ROUTER_NS)
    _sh("ip", "link", "set", "frx-rl.30", "up", ns=ROUTER_NS)
    try:
        one_tag, _ = _tls_frame("allowed.example", [(ETH_P_8021Q, 30)], lan_attached["dst"], lan_attached["src"])
        three_tags, _ = _tls_frame("www.blocked.example", _THREE_TAGS, lan_attached["dst"], lan_attached["src"])

        ip_before = _ip_in_receives(ROUTER_NS)
        _inject(lab, one_tag)
        assert _ip_in_receives(ROUTER_NS) == ip_before + 1

        ip_before = _ip_in_receives(ROUTER_NS)
        _inject(lab, three_tags)
        assert _ip_in_receives(ROUTER_NS) == ip_before
    finally:
        _sh("ip", "link", "del", "frx-rl.30", ns=ROUTER_NS)


# --- SEC-7: the parse ends where the IPv4 datagram ends (review v0.2.0 R9) ---
#
# Bytes on the wire after the IPv4 total length are not part of the
# datagram: Ethernet padding on a short frame, or anything a sender puts
# there. The router never forwards them, so the filter must not read a
# ClientHello -- or the rest of one -- out of them.


def _counted(lab, frame: bytes) -> dict[str, int]:
    """Inject `frame`; return how much each counter moved."""
    before = xdp.get_stats()
    _inject(lab, frame)
    after = xdp.get_stats()
    return {name: after[name] - before[name] for name in after}


def test_a_client_hello_after_the_end_of_the_datagram_is_not_parsed(lab, lan_attached):
    """A segment with no payload, followed on the wire by a ClientHello for
    a blocklisted name: the datagram carries no TLS at all."""
    _, hello = _tls_frame("www.blocked.example", [], lan_attached["dst"], lan_attached["src"])
    frame = _tcp_frame(hello, [], lan_attached["dst"], lan_attached["src"], datagram_payload=0)
    moved = _counted(lab, frame)
    assert moved["drop_match"] == 0
    assert moved["pass_not_tls"] == 1


def _hello_with_sni_last(sni: str) -> tuple[bytes, int]:
    """A ClientHello record whose server_name is its last extension, and
    the offset in it just past the name's last byte."""
    import tlsfp_samples as samples

    sni_ext = samples.default_extensions(sni=sni, pq=False)[0]
    exts = samples.default_extensions(sni=None, pq=False) + [sni_ext]
    record = samples.tls_records(samples.client_hello(exts))
    assert record.endswith(sni.encode())
    return record, len(record)


@pytest.mark.parametrize("cut, dropped", [
    (-len("example"), False),  # the datagram ends inside the name
    (-1, False),               # ... one byte before the name ends
    (0, True),                 # ... exactly where the name ends
], ids=["mid-name", "one-short", "at-name-end"])
def test_a_name_is_matched_only_when_the_datagram_holds_all_of_it(lab, lan_attached, cut, dropped):
    """The datagram's end, not the frame's, bounds the name. The rest of
    the hello and MAX_SNI_LEN bytes of padding follow on the wire, so
    the frame itself always holds the whole name: before SEC-7 every case
    here was dropped. A name cut by the datagram's end can't be told from
    a different, shorter name, so it is passed (as no usable server_name),
    never matched on bytes the router doesn't forward."""
    record, name_end = _hello_with_sni_last("www.blocked.example")
    frame = _tcp_frame(record + bytes(xdp.MAX_SNI_LEN), [], lan_attached["dst"], lan_attached["src"],
                       datagram_payload=name_end + cut)
    moved = _counted(lab, frame)
    assert moved["drop_match"] == (1 if dropped else 0)
    if not dropped:
        assert moved["pass_no_sni"] == 1


def test_a_datagram_ending_inside_the_client_hello_is_truncated(lab, lan_attached):
    """Cut before the extensions even start: the hello is incomplete in
    this datagram, which is the truncated case, whatever the frame holds."""
    _, hello = _tls_frame("www.blocked.example", [], lan_attached["dst"], lan_attached["src"])
    frame = _tcp_frame(hello, [], lan_attached["dst"], lan_attached["src"], datagram_payload=60)
    moved = _counted(lab, frame)
    assert moved["drop_match"] == 0
    assert moved["pass_truncated"] == 1


def test_ethernet_padding_after_a_complete_client_hello_changes_nothing(lab, lan_attached):
    """The ordinary case the bound must not break: a whole hello, then
    padding past the datagram."""
    _, hello = _tls_frame("www.blocked.example", [], lan_attached["dst"], lan_attached["src"])
    frame = _tcp_frame(hello + bytes(18), [], lan_attached["dst"], lan_attached["src"],
                       datagram_payload=len(hello))
    assert _counted(lab, frame)["drop_match"] == 1


def test_padding_on_a_pure_ack_does_not_use_up_a_split_hellos_segments(lab, lan_attached):
    """Phase 19 follows a split ClientHello for HELLO_MAX_EXTRA_SEGMENTS
    more segments of its flow. The client's pure ACKs in between carry no
    payload, but a short frame is padded on the wire: read as payload,
    each one used up a segment, and the hello's real second half was
    never copied, so it could not be fingerprinted."""
    import tlsfp_samples as samples

    dst, src, sport = lan_attached["dst"], lan_attached["src"], 40777
    record = samples.tls_records(samples.client_hello(samples.default_extensions(sni="fp.example")))
    first, rest = record[:1000], record[1000:]
    padded_ack = _tcp_frame(bytes(6), [], dst, src, datagram_payload=0, sport=sport)

    segments: list[xdp.HelloSegment] = []
    xdp.set_settings(xdp.SETTING_REPORT_HELLO)
    try:
        with xdp.RingBufferReader(segments.append, xdp.PIN_HELLO_PKTS_PATH,
                                  decode=xdp.HelloSegment.from_bytes) as reader:
            while reader.poll(50) > 0:
                pass
            segments.clear()
            _inject(lab, _tcp_frame(first, [], dst, src, sport=sport))
            for _ in range(3):  # HELLO_MAX_EXTRA_SEGMENTS
                _inject(lab, padded_ack)
            _inject(lab, _tcp_frame(rest, [], dst, src, sport=sport))
            reader.poll(500)
    finally:
        xdp.set_settings(0)
    ours = [s for s in segments if s.sport == sport]
    assert [s.first for s in ours] == [True, False]
    assert ours[1].payload == rest


# --- SEC-20: a short name at the very end of the frame ---------------------
#
# parse_sni_body() used to demand MAX_SNI_LEN readable bytes from the
# name's start, whatever the name's length. A ClientHello whose
# server_name is its last extension, with nothing after it, then failed
# open: any client can send that shape, and browsers that permute their
# extensions send it by chance.


@pytest.mark.parametrize("wire_sni", [
    "blocked.example",          # 15 bytes: 17 short of the old window
    "www.blocked.example",      # 19 bytes
    "WWW.Blocked.Example.",     # normalized after the copy, as before
], ids=["short", "subdomain", "case-and-dot"])
def test_a_blocklisted_name_in_the_last_extension_is_dropped(lab, lan_attached, wire_sni):
    record, name_end = _hello_with_sni_last(wire_sni)
    assert name_end == len(record)  # the frame ends exactly at the name
    frame = _tcp_frame(record, [], lan_attached["dst"], lan_attached["src"])
    moved = _counted(lab, frame)
    assert moved["drop_match"] == 1
    assert moved["pass_no_sni"] == 0


def test_a_frame_that_ends_inside_the_name_is_truncated_not_a_shorter_name(lab, lan_attached):
    """The per-byte copy must not turn a cut name into a different, shorter
    one: 'blocked.example' cut after 'blocked.exam' must not be looked up
    at all. The IP total length still claims the whole hello, so only the
    frame's end stops the copy."""
    record, _ = _hello_with_sni_last("blocked.example")
    frame = _tcp_frame(record[:-3], [], lan_attached["dst"], lan_attached["src"],
                       datagram_payload=len(record))
    moved = _counted(lab, frame)
    assert moved["drop_match"] == 0
    assert moved["pass_no_match"] == 0
    assert moved["pass_truncated"] == 1
