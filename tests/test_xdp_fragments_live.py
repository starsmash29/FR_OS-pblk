"""The XDP SNI filter against IP fragments (ROADMAP FND-1d, H2), with
real packets in real network namespaces (the lab of test_xdp_live.py).

RFC 1858's "tiny fragment": a client cuts its IPv4 datagram so that the
first fragment holds the TCP header and only the first bytes of the TLS
record, and the second fragment the rest. The filter saw neither as a
ClientHello and passed both; the server's kernel put the datagram back
together, and the hello for a blocked name arrived whole. A LAN host's
TCP never fragments on its own (it sends with DF, segments by MSS), so
the filter now drops a TCP fragment on the ports it runs on, and counts
it (`drop_fragment`).

The frames go in raw from the client's side, as in test_xdp_live.py;
what reached the server is read off the server's own reassembly counter.
"""

from __future__ import annotations

import socket
import struct
import subprocess

import pytest

from test_xdp_live import (  # noqa: F401 -- the fixtures are used by name
    CLIENT_IP,
    SERVER_IP,
    SERVER_NS,
    _counted,
    _hello_with_sni_last,
    _ipv4_checksum,
    _skip_reason,
    lab,
    lan_attached,
)

pytestmark = pytest.mark.skipif(_skip_reason() is not None, reason=str(_skip_reason()))

ETH_P_IP = 0x0800
IP_MF = 0x2000


def _snmp(ns: str, name: str) -> int:
    snmp = subprocess.run(["ip", "netns", "exec", ns, "cat", "/proc/net/snmp"],
                          check=True, capture_output=True, text=True).stdout.splitlines()
    names, values = [line.split() for line in snmp if line.startswith("Ip:")][:2]
    return int(values[names.index(name)])


def _tcp_segment(payload: bytes, *, sport: int, seq: int = 1000) -> bytes:
    """A TCP segment to SERVER_IP:443 with a right checksum."""
    tcp = struct.pack("!HHIIBBHHH", sport, 443, seq, 0, 5 << 4, 0x18, 64240, 0, 0)
    pseudo = socket.inet_aton(CLIENT_IP) + socket.inet_aton(SERVER_IP) + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    checksum = _ipv4_checksum(pseudo + tcp + payload)
    return tcp[:16] + struct.pack("!H", checksum) + tcp[18:] + payload


def _ipv4_fragments(segment: bytes, cuts: list[int], lan, *, ident: int) -> list[bytes]:
    """The datagram carrying `segment`, cut at `cuts` (multiples of 8,
    in bytes of the IP payload), one Ethernet frame per fragment."""
    bounds = [0, *cuts, len(segment)]
    frames = []
    for start, end in zip(bounds, bounds[1:]):
        flags = (IP_MF if end < len(segment) else 0) | (start // 8)
        ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + end - start, ident, flags, 64, 6, 0,
                                   socket.inet_aton(CLIENT_IP), socket.inet_aton(SERVER_IP)))
        ip[10:12] = _ipv4_checksum(bytes(ip)).to_bytes(2, "big")
        frames.append(lan["dst"] + lan["src"] + ETH_P_IP.to_bytes(2, "big") + bytes(ip) + segment[start:end])
    return frames


def _send_fragments(lab, frames: list[bytes]) -> tuple[dict[str, int], int]:
    """Inject the fragments in order; returns how much the filter's
    counters moved, and how many datagrams the server put back together."""
    before = _snmp(SERVER_NS, "ReasmOKs")
    moved: dict[str, int] = {}
    for frame in frames:
        for name, value in _counted(lab, frame).items():
            moved[name] = moved.get(name, 0) + value
    return moved, _snmp(SERVER_NS, "ReasmOKs") - before


@pytest.mark.parametrize("cut", [24, 8], ids=["tcp-header-and-4-bytes", "tiny-8-bytes-ports-only"])
def test_a_client_hello_cut_into_fragments_never_reaches_the_server(lab, lan_attached, cut):
    """H2: the first fragment holds the TCP header and at most the record's
    first bytes (or, RFC 1858's tiniest, only the ports), the second the
    rest of the hello for a blocked name. Before the fix the filter passed
    both and the server reassembled the hello."""
    record, _ = _hello_with_sni_last("www.blocked.example")
    frames = _ipv4_fragments(_tcp_segment(record, sport=42001 + cut), [cut], lan_attached, ident=0x4200 + cut)
    moved, reassembled = _send_fragments(lab, frames)
    assert reassembled == 0, f"the server put the hello together: {moved}"
    assert moved["drop_fragment"] == 2 and moved["drop_match"] == 0, moved


def test_fragments_the_other_way_round_are_dropped_too(lab, lan_attached):
    """The last fragment first: the order a sender picks changes nothing."""
    record, _ = _hello_with_sni_last("www.blocked.example")
    frames = _ipv4_fragments(_tcp_segment(record, sport=42101), [24], lan_attached, ident=0x4300)
    moved, reassembled = _send_fragments(lab, frames[::-1])
    assert reassembled == 0 and moved["drop_fragment"] == 2, moved


def test_a_whole_client_hello_with_df_is_parsed_as_before(lab, lan_attached):
    """The ordinary case, one datagram with DF, is untouched: an allowed
    name is parsed and passed, and reaches the server's IP layer."""
    record, _ = _hello_with_sni_last("www.allowed.example")
    segment = _tcp_segment(record, sport=42201)
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0x4400, 0x4000, 64, 6, 0,
                               socket.inet_aton(CLIENT_IP), socket.inet_aton(SERVER_IP)))
    ip[10:12] = _ipv4_checksum(bytes(ip)).to_bytes(2, "big")
    frame = lan_attached["dst"] + lan_attached["src"] + ETH_P_IP.to_bytes(2, "big") + bytes(ip) + segment
    moved = _counted(lab, frame)
    assert moved["pass_no_match"] == 1 and moved["drop_fragment"] == 0, moved


def test_fragments_of_another_protocol_are_left_alone(lab, lan_attached):
    """Only TCP: a fragmented UDP datagram (a large DNS answer, say) is
    none of the filter's business and goes through, reassembled by the
    server."""
    body = b"x" * 64
    udp = struct.pack("!HHHH", 42301, 9, 8 + len(body), 0) + body
    frames = []
    bounds = [0, 32, len(udp)]
    for start, end in zip(bounds, bounds[1:]):
        flags = (IP_MF if end < len(udp) else 0) | (start // 8)
        ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + end - start, 0x4500, flags, 64, 17, 0,
                                   socket.inet_aton(CLIENT_IP), socket.inet_aton(SERVER_IP)))
        ip[10:12] = _ipv4_checksum(bytes(ip)).to_bytes(2, "big")
        frames.append(lan_attached["dst"] + lan_attached["src"] + ETH_P_IP.to_bytes(2, "big") + bytes(ip)
                      + udp[start:end])
    moved, reassembled = _send_fragments(lab, frames)
    assert reassembled == 1 and moved["drop_fragment"] == 0, moved
