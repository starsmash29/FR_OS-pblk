"""Tests for frfw.iot.mdns: query encoding, the bounded response parser
(fed deliberately hostile packets too), and a real UDP round trip
against an in-process responder."""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from frfw.iot import mdns


def _name(n: str) -> bytes:
    return b"".join(bytes([len(l)]) + l.encode() for l in n.split(".")) + b"\x00"


def _response(answers: list[tuple[str, int, bytes]], *, qid: int = 0x1234, question: bool = True) -> bytes:
    body = _name(mdns.SERVICES_META_QUERY) + struct.pack("!HH", 12, 1) if question else b""
    rr = b""
    for owner, rtype, rdata in answers:
        rr += _name(owner) + struct.pack("!HHIH", rtype, 1, 10, len(rdata)) + rdata
    header = struct.pack("!HHHHHH", qid, 0x8400, 1 if question else 0, len(answers), 0, 0)
    return header + body + rr


def test_build_query_is_a_single_ptr_question():
    q = mdns.build_query(query_id=7)
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", q[:12])
    assert (qid, flags, qd, an, ns, ar) == (7, 0, 1, 0, 0, 0)
    assert q[12:] == _name("_services._dns-sd._udp.local") + struct.pack("!HH", 12, 1)


def test_parse_meta_ptr_answers():
    packet = _response(
        [
            (mdns.SERVICES_META_QUERY, 12, _name("_hap._tcp.local")),
            (mdns.SERVICES_META_QUERY, 12, _name("_googlecast._tcp.local")),
            ("printer.local", 1, b"\x0a\x00\x00\x05"),  # an A record, ignored
        ]
    )
    assert mdns.parse_services(packet) == {"_hap._tcp", "_googlecast._tcp"}


def test_parse_instance_ptr_owner_is_the_service_type():
    packet = _response([("_ipp._tcp.local", 12, _name("Office Printer._ipp._tcp.local"))])
    assert mdns.parse_services(packet) == {"_ipp._tcp"}


def test_parse_follows_compression_pointers():
    # Answer owner is a pointer back to the question name at offset 12,
    # and the rdata ends with a pointer to that name's "local" label.
    question = _name(mdns.SERVICES_META_QUERY)
    local_offset = 12 + len(question) - len(_name("local"))
    rdata = bytes([4]) + b"_hap" + bytes([4]) + b"_tcp" + struct.pack("!H", 0xC000 | local_offset)
    answer = struct.pack("!H", 0xC000 | 12) + struct.pack("!HHIH", 12, 1, 10, len(rdata)) + rdata
    packet = struct.pack("!HHHHHH", 1, 0x8400, 1, 1, 0, 0) + question + struct.pack("!HH", 12, 1) + answer
    assert mdns.parse_services(packet) == {"_hap._tcp"}


def test_parse_rejects_pointer_loop_without_hanging():
    # A name that is just a pointer to itself.
    header = struct.pack("!HHHHHH", 1, 0x8400, 0, 1, 0, 0)
    loop = struct.pack("!H", 0xC000 | 12)
    packet = header + loop + struct.pack("!HHIH", 12, 1, 10, 0)
    assert mdns.parse_services(packet) == set()


@pytest.mark.parametrize(
    "packet",
    [
        b"",
        b"\x00" * 11,
        struct.pack("!HHHHHH", 1, 0x8400, 0, 1, 0, 0) + b"\x3f",  # label runs past end
        struct.pack("!HHHHHH", 1, 0x8400, 0, 5000, 0, 0),  # absurd record count
        struct.pack("!HHHHHH", 1, 0x8400, 0, 1, 0, 0) + _name("x.local") + b"\x00\x0c",  # truncated RR
    ],
)
def test_parse_malformed_packets_return_empty(packet):
    assert mdns.parse_services(packet) == set()


def test_parse_ignores_queries_and_non_service_names():
    query = mdns.build_query()
    assert mdns.parse_services(query) == set()
    packet = _response([(mdns.SERVICES_META_QUERY, 12, _name("not a service.local"))])
    assert mdns.parse_services(packet) == set()


class _Responder:
    """A tiny in-process stand-in for a device's mDNS responder: answers
    whatever arrives with a fixed service list, from its own port -- the
    discover() side is pointed at it as a unicast target."""

    def __init__(self, services: list[str]):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.services = services
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        self.sock.settimeout(3)
        try:
            data, addr = self.sock.recvfrom(9000)
        except OSError:
            return
        qid = struct.unpack("!H", data[:2])[0]
        answers = [(mdns.SERVICES_META_QUERY, 12, _name(f"{s}.local")) for s in self.services]
        self.sock.sendto(_response(answers, qid=qid), addr)

    def close(self):
        self.sock.close()


def test_discover_real_udp_round_trip():
    responder = _Responder(["_hap._tcp", "_shelly._tcp"])
    try:
        # "127.0.0.2" as our own interface address, so the loopback reply
        # from 127.0.0.1 isn't discarded as the router's own answer.
        result = mdns.discover(
            ["127.0.0.2"], timeout=1.0, target=("127.0.0.1", responder.port), bind_port=0
        )
    finally:
        responder.close()
    assert result == {"127.0.0.1": {"_hap._tcp", "_shelly._tcp"}}


def test_discover_ignores_the_routers_own_answers():
    responder = _Responder(["_hap._tcp"])
    try:
        result = mdns.discover(
            ["127.0.0.1"], timeout=1.0, target=("127.0.0.1", responder.port), bind_port=0
        )
    finally:
        responder.close()
    assert result == {}


def test_discover_with_no_interfaces_sends_nothing():
    assert mdns.discover([], timeout=0.1) == {}


def test_discover_reports_port_in_use():
    blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    blocker.bind(("0.0.0.0", 0))
    port = blocker.getsockname()[1]
    try:
        with pytest.raises(mdns.MdnsError, match="another IoT scan"):
            mdns.discover(["127.0.0.1"], timeout=0.1, bind_port=port)
    finally:
        blocker.close()
