"""One-shot mDNS service discovery (RFC 6762 / RFC 6763), stdlib only.

Sends a single `_services._dns-sd._udp.local PTR` query to
224.0.0.251:5353 on each IoT-zone interface and collects, for a couple
of seconds, which service types each responding host advertises
(`_hap._tcp` = HomeKit accessory, `_googlecast._tcp` = Chromecast, ...).
That service list is one of frfw.iot.classify's strongest signals.

The query deliberately goes out from a fixed, non-5353 source port
(frfw.nft.builder.IOT_MDNS_REPLY_PORT): RFC 6762 section 6.7 makes that
a "legacy unicast" query, which responders answer by unicast straight
back to the querier's port. So nothing ever has to listen on 5353 (no
clash with an avahi-daemon on the same box), and the firewall needs one
narrow input accept rule instead of opening the mDNS port.

Everything in a response is untrusted LAN input. The parser below is
bounded everywhere it could loop or allocate: label and name lengths
(63/255 bytes, the DNS maximums), a cap on compression-pointer jumps
(so a pointer loop can't spin forever), a cap on records per packet and
on packets per scan, and only names that look like a DNS-SD service
type (`_name._tcp` / `_name._udp`) are ever kept.
"""

from __future__ import annotations

import random
import re
import socket
import struct
import time

from frfw.nft.builder import IOT_MDNS_REPLY_PORT

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
SERVICES_META_QUERY = "_services._dns-sd._udp.local"

_TYPE_PTR = 12
_CLASS_IN = 1
_MAX_LABEL = 63
_MAX_NAME = 255
_MAX_POINTER_JUMPS = 32
_MAX_RECORDS = 256
_MAX_PACKET = 9000
_MAX_SERVICES_PER_HOST = 64

_SERVICE_TYPE_RE = re.compile(r"^_[a-z0-9][a-z0-9-]{0,62}\._(tcp|udp)$")


class MdnsError(Exception):
    pass


class _ParseError(Exception):
    pass


def build_query(name: str = SERVICES_META_QUERY, query_id: int | None = None) -> bytes:
    query_id = random.randrange(0, 0x10000) if query_id is None else query_id
    header = struct.pack("!HHHHHH", query_id, 0, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack("!HH", _TYPE_PTR, _CLASS_IN)


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not raw or len(raw) > _MAX_LABEL:
            raise ValueError(f"invalid DNS label {label!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Returns (name, offset just past the name *at its original
    position* -- i.e. after the first pointer if the name is compressed)."""
    labels: list[str] = []
    total = 0
    jumps = 0
    end_offset: int | None = None
    pos = offset
    while True:
        if pos >= len(packet):
            raise _ParseError("name runs past end of packet")
        length = packet[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(packet):
                raise _ParseError("truncated compression pointer")
            jumps += 1
            if jumps > _MAX_POINTER_JUMPS:
                raise _ParseError("too many compression pointers")
            if end_offset is None:
                end_offset = pos + 2
            pos = ((length & 0x3F) << 8) | packet[pos + 1]
            continue
        if length & 0xC0:
            raise _ParseError("unsupported label type")
        pos += 1
        if length == 0:
            break
        if pos + length > len(packet):
            raise _ParseError("label runs past end of packet")
        total += length + 1
        if total > _MAX_NAME:
            raise _ParseError("name too long")
        labels.append(packet[pos:pos + length].decode("ascii", errors="replace"))
        pos += length
    return ".".join(labels), (end_offset if end_offset is not None else pos)


def _strip_local(name: str) -> str:
    name = name.lower()
    return name[: -len(".local")] if name.endswith(".local") else name


def parse_services(packet: bytes) -> set[str]:
    """DNS-SD service types advertised in one mDNS response packet.
    Returns an empty set (never raises) for anything malformed."""
    try:
        return _parse_services(packet)
    except (_ParseError, struct.error):
        return set()


def _parse_services(packet: bytes) -> set[str]:
    if len(packet) < 12:
        raise _ParseError("short header")
    _id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    if not flags & 0x8000:
        return set()  # a query, not a response
    if qdcount + ancount + nscount + arcount > _MAX_RECORDS:
        raise _ParseError("too many records")

    offset = 12
    for _ in range(qdcount):
        _name, offset = _decode_name(packet, offset)
        offset += 4

    meta = SERVICES_META_QUERY
    services: set[str] = set()
    for _ in range(ancount + nscount + arcount):
        owner, offset = _decode_name(packet, offset)
        if offset + 10 > len(packet):
            raise _ParseError("truncated resource record")
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        rdata_offset = offset
        offset += rdlength
        if offset > len(packet):
            raise _ParseError("rdata runs past end of packet")
        if rtype != _TYPE_PTR:
            continue
        owner_l = owner.lower()
        if owner_l == meta:
            target, _ = _decode_name(packet, rdata_offset)
            candidate = _strip_local(target)
        else:
            # Instance enumeration ("<name>._hap._tcp.local PTR ...") --
            # the owner itself is the service type.
            candidate = _strip_local(owner_l)
        if _SERVICE_TYPE_RE.match(candidate):
            services.add(candidate)
    return services


def discover(
    interface_addresses: list[str],
    *,
    timeout: float = 2.0,
    target: tuple[str, int] = (MDNS_GROUP, MDNS_PORT),
    bind_port: int = IOT_MDNS_REPLY_PORT,
    max_packets: int = 512,
) -> dict[str, set[str]]:
    """{responder IPv4 -> service types} for everything that answered
    within `timeout`. `interface_addresses` are the router's own IPv4
    addresses on the IoT zones' interfaces; the query is sent once out
    of each (IP_MULTICAST_IF). The router's own answers (e.g. from a
    local avahi-daemon) are ignored."""
    results: dict[str, set[str]] = {}
    if not interface_addresses:
        return results
    query = build_query()
    own = set(interface_addresses)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as exc:
        raise MdnsError(f"cannot create UDP socket: {exc}") from exc
    with sock:
        try:
            sock.bind(("0.0.0.0", bind_port))
        except OSError as exc:
            raise MdnsError(
                f"cannot bind UDP port {bind_port} ({exc}) -- is another IoT scan already running?"
            ) from exc
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sent = 0
        for address in interface_addresses:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(address))
                sock.sendto(query, target)
                sent += 1
            except OSError:
                continue
        if not sent:
            return results

        deadline = time.monotonic() + timeout
        for _ in range(max_packets):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, (src_ip, src_port) = sock.recvfrom(_MAX_PACKET)
            except (socket.timeout, TimeoutError):
                break
            except OSError:
                break
            if src_port != target[1] or src_ip in own:
                continue
            found = parse_services(data)
            if found:
                bucket = results.setdefault(src_ip, set())
                for service in sorted(found):
                    if len(bucket) >= _MAX_SERVICES_PER_HOST:
                        break
                    bucket.add(service)
    return results
