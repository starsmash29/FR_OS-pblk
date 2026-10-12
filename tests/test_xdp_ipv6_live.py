"""The XDP SNI filter over IPv6 (ROADMAP FND-1d), against real packets in
the lab of test_xdp_live.py: the compiled program on the router's LAN
side, frames injected raw from the client's side.

The container's kernel may have no IPv6 at all; XDP runs before the IP
stack, so the program's verdicts -- its counters, its events, its hello
copies -- are what these tests read, as test_xdp_live.py's injected-frame
tests do. Each test is a flow of its own (its source port), so what the
program remembers of one (a followed split hello, ROADMAP SEC-17) never
reaches another. The boot test routes real IPv6 through it.
"""

from __future__ import annotations

import socket
import struct

import pytest

from test_xdp_live import (  # noqa: F401 -- the fixtures are used by name
    ETH_P_8021AD,
    ETH_P_8021Q,
    _counted,
    _hello_with_sni_last,
    _inject,
    _ipv4_checksum,
    _skip_reason,
    _tls_frame,
    lab,
    lan_attached,
)
from frfw import xdp

pytestmark = pytest.mark.skipif(_skip_reason() is not None, reason=str(_skip_reason()))

ETH_P_IPV6 = 0x86DD
CLIENT_IP6, SERVER_IP6 = "fd81:1::10", "fd81:2::10"
HOP, ROUTING, FRAGMENT, DEST, TCP, UDP = 0, 43, 44, 60, 6, 17


def _tcp6(payload: bytes, *, sport: int, seq: int = 1000, flags: int = 0x18, bad_checksum: bool = False,
          src: str = CLIENT_IP6) -> bytes:
    """A TCP segment to SERVER_IP6:443, its checksum over the IPv6
    pseudo-header (RFC 8200 8.1)."""
    tcp = struct.pack("!HHIIBBHHH", sport, 443, seq, 0, 5 << 4, flags, 64240, 0, 0)
    pseudo = (socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, SERVER_IP6)
              + struct.pack("!I3xB", len(tcp) + len(payload), TCP))
    checksum = _ipv4_checksum(pseudo + tcp + payload) ^ (0xFFFF if bad_checksum else 0)
    return tcp[:16] + struct.pack("!H", checksum) + tcp[18:] + payload


def _options(nh: int, size: int = 8) -> bytes:
    """A hop-by-hop or destination options header of `size` bytes, a PadN
    option filling it."""
    return bytes([nh, size // 8 - 1, 1, size - 4]) + bytes(size - 4)


def _routing(nh: int) -> bytes:
    """A routing header with no segments left: the server skips it."""
    return bytes([nh, 0, 0, 0]) + bytes(4)


def _fragment(nh: int, offset: int = 0, more: bool = True, ident: int = 0x1D2) -> bytes:
    return struct.pack("!BBHI", nh, 0, (offset // 8) << 3 | int(more), ident)


def _frame(lan, upper: bytes, chain: list[int], *, tags: list[tuple[int, int]] = (), src: str = CLIENT_IP6,
           dst: str = SERVER_IP6, datagram: int | None = None, trailer: bytes = b"",
           fragment: tuple[int, bool] | None = None) -> bytes:
    """An Ethernet frame carrying an IPv6 datagram: the extension headers
    in `chain` (HOP, ROUTING, DEST, FRAGMENT), then `upper`, whose
    protocol is the last element's next header -- TCP, or UDP when
    `upper` is a UDP datagram. `datagram` overrides the payload length
    the header claims; `trailer` goes on the wire after it (SEC-7)."""
    protocols = [*chain, UDP if upper[2:4] == b"\x00\x09" else TCP]
    headers = b""
    for kind, after in zip(chain, protocols[1:]):
        if kind == ROUTING:
            headers += _routing(after)
        elif kind == FRAGMENT:
            offset, more = fragment or (0, True)
            headers += _fragment(after, offset, more)
        else:
            headers += _options(after)
    body = headers + upper
    length = len(body) if datagram is None else datagram
    ip = (struct.pack("!IHBB", 6 << 28, length, protocols[0], 64)
          + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst))
    ethertypes = [tpid for tpid, _ in tags] + [ETH_P_IPV6]
    frame = lan["dst"] + lan["src"] + ethertypes[0].to_bytes(2, "big")
    for (_, vid), inner in zip(tags, ethertypes[1:]):
        frame += vid.to_bytes(2, "big") + inner.to_bytes(2, "big")
    return frame + ip + body + trailer


def _hello(sni: str) -> bytes:
    import tlsfp_samples as samples

    return samples.tls_records(samples.client_hello(samples.default_extensions(sni=sni, pq=False)))


# --- the ordinary case ---------------------------------------------------------


@pytest.mark.parametrize("tags", [[], [(ETH_P_8021Q, 30)], [(ETH_P_8021AD, 100), (ETH_P_8021Q, 30)]],
                         ids=["untagged", "802.1q", "qinq"])
def test_a_blocklisted_name_over_ipv6_is_dropped_and_reported(lab, lan_attached, tags):
    events: list[xdp.SniEvent] = []
    with xdp.RingBufferReader(events.append) as reader:
        while reader.poll(50) > 0:
            pass
        events.clear()
        moved = _counted(lab, _frame(lan_attached, _tcp6(_hello("www.blocked.example"), sport=43100 + len(tags)), [],
                                     tags=tags))
        reader.poll(500)
    assert moved["drop_match"] == 1, moved
    drops = [e for e in events if e.action == "drop"]
    assert drops and (drops[0].saddr, drops[0].daddr, drops[0].dport, drops[0].hostname) == (
        CLIENT_IP6, SERVER_IP6, 443, "www.blocked.example")


def test_an_allowed_name_over_ipv6_is_parsed_and_passed(lab, lan_attached):
    moved = _counted(lab, _frame(lan_attached, _tcp6(_hello("www.allowed.example"), sport=43002), []))
    assert moved["pass_no_match"] == 1 and moved["drop_match"] == 0, moved


def test_the_same_name_over_ipv4_and_ipv6_is_the_same_verdict(lab, lan_attached):
    """One blocklist for both families."""
    frame4, _ = _tls_frame("Blocked.Example.", [], lan_attached["dst"], lan_attached["src"])
    assert _counted(lab, frame4)["drop_match"] == 1
    frame6 = _frame(lan_attached, _tcp6(_hello("Blocked.Example."), sport=43003), [])
    assert _counted(lab, frame6)["drop_match"] == 1


def test_a_hello_after_the_end_of_the_ipv6_datagram_is_not_parsed(lab, lan_attached):
    """SEC-7 over IPv6: the payload length, not the frame, ends the
    datagram. A segment with no payload, a hello on the wire after it."""
    segment = _tcp6(b"", sport=43004)
    frame = _frame(lan_attached, segment, [], trailer=_hello("www.blocked.example"))
    moved = _counted(lab, frame)
    assert moved["drop_match"] == 0 and moved["pass_not_tls"] == 1, moved


def test_hello_copies_over_ipv6_carry_ipv6_addresses(lab, lan_attached):
    segments: list[xdp.HelloSegment] = []
    record = _hello("fp.example")
    xdp.set_settings(xdp.SETTING_REPORT_HELLO)
    try:
        with xdp.RingBufferReader(segments.append, xdp.PIN_HELLO_PKTS_PATH,
                                  decode=xdp.HelloSegment.from_bytes) as reader:
            while reader.poll(50) > 0:
                pass
            segments.clear()
            _inject(lab, _frame(lan_attached, _tcp6(record, sport=43005), [(DEST)]))
            reader.poll(500)
    finally:
        xdp.set_settings(0)
    assert len(segments) == 1 and segments[0].first
    assert (segments[0].saddr, segments[0].daddr, segments[0].dport) == (CLIENT_IP6, SERVER_IP6, 443)
    assert segments[0].payload == record[:len(segments[0].payload)]


# --- extension headers ---------------------------------------------------------


@pytest.mark.parametrize("chain", [[HOP], [DEST], [ROUTING], [HOP, DEST, ROUTING, DEST]],
                         ids=["hop-by-hop", "destination", "routing", "four"])
def test_a_hello_behind_extension_headers_is_still_read(lab, lan_attached, chain):
    """A server skips these headers, so a client could hide its hello
    behind them; the program walks up to four."""
    moved = _counted(lab, _frame(lan_attached, _tcp6(_hello("www.blocked.example"), sport=43010 + len(chain)),
                                 chain))
    assert moved["drop_match"] == 1, moved


def test_more_extension_headers_than_are_walked_are_dropped(lab, lan_attached):
    """Five: no LAN host sends that, so it is dropped, not passed unread --
    and so is a deeper chain whose upper layer isn't TCP at all."""
    chain = [HOP, DEST, ROUTING, DEST, DEST]
    moved = _counted(lab, _frame(lan_attached, _tcp6(_hello("www.allowed.example"), sport=43020), chain))
    assert moved["drop_ipv6_headers"] == 1 and moved["pass_no_match"] == 0, moved


def test_an_ipv4_mapped_address_is_dropped(lab, lan_attached):
    """Never valid on the wire (RFC 4291 2.5.5.2), and the program tells an
    IPv4 flow by that prefix."""
    moved = _counted(lab, _frame(lan_attached, _tcp6(_hello("www.allowed.example"), sport=43021,
                                                     src="::ffff:10.81.1.10"), [], src="::ffff:10.81.1.10"))
    assert moved["drop_ipv6_headers"] == 1, moved


# --- fragments (H2 over IPv6) ----------------------------------------------------


@pytest.mark.parametrize("offset, more", [(0, True), (24, False), (0, False)],
                         ids=["first", "later", "atomic"])
def test_a_tcp_fragment_over_ipv6_is_dropped(lab, lan_attached, offset, more):
    """Every fragment of a TCP datagram names TCP as what follows the
    fragment header, the later ones too; and an atomic fragment
    (RFC 6946) is one a LAN host's TCP never sends either."""
    segment = _tcp6(_hello("www.blocked.example"), sport=43030 + offset + more)
    moved = _counted(lab, _frame(lan_attached, segment[:24] if more else segment[24:], [FRAGMENT],
                                 fragment=(offset, more)))
    assert moved["drop_fragment"] == 1 and moved["drop_match"] == 0, moved


def test_a_fragment_behind_a_destination_header_is_dropped_too(lab, lan_attached):
    moved = _counted(lab, _frame(lan_attached, _tcp6(b"\x16\x03\x01", sport=43040), [HOP, FRAGMENT]))
    assert moved["drop_fragment"] == 1, moved


def test_a_udp_fragment_over_ipv6_is_left_alone(lab, lan_attached):
    udp = struct.pack("!HHHH", 43041, 9, 8 + 32, 0) + bytes(32)
    moved = _counted(lab, _frame(lan_attached, udp[:24], [FRAGMENT]))
    assert moved["drop_fragment"] == 0 and sum(moved.values()) == 0, moved


# --- a split hello over IPv6 (SEC-17, SEC-24, SEC-28) ---------------------------


def _first_and_rest(name: str, sport: int, lan, *, base: int = 5000) -> tuple[bytes, bytes, bytes]:
    """A hello whose name is its last bytes, as two segments: the first
    holds no name. Returns (first, rest, rest-with-a-bad-checksum)."""
    record, end = _hello_with_sni_last(name)
    cut = end - 30
    first = _frame(lan, _tcp6(record[:cut], sport=sport, seq=base), [])
    rest = _tcp6(record[cut:], sport=sport, seq=base + cut)
    bad = _tcp6(record[cut:], sport=sport, seq=base + cut, bad_checksum=True)
    return first, _frame(lan, rest, []), _frame(lan, bad, [])


@pytest.mark.parametrize("name, verdict", [("www.blocked.example", "drop_match"),
                                           ("www.allowed.example", "pass_no_match")])
def test_a_split_hello_over_ipv6_is_followed_to_its_name(lab, lan_attached, name, verdict):
    first, rest, _ = _first_and_rest(name, 43050 + len(verdict), lan_attached)
    assert _counted(lab, first)["pass_truncated"] == 1
    assert _counted(lab, rest)[verdict] == 1


def test_a_followed_segment_with_a_bad_ipv6_checksum_is_dropped_unread(lab, lan_attached):
    """The checksum over IPv6's pseudo-header: the right one is read (the
    test above), a wrong one dropped, and the walk's state kept for the
    right one that follows."""
    first, rest, bad = _first_and_rest("www.blocked.example", 43090, lan_attached)
    _counted(lab, first)
    moved = _counted(lab, bad)
    assert moved["drop_bad_checksum"] == 1 and moved["drop_match"] == 0, moved
    assert _counted(lab, rest)["drop_match"] == 1


def test_a_segment_ahead_of_the_walk_over_ipv6_waits(lab, lan_attached):
    record, end = _hello_with_sni_last("www.blocked.example")
    cut1, cut2, sport, base = end - 30, end - 3, 43070, 7000
    _counted(lab, _frame(lan_attached, _tcp6(record[:cut1], sport=sport, seq=base), []))
    early = _counted(lab, _frame(lan_attached, _tcp6(record[cut2:], sport=sport, seq=base + cut2), []))
    assert early["drop_reordered"] == 1 and early["drop_match"] == 0, early
    _counted(lab, _frame(lan_attached, _tcp6(record[cut1:cut2], sport=sport, seq=base + cut1), []))
    assert _counted(lab, _frame(lan_attached, _tcp6(record[cut2:], sport=sport, seq=base + cut2), []))[
        "drop_match"] == 1
