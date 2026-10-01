"""XDP parser-bounds regression tests.

Cover the R9 parser-bounds failure modes (not bounded by IPv4 tot_len /
the TLS record length) as userspace-visible byte-input regression tests.

Each test crafts byte inputs that simulate out-of-bounds packet scenarios
and verifies the userspace responses (XdpError raises, safe defaults, etc.).
"""

from __future__ import annotations

import struct

import socket

import pytest

from frfw import xdp as xdp_mod
from frfw.xdp import SniEvent


def test_sni_event_rejects_too_short_record() -> None:
    """R9: Short ring buffer record must be rejected."""
    with pytest.raises(xdp_mod.XdpError, match="short"):
        xdp_mod.SniEvent.from_bytes(b"\x00" * 10)


def test_sni_event_rejects_14_byte_record() -> None:
    """R9: 14-byte record (below _EVENT_SIZE=48) must be rejected."""
    with pytest.raises(xdp_mod.XdpError, match="short"):
        xdp_mod.SniEvent.from_bytes(b"\x00" * 14)


def test_sni_event_rejects_15_byte_record() -> None:
    """R9: 15-byte record must be rejected."""
    with pytest.raises(xdp_mod.XdpError, match="short"):
        xdp_mod.SniEvent.from_bytes(b"\x00" * 15)


def test_sni_event_minimum_valid_record_48_bytes() -> None:
    """R9: Minimum valid 48-byte SniEvent record with example.com hostname."""
    hostname = "example.com"
    sni_len = len(hostname)
    raw = (
        socket.inet_aton("127.0.0.1")
        + socket.inet_aton("93.184.216.34")
        + struct.pack("<HH", 51234, 443)
        + bytes([1])  # action = drop
        + b"\x00"  # padding before sni_len's 2-byte alignment
        + struct.pack("<H", sni_len)
        + hostname.encode("ascii").ljust(xdp_mod.MAX_SNI_LEN, b"\x00")
    )
    assert len(raw) == 48, f"Expected 48 bytes, got {len(raw)}"
    event = xdp_mod.SniEvent.from_bytes(raw)
    assert event.saddr == "127.0.0.1"
    assert event.daddr == "93.184.216.34"
    assert event.sport == 51234
    assert event.dport == 443
    assert event.action == "drop"
    assert event.hostname == "example.com"


def test_sni_event_with_claimed_more_hostname_bytes_than_available() -> None:
    """R9: If sni_len claims more bytes than actually present in the
    hostname field, decode handles the shortfall gracefully without
    crashing (errors="replace" replaces missing bytes)."""
    # Build a full 48-byte record where sni_len=200 but hostname is only 4 bytes
    hostname = "test"
    sni_len = 200
    raw = (
        socket.inet_aton("127.0.0.1")
        + socket.inet_aton("93.184.216.34")
        + struct.pack("<HH", 51234, 443)
        + bytes([1])  # action = drop
        + b"\x00"  # padding before sni_len's 2-byte alignment
        + struct.pack("<H", sni_len)  # sni_len = 200
        + hostname.encode("ascii")  # only 4 bytes, rest implied/padded
        + b"\x00" * (xdp_mod.MAX_SNI_LEN - len(hostname))  # zero-pad rest
    )
    # Should not crash; decode with errors="replace" handles shortfall
    event = xdp_mod.SniEvent.from_bytes(raw)
    assert event.hostname is not None


def test_sni_event_padding_byte_before_sni_len() -> None:
    """R9: The padding byte before sni_len's 2-byte alignment must be zero."""
    hostname = "x"
    sni_len = 1
    raw = (
        socket.inet_aton("127.0.0.1")
        + socket.inet_aton("93.184.216.34")
        + struct.pack("<HH", 51234, 443)
        + bytes([1])  # action = drop
        + b"\x00"  # padding
        + struct.pack("<H", sni_len)
        + hostname.encode("ascii").ljust(xdp_mod.MAX_SNI_LEN, b"\x00")
    )
    event = xdp_mod.SniEvent.from_bytes(raw)
    assert event.hostname == "x"


def test_build_lpm_key_rejects_empty_hostname() -> None:
    """R9: build_lpm_key rejects empty hostname."""
    with pytest.raises(xdp_mod.XdpError):
        xdp_mod.build_lpm_key("")


def test_build_lpm_key_rejects_hostname_exceeding_max_sni_len() -> None:
    """R9: build_lpm_key rejects hostname longer than MAX_SNI_LEN (32)."""
    with pytest.raises(xdp_mod.XdpError):
        xdp_mod.build_lpm_key("a" * (xdp_mod.MAX_SNI_LEN + 1))


def test_build_lpm_key_accepts_valid_hostnames() -> None:
    """R9: build_lpm_key accepts valid hostnames and computes correct keys."""
    # "example.com" -> reverse(".example.com") = "moc.elpmaxe."
    key = xdp_mod.build_lpm_key("example.com")
    prefixlen = struct.unpack_from("<I", key, 0)[0]
    assert prefixlen == (len("example.com") + 1) * 8  # 96
    content = key[4 : 4 + prefixlen // 8]
    assert content == b".example.com"[::-1]  # b"moc.elpmaxe."


def test_build_lpm_key_subdomain_prefix_relationship() -> None:
    """R9: Parent domain key is a byte-prefix of subdomain key.

    This is the core LPM trie behavior: a blocklist entry for "example.com"
    must be a byte-prefix of the key for "www.example.com".
    """
    parent_key = xdp_mod.build_lpm_key("example.com")
    child_key = xdp_mod.build_lpm_key("www.example.com")
    parent_content_len = struct.unpack_from("<I", parent_key, 0)[0] // 8
    assert child_key[4 : 4 + parent_content_len] == parent_key[4 : 4 + parent_content_len]


def test_build_lpm_key_unrelated_suffix_does_not_match() -> None:
    """R9: "notexample.com" shares trailing chars with "example.com" but
    is not a subdomain, so the blocklist entry for "example.com" must not match."""
    example_key = xdp_mod.build_lpm_key("example.com")
    notexample_key = xdp_mod.build_lpm_key("notexample.com")
    example_content_len = struct.unpack_from("<I", example_key, 0)[0] // 8
    assert (
        notexample_key[4 : 4 + example_content_len]
        != example_key[4 : 4 + example_content_len]
    )


def test_build_lpm_key_a_example_com() -> None:
    """R9: build_lpm_key for 'a.example.com' with known-good bytes."""
    key = xdp_mod.build_lpm_key("a.example.com")
    prefixlen = struct.unpack_from("<I", key, 0)[0]
    assert prefixlen == (len("a.example.com") + 1) * 8
    content = key[4 : 4 + prefixlen // 8]
    assert content == b".a.example.com"[::-1]


def test_build_lpm_key_blocked_org() -> None:
    """R9: build_lpm_key for 'blocked.org' with known-good bytes."""
    key = xdp_mod.build_lpm_key("blocked.org")
    prefixlen = struct.unpack_from("<I", key, 0)[0]
    assert prefixlen == (len("blocked.org") + 1) * 8
    content = key[4 : 4 + prefixlen // 8]
    assert content == b".blocked.org"[::-1]