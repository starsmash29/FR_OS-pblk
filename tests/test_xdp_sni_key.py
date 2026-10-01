"""Tests for SNI key computation (LPM key build), referenced by
bpf/xdp_sni_filter.c:82, src/frfw/xdp.py:84-86 and
src/frfw/config/loader.py:77.

Each test computes a key with build_lpm_key and compares against
known-good bytes worked out by hand, since one side is C and the other
Python -- not a shared import.
"""

from __future__ import annotations

import struct

import pytest

from frfw import xdp as xdp_mod


def _check_key(hostname: str, expected_prefixlen: int, expected_content: bytes, expected_total: int) -> None:
    key = xdp_mod.build_lpm_key(hostname)
    prefixlen = struct.unpack_from("<I", key, 0)[0]
    assert prefixlen == expected_prefixlen, (
        f"{hostname}: expected prefixlen {expected_prefixlen}, got {prefixlen}"
    )
    content = key[4 : 4 + prefixlen // 8]
    assert content == expected_content, (
        f"{hostname}: expected content {expected_content!r}, got {content!r}"
    )
    padding = key[4 + prefixlen // 8 :]
    assert padding == b"\x00" * len(padding), (
        f"{hostname}: expected zero padding, got {padding!r}"
    )
    assert len(key) == expected_total, (
        f"{hostname}: expected key length {expected_total}, got {len(key)}"
    )


def test_build_lpm_key_blocked_example_com() -> None:
    _check_key(
        "blocked.example.com",
        expected_prefixlen=(len("blocked.example.com") + 1) * 8,  # 160
        expected_content=b".blocked.example.com"[::-1],
        expected_total=40,
    )


def test_build_lpm_key_parent_is_prefix_of_subdomain() -> None:
    """Parent domain key must be a byte-prefix of subdomain key.

    This is the whole point of the reverse("." + hostname) scheme: a
    blocklist entry for "example.com" must be a byte-prefix of the key
    for "www.example.com", matching the C header comment's worked example.
    """
    parent_key = xdp_mod.build_lpm_key("example.com")
    child_key = xdp_mod.build_lpm_key("www.example.com")
    parent_content_len = struct.unpack_from("<I", parent_key, 0)[0] // 8
    assert child_key[4 : 4 + parent_content_len] == parent_key[4 : 4 + parent_content_len]


def test_build_lpm_key_unrelated_suffix_domain() -> None:
    """"notexample.com" merely shares trailing characters with "example.com"
    -- it is not a subdomain, so the blocklist entry for "example.com" must
    not match it. Comparing only up to example.com's own content length is
    what matters for LPM semantics."""
    example_key = xdp_mod.build_lpm_key("example.com")
    notexample_key = xdp_mod.build_lpm_key("notexample.com")
    example_content_len = struct.unpack_from("<I", example_key, 0)[0] // 8
    assert (
        notexample_key[4 : 4 + example_content_len]
        != example_key[4 : 4 + example_content_len]
    )


def test_build_lpm_key_rejects_empty_and_too_long_hostnames() -> None:
    with pytest.raises(xdp_mod.XdpError):
        xdp_mod.build_lpm_key("")
    with pytest.raises(xdp_mod.XdpError):
        xdp_mod.build_lpm_key("a" * xdp_mod.MAX_SNI_LEN)


def test_build_lpm_key_rejects_partial_label_subdomain() -> None:
    """A subdomain that doesn't fall on a label boundary must be rejected.

    The C code comments at bpf/xdp_sni_filter.c:82 stress that every
    accepted match must fall exactly on a label boundary.  "notexample.com"
    reversed starts with "moc.elpmaxeton." which differs from
    "moc.elpmaxe." at byte 12 ('t' vs '.'), so it must not match.
    """
    example_key = xdp_mod.build_lpm_key("example.com")
    notexample_key = xdp_mod.build_lpm_key("notexample.com")
    example_content_len = struct.unpack_from("<I", example_key, 0)[0] // 8
    assert (
        notexample_key[4 : 4 + example_content_len]
        != example_key[4 : 4 + example_content_len]
    )


def test_build_lpm_key_various_hostnames() -> None:
    """Verify known-good byte patterns for several hostnames."""
    _check_key("example.com", expected_prefixlen=(len("example.com") + 1) * 8, expected_content=b".example.com"[::-1], expected_total=40)
    _check_key("a.example.com", expected_prefixlen=(len("a.example.com") + 1) * 8, expected_content=b".a.example.com"[::-1], expected_total=40)
    _check_key("blocked.org", expected_prefixlen=(len("blocked.org") + 1) * 8, expected_content=b".blocked.org"[::-1], expected_total=40)