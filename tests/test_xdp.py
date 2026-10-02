"""Tests for frfw.xdp. All `ip`/`bpftool` subprocess calls are
monkeypatched throughout -- a real, non-mocked round trip (compiling
bpf/xdp_sni_filter.c, loading and pinning it, attaching to `lo`,
populating the blocklist, sending a real crafted TLS ClientHello over
loopback and confirming both the drop and the ring buffer event) was
done manually during development; see this module's session notes for
the exact commands. Reproducing that here would need a container with
CAP_BPF/CAP_NET_ADMIN and a matching kernel/clang/bpftool, which is not
this sandbox's normal test environment.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import subprocess

import pytest

from frfw import paths
from frfw import xdp as xdp_mod
from frfw.config.schema import Config, Interface, NatConfig, XdpSniFilterConfig, Zone


def _config(*, enabled=False, interfaces=None, blocklist=None) -> Config:
    return Config(
        version=1,
        hostname="r",
        interfaces={
            "wan": Interface(name="wan", device="eth0", zone="wan"),
            "lan": Interface(name="lan", device="eth1", zone="lan"),
        },
        zones={"wan": Zone(name="wan"), "lan": Zone(name="lan")},
        rules=[],
        nat=NatConfig(),
        xdp_sni_filter=XdpSniFilterConfig(
            enabled=enabled,
            interfaces=interfaces or [],
            blocklist=blocklist or [],
        ),
    )


@pytest.fixture(autouse=True)
def _pretend_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)


# --- build_lpm_key -----------------------------------------------------------


def test_build_lpm_key_matches_known_good_bytes():
    # Confirmed byte-for-byte against the kernel's own computed key for
    # this exact hostname via a temporary bpf_printk during development
    # (see bpf/xdp_sni_filter.c's build_lpm_key -- the barrel shift
    # brings reverse("." + hostname) to the *front* of the key, zero-
    # padded after, not the other way around).
    key = xdp_mod.build_lpm_key("blocked.example.com")

    prefixlen = struct.unpack_from("<I", key, 0)[0]
    assert prefixlen == (len("blocked.example.com") + 1) * 8  # 160

    content = key[4 : 4 + prefixlen // 8]
    assert content == b".blocked.example.com"[::-1]

    padding = key[4 + prefixlen // 8 :]
    assert padding == b"\x00" * len(padding)
    assert len(key) == 40  # struct lpm_sni_key, 8-byte aligned


def test_build_lpm_key_blocking_parent_domain_is_a_prefix_of_subdomain_key():
    # This is the whole point of the reverse("." + hostname) scheme: a
    # blocklist entry for "example.com" must be a byte-prefix of the key
    # for "www.example.com" (so the LPM trie's prefix match blocks it
    # too), matching bpf/xdp_sni_filter.c's header comment's worked
    # example.
    parent_key = xdp_mod.build_lpm_key("example.com")
    child_key = xdp_mod.build_lpm_key("www.example.com")
    # Only the *content* bytes (after the 4-byte prefixlen header, which
    # differs by construction since the two hostnames differ in length)
    # need to match as a prefix -- that's what the LPM trie itself
    # actually compares.
    parent_content_len = struct.unpack_from("<I", parent_key, 0)[0] // 8
    assert child_key[4 : 4 + parent_content_len] == parent_key[4 : 4 + parent_content_len]


def test_build_lpm_key_does_not_match_unrelated_suffix_domain():
    # "notexample.com" merely shares trailing *characters* with
    # "example.com" -- it is not a subdomain of it -- so a blocklist
    # entry for "example.com" must not match it. Comparing only up to
    # example.com's own content length is what actually matters for LPM
    # semantics (that's the number of bytes a stored prefixlen=96 entry
    # would check); reverse(".example.com") = "moc.elpmaxe." vs
    # reverse(".notexample.com")'s first 12 bytes = "moc.elpmaxeton."[:12]
    # diverge right at the byte that would need to be '.' for a real
    # label boundary, matching bpf/xdp_sni_filter.c's header comment's
    # own worked example.
    example_key = xdp_mod.build_lpm_key("example.com")
    notexample_key = xdp_mod.build_lpm_key("notexample.com")
    example_content_len = struct.unpack_from("<I", example_key, 0)[0] // 8
    assert (
        notexample_key[4 : 4 + example_content_len]
        != example_key[4 : 4 + example_content_len]
    )


def test_build_lpm_key_rejects_empty_and_too_long_hostnames():
    with pytest.raises(xdp_mod.XdpError):
        xdp_mod.build_lpm_key("")
    with pytest.raises(xdp_mod.XdpError):
        xdp_mod.build_lpm_key("a" * xdp_mod.MAX_SNI_LEN)


# --- SNI normalization (review-triage B3) ---------------------------------------
#
# A blocklist entry only blocks a client if the key it is stored as is
# the key the kernel program builds from the name the client actually
# sends. These are the userspace half of that agreement; the kernel
# half (the normalization block in bpf/xdp_sni_filter.c's extract_sni)
# is exercised with real packets in tests/test_xdp_live.py, and compared
# against this module's normalize_sni() directly by the
# `kernel_normalizer` tests below.


def test_normalize_sni_folds_ascii_letters_only():
    # DNS names are case-insensitive (RFC 4343), so case has to go. But
    # only A-Z: the tempting one-liner `| 0x20` on every byte would turn
    # '_' (0x5F) into DEL (0x7F) and '@' (0x40) into a backtick, i.e.
    # mangle names the kernel side never mangles -- and produce a key
    # that matches nothing.
    assert xdp_mod.normalize_sni("Blocked.Example.COM") == "blocked.example.com"
    assert xdp_mod.normalize_sni("A_B@C") == "a_b@c"
    assert xdp_mod.normalize_sni("MiXeD-Case.Example.12") == "mixed-case.example.12"


def test_normalize_sni_strips_a_run_of_trailing_dots():
    # "example.com." is the fully-qualified spelling of "example.com"
    # (RFC 1035 3.1) and clients do send it; a client must not be able
    # to pad dots to slip one byte off the stored key either.
    assert xdp_mod.normalize_sni("example.com.") == "example.com"
    assert xdp_mod.normalize_sni("example.com...") == "example.com"
    assert xdp_mod.normalize_sni("Example.COM..") == "example.com"


def test_build_lpm_key_is_case_insensitive():
    # The bypass: a blocklist entry of "blocked.example.com" never
    # matched a client sending "Blocked.Example.COM", because the raw
    # wire bytes were compared without folding.
    assert (
        xdp_mod.build_lpm_key("Blocked.Example.COM")
        == xdp_mod.build_lpm_key("blocked.example.com")
    )


def test_build_lpm_key_ignores_a_trailing_dot():
    assert (
        xdp_mod.build_lpm_key("example.com.")
        == xdp_mod.build_lpm_key("example.com")
    )
    assert (
        xdp_mod.build_lpm_key("Blocked.Example.com..")
        == xdp_mod.build_lpm_key("blocked.example.com")
    )


def test_build_lpm_key_of_a_trailing_dot_name_is_the_parent_key():
    # Not just equal to the normalized key: the normalized key itself
    # must be the one the parent's own entry uses, or "example.com" in
    # the blocklist still misses "example.com." on the wire.
    dotted = xdp_mod.build_lpm_key("example.com.")
    plain = xdp_mod.build_lpm_key("example.com")
    assert dotted == plain
    content_len = struct.unpack_from("<I", plain, 0)[0] // 8
    subdomain = xdp_mod.build_lpm_key("www.example.com.")
    # And the label-boundary prefix property survives normalization, so
    # the parent entry still covers subdomains spelled with a dot.
    assert subdomain[4 : 4 + content_len] == plain[4 : 4 + content_len]


def test_build_lpm_key_rejects_a_name_at_the_kernel_limit_even_with_a_trailing_dot():
    # 31 'a' + '.' is 32 bytes *on the wire*, which is exactly what
    # parse_sni_body() in bpf/xdp_sni_filter.c refuses (name_len_raw >=
    # MAX_SNI_LEN) before it ever looks at a trailing dot. Normalizing
    # it down to 31 bytes here would install a key the kernel side
    # provably never builds -- the length check has to come first, on
    # the raw name.
    at_limit = "a" * (xdp_mod.MAX_SNI_LEN - 1) + "."
    assert len(at_limit) == xdp_mod.MAX_SNI_LEN
    with pytest.raises(xdp_mod.XdpError, match="NOT blocked"):
        xdp_mod.build_lpm_key(at_limit)
    # One byte shorter is fine, and the dot is simply dropped.
    just_fits = "a" * (xdp_mod.MAX_SNI_LEN - 2) + "."
    assert len(just_fits) == xdp_mod.MAX_SNI_LEN - 1
    assert xdp_mod.build_lpm_key(just_fits) == xdp_mod.build_lpm_key(
        "a" * (xdp_mod.MAX_SNI_LEN - 2)
    )


def test_build_lpm_key_rejects_a_name_of_only_dots():
    for name in (".", "..", "..."):
        with pytest.raises(xdp_mod.XdpError):
            xdp_mod.build_lpm_key(name)


# --- kernel/userspace drift (SEC-17, review finding M1) ------------------------
#
# normalize_sni() above and the two #pragma unroll loops inside
# extract_sni() are two copies of one rule, in two languages. Nothing
# about writing them twice keeps them equal: editing either side alone
# leaves every other test in this file green while the filter keys on
# something the trie does not contain, and a blocklisted name becomes
# reachable again -- which is the whole bug SEC-17 exists to close.
#
# So instead of asserting the properties of a *transcribed* copy (which
# only tests the transcription), these tests compile the real text out of
# bpf/xdp_sni_filter.c and compare its output against normalize_sni()'s,
# byte for byte, over a corpus. Change one side without the other and
# this fails; there is no third copy left to drift.
#
# The comparison runs the C with the host compiler, not with clang for
# the BPF target: the normalization loops are plain C over an unsigned
# char buffer, and the question here is what *bytes they produce*, not
# whether the verifier accepts the program (that stays with the live
# tests and the integrator's load). A compiler that is not clang simply
# ignores #pragma unroll, which does not change the emitted bytes.

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_KERNEL_SOURCE = os.path.join(_REPO_ROOT, "bpf", "xdp_sni_filter.c")

# The C block, as it appears in extract_sni(). Anchored on the two
# statements that open and close it so the extraction cannot silently
# widen to the wrong region if the file is edited: if either anchor is
# gone, the tests below fail loudly instead of comparing nothing.
_KERNEL_BLOCK_START = "__u32 n = 0;"
_KERNEL_BLOCK_END = "return (int)n;"


def _extract_kernel_normalizer() -> str:
    """The exact C text between the two anchors, or a failure explaining
    which one moved. Extracted by text, not by a hand-kept copy, because
    a kept copy is a third implementation to keep in step."""
    with open(_KERNEL_SOURCE, encoding="utf-8") as fh:
        source = fh.read()
    start = source.find(_KERNEL_BLOCK_START)
    assert start != -1, f"{_KERNEL_BLOCK_START!r} not found in {_KERNEL_SOURCE}"
    end = source.find(_KERNEL_BLOCK_END, start)
    assert end != -1, f"{_KERNEL_BLOCK_END!r} not found after the start anchor"
    return source[start:end + len(_KERNEL_BLOCK_END)]


#: C harness: runs the extracted block over names fed as hex on stdin and
#: prints, one per line, the normalized length and the normalized bytes.
#: (fp -> int) is the only shape extract_sni()'s block needs -- the loops
#: read found_sp[j] under `j < found_len` and write out_sni[j].
_HARNESS = """\
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SNI_LEN 32
typedef unsigned int __u32;

static int normalize(const unsigned char *found_sp, int found_len,
                     unsigned char *out_sni)
{
%s
}

int main(void)
{
\tstatic char line[4096];
\twhile (fgets(line, sizeof line, stdin)) {
\t\tunsigned char in[MAX_SNI_LEN] = {0};
\t\tunsigned char out[MAX_SNI_LEN] = {0};
\t\tint len = 0;
\t\tfor (size_t k = 0; line[k] && line[k] != '\\n' && len < MAX_SNI_LEN; k += 2) {
\t\t\tunsigned int byte = 0;
\t\t\tif (sscanf(line + k, "%%2x", &byte) != 1)
\t\t\t\tbreak;
\t\t\tin[len++] = (unsigned char)byte;
\t\t}
\t\tint n = normalize(in, len, out);
\t\tprintf("%%d ", n);
\t\tfor (int j = 0; j < n; j++)
\t\t\tprintf("%%02x", out[j]);
\t\tprintf("\\n");
\t}
\treturn 0;
}
"""


def _run_kernel_normalizer(tmp_path, names):
    """Normalized (length, bytes) for each name, from the real C."""
    harness = tmp_path / "normalize_harness.c"
    binary = tmp_path / "normalize_harness"
    harness.write_text(_HARNESS % _extract_kernel_normalizer(), encoding="utf-8")

    compile_proc = subprocess.run(
        ["cc", "-O1", "-std=gnu99", "-w", "-o", str(binary), str(harness)],
        capture_output=True, text=True,
    )
    assert compile_proc.returncode == 0, f"harness did not compile:\n{compile_proc.stderr}"

    stdin = "".join(name.encode("ascii").hex() + "\n" for name in names)
    run_proc = subprocess.run(
        [str(binary)], input=stdin, capture_output=True, text=True, check=True,
    )
    results = []
    for line in run_proc.stdout.splitlines():
        length, _, hexed = line.partition(" ")
        results.append((int(length), bytes.fromhex(hexed)))
    assert len(results) == len(names)
    return results


#: Every byte value that can reach the fold, so the range test is checked
#: against its whole neighbourhood and not just the letters: '@' (0x40) and
#: '[' (0x5B) bracket 'A'-'Z', and '_' (0x5F) is the byte a blind `| 0x20`
#: would corrupt into DEL. Length 1 keeps every byte isolated.
_FOLD_ALPHABET = (
    "".join(chr(b) for b in range(0x21, 0x7F) if chr(b) not in "abcdefghijklmnopqrstuvwxyz0123456789.-")
)


def test_the_kernel_normalizer_and_the_userspace_mirror_agree_byte_for_byte(tmp_path):
    """The drift detector. Every printable ASCII byte is folded in every
    position of a short name, plus the bypass spellings, and the C's
    output must equal normalize_sni()'s for every one of them."""
    names = [
        # every non-alphanumeric printable byte, alone and around a letter:
        # this is where a `| 0x20` and a range test disagree.
        *(b for b in _FOLD_ALPHABET),
        *(f"a{b}c" for b in _FOLD_ALPHABET),
        *(f"WWW{b}EXAMPLE" for b in _FOLD_ALPHABET),
        # the spellings the bypass was written with
        "Blocked.Example.COM", "BLOCKED.EXAMPLE.COM", "ExAmPlE.CoM",
        "example.com.", "example.com..", "example.com.....",
        "Blocked.Example.COM...", "...", "..", ".",
        "A", "Z", "a", "z", "0", "9", "-", "_",
        "a" * (xdp_mod.MAX_SNI_LEN - 1),
        "a" * (xdp_mod.MAX_SNI_LEN - 2) + ".",
        # dots in the middle must survive (only a *trailing* run is trimmed)
        "a.b.c", ".a.b", "a..b", "A.B.C.D",
    ]
    kernel = _run_kernel_normalizer(tmp_path, names)

    mismatches = [
        (name, klen, kbytes, xdp_mod.normalize_sni(name).encode("ascii"))
        for name, (klen, kbytes) in zip(names, kernel)
        if kbytes != xdp_mod.normalize_sni(name).encode("ascii")
        or klen != len(xdp_mod.normalize_sni(name))
    ]
    assert not mismatches, f"kernel and userspace normalize differently: {mismatches}"


def test_the_kernel_normalizer_agrees_with_the_mirror_on_every_name_of_a_short_alphabet(tmp_path):
    """Exhaustive over a small alphabet up to length 5 -- every case and
    every dot pattern those four letters can spell, which is where a
    trim-the-wrong-run or fold-the-wrong-side bug would show up. Cheap
    enough to run in full (1365 names), unlike the 32-byte space."""
    alphabet = "aA.1_"
    names = []
    for length in range(1, 6):
        stack = [""]
        for _ in range(length):
            stack = [prefix + ch for prefix in stack for ch in alphabet]
        names.extend(stack)

    kernel = _run_kernel_normalizer(tmp_path, names)
    for name, (klen, kbytes) in zip(names, kernel):
        expected = xdp_mod.normalize_sni(name).encode("ascii")
        assert (klen, kbytes) == (len(expected), expected), (
            f"{name!r}: kernel gave {klen}/{kbytes.hex()}, "
            f"userspace gave {len(expected)}/{expected.hex()}"
        )


def test_the_kernel_normalizer_refuses_a_name_at_the_length_limit_on_both_sides(tmp_path):
    """The length refusal is the third bypass, and it is the *same*
    refusal on both sides: parse_sni_body() drops a wire name of
    MAX_SNI_LEN or more before extract_sni()'s block ever runs, and
    build_lpm_key() raises on the raw length. If either side ever moved
    its check after normalization, a 32-byte name would fold to 31 and
    install a key the kernel never builds -- so this pins the order."""
    at_limit = "a" * xdp_mod.MAX_SNI_LEN
    with pytest.raises(xdp_mod.XdpError, match="NOT blocked"):
        xdp_mod.build_lpm_key(at_limit)
    # The C block itself would happily fold it, which is exactly why the
    # check in front of it matters: assert that, so the test does not
    # accidentally start asserting the block refuses it.
    (klen, kbytes), = _run_kernel_normalizer(tmp_path, [at_limit])
    assert (klen, kbytes) == (xdp_mod.MAX_SNI_LEN, at_limit.encode("ascii"))


# --- SniEvent decoding --------------------------------------------------------


def test_sni_event_decodes_real_struct_layout():
    # Matches struct sni_event's confirmed layout (offsetof, compiled and
    # checked, not assumed): saddr@0, daddr@4, sport@8, dport@10,
    # action@12, sni_len@14, sni@16, total 48 bytes.
    raw = (
        socket.inet_aton("127.0.0.1")
        + socket.inet_aton("93.184.216.34")
        + struct.pack("<HH", 51234, 443)
        + bytes([1])
        + b"\x00"  # padding before sni_len's 2-byte alignment
        + struct.pack("<H", 11)
        + b"example.com".ljust(xdp_mod.MAX_SNI_LEN, b"\x00")
    )
    assert len(raw) == 48

    event = xdp_mod.SniEvent.from_bytes(raw)
    assert event.saddr == "127.0.0.1"
    assert event.daddr == "93.184.216.34"
    assert event.sport == 51234
    assert event.dport == 443
    assert event.hostname == "example.com"


def test_sni_event_rejects_short_record():
    with pytest.raises(xdp_mod.XdpError, match="short"):
        xdp_mod.SniEvent.from_bytes(b"\x00" * 10)


def test_format_event_json_round_trips_through_json_parse():
    # This is the exact line the event-logger daemon prints to stdout
    # (captured by journald) and what the webUI's live log stream
    # (frfw.webui.routes.xdp) relays close to verbatim -- it must be
    # one complete, parseable JSON object per line, with no other text.
    event = xdp_mod.SniEvent(
        saddr="127.0.0.1", daddr="93.184.216.34", sport=51234, dport=443,
        hostname="example.com",
    )
    line = xdp_mod.format_event_json(event)
    parsed = json.loads(line)
    assert parsed["saddr"] == "127.0.0.1"
    assert parsed["daddr"] == "93.184.216.34"
    assert parsed["sport"] == 51234
    assert parsed["dport"] == 443
    assert parsed["sni"] == "example.com"
    assert parsed["action"] == "drop"
    assert isinstance(parsed["ts"], float)


# --- attach: native-then-generic fallback -------------------------------------


def test_attach_prefers_native_mode(monkeypatch):
    calls = []

    def fake_run_ip(args):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(xdp_mod, "_run_ip", fake_run_ip)

    mode = xdp_mod.attach("eth0")

    assert mode == xdp_mod.AttachMode.NATIVE
    assert calls == [["link", "set", "dev", "eth0", "xdpdrv", "pinned", str(xdp_mod.PIN_PROG_PATH)]]


def test_attach_falls_back_to_generic_when_native_fails(monkeypatch):
    calls = []

    def fake_run_ip(args):
        calls.append(args)
        ok = "xdpgeneric" in args
        return subprocess.CompletedProcess(args, 0 if ok else 1, stdout="", stderr="not supported")

    monkeypatch.setattr(xdp_mod, "_run_ip", fake_run_ip)

    mode = xdp_mod.attach("eth0")

    assert mode == xdp_mod.AttachMode.GENERIC
    assert len(calls) == 2
    assert "xdpdrv" in calls[0]
    assert "xdpgeneric" in calls[1]


def test_attach_raises_when_both_modes_fail(monkeypatch):
    monkeypatch.setattr(
        xdp_mod,
        "_run_ip",
        lambda args: subprocess.CompletedProcess(args, 1, stdout="", stderr="no such device"),
    )

    with pytest.raises(xdp_mod.XdpError, match="no such device"):
        xdp_mod.attach("nonexistent0")


# --- sync_blocklist reconciliation --------------------------------------------


def _bpftool_json(entries):
    return subprocess.CompletedProcess([], 0, stdout=json.dumps(entries), stderr="")


def test_sync_blocklist_adds_missing_and_removes_stale(monkeypatch):
    stale_key = xdp_mod.build_lpm_key("old.example.com")
    stale_entry = {
        "key": {
            "prefixlen": struct.unpack_from("<I", stale_key, 0)[0],
            "reversed": list(stale_key[4:]),
        },
        "value": 1,
    }

    calls = []

    def fake_bpftool(args):
        calls.append(args)
        if args[:2] == ["map", "dump"]:
            return _bpftool_json([stale_entry])
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(xdp_mod, "_bpftool", fake_bpftool)

    xdp_mod.sync_blocklist(["new.example.com"])

    update_calls = [c for c in calls if c[:2] == ["map", "update"]]
    delete_calls = [c for c in calls if c[:2] == ["map", "delete"]]
    assert len(update_calls) == 1
    assert len(delete_calls) == 1
    new_key_hex = xdp_mod._key_hex_args(xdp_mod.build_lpm_key("new.example.com"))
    assert update_calls[0][-len(new_key_hex) - 2 : -2] == new_key_hex  # before "value ..."


def test_sync_blocklist_noop_when_already_matching(monkeypatch):
    key = xdp_mod.build_lpm_key("same.example.com")
    entry = {
        "key": {"prefixlen": struct.unpack_from("<I", key, 0)[0], "reversed": list(key[4:])},
        "value": 1,
    }

    calls = []

    def fake_bpftool(args):
        calls.append(args)
        if args[:2] == ["map", "dump"]:
            return _bpftool_json([entry])
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(xdp_mod, "_bpftool", fake_bpftool)

    xdp_mod.sync_blocklist(["same.example.com"])

    assert not [c for c in calls if c[:2] in (["map", "update"], ["map", "delete"])]


def test_sync_blocklist_installs_the_normalized_key(monkeypatch):
    # The blocklist entry as written in the config and the name on the
    # wire rarely agree on case or a trailing dot; what lands in the trie
    # must be the normalized key, or the kernel's lookup (which
    # normalizes) never finds it.
    calls = []

    def fake_bpftool(args):
        calls.append(args)
        if args[:2] == ["map", "dump"]:
            return _bpftool_json([])
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(xdp_mod, "_bpftool", fake_bpftool)

    xdp_mod.sync_blocklist(["Blocked.Example.COM."])

    update_calls = [c for c in calls if c[:2] == ["map", "update"]]
    assert len(update_calls) == 1
    wanted = xdp_mod._key_hex_args(xdp_mod.build_lpm_key("blocked.example.com"))
    assert update_calls[0][-len(wanted) - 2 : -2] == wanted  # before "value ..."


def test_sync_blocklist_names_every_name_it_cannot_block(monkeypatch):
    # Fails closed (the whole sync aborts, so nothing is half-applied)
    # and says which entries are not blocked -- an operator who added a
    # too-long name must not have to guess that it is silently absent.
    calls = []

    def fake_bpftool(args):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="[]", stderr="")

    monkeypatch.setattr(xdp_mod, "_bpftool", fake_bpftool)

    too_long = "a" * 28 + ".com"  # 32 bytes
    with pytest.raises(xdp_mod.XdpError) as excinfo:
        xdp_mod.sync_blocklist(["ok.example.com", too_long])

    message = str(excinfo.value)
    assert "NOT blocked" in message
    assert too_long in message
    # Nothing was written or deleted on the way to failing.
    assert not [c for c in calls if c[:2] in (["map", "update"], ["map", "delete"])]


# --- sync_sni_filter orchestration --------------------------------------------


def test_sync_disabled_and_never_attached_is_a_noop(tmp_path):
    result = xdp_mod.sync_sni_filter(
        _config(enabled=False), state_path=tmp_path / "xdp_state.json"
    )
    assert not result.applied
    assert "disabled" in result.message.lower()


def test_sync_dry_run_enabled_makes_no_calls(monkeypatch, tmp_path):
    monkeypatch.setattr("os.geteuid", lambda: 1000)  # not root -- dry-run must not care
    monkeypatch.setattr(xdp_mod, "ensure_compiled", lambda: (_ for _ in ()).throw(AssertionError))

    result = xdp_mod.sync_sni_filter(
        _config(enabled=True, interfaces=["wan"], blocklist=["a.example.com"]),
        dry_run=True,
        state_path=tmp_path / "xdp_state.json",
    )

    assert not result.applied
    assert "would attach" in result.message.lower()
    assert "eth0" in result.message


def test_sync_enable_attaches_and_populates_blocklist(monkeypatch, tmp_path):
    state_path = tmp_path / "xdp_state.json"
    calls = []

    monkeypatch.setattr(xdp_mod, "ensure_compiled", lambda: tmp_path / "xdp_sni_filter.o")
    monkeypatch.setattr(xdp_mod, "load_and_pin", lambda obj_path: calls.append(("load", obj_path)))
    monkeypatch.setattr(xdp_mod, "attach", lambda device: (calls.append(("attach", device)), xdp_mod.AttachMode.NATIVE)[1])
    monkeypatch.setattr(xdp_mod, "sync_blocklist", lambda hosts: calls.append(("blocklist", tuple(hosts))))

    result = xdp_mod.sync_sni_filter(
        _config(enabled=True, interfaces=["wan"], blocklist=["a.example.com"]),
        state_path=state_path,
    )

    assert result.applied
    assert ("attach", "eth0") in calls
    assert ("blocklist", ("a.example.com",)) in calls
    assert state_path.is_file()
    assert json.loads(state_path.read_text())["attached"] == {"eth0": "xdpdrv"}


def test_sync_disable_detaches_and_unloads_previously_attached(monkeypatch, tmp_path):
    state_path = tmp_path / "xdp_state.json"
    state_path.write_text(json.dumps({"attached": {"eth0": "xdpgeneric"}}))
    calls = []

    monkeypatch.setattr(xdp_mod, "detach", lambda device, mode: calls.append(("detach", device, mode)))
    monkeypatch.setattr(xdp_mod, "unload", lambda: calls.append(("unload",)))
    monkeypatch.setattr(xdp_mod, "live_attachment", lambda device: (xdp_mod.AttachMode.GENERIC, 7))

    result = xdp_mod.sync_sni_filter(_config(enabled=False), state_path=state_path)

    assert result.applied
    assert ("detach", "eth0", xdp_mod.AttachMode.GENERIC) in calls
    assert ("unload",) in calls
    assert json.loads(state_path.read_text())["attached"] == {}


def test_sync_leaves_already_attached_interface_alone(monkeypatch, tmp_path):
    # Re-running apply with the same config must not re-attach (which
    # would be visible as a brief drop in coverage) an interface that's
    # already attached.
    state_path = tmp_path / "xdp_state.json"
    state_path.write_text(json.dumps({"attached": {"eth0": "xdpdrv"}}))
    calls = []

    monkeypatch.setattr(xdp_mod, "ensure_compiled", lambda: tmp_path / "xdp_sni_filter.o")
    monkeypatch.setattr(xdp_mod, "load_and_pin", lambda obj_path: None)
    monkeypatch.setattr(xdp_mod, "attach", lambda device: calls.append(("attach", device)))
    monkeypatch.setattr(xdp_mod, "detach", lambda device, mode: calls.append(("detach", device, mode)))
    monkeypatch.setattr(xdp_mod, "sync_blocklist", lambda hosts: None)
    # The kernel really has the pinned program on eth0.
    monkeypatch.setattr(xdp_mod, "live_attachment", lambda device: (xdp_mod.AttachMode.NATIVE, 7))
    monkeypatch.setattr(xdp_mod, "pinned_prog_id", lambda: 7)

    xdp_mod.sync_sni_filter(
        _config(enabled=True, interfaces=["wan"], blocklist=[]), state_path=state_path
    )

    assert ("attach", "eth0") not in calls
    assert not [c for c in calls if c[0] == "detach"]


def _sync_after_reboot(monkeypatch, tmp_path, live):
    state_path = tmp_path / "xdp_state.json"
    state_path.write_text(json.dumps({"attached": {"eth0": "xdpdrv"}}))  # survived the reboot
    calls = []
    monkeypatch.setattr(xdp_mod, "ensure_compiled", lambda: tmp_path / "xdp_sni_filter.o")
    monkeypatch.setattr(xdp_mod, "load_and_pin", lambda obj_path: None)
    monkeypatch.setattr(xdp_mod, "attach", lambda device: (calls.append(("attach", device)), xdp_mod.AttachMode.NATIVE)[1])
    monkeypatch.setattr(xdp_mod, "detach", lambda device, mode: calls.append(("detach", device, mode)))
    monkeypatch.setattr(xdp_mod, "sync_blocklist", lambda hosts: None)
    monkeypatch.setattr(xdp_mod, "live_attachment", lambda device: live)
    monkeypatch.setattr(xdp_mod, "pinned_prog_id", lambda: 42)
    xdp_mod.sync_sni_filter(_config(enabled=True, interfaces=["wan"], blocklist=[]), state_path=state_path)
    return calls, state_path


def test_sync_reattaches_after_a_reboot(monkeypatch, tmp_path):
    """B1 (review triage): the state file survives a reboot, the kernel
    attachment doesn't. The boot apply used to skip every device the
    file listed, so the filter stayed off for good."""
    calls, state_path = _sync_after_reboot(monkeypatch, tmp_path, live=None)
    assert calls == [("attach", "eth0")]
    assert json.loads(state_path.read_text())["attached"] == {"eth0": "xdpdrv"}


def test_sync_replaces_an_attachment_of_an_older_program(monkeypatch, tmp_path):
    calls, _ = _sync_after_reboot(monkeypatch, tmp_path, live=(xdp_mod.AttachMode.GENERIC, 13))
    assert calls == [("detach", "eth0", xdp_mod.AttachMode.GENERIC), ("attach", "eth0")]


def test_status_reports_what_the_kernel_has_not_the_state_file(monkeypatch, tmp_path):
    state_path = tmp_path / "xdp_state.json"
    state_path.write_text(json.dumps({"attached": {"eth0": "xdpdrv", "eth1": "xdpdrv"}}))
    live = {"eth1": (xdp_mod.AttachMode.GENERIC, 5)}
    monkeypatch.setattr(xdp_mod, "live_attachment", lambda device: live.get(device))
    assert xdp_mod.get_attached(state_path=state_path) == {"eth1": "xdpgeneric"}


IP_JSON_ATTACHED = json.dumps([{
    "ifindex": 66, "ifname": "frv0", "mtu": 1500,
    "xdp": {"mode": 2, "prog": {"id": 17, "name": "xdp_sni_filter", "tag": "9b415647d68643a9", "jited": 1},
            "attached": [{"mode": 2, "prog": {"id": 17, "name": "xdp_sni_filter", "tag": "9b415647d68643a9", "jited": 1}}]},
    "operstate": "UP",
}])  # real `ip -j link show` output (iproute2 6.x) with the filter in generic mode


@pytest.mark.parametrize("stdout, rc, expected", [
    (IP_JSON_ATTACHED, 0, (xdp_mod.AttachMode.GENERIC, 17)),
    (IP_JSON_ATTACHED.replace('"mode": 2', '"mode": 1'), 0, (xdp_mod.AttachMode.NATIVE, 17)),
    (IP_JSON_ATTACHED.replace("xdp_sni_filter", "someone_else"), 0, None),
    (json.dumps([{"ifname": "frv0", "mtu": 1500}]), 0, None),
    ("", 1, None),
])
def test_live_attachment_parses_ip_json(monkeypatch, stdout, rc, expected):
    import subprocess as sp
    monkeypatch.setattr(xdp_mod, "_run_ip", lambda args: sp.CompletedProcess(args, rc, stdout=stdout, stderr=""))
    assert xdp_mod.live_attachment("frv0") == expected


@pytest.mark.skipif(
    os.geteuid() != 0 or not shutil.which("ip") or not paths.XDP_BPF_OBJ_PATH.is_file(),
    reason="needs root, iproute2 and the compiled XDP object",
)
def test_live_attachment_and_status_against_a_real_kernel(tmp_path):
    """B1 with the real kernel: what `get_attached` reports follows the
    attachment, not the state file -- the state after a reboot is exactly
    "file says attached, kernel has nothing"."""
    import subprocess as sp

    dev = "frb1test0"
    sp.run(["ip", "link", "add", dev, "type", "veth", "peer", "name", dev[:-1] + "1"], check=True)
    try:
        state_path = tmp_path / "xdp_state.json"
        state_path.write_text(json.dumps({"attached": {dev: "xdpgeneric"}}))
        assert xdp_mod.live_attachment(dev) is None
        assert xdp_mod.get_attached(state_path=state_path) == {}  # "after the reboot"

        sp.run(["ip", "link", "set", "dev", dev, "xdpgeneric", "obj", str(paths.XDP_BPF_OBJ_PATH), "sec", "xdp"],
               check=True, capture_output=True)
        mode, prog_id = xdp_mod.live_attachment(dev)
        assert mode is xdp_mod.AttachMode.GENERIC and prog_id > 0
        assert xdp_mod.get_attached(state_path=state_path) == {dev: "xdpgeneric"}
    finally:
        sp.run(["ip", "link", "del", dev], check=False)
