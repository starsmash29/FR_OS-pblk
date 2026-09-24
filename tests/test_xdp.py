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
import socket
import struct
import subprocess

import pytest

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

    xdp_mod.sync_sni_filter(
        _config(enabled=True, interfaces=["wan"], blocklist=[]), state_path=state_path
    )

    assert ("attach", "eth0") not in calls
    assert not [c for c in calls if c[0] == "detach"]
