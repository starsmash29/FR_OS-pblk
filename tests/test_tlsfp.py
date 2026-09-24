"""Phase 19: TLS client fingerprinting -- parsing, JA3/JA4, reassembly,
the inventory and the fr-tls-fp daemon's decisions, config, CLI, metrics.

Real packets through the real XDP program: tests/test_xdp_live.py. The
JA4 implementation was additionally checked by hand against FoxIO's
reference outputs for their public capture set (151 of 152 streams
equal; the one difference is a documented spec/reference disagreement
about non-ASCII ALPN values, see ARCHITECTURE.md).
"""

from __future__ import annotations

import json
import random
import struct

import pytest

import tlsfp_samples as samples
from frfw import xdp
from frfw.config import ConfigError, parse_config
from frfw.tlsfp.clienthello import ParseError, handshake_from_records, is_grease, parse_client_hello
from frfw.tlsfp.daemon import TlsFingerprintDaemon, load_state
from frfw.tlsfp.fingerprint import ja3, ja3_string, ja4, ja4_parts
from frfw.tlsfp.inventory import LEARNING_SECONDS, MAX_FINGERPRINTS_PER_CLIENT, FingerprintInventory
from frfw.tlsfp.reassembly import Reassembler

T0 = 1_700_000_000.0


# --- JA4 / JA3 against the published examples -------------------------------------------------

SPEC_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
                0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
SPEC_EXTENSIONS = [0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002D, 0x000D, 0x0005,
                   0x0023, 0x0012, 0x002B, 0xFF01, 0x000B, 0x000A, 0x0015]
SPEC_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def _spec_hello(extension_order=SPEC_EXTENSIONS, grease=False):
    bodies = {
        0x0000: b"\x00\x0e\x00\x00\x0bexample.com",
        0x0010: b"\x00\x03\x02h2",
        0x002B: b"\x02\x03\x04",
        0x000D: struct.pack("!H", 2 * len(SPEC_SIGALGS)) + b"".join(struct.pack("!H", s) for s in SPEC_SIGALGS),
    }
    exts = [samples.extension(t, bodies.get(t, b"")) for t in extension_order]
    ciphers = list(SPEC_CIPHERS)
    if grease:
        exts.insert(0, samples.extension(0x2A2A, b""))
        ciphers.insert(0, 0x9A9A)
    return parse_client_hello(samples.client_hello(exts, ciphers=ciphers))


def test_ja4_matches_the_specification_example():
    assert ja4(_spec_hello()) == "t13d1516h2_8daaf6152771_e5627efa2ab1"


def test_grease_is_ignored_and_extension_order_only_changes_ja3():
    base = _spec_hello()
    shuffled_order = list(SPEC_EXTENSIONS)
    random.Random(4).shuffle(shuffled_order)
    shuffled = _spec_hello(shuffled_order)
    greased = _spec_hello(grease=True)
    assert ja4(shuffled) == ja4(base) == ja4(greased)
    assert ja3(greased) == ja3(base)
    assert ja3(shuffled) != ja3(base)  # why browsers' JA3 keeps changing


def test_ja3_matches_the_reference_example():
    exts = [
        samples.extension(0x0000, b"\x00\x0e\x00\x00\x0bexample.com"),
        samples.extension(0x000A, b"\x00\x06\x00\x17\x00\x18\x00\x19"),
        samples.extension(0x000B, b"\x01\x00"),
    ]
    ciphers = [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4]
    hello = parse_client_hello(samples.client_hello(exts, ciphers=ciphers, legacy_version=0x0301))
    assert ja3_string(hello) == "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
    assert ja3(hello) == "ada70206e40642a3e4461f35503241d5"


@pytest.mark.parametrize(
    "alpn, expected",
    [
        ((b"h2",), "h2"), ((b"http/1.1",), "h1"), ((), "00"), ((b"",), "00"), ((b"x",), "xx"),
        ((b"\xab",), "ab"), ((b"\x20",), "20"), ((b"\xab\xcd",), "ad"), ((b"\x30\xab",), "3b"),
        ((b"\x30\x31\xab\xcd",), "3d"), ((b"\x30\xab\xcd\x31",), "01"),
    ],
)
def test_alpn_characters_follow_the_specification(alpn, expected):
    hello = parse_client_hello(samples.client_hello(samples.default_extensions(alpn=alpn, pq=False)))
    assert ja4(hello)[8:10] == expected


def test_sni_absence_version_fallback_and_empty_lists():
    no_sni = parse_client_hello(samples.client_hello(samples.default_extensions(sni=None, pq=False)))
    assert ja4(no_sni)[3] == "i"
    bare = parse_client_hello(samples.client_hello([], ciphers=[0x002F], legacy_version=0x0302))
    assert ja4(bare) == "t11i010000_" + ja4(bare).split("_")[1] + "_000000000000"
    none_at_all = parse_client_hello(samples.client_hello([], ciphers=[]))
    assert ja4(none_at_all) == "t12i000000_000000000000_000000000000"
    assert ja4_parts(no_sni, transport="q")[0].startswith("q13i")


def test_grease_detection():
    assert all(is_grease(v) for v in (0x0A0A, 0x1A1A, 0xFAFA))
    assert not any(is_grease(v) for v in (0x0A1A, 0x1301, 0x0000, 0x0B0B))


# --- record handling and robustness ------------------------------------------------------------


def test_handshake_spanning_several_records():
    message = samples.client_hello(samples.default_extensions())
    wire = samples.tls_records(message, record_size=500)
    assert handshake_from_records(wire) == message
    assert handshake_from_records(wire[:-1]) is None


@pytest.mark.parametrize("stream", [b"\x17\x03\x03\x00\x10" + bytes(16), b"GET / HTTP/1.1\r\n",
                                    b"\x16\x03\x03\x00\x04\x02\x00\x00\x00"])
def test_non_client_hello_streams_are_rejected(stream):
    with pytest.raises(ParseError):
        handshake_from_records(stream)


def test_malformed_input_only_ever_raises_parse_error():
    rng = random.Random(19)
    message = samples.client_hello(samples.default_extensions())
    for i in range(3000):
        data = bytearray(message)
        if i % 3 == 0:
            data = data[: rng.randrange(1, len(data))]
        for _ in range(rng.randint(1, 6)):
            data[rng.randrange(len(data))] = rng.randrange(256) if data else 0
        try:
            parse_client_hello(bytes(data))
        except ParseError:
            pass


# --- reassembly ---------------------------------------------------------------------------------


def _segments(wire: bytes, size: int, isn: int):
    return [(isn + i, wire[i:i + size]) for i in range(0, len(wire), size)]


def test_reassembly_in_order_out_of_order_and_with_retransmits():
    message = samples.client_hello(samples.default_extensions())
    wire = samples.tls_records(message)
    key = ("10.0.0.5", 50000, "1.2.3.4", 443)
    for order in ("forward", "shuffled"):
        r = Reassembler()
        segs = _segments(wire, 700, 0xFFFFFF00)  # sequence numbers wrap past 2^32
        first, rest = segs[0], segs[1:]
        if order == "shuffled":
            rest = list(reversed(rest))
        assert r.add(key, first[0] & 0xFFFFFFFF, first[1], T0, first=True) is None
        results = []
        for seq, chunk in rest:
            results.append(r.add(key, seq & 0xFFFFFFFF, chunk, T0, first=False))
            results.append(r.add(key, seq & 0xFFFFFFFF, chunk, T0, first=False))  # retransmit
        assert message in results
        assert len(r) == 0


def test_reassembly_bounds_and_expiry():
    key = ("10.0.0.5", 1, "1.2.3.4", 443)
    wire = samples.tls_records(samples.client_hello(samples.default_extensions()))
    r = Reassembler(max_flows=2, timeout=5)
    assert r.add(key, 100, b"\x00" * 10, T0, first=False) is None  # no hello started: ignored
    r.add(key, 100, wire[:500], T0, first=True)
    assert len(r) == 1
    assert r.add(key, 600, wire[500:], T0 + 10, first=False) is None  # expired meanwhile
    for port in range(5):
        r.add(("10.0.0.6", port, "1.2.3.4", 443), 1, wire[:500], T0 + 20 + port, first=True)
    assert len(r) == 2


# --- inventory and daemon -------------------------------------------------------------------------


def test_inventory_learning_period_and_new_fingerprints():
    inv = FingerprintInventory(started=T0)
    assert inv.observe("10.0.0.5", "t13d_a", "j1", "a.example", T0) is False  # learning
    later = T0 + LEARNING_SECONDS + 1
    assert inv.observe("10.0.0.6", "t13d_a", "j1", None, later) is False    # known on the network
    assert inv.observe("10.0.0.6", "t13d_b", "j2", None, later) is True     # genuinely new
    for i in range(MAX_FINGERPRINTS_PER_CLIENT + 3):
        inv.observe("10.0.0.7", f"fp{i}", "j", None, later + i)
    assert len(inv.clients["10.0.0.7"]) == MAX_FINGERPRINTS_PER_CLIENT
    restored = FingerprintInventory.restore(json.loads(json.dumps(inv.snapshot(later))), later)
    assert restored.started == T0 and restored.clients["10.0.0.5"]["t13d_a"].sni == ["a.example"]
    assert FingerprintInventory.restore({"clients": {"x": {"y": {"first_seen": "?"}}}}, T0).clients == {}


class _Clock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


def _config(minimal_config_dict, **tls):
    raw = dict(minimal_config_dict)
    raw["xdp_sni_filter"] = {"enabled": True, "interfaces": ["lan"]}
    raw["tls_fingerprint"] = {"enabled": True, **tls}
    return parse_config(raw)


def test_daemon_fingerprints_segments_and_acts_on_the_blocklist(minimal_config_dict, tmp_path):
    message = samples.client_hello(samples.default_extensions(sni="bad.example"))
    fingerprint = ja4(parse_client_hello(message))
    quarantined = []
    clock = _Clock(T0)
    config = _config(minimal_config_dict, blocklist=[{"fingerprint": fingerprint, "label": "test tool"}],
                     quarantine_on_match=True)
    daemon = TlsFingerprintDaemon(config, state_path=tmp_path / "s.json", clock=clock,
                                  quarantine_fn=lambda ip, d: quarantined.append((ip, d)) or {"ok": True})
    wire = samples.tls_records(message)
    for i, (seq, chunk) in enumerate(_segments(wire, 1000, 5000)):
        daemon.handle_segment(xdp.HelloSegment("10.0.0.9", "1.2.3.4", 40000, 443, seq, i == 0, chunk))
    assert quarantined == [("10.0.0.9", 7200)]
    (event,) = [e for e in daemon.inventory.events if e["type"] == "blocklist"]
    assert (event["label"], event["action"], event["sni"]) == ("test tool", "quarantined", "bad.example")

    clock.now += 60  # same client again soon: reported, not re-quarantined
    daemon.handle_hello("10.0.0.9", fingerprint, "x", None, clock.now)
    assert len(quarantined) == 1 and daemon.inventory.events[-1]["action"] == "already quarantined"

    state = daemon.write_state()
    assert load_state(tmp_path / "s.json")["clients"]["10.0.0.9"][fingerprint]["count"] == 2
    assert state["stats"] == {"hellos": 1, "parse_errors": 0}


def test_daemon_reports_without_quarantine_and_follows_config_updates(minimal_config_dict, tmp_path):
    calls = []
    daemon = TlsFingerprintDaemon(_config(minimal_config_dict), state_path=tmp_path / "s.json",
                                  quarantine_fn=lambda ip, d: calls.append(ip) or {"ok": True}, clock=_Clock(T0))
    daemon.handle_hello("10.0.0.9", "t13d0000000_aaaaaaaaaaaa_bbbbbbbbbbbb", "0" * 32, None, T0)
    assert not [e for e in daemon.inventory.events if e["type"] == "blocklist"]
    daemon.update_config(_config(minimal_config_dict, blocklist=["0" * 32]))
    daemon.handle_hello("10.0.0.9", "t13d0000000_aaaaaaaaaaaa_bbbbbbbbbbbb", "0" * 32, None, T0 + 1)
    assert daemon.inventory.events[-1]["action"] == "reported" and calls == []


def test_unparseable_segments_are_counted_not_fatal(minimal_config_dict, tmp_path):
    daemon = TlsFingerprintDaemon(_config(minimal_config_dict), state_path=tmp_path / "s.json")
    daemon.handle_segment(xdp.HelloSegment("10.0.0.9", "1.2.3.4", 1, 443, 1, True, b"\x16\x03\x01\x00\x05\x02\x00\x00\x01\x00"))
    assert daemon.stats == {"hellos": 0, "parse_errors": 1}


def test_hello_segment_decoding():
    header = struct.pack("<4s4sHHIHBB", bytes([10, 0, 0, 9]), bytes([1, 2, 3, 4]), 40000, 443, 77, 5, 1, 0)
    segment = xdp.HelloSegment.from_bytes(header + b"hello" + bytes(xdp.HELLO_SNAP - 5))
    assert (segment.saddr, segment.dport, segment.seq, segment.first, segment.payload) == (
        "10.0.0.9", 443, 77, True, b"hello")
    with pytest.raises(xdp.XdpError):
        xdp.HelloSegment.from_bytes(b"short")


def test_xdp_sync_sets_the_hello_bit(minimal_config_dict, tmp_path, monkeypatch):
    written = []
    settings, hello_pkts = tmp_path / "settings", tmp_path / "hello_pkts"
    settings.touch()
    hello_pkts.touch()
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(xdp, "PIN_SETTINGS_PATH", settings)
    monkeypatch.setattr(xdp, "PIN_HELLO_PKTS_PATH", hello_pkts)
    monkeypatch.setattr(xdp, "ensure_compiled", lambda: tmp_path / "x.o")
    monkeypatch.setattr(xdp, "load_and_pin", lambda obj: None)
    monkeypatch.setattr(xdp, "attach", lambda dev: xdp.AttachMode.GENERIC)
    monkeypatch.setattr(xdp, "sync_blocklist", lambda names: None)
    monkeypatch.setattr(xdp, "set_settings", written.append)
    result = xdp.sync_sni_filter(_config(minimal_config_dict), state_path=tmp_path / "state.json")
    assert written == [xdp.SETTING_REPORT_HELLO] and "copying ClientHellos" in result.message

    hello_pkts.unlink()  # a program pinned before phase 19
    result = xdp.sync_sni_filter(_config(minimal_config_dict), state_path=tmp_path / "state.json")
    assert written[-1] == 0 and "predates it" in result.message


# --- config and CLI ------------------------------------------------------------------------------


def test_tls_fingerprint_config(minimal_config_dict):
    config = _config(minimal_config_dict, blocklist=[
        {"fingerprint": "T13D1516H2_8daaf6152771_e5627efa2ab1", "label": "x"}, "ada70206e40642a3e4461f35503241d5",
    ])
    assert [e.fingerprint for e in config.tls_fingerprint.blocklist] == [
        "t13d1516h2_8daaf6152771_e5627efa2ab1", "ada70206e40642a3e4461f35503241d5"]


@pytest.mark.parametrize(
    "tls, xdp_on, error",
    [
        ({"enabled": True}, False, "requires xdp_sni_filter.enabled"),
        ({"blocklist": ["not-a-fingerprint"]}, True, "neither a JA4"),
        ({"blocklist": ["ada70206e40642a3e4461f35503241d5"] * 2}, True, "listed twice"),
        ({"quarantine_on_match": "yes"}, True, "must be a boolean"),
    ],
)
def test_invalid_tls_fingerprint_config(minimal_config_dict, tls, xdp_on, error):
    raw = dict(minimal_config_dict)
    if xdp_on:
        raw["xdp_sni_filter"] = {"enabled": True, "interfaces": ["lan"]}
    raw["tls_fingerprint"] = tls
    with pytest.raises(ConfigError, match=error):
        parse_config(raw)


def test_cli_lists_fingerprints(monkeypatch, capsys):
    import frfw.cli as cli_mod
    from frfw.cli import main

    monkeypatch.setattr(cli_mod, "load_tlsfp_state", lambda: {"clients": {"10.0.0.5": {
        "t13d1516h2_8daaf6152771_e5627efa2ab1": {"count": 3, "last_seen": 1, "sni": ["a.example"]}}},
        "events": [{"type": "blocklist"}]})
    assert main(["tls-fingerprints"]) == 0
    out = capsys.readouterr().out
    assert "t13d1516h2_8daaf6152771_e5627efa2ab1" in out and "a.example" in out and "1 blocklist match" in out
