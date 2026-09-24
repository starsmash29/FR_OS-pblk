"""Phase 16: application identification -- the bundled catalog, name
matching, usage accounting, the fr-appid daemon's log parsing, the
`app_control` config section and how blocking reaches the resolver and
the XDP blocklist.

One test runs a real dnsmasq with the generated config: a blocked app's
names answer NXDOMAIN, and the real query log fed to the daemon is
attributed to the right apps.
"""

from __future__ import annotations

import dataclasses
import json
import shutil
import socket
import subprocess
import threading
import time

import pytest

from frfw import appid, provision, xdp
from frfw.adblock import dns_service
from frfw.appid import AppMatcher, blocking_names, load_catalog, parse_catalog
from frfw.appid.daemon import AppIdDaemon, load_usage, source_units
from frfw.appid.usage import (
    ACTIVE_WINDOW_SECONDS,
    MAX_CLIENTS_PER_APP,
    RETENTION_SECONDS,
    UsageTracker,
)
from frfw.config import ConfigError, parse_config

requires_dnsmasq = pytest.mark.skipif(shutil.which("dnsmasq") is None, reason="dnsmasq not installed")

T0 = 1_700_000_000.0


def _raw(dhcp_config_dict, *, adblocker=None, xdp_filter=None, **app_control):
    raw = dict(dhcp_config_dict)
    raw["adblocker"] = adblocker if adblocker is not None else {
        "enabled": True, "source_urls": ["https://lists.example/ads"],
        "serve_lan": True, "query_logging": True,
    }
    if xdp_filter is not None:
        raw["xdp_sni_filter"] = xdp_filter
    raw["app_control"] = app_control
    return raw


# --- catalog ---------------------------------------------------------------------------


def test_bundled_catalog_is_sane():
    catalog = load_catalog()
    assert len(catalog.apps) >= 40
    assert catalog.license == "MIT"
    assert len(catalog.ref) == 40  # a pinned v2fly commit, not a branch name
    owners: dict[str, str] = {}
    for app in catalog.apps:
        assert app.domains or app.exact, app.id
        for name in app.all_names():
            assert name == name.lower() and not name.endswith(".")
            # The generator gives every name to exactly one app.
            assert owners.setdefault(name, app.id) == app.id, name


@pytest.mark.parametrize(
    "name, app",
    [
        ("www.netflix.com", "netflix"),
        ("rr3---sn-4g5e6nsz.googlevideo.com", "youtube"),
        ("scontent-vie1-1.xx.fbcdn.net", "facebook"),
        ("www.messenger.com", "messenger"),  # also claimed by the Facebook list
        ("web.whatsapp.com", "whatsapp"),
        ("WWW.TIKTOK.COM.", "tiktok"),
        ("zoom.us", "zoom"),
        ("steamcdn-a.akamaihd.net", "steam"),  # an exact CDN entry
    ],
)
def test_real_catalog_attributes_well_known_names(name, app):
    assert AppMatcher(load_catalog()).match(name) == app


@pytest.mark.parametrize(
    "name", ["notnetflix.com", "example.com", "akamaihd.net", "other.akamaihd.net", "", "."]
)
def test_real_catalog_does_not_match_lookalikes_or_shared_cdns(name):
    assert AppMatcher(load_catalog()).match(name) is None


def _catalog(*apps):
    return parse_catalog({"apps": [
        {"id": i, "name": i, "category": "c", "domains": d, "exact": e} for i, d, e in apps
    ]})


def test_longest_suffix_wins_and_exact_entries_do_not_cover_subdomains():
    matcher = AppMatcher(_catalog(
        ("umbrella", ["example.com"], []),
        ("specific", ["video.example.com"], ["cdn.other.net"]),
    ))
    assert matcher.match("a.video.example.com") == "specific"
    assert matcher.match("www.example.com") == "umbrella"
    assert matcher.match("cdn.other.net") == "specific"
    assert matcher.match("x.cdn.other.net") is None


@pytest.mark.parametrize("data", [[], {"apps": {}}, {"apps": [{"id": "x"}]},
                                  {"apps": [{"id": "a", "name": "a", "category": "c"}] * 2}])
def test_malformed_catalog_is_rejected(data):
    with pytest.raises(appid.CatalogError):
        parse_catalog(data)


def test_blocking_names_cover_exact_and_suffix_entries_of_the_chosen_apps():
    catalog = _catalog(("a", ["a.com"], ["x.cdn.net"]), ("b", ["b.com"], []))
    assert blocking_names(["a", "nope"], catalog) == ["a.com", "x.cdn.net"]


# --- usage accounting --------------------------------------------------------------------


def test_usage_snapshot_counts_hits_clients_and_activity():
    tracker = UsageTracker()
    tracker.record("netflix", "10.0.0.5", "dns", now=T0)
    tracker.record("netflix", "10.0.0.5", "sni", now=T0 + 60)
    tracker.record("netflix", "10.0.0.6", "dns", now=T0 - ACTIVE_WINDOW_SECONDS - 60)
    snap = tracker.snapshot(now=T0 + 60)
    netflix = snap["apps"]["netflix"]
    assert netflix["hits_24h"] == 3
    assert netflix["active_clients"] == 1
    assert netflix["clients"]["10.0.0.5"]["sources"] == ["dns", "sni"]
    assert netflix["clients"]["10.0.0.6"]["active"] is False


def test_usage_older_than_retention_is_pruned():
    tracker = UsageTracker()
    tracker.record("netflix", "10.0.0.5", "dns", now=T0)
    later = T0 + RETENTION_SECONDS + 2 * 3600
    tracker.record("zoom", "10.0.0.5", "dns", now=later)
    assert set(tracker.snapshot(now=later)["apps"]) == {"zoom"}


def test_usage_survives_a_restart_and_ignores_damaged_rows():
    tracker = UsageTracker()
    tracker.record("netflix", "10.0.0.5", "dns", now=T0)
    snap = json.loads(json.dumps(tracker.snapshot(now=T0)))
    snap["apps"]["zoom"] = {"clients": {"10.0.0.9": {"first_seen": "soon"}}}
    snap["apps"]["bogus"] = "not a dict"
    restored = UsageTracker.restore(snap)
    restored.record("netflix", "10.0.0.5", "dns", now=T0 + 1)
    assert set(restored.snapshot(now=T0 + 1)["apps"]) == {"netflix"}
    assert restored.snapshot(now=T0 + 1)["apps"]["netflix"]["hits_24h"] == 2
    assert UsageTracker.restore(None).snapshot(now=T0)["apps"] == {}


def test_client_count_per_app_is_bounded():
    tracker = UsageTracker()
    for i in range(MAX_CLIENTS_PER_APP + 5):
        tracker.record("netflix", f"10.1.{i // 256}.{i % 256}", "dns", now=T0 + i)
    clients = tracker.snapshot(now=T0 + 10_000)["apps"]["netflix"]["clients"]
    assert len(clients) == MAX_CLIENTS_PER_APP
    assert "10.1.0.0" not in clients  # the least recently seen went first


# --- daemon: log parsing ---------------------------------------------------------------------


class _Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now


def _daemon(dhcp_config_dict, tmp_path, clock=None, **app_control):
    config = parse_config(_raw(dhcp_config_dict, enabled=True, **app_control))
    return AppIdDaemon(config, usage_path=tmp_path / "usage.json", clock=clock or _Clock())


def test_dns_query_lines_are_attributed_and_other_lines_ignored(dhcp_config_dict, tmp_path):
    daemon = _daemon(dhcp_config_dict, tmp_path)
    for line in [
        "2 10.0.0.5/46381 query[A] www.netflix.com from 10.0.0.5",
        "2 10.0.0.5/46381 forwarded www.netflix.com to 1.1.1.1",
        "2 10.0.0.5/46381 reply www.netflix.com is 1.2.3.4",
        "7 10.0.0.5/1234 query[PTR] 5.0.0.10.in-addr.arpa from 10.0.0.5",
        "8 10.0.0.7/1234 query[A] unknown.example from 10.0.0.7",
        "started, version 2.91 cachesize 150",
        "",
    ]:
        daemon.handle_dns_log_line(line)
    apps = daemon.write_snapshot()["apps"]
    assert set(apps) == {"netflix"}
    assert apps["netflix"]["clients"]["10.0.0.5"]["hits_24h"] == 1


def test_simultaneous_record_types_count_once_but_later_lookups_count_again(dhcp_config_dict, tmp_path):
    clock = _Clock()
    daemon = _daemon(dhcp_config_dict, tmp_path, clock)
    for qtype in ("A", "AAAA", "HTTPS"):
        daemon.handle_dns_log_line(f"3 10.0.0.5/5 query[{qtype}] zoom.us from 10.0.0.5")
    clock.now += 60
    daemon.handle_dns_log_line("4 10.0.0.5/5 query[A] zoom.us from 10.0.0.5")
    assert daemon.write_snapshot()["apps"]["zoom"]["hits_24h"] == 2


def test_sni_events_count_passes_and_drops_only(dhcp_config_dict, tmp_path):
    daemon = _daemon(dhcp_config_dict, tmp_path)
    ev = {"ts": T0, "saddr": "10.0.0.8", "sport": 5, "daddr": "1.2.3.4", "dport": 443}
    daemon.handle_sni_event_line(json.dumps({**ev, "action": "pass", "sni": "www.reddit.com"}))
    daemon.handle_sni_event_line(json.dumps({**ev, "action": "drop", "sni": "discord.gg"}))
    daemon.handle_sni_event_line(json.dumps({**ev, "action": "maybe", "sni": "zoom.us"}))
    daemon.handle_sni_event_line("not json")
    daemon.handle_sni_event_line(json.dumps(["a", "list"]))
    apps = daemon.write_snapshot()["apps"]
    assert set(apps) == {"reddit", "discord"}
    assert apps["reddit"]["clients"]["10.0.0.8"]["sources"] == ["sni"]


def test_snapshot_is_written_atomically_and_reloaded_on_start(dhcp_config_dict, tmp_path):
    daemon = _daemon(dhcp_config_dict, tmp_path)
    daemon.observe("10.0.0.5", "www.netflix.com", "dns")
    daemon.write_snapshot()
    assert not (tmp_path / "usage.tmp").exists()
    assert load_usage(tmp_path / "usage.json")["apps"]["netflix"]["hits_24h"] == 1
    again = _daemon(dhcp_config_dict, tmp_path)
    again.observe("10.0.0.5", "www.netflix.com", "sni")
    assert again.write_snapshot()["apps"]["netflix"]["hits_24h"] == 2


def test_load_usage_tolerates_missing_or_damaged_file(tmp_path):
    assert load_usage(tmp_path / "nope.json") == {"generated": None, "apps": {}}
    (tmp_path / "bad.json").write_text("{")
    assert load_usage(tmp_path / "bad.json")["apps"] == {}


def test_source_units_follow_the_config(dhcp_config_dict):
    xdp_on = {"enabled": True, "interfaces": ["lan"]}
    assert source_units(parse_config(_raw(dhcp_config_dict, enabled=False))) == []
    assert source_units(parse_config(_raw(dhcp_config_dict, enabled=True))) == ["fr-adblock-dns.service"]
    both = parse_config(_raw(dhcp_config_dict, xdp_filter=xdp_on, enabled=True, observe_sni=True))
    assert source_units(both) == ["fr-adblock-dns.service", "fr-xdp-sni-logger.service"]
    no_logging = _raw(dhcp_config_dict, xdp_filter=xdp_on, enabled=True, observe_sni=True)
    no_logging["adblocker"]["query_logging"] = False
    assert source_units(parse_config(no_logging)) == ["fr-xdp-sni-logger.service"]


# --- config ---------------------------------------------------------------------------------


def test_app_control_defaults_and_round_trip(dhcp_config_dict, minimal_config_dict):
    default = parse_config(minimal_config_dict).app_control
    assert (default.enabled, default.blocked_apps, default.observe_sni, default.block_via_xdp) == (
        False, [], False, False
    )
    config = parse_config(_raw(
        dhcp_config_dict, xdp_filter={"enabled": True, "interfaces": ["lan"]},
        enabled=True, blocked_apps=["tiktok", "roblox"], block_via_xdp=True, observe_sni=True,
    ))
    assert config.app_control.blocked_apps == ["tiktok", "roblox"]


@pytest.mark.parametrize(
    "app_control, error",
    [
        ({"enabled": "yes"}, "app_control.enabled must be a boolean"),
        ({"blocked_apps": "tiktok"}, "must be a list"),
        ({"blocked_apps": ["myspace"]}, "unknown app 'myspace'"),
        ({"blocked_apps": ["tiktok", "tiktok"]}, "listed twice"),
        ({"enabled": True, "observe_sni": True}, "observe_sni requires xdp_sni_filter.enabled"),
        ({"enabled": True, "block_via_xdp": True}, "block_via_xdp requires xdp_sni_filter.enabled"),
    ],
)
def test_invalid_app_control(dhcp_config_dict, app_control, error):
    with pytest.raises(ConfigError, match=error):
        parse_config(_raw(dhcp_config_dict, **app_control))


def test_blocking_needs_the_resolver_serving_the_lan(dhcp_config_dict):
    adblocker = {"enabled": True, "source_urls": ["https://x/ads"]}
    with pytest.raises(ConfigError, match="needs adblocker.enabled and adblocker.serve_lan"):
        parse_config(_raw(dhcp_config_dict, adblocker=adblocker, enabled=True, blocked_apps=["tiktok"]))
    # ...but a disabled section never fails on another section's settings.
    parse_config(_raw(dhcp_config_dict, adblocker={}, enabled=False, blocked_apps=["tiktok"],
                      observe_sni=True))


# --- enforcement --------------------------------------------------------------------------


def test_resolver_config_blocks_every_name_of_blocked_apps_only_while_enabled(dhcp_config_dict, tmp_path):
    def render(**app_control):
        config = parse_config(_raw(dhcp_config_dict, **app_control))
        return dns_service.render_dnsmasq_config(config, hosts_path=tmp_path / "h", category_dir=tmp_path / "d")

    text = render(enabled=True, blocked_apps=["tiktok"])
    lines = [l for l in text.splitlines() if l.startswith("address=/")]
    tiktok = load_catalog().by_id()["tiktok"]
    assert lines == [f"address=/{n}/" for n in sorted(tiktok.all_names())]
    assert "address=/" not in render(enabled=False, blocked_apps=["tiktok"])


def test_provision_merges_short_blocked_app_names_into_xdp_blocklist(dhcp_config_dict, tmp_path, monkeypatch):
    seen = {}

    def fake_sync(config, *, dry_run, state_path):
        seen["blocklist"] = config.xdp_sni_filter.blocklist
        return xdp.SyncResult(False, "xdp")

    monkeypatch.setattr(provision.xdp, "sync_sni_filter", fake_sync)
    config = parse_config(_raw(
        dhcp_config_dict, xdp_filter={"enabled": True, "interfaces": ["lan"], "blocklist": ["own.example"]},
        enabled=True, blocked_apps=["tiktok"], block_via_xdp=True,
    ))
    provision.apply_all(config, dry_run=True, backup_dir=tmp_path, kea_config_path=tmp_path / "kea.json",
                        xdp_state_path=tmp_path / "xdp.json")
    names = load_catalog().by_id()["tiktok"].all_names()
    expected = {"own.example"} | {n for n in names if len(n) < xdp.MAX_SNI_LEN}
    assert set(seen["blocklist"]) == expected
    assert any(len(n) >= xdp.MAX_SNI_LEN for n in names)  # some really are too long for XDP

    no_xdp = dataclasses.replace(config, app_control=dataclasses.replace(config.app_control, block_via_xdp=False))
    provision.apply_all(no_xdp, dry_run=True, backup_dir=tmp_path, kea_config_path=tmp_path / "kea.json",
                        xdp_state_path=tmp_path / "xdp.json")
    assert seen["blocklist"] == ["own.example"]


def test_xdp_sync_refuses_a_blocklist_larger_than_the_kernel_map(minimal_config_dict, tmp_path, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)
    raw = dict(minimal_config_dict)
    raw["xdp_sni_filter"] = {"enabled": True, "interfaces": ["lan"]}
    config = parse_config(raw)
    big = dataclasses.replace(config, xdp_sni_filter=dataclasses.replace(
        config.xdp_sni_filter, blocklist=[f"n{i}.example" for i in range(xdp.BLOCKLIST_MAX_ENTRIES + 1)]
    ))
    with pytest.raises(xdp.XdpError, match="more than the kernel map"):
        xdp.sync_sni_filter(big, state_path=tmp_path / "state.json")


def test_xdp_sync_turns_pass_reporting_on_and_off(minimal_config_dict, tmp_path, monkeypatch):
    calls = []
    settings = tmp_path / "settings"
    settings.touch()
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(xdp, "PIN_SETTINGS_PATH", settings)
    monkeypatch.setattr(xdp, "ensure_compiled", lambda: tmp_path / "x.o")
    monkeypatch.setattr(xdp, "load_and_pin", lambda obj: None)
    monkeypatch.setattr(xdp, "attach", lambda dev: xdp.AttachMode.GENERIC)
    monkeypatch.setattr(xdp, "sync_blocklist", lambda names: None)
    monkeypatch.setattr(xdp, "_map_update", lambda path, key, value: calls.append(value))
    raw = dict(minimal_config_dict)
    raw["xdp_sni_filter"] = {"enabled": True, "interfaces": ["lan"]}
    raw["app_control"] = {"enabled": True, "observe_sni": True}
    result = xdp.sync_sni_filter(parse_config(raw), state_path=tmp_path / "state.json")
    assert "reporting passed SNIs" in result.message
    raw["app_control"] = {"enabled": False, "observe_sni": True}
    xdp.sync_sni_filter(parse_config(raw), state_path=tmp_path / "state.json")
    assert calls == [b"\x01\x00\x00\x00", b"\x00\x00\x00\x00"]


def test_xdp_sync_explains_when_the_loaded_program_predates_pass_reporting(minimal_config_dict, tmp_path, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(xdp, "PIN_SETTINGS_PATH", tmp_path / "missing")
    monkeypatch.setattr(xdp, "ensure_compiled", lambda: tmp_path / "x.o")
    monkeypatch.setattr(xdp, "load_and_pin", lambda obj: None)
    monkeypatch.setattr(xdp, "attach", lambda dev: xdp.AttachMode.GENERIC)
    monkeypatch.setattr(xdp, "sync_blocklist", lambda names: None)
    raw = dict(minimal_config_dict)
    raw["xdp_sni_filter"] = {"enabled": True, "interfaces": ["lan"]}
    raw["app_control"] = {"enabled": True, "observe_sni": True}
    result = xdp.sync_sni_filter(parse_config(raw), state_path=tmp_path / "state.json")
    assert "predates it" in result.message
    with pytest.raises(xdp.XdpError, match="no settings map"):
        xdp.set_report_pass(True)


def test_pass_event_decoding_and_json():
    raw = bytearray(xdp._EVENT_SIZE)
    raw[0:4] = socket.inet_aton("10.0.0.5")
    raw[4:8] = socket.inet_aton("1.2.3.4")
    raw[8:12] = (40000).to_bytes(2, "little") + (443).to_bytes(2, "little")
    raw[12] = 0
    raw[14:16] = (7).to_bytes(2, "little")
    raw[16:23] = b"zoom.us"
    event = xdp.SniEvent.from_bytes(bytes(raw))
    assert (event.action, event.hostname, event.saddr) == ("pass", "zoom.us", "10.0.0.5")
    assert json.loads(xdp.format_event_json(event))["action"] == "pass"


# --- real dnsmasq, end to end --------------------------------------------------------------


def _query(port: int, name: str) -> int:
    packet = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    packet += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        s.sendto(packet, ("127.0.0.1", port))
        data, _ = s.recvfrom(4096)
    return data[3] & 0x0F


@requires_dnsmasq
def test_real_dnsmasq_blocks_apps_and_its_log_is_attributed(dhcp_config_dict, tmp_path):
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 0))
    up_port = upstream.getsockname()[1]

    def serve():  # NOERROR, no answers, for anything forwarded
        while True:
            try:
                data, addr = upstream.recvfrom(4096)
            except OSError:
                return
            upstream.sendto(data[:2] + b"\x81\x80" + data[4:6] + b"\0" * 6 + data[12:], addr)

    threading.Thread(target=serve, daemon=True).start()
    config = parse_config(_raw(dhcp_config_dict, enabled=True, blocked_apps=["tiktok"]))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    text = dns_service.render_dnsmasq_config(config, hosts_path=tmp_path / "h", category_dir=tmp_path / "d")
    text = text.replace("port=53\n", f"port={port}\n").replace("server=1.1.1.1", f"server=127.0.0.1#{up_port}")
    text = text.replace("user=nobody\ngroup=nogroup\n", "user=root\n")
    text = "\n".join(l for l in text.splitlines() if not l.startswith("interface=")) + "\nlisten-address=127.0.0.1\n"
    (tmp_path / "h").write_text("")
    log = tmp_path / "dnsmasq.log"
    conf = tmp_path / "dnsmasq.conf"
    conf.write_text(text + f"log-facility={log}\n")

    proc = subprocess.Popen(["dnsmasq", "--keep-in-foreground", f"--conf-file={conf}"])
    try:
        deadline = time.time() + 5
        while time.time() < deadline and "started" not in (log.read_text() if log.exists() else ""):
            time.sleep(0.1)
        assert _query(port, "www.tiktok.com") == 3
        assert _query(port, "tiktokcdn.com") == 3
        assert _query(port, "www.netflix.com") == 0
        assert _query(port, "example.org") == 0
        time.sleep(0.3)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        upstream.close()

    daemon = AppIdDaemon(config, usage_path=tmp_path / "usage.json")
    for line in log.read_text().splitlines():
        if ": " in line:
            daemon.handle_dns_log_line(line.split(": ", 1)[1])
    apps = daemon.write_snapshot()["apps"]
    assert set(apps) == {"tiktok", "netflix"}
    assert apps["tiktok"]["hits_24h"] == 2  # blocked lookups are still attempts
    assert set(apps["netflix"]["clients"]) == {"127.0.0.1"}
