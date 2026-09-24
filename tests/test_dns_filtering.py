"""Phase 15: categorized DNS filtering, allowlist, LAN DNS enforcement,
the DGA heuristic, and the DNS signals fed to the AI IDS.

Network fetches go through frfw.adblock's one `_fetch_url` seam
(monkeypatched, like tests/test_adblock.py). Where the environment has a
real `dnsmasq`/`nft`, the generated configs are checked against them, and
one test runs a real dnsmasq instance end to end: blocked lookups,
the DoH canary, the query log, and the AI IDS consuming that log.
"""

from __future__ import annotations

import random
import shutil
import socket
import string
import struct
import subprocess
import threading
import time

import pytest

from frfw import adblock
from frfw.adblock import dga, dns_service
from frfw.adblock.categories import PRESETS, THREAT_CATEGORIES
from frfw.ai_ids.daemon import IDSDaemon
from frfw.ai_ids.engine import AnomalyEngine
from frfw.config import ConfigError, parse_config
from frfw.kea import build_kea_config
from frfw.nft import build_ruleset

requires_dnsmasq = pytest.mark.skipif(shutil.which("dnsmasq") is None, reason="dnsmasq not installed")
requires_nft = pytest.mark.skipif(shutil.which("nft") is None, reason="nft not installed")


def _config(dhcp_config_dict, **adblocker):
    raw = dict(dhcp_config_dict)
    raw["adblocker"] = {"enabled": True, "source_urls": ["https://lists.example/ads"], **adblocker}
    return parse_config(raw)


# --- parsing: plain domain lists ------------------------------------------------


def test_parse_accepts_plain_domain_lists_and_rejects_filter_syntax():
    text = "# Phishing Army\n0-ilxrc-w285.p9bckp.sbs\nBAD.Example.org.\n||adblock.style^\nnodot\nlocalhost\n"
    assert adblock.parse_hosts_text(text) == {"0-ilxrc-w285.p9bckp.sbs", "bad.example.org"}


def test_parse_urlhaus_tab_separated_hosts_format():
    text = "#####\n# abuse.ch URLhaus Host file\n127.0.0.1\t123.ywxww.net\n127.0.0.1\t198-macros.com\n"
    assert adblock.parse_hosts_text(text) == {"123.ywxww.net", "198-macros.com"}


# --- refresh with categories --------------------------------------------------


@pytest.fixture
def fake_fetch(monkeypatch):
    pages = {}

    def fetch(url, timeout):
        if url not in pages:
            raise adblock.AdblockError(f"could not fetch {url}: 404")
        return pages[url]

    monkeypatch.setattr(adblock, "_fetch_url", fetch)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    return pages


def test_refresh_writes_one_file_per_category(fake_fetch, tmp_path):
    fake_fetch["https://a/ads"] = "0.0.0.0 ads.example\n"
    fake_fetch["https://a/mal"] = "127.0.0.1\tbad.example\n127.0.0.1\tworse.example\n"
    fake_fetch["https://a/phish"] = "phish.example\n"
    result = adblock.refresh(
        ["https://a/ads"],
        hosts_path=tmp_path / "adblock.hosts",
        categories={"malware": ["https://a/mal"], "phishing": ["https://a/phish"]},
        category_dir=tmp_path / "adblock.d",
    )
    assert result.category_counts == {"ads": 1, "malware": 2, "phishing": 1}
    assert adblock.read_hosts_file(tmp_path / "adblock.d" / "malware.hosts") == {"bad.example", "worse.example"}
    assert adblock.category_counts(["malware", "phishing"], hosts_path=tmp_path / "adblock.hosts",
                                   category_dir=tmp_path / "adblock.d") == {"ads": 1, "malware": 2, "phishing": 1}


def test_refresh_applies_allowlist_including_subdomains(fake_fetch, tmp_path):
    fake_fetch["https://a/ads"] = "0.0.0.0 cdn.good.example\n0.0.0.0 good.example\n0.0.0.0 bad.example\n0.0.0.0 notgood.example\n"
    adblock.refresh(["https://a/ads"], hosts_path=tmp_path / "h", category_dir=tmp_path / "d", allowlist=["good.example"])
    assert adblock.read_hosts_file(tmp_path / "h") == {"bad.example", "notgood.example"}


def test_refresh_never_blocks_the_firefox_doh_canary(fake_fetch, tmp_path):
    """The real DoH-resolver list contains the canary; blocking it with
    0.0.0.0 would defeat Firefox's DoH opt-out (found end to end)."""
    fake_fetch["https://a/doh"] = "dns.google\nuse-application-dns.net\n"
    adblock.refresh([], hosts_path=tmp_path / "h", categories={"doh-bypass": ["https://a/doh"]}, category_dir=tmp_path / "d")
    assert adblock.read_hosts_file(tmp_path / "d" / "doh-bypass.hosts") == {"dns.google"}


def test_refresh_keeps_previous_file_when_a_category_fails_entirely(fake_fetch, tmp_path):
    (tmp_path / "d").mkdir()
    adblock.write_hosts_file({"old.example"}, tmp_path / "d" / "malware.hosts")
    fake_fetch["https://a/ads"] = "0.0.0.0 ads.example\n"
    result = adblock.refresh(
        ["https://a/ads"], hosts_path=tmp_path / "h",
        categories={"malware": ["https://a/down"]}, category_dir=tmp_path / "d",
    )
    assert "kept previous list for: malware" in result.message
    assert adblock.read_hosts_file(tmp_path / "d" / "malware.hosts") == {"old.example"}


def test_refresh_removes_categories_dropped_from_config(fake_fetch, tmp_path):
    (tmp_path / "d").mkdir()
    adblock.write_hosts_file({"x.example"}, tmp_path / "d" / "gambling.hosts")
    fake_fetch["https://a/ads"] = "0.0.0.0 ads.example\n"
    adblock.refresh(["https://a/ads"], hosts_path=tmp_path / "h", categories={}, category_dir=tmp_path / "d")
    assert not (tmp_path / "d" / "gambling.hosts").exists()


def test_presets_are_valid_config():
    names = {p.name for p in PRESETS}
    assert THREAT_CATEGORIES <= names
    raw_categories = {p.name: list(p.urls) for p in PRESETS}
    config = parse_config(
        {"version": 1, "hostname": "t", "zones": {"lan": {}}, "interfaces": {"lan": {"device": "eth1", "zone": "lan"}},
         "rules": [], "nat": {}, "adblocker": {"enabled": True, "categories": raw_categories}}
    )
    assert set(config.adblocker.categories) == names
    assert any("non-commercial" in p.note for p in PRESETS if p.name == "phishing")


# --- config validation ------------------------------------------------------------


def test_categories_and_flags_parse(dhcp_config_dict):
    config = _config(
        dhcp_config_dict,
        categories={"malware": ["https://urlhaus.abuse.ch/downloads/hostfile/"]},
        allowlist=["Example.COM."],
        serve_lan=True,
        force_dns=True,
        query_logging=True,
    )
    assert config.adblocker.categories == {"malware": ["https://urlhaus.abuse.ch/downloads/hostfile/"]}
    assert config.adblocker.allowlist == ["example.com"]
    assert config.adblocker.serve_lan and config.adblocker.force_dns and config.adblocker.query_logging


@pytest.mark.parametrize(
    "adblocker,error",
    [
        ({"categories": {"ads": ["https://x/y"]}}, "'ads' is reserved"),
        ({"categories": {"Bad Name": ["https://x/y"]}}, "Invalid adblocker category name"),
        ({"categories": {"malware": []}}, "has no URLs"),
        ({"categories": {"malware": ["ftp://x"]}}, "invalid URL"),
        ({"allowlist": ["not a domain"]}, "invalid domain name"),
        ({"force_dns": True}, "force_dns requires adblocker.serve_lan"),
        ({"serve_lan": "yes"}, "must be a boolean"),
    ],
)
def test_invalid_adblocker_settings(dhcp_config_dict, adblocker, error):
    with pytest.raises(ConfigError, match=error):
        _config(dhcp_config_dict, **adblocker)


def test_serve_lan_needs_a_dhcp_pool(minimal_config_dict):
    minimal_config_dict["adblocker"] = {"enabled": True, "source_urls": ["https://x/y"], "serve_lan": True}
    with pytest.raises(ConfigError, match="needs at least one DHCP pool"):
        parse_config(minimal_config_dict)


def test_categories_alone_are_enough_to_enable(minimal_config_dict):
    minimal_config_dict["adblocker"] = {"enabled": True, "categories": {"malware": ["https://x/y"]}}
    assert parse_config(minimal_config_dict).adblocker.enabled


# --- generated configs: dnsmasq, Kea, nftables ------------------------------------


def test_dnsmasq_config_lists_every_category_and_optional_lines(dhcp_config_dict, tmp_path):
    config = _config(dhcp_config_dict, categories={"phishing": ["https://x/p"], "malware": ["https://x/m"]},
                     serve_lan=True, force_dns=True, query_logging=True)
    text = dns_service.render_dnsmasq_config(config, hosts_path=tmp_path / "h", category_dir=tmp_path / "d")
    lines = text.splitlines()
    assert [l for l in lines if l.startswith("addn-hosts=")] == [
        f"addn-hosts={tmp_path / 'h'}", f"addn-hosts={tmp_path / 'd' / 'malware.hosts'}",
        f"addn-hosts={tmp_path / 'd' / 'phishing.hosts'}",
    ]
    assert "log-queries=extra" in lines
    assert "address=/use-application-dns.net/" in lines


def test_dnsmasq_config_omits_optional_lines_by_default(dhcp_config_dict, tmp_path):
    text = dns_service.render_dnsmasq_config(_config(dhcp_config_dict), hosts_path=tmp_path / "h", category_dir=tmp_path / "d")
    assert "log-queries" not in text and "use-application-dns.net" not in text


def test_upstreams_never_include_the_router_itself(dhcp_config_dict):
    dhcp_config_dict["dhcp"]["lan"]["dns_servers"] = ["10.0.0.1", "9.9.9.9"]  # 10.0.0.1 is the router
    config = _config(dhcp_config_dict, serve_lan=True)
    assert dns_service._upstream_servers(config) == ["9.9.9.9"]


@requires_dnsmasq
def test_full_featured_dnsmasq_config_passes_real_dnsmasq_test(dhcp_config_dict, tmp_path):
    config = _config(dhcp_config_dict, categories={"malware": ["https://x/m"]}, serve_lan=True, force_dns=True, query_logging=True)
    for path in (tmp_path / "h", tmp_path / "d" / "malware.hosts"):
        adblock.write_hosts_file({"bad.example"}, path)
    conf = tmp_path / "dnsmasq.conf"
    conf.write_text(dns_service.render_dnsmasq_config(config, hosts_path=tmp_path / "h", category_dir=tmp_path / "d"))
    proc = subprocess.run(["dnsmasq", "--test", f"--conf-file={conf}"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_enforce_allowlist_removes_entries_on_apply(dhcp_config_dict, tmp_path):
    adblock.write_hosts_file({"a.example", "keep.example"}, tmp_path / "h")
    adblock.write_hosts_file({"sub.a.example", "use-application-dns.net"}, tmp_path / "d" / "malware.hosts")
    config = _config(dhcp_config_dict, categories={"malware": ["https://x/m"]}, allowlist=["a.example"])
    removed = dns_service.enforce_allowlist(config, hosts_path=tmp_path / "h", category_dir=tmp_path / "d")
    assert removed == 3
    assert adblock.read_hosts_file(tmp_path / "h") == {"keep.example"}
    assert adblock.read_hosts_file(tmp_path / "d" / "malware.hosts") == set()


def test_kea_announces_router_only_with_serve_lan(dhcp_config_dict):
    def dns_option(config):
        options = build_kea_config(config)["Dhcp4"]["subnet4"][0]["option-data"]
        return next(o["data"] for o in options if o["name"] == "domain-name-servers")

    assert dns_option(_config(dhcp_config_dict)) == "1.1.1.1"
    assert dns_option(_config(dhcp_config_dict, serve_lan=True)) == "10.0.0.1"


def test_ruleset_serve_lan_accepts_dns_and_force_dns_redirects(dhcp_config_dict):
    plain = build_ruleset(_config(dhcp_config_dict))
    assert "dns-resolver" not in plain and "force-dns" not in plain

    served = build_ruleset(_config(dhcp_config_dict, serve_lan=True))
    assert 'iifname @lan_ifaces udp dport 53 accept comment "dns-resolver"' in served
    assert "force-dns" not in served

    forced = build_ruleset(_config(dhcp_config_dict, serve_lan=True, force_dns=True))
    assert 'iifname @lan_ifaces udp dport 53 redirect to :53 comment "force-dns"' in forced
    assert 'iifname @lan_ifaces tcp dport 853 reject comment "force-dns-block-dot"' in forced


@requires_nft
def test_force_dns_ruleset_passes_nft_check_even_without_other_nat(dhcp_config_dict):
    dhcp_config_dict["nat"] = {}
    ruleset = build_ruleset(_config(dhcp_config_dict, serve_lan=True, force_dns=True))
    assert "chain prerouting" in ruleset
    proc = subprocess.run(["nft", "-c", "-f", "-"], input=ruleset, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


# --- DGA heuristic ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,label",
    [("www.example.co.uk", "example"), ("a.b.example.com", "example"), ("example.com.", "example"),
     ("localhost", None), ("bad..name", None)],
)
def test_registered_label(name, label):
    assert dga.registered_label(name) == label


@pytest.mark.parametrize(
    "name",
    ["d1a2b3c4d5e6f7.cloudfront.net", "r4---sn-4g5e6nzz.googlevideo.com", "xmzkfjqabcde",
     "xn--72ca2bsl7gxbd4m7c.com", "www.wikipedia.org", "sputniknews.com", "humboldtreview.com",
     "microsoftonline.com", "googleusercontent.com", "stackoverflow.com"],
)
def test_ordinary_and_cdn_names_are_not_flagged(name):
    assert not dga.looks_generated(name)


def test_random_names_are_mostly_flagged_and_real_brands_are_not():
    rng = random.Random(1234)
    randoms = ["".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(12, 20))) + ".com" for _ in range(500)]
    assert sum(map(dga.looks_generated, randoms)) / len(randoms) > 0.45
    brands = ["facebook", "instagram", "wikipedia", "microsoft", "netflix", "amazonaws", "cloudflare", "whatsapp",
              "linkedin", "pinterest", "salesforce", "spotify", "dropbox", "wordpress", "blogspot", "bloomberg",
              "washingtonpost", "nytimes", "theguardian", "booking", "tripadvisor", "stackexchange", "craigslist",
              "duckduckgo", "protonmail", "telegram", "deutschebahn", "mercadolibre", "aliexpress", "rakuten"]
    assert [b for b in brands if dga.looks_generated(b + ".com")] == []


# --- AI IDS: DNS features ------------------------------------------------------------------


def test_engine_counts_distinct_nxdomain_names_not_retries():
    engine = AnomalyEngine()
    for _ in range(100):
        engine.observe_dns_nxdomain("10.0.0.5", "dead.example", generated=False, now=0.0)
    assert engine.evaluate("10.0.0.5", now=1.0) is None  # one dead name retried, not a burst


def test_engine_flags_dga_burst_and_threat_lookups():
    engine = AnomalyEngine()
    for i in range(12):
        engine.observe_dns_nxdomain("10.0.0.6", f"rnd{i}xkqjzpvtr.com", generated=True, now=0.0)
    for _ in range(3):
        engine.observe_dns_threat_block("10.0.0.6", now=0.0)
    event = engine.evaluate("10.0.0.6", now=1.0)
    assert event is not None
    assert set(event.reasons) == {"DGA-like NXDOMAIN lookups", "malware/phishing DNS lookups"}
    assert (event.dga_nxdomain_count, event.dns_threat_count) == (12, 3)


def _daemon(dhcp_config_dict, tmp_path, categories):
    raw = dict(dhcp_config_dict)
    raw["adblocker"] = {"enabled": True, "categories": {c: ["https://x/y"] for c in categories}, "query_logging": True}
    raw["ai_ids"] = {"enabled": True}
    return IDSDaemon(parse_config(raw), clock=lambda: 0.0, adblock_category_dir=tmp_path / "d",
                     quarantine_fn=lambda ip, d: {"ok": True}, events_path=tmp_path / "events.json")


def test_daemon_parses_real_dnsmasq_log_lines(dhcp_config_dict, tmp_path):
    daemon = _daemon(dhcp_config_dict, tmp_path, ["malware", "gambling"])
    malware_file = tmp_path / "d" / "malware.hosts"
    lines = [
        "1 10.0.0.9/33904 query[A] bad.example from 10.0.0.9",
        f"1 10.0.0.9/33904 {malware_file} bad.example is 0.0.0.0",
        f"2 10.0.0.9/33905 {tmp_path / 'd' / 'gambling.hosts'} casino.example is 0.0.0.0",  # policy, not a threat
        "3 10.0.0.9/46443 forwarded xkqjzpvtrwmnbfgh.com to 1.1.1.1",
        "3 10.0.0.9/46443 reply xkqjzpvtrwmnbfgh.com is NXDOMAIN",
        "4 10.0.0.9/46444 cached www.nxtest.example is NXDOMAIN",
        "5 10.0.0.9/46445 config use-application-dns.net is NXDOMAIN",  # the DoH canary: ignored
        "started, version 2.91 cachesize 150",
    ]
    for line in lines:
        daemon.handle_dns_log_line(line)
    window = daemon.engine._ips["10.0.0.9"]
    assert len(window.dns_threat_ts) == 1
    assert {n for _t, n in window.nxdomain_ts} == {"xkqjzpvtrwmnbfgh.com", "www.nxtest.example"}
    assert {n for _t, n in window.dga_nxdomain_ts} == {"xkqjzpvtrwmnbfgh.com"}


# --- real dnsmasq, end to end ------------------------------------------------------------------


def _query(port: int, name: str, qtype: int = 1) -> int:
    packet = struct.pack("!HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0)
    packet += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack("!HH", qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        s.sendto(packet, ("127.0.0.1", port))
        data, _ = s.recvfrom(4096)
    return data[3] & 0x0F  # rcode


@requires_dnsmasq
def test_real_dnsmasq_blocks_logs_and_feeds_the_ai_ids(dhcp_config_dict, tmp_path):
    """A real dnsmasq with the generated config: a malware-category name is
    answered 0.0.0.0 from its category file, the DoH canary is NXDOMAIN
    even though the DoH list contains it, random names forwarded to a
    (fake, NXDOMAIN-only) upstream are logged -- and that real log, fed
    line by line to the AI IDS daemon, gets the host flagged."""
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 0))
    up_port = upstream.getsockname()[1]

    def serve():
        while True:
            try:
                data, addr = upstream.recvfrom(4096)
            except OSError:
                return
            upstream.sendto(data[:2] + bytes([0x81, 0x83]) + data[4:6] + b"\0" * 6 + data[12:], addr)

    threading.Thread(target=serve, daemon=True).start()

    config = _config(
        dhcp_config_dict,
        categories={"malware": ["https://x/m"], "doh-bypass": ["https://x/d"]},
        serve_lan=True, force_dns=True, query_logging=True,
    )
    adblock.write_hosts_file({"ads.example"}, tmp_path / "h")
    adblock.write_hosts_file({"bad-malware.example"}, tmp_path / "d" / "malware.hosts")
    adblock.write_hosts_file({"dns.google", "use-application-dns.net"}, tmp_path / "d" / "doh-bypass.hosts")
    dns_service.enforce_allowlist(config, hosts_path=tmp_path / "h", category_dir=tmp_path / "d")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    text = dns_service.render_dnsmasq_config(config, hosts_path=tmp_path / "h", category_dir=tmp_path / "d")
    text = text.replace("port=53\n", f"port={port}\n").replace("server=1.1.1.1", f"server=127.0.0.1#{up_port}")
    # dnsmasq drops to `nobody` by default, which can't read pytest's 0700
    # tmp dir (production lists live in world-readable /etc/fr_os paths).
    text = text.replace("user=nobody\ngroup=nogroup\n", "user=root\n")
    text = "\n".join(l for l in text.splitlines() if not l.startswith("interface=")) + "\nlisten-address=127.0.0.1\n"
    log = tmp_path / "dnsmasq.log"
    conf = tmp_path / "dnsmasq.conf"
    conf.write_text(text + f"log-facility={log}\n")

    proc = subprocess.Popen(["dnsmasq", "--keep-in-foreground", f"--conf-file={conf}"])
    try:
        deadline = time.time() + 5
        while time.time() < deadline and "started" not in (log.read_text() if log.exists() else ""):
            time.sleep(0.1)
        assert _query(port, "bad-malware.example") == 0
        assert _query(port, "use-application-dns.net") == 3
        assert _query(port, "use-application-dns.net", qtype=28) == 3
        rng = random.Random(99)
        for _ in range(25):
            _query(port, "".join(rng.choice(string.ascii_lowercase) for _ in range(16)) + ".com")
        time.sleep(0.3)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        upstream.close()

    messages = [l.split(": ", 1)[1] for l in log.read_text().splitlines() if ": " in l]
    assert any(m.endswith("bad-malware.example is 0.0.0.0") and "malware.hosts" in m for m in messages)

    daemon = _daemon(dhcp_config_dict, tmp_path, ["malware", "doh-bypass"])
    for m in messages:
        daemon.handle_dns_log_line(m)
    (event,) = daemon.evaluate_and_enforce()
    assert event.ip == "127.0.0.1"
    assert "DGA-like NXDOMAIN lookups" in event.reasons
    assert event.dns_threat_count == 1
