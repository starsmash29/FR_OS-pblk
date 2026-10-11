"""Local names and split-horizon overrides (ROADMAP DNS-1).

`local_dns` is answered by the router's own resolver (the ad-block
dnsmasq, frfw.adblock.dns_service): the config's validation, the
generated lines, that a local name is never blocked, and a real dnsmasq
answering for it -- without asking the upstream, over IPv4 or IPv6.
"""

from __future__ import annotations

import random
import shutil
import socket
import struct
import subprocess
import threading
import time

import pytest

from frfw import adblock
from frfw.adblock import dns_service
from frfw.config import ConfigError, parse_config

requires_dnsmasq = pytest.mark.skipif(shutil.which("dnsmasq") is None, reason="dnsmasq not installed")


def _raw(dhcp_config_dict, local_dns, *, serve_lan=True, enabled=True, **extra):
    raw = dict(dhcp_config_dict)
    raw["adblocker"] = {"enabled": enabled, "source_urls": ["https://lists.example/ads"], "serve_lan": serve_lan}
    raw["local_dns"] = local_dns
    raw.update(extra)
    return raw


def _config(dhcp_config_dict, local_dns, **kwargs):
    return parse_config(_raw(dhcp_config_dict, local_dns, **kwargs))


# --- the config ----------------------------------------------------------------


def test_names_are_normalized_and_addresses_checked(dhcp_config_dict):
    config = _config(dhcp_config_dict, {
        "domain": "LAN.",
        "hosts": {"NAS.lan.": "192.168.10.20"},
        "overrides": {"intranet.example.com": "10.73.1.5"},
    })
    assert config.local_dns.domain == "lan"
    assert config.local_dns.hosts == {"nas.lan": "192.168.10.20"}
    assert config.local_dns.overrides == {"intranet.example.com": "10.73.1.5"}
    assert config.local_dns.names() == ["nas.lan", "intranet.example.com", "lan"]


def test_no_local_dns_is_the_default(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    assert config.local_dns.names() == []
    assert dns_service.local_dns_lines(config) == []


@pytest.mark.parametrize("local_dns, message", [
    ({"hosts": {"nas.lan": "192.168.10.300"}}, "invalid IPv4 address"),
    ({"hosts": {"nas.lan": "fd00::1"}}, "invalid IPv4 address"),
    ({"hosts": {"nas lan": "10.0.0.5"}}, "invalid hostname"),
    ({"hosts": {"nas.lan/#": "10.0.0.5"}}, "invalid hostname"),  # would end dnsmasq's address=/name/
    ({"hosts": {"nas.lan,10.6.6.6": "10.0.0.5"}}, "invalid hostname"),  # a second host-record address
    ({"hosts": {"nas.lan\nserver=6.6.6.6": "10.0.0.5"}}, "invalid hostname"),  # a config line of its own
    ({"overrides": {"com": "10.0.0.5"}}, "at least two labels"),
    ({"hosts": {"nas": "10.0.0.5"}}, "at least two labels"),
    ({"domain": "com"}, "could be a public top-level domain"),
    ({"hosts": {"nas.lan": "10.0.0.5"}, "overrides": {"nas.lan": "10.0.0.6"}}, "both a host and an override"),
    ({"hosts": {"nas.lan": "10.0.0.5", "NAS.lan": "10.0.0.6"}}, "listed twice"),
    ({"hosts": ["nas.lan"]}, "must be a mapping"),
    ({"zones": {}}, "unknown key"),
])
def test_bad_entries_are_refused(dhcp_config_dict, local_dns, message):
    with pytest.raises(ConfigError, match=message):
        _config(dhcp_config_dict, local_dns)


def test_two_label_domains_and_the_private_single_labels_are_accepted(dhcp_config_dict):
    for domain in ("lan", "home", "internal", "home.arpa", "office.example.com"):
        assert _config(dhcp_config_dict, {"domain": domain}).local_dns.domain == domain


@pytest.mark.parametrize("adblocker", [{"serve_lan": False}, {"enabled": False}])
def test_entries_need_the_resolver_serving_the_lan(dhcp_config_dict, adblocker):
    with pytest.raises(ConfigError, match="needs adblocker.enabled and adblocker.serve_lan"):
        _config(dhcp_config_dict, {"hosts": {"nas.lan": "10.0.0.5"}}, **adblocker)
    # An empty section asks for nothing.
    assert _config(dhcp_config_dict, {}, **adblocker).local_dns.names() == []


def test_a_name_of_a_blocked_app_is_refused(dhcp_config_dict):
    app_control = {"enabled": True, "blocked_apps": ["tiktok"]}
    with pytest.raises(ConfigError, match="overlaps the blocked app name 'musical.ly'"):
        _config(dhcp_config_dict, {"overrides": {"www.musical.ly": "10.0.0.5"}}, app_control=app_control)
    assert _config(dhcp_config_dict, {"overrides": {"www.example.com": "10.0.0.5"}},
                   app_control=app_control).local_dns.overrides


# --- the resolver's config -------------------------------------------------------


def test_the_lines_answer_locally_and_never_upstream(dhcp_config_dict, tmp_path):
    config = _config(dhcp_config_dict, {
        "domain": "lan",
        "hosts": {"nas.lan": "192.168.10.20"},
        "overrides": {"intranet.example.com": "10.73.1.5"},
    })
    assert dns_service.local_dns_lines(config) == [
        "local=/lan/",
        "host-record=nas.lan,192.168.10.20",
        "local=/nas.lan/",
        "address=/intranet.example.com/10.73.1.5",
        "local=/intranet.example.com/",
    ]
    text = dns_service.render_dnsmasq_config(config, hosts_path=tmp_path / "h", category_dir=tmp_path / "d")
    assert "host-record=nas.lan,192.168.10.20\n" in text
    assert text.index("addn-hosts=") < text.index("host-record=") < text.index("user=nobody")


def test_local_names_are_never_blocked(dhcp_config_dict, tmp_path):
    raw = _raw(dhcp_config_dict, {"hosts": {"nas.lan": "10.0.0.5"}, "overrides": {"example.com": "10.0.0.6"}})
    raw["adblocker"]["allowlist"] = ["good.example.org"]
    config = parse_config(raw)
    assert dns_service.never_blocked(config) == ["good.example.org", "nas.lan", "example.com"]

    hosts = tmp_path / "h"
    adblock.write_hosts_file({"nas.lan", "ads.example.com", "example.com", "ads.example.net"}, hosts)
    assert dns_service.enforce_allowlist(config, hosts_path=hosts, category_dir=tmp_path / "d") == 3
    assert adblock.read_hosts_file(hosts) == {"ads.example.net"}


# --- a real dnsmasq --------------------------------------------------------------


def _query(port: int, name: str, qtype: int = 1) -> tuple[int, list[bytes]]:
    """(rcode, the answers' RDATA) for one query."""
    packet = struct.pack("!HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0)
    packet += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack("!HH", qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        s.sendto(packet, ("127.0.0.1", port))
        data, _ = s.recvfrom(4096)
    count = struct.unpack("!H", data[6:8])[0]
    offset = len(packet)  # past the echoed question
    answers = []
    for _ in range(count):
        offset += 2 if data[offset] & 0xC0 == 0xC0 else data.index(b"\0", offset) + 1 - offset
        rdlength = struct.unpack("!H", data[offset + 8:offset + 10])[0]
        answers.append(data[offset + 10:offset + 10 + rdlength])
        offset += 10 + rdlength
    return data[3] & 0x0F, answers


@requires_dnsmasq
def test_real_dnsmasq_answers_local_names_and_asks_nobody(dhcp_config_dict, tmp_path):
    """A real dnsmasq with the generated config: hosts and overrides are
    answered (an override for its subdomains too), a blocklisted local
    name is answered with its address once never_blocked() took it off
    the list, the PTR of a host is its name, and nothing local -- an
    AAAA query or a name under the local domain -- reaches the upstream,
    which records every query it gets."""
    asked: list[bytes] = []
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 0))
    up_port = upstream.getsockname()[1]

    def serve():
        while True:
            try:
                data, addr = upstream.recvfrom(4096)
            except OSError:
                return
            asked.append(data[12:])
            upstream.sendto(data[:2] + bytes([0x81, 0x83]) + data[4:6] + b"\0" * 6 + data[12:], addr)

    threading.Thread(target=serve, daemon=True).start()

    config = _config(dhcp_config_dict, {
        "domain": "lan",
        "hosts": {"nas.lan": "192.168.10.20"},
        "overrides": {"intranet.example.com": "10.73.1.5"},
    })
    adblock.write_hosts_file({"nas.lan", "intranet.example.com", "ads.example"}, tmp_path / "h")
    dns_service.enforce_allowlist(config, hosts_path=tmp_path / "h", category_dir=tmp_path / "d")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    text = dns_service.render_dnsmasq_config(config, hosts_path=tmp_path / "h", category_dir=tmp_path / "d")
    text = text.replace("port=53\n", f"port={port}\n").replace("server=1.1.1.1", f"server=127.0.0.1#{up_port}")
    # As in test_dns_filtering: `nobody` can't read pytest's tmp dir.
    text = text.replace("user=nobody\ngroup=nogroup\n", "user=root\n")
    text = "\n".join(l for l in text.splitlines() if not l.startswith("interface=")) + "\nlisten-address=127.0.0.1\n"
    conf = tmp_path / "dnsmasq.conf"
    conf.write_text(text + "\n")
    subprocess.run(["dnsmasq", "--test", f"--conf-file={conf}"], check=True, capture_output=True)

    proc = subprocess.Popen(["dnsmasq", "--keep-in-foreground", f"--conf-file={conf}"],
                            stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 5
        while True:
            try:
                result = _query(port, "nas.lan")
                break
            except OSError:
                if time.time() > deadline:
                    raise
                time.sleep(0.1)
        assert result == (0, [socket.inet_aton("192.168.10.20")])
        assert _query(port, "intranet.example.com") == (0, [socket.inet_aton("10.73.1.5")])
        assert _query(port, "a.b.intranet.example.com") == (0, [socket.inet_aton("10.73.1.5")])
        assert _query(port, "ads.example") == (0, [socket.inet_aton("0.0.0.0")])  # still blocked
        rcode, (ptr,) = _query(port, "20.10.168.192.in-addr.arpa", qtype=12)
        assert rcode == 0 and ptr == b"\x03nas\x03lan\x00"
        # Answered by the router alone: empty, not the upstream's.
        assert _query(port, "nas.lan", qtype=28) == (0, [])
        assert _query(port, "x.intranet.example.com", qtype=28) == (0, [])
        assert _query(port, "printer.lan")[0] == 3  # NXDOMAIN
        assert asked == []
        assert _query(port, "elsewhere.example")[0] == 3  # the fake upstream's NXDOMAIN
        assert len(asked) == 1
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        upstream.close()
