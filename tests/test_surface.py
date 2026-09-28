"""Security-lessons I3: the attack-surface view -- what listens, and which
zone's traffic the firewall lets reach it."""

from __future__ import annotations

import shutil
import subprocess

import pytest
import yaml

from frfw import surface
from frfw.config import parse_config
from frfw.nft import builder

SS_OUTPUT = """\
tcp LISTEN 0      4096       0.0.0.0:22        0.0.0.0:* users:(("sshd",pid=612,fd=3))
tcp LISTEN 0      2048   192.168.1.1:443       0.0.0.0:* users:(("fr-webui",pid=700,fd=7))
tcp LISTEN 0      2048     127.0.0.1:443       0.0.0.0:* users:(("fr-webui",pid=700,fd=6))
udp UNCONN 0      0     0.0.0.0%eth1:67        0.0.0.0:*
udp UNCONN 0      0      192.168.1.1:53        0.0.0.0:* users:(("dnsmasq",pid=801,fd=4))
tcp LISTEN 0      32              *:8080             *:*
tcp LISTEN 0      128          [::1]:631          [::]:*
udp UNCONN 0      0        127.0.0.1:33863     0.0.0.0:*
this line is junk
"""


def _config(rules=(), **extra):
    raw = {
        "version": 1, "hostname": "router",
        "zones": {"wan": {}, "lan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"},
                       "lan": {"device": "eth1", "zone": "lan", "address": "192.168.1.1/24"}},
        "rules": list(rules),
        "nat": {"masquerade": [{"out_zone": "wan"}]},
        **extra,
    }
    return parse_config(raw)


ADDRESSES = {"lo": ["127.0.0.1", "::1"], "eth0": ["203.0.113.7"], "eth1": ["192.168.1.1"]}


def test_ss_output_is_parsed():
    listeners = {(l.proto, l.address, l.port): l for l in surface.parse_ss(SS_OUTPUT)}
    assert listeners[("tcp", "0.0.0.0", 22)].process == "sshd"
    assert listeners[("udp", "0.0.0.0", 67)].device == "eth1"
    assert listeners[("udp", "0.0.0.0", 67)].label == "DHCP server (Kea)"  # no process name: by port
    assert listeners[("tcp", "::", 8080)].wildcard
    assert listeners[("tcp", "::1", 631)].loopback
    assert len(listeners) == 8


def test_a_loopback_service_is_reachable_from_nowhere():
    rows = {(r.listener.address, r.listener.port): r for r in
            surface.surface(_config(), surface.parse_ss(SS_OUTPUT), ADDRESSES)}
    assert rows[("127.0.0.1", 443)].zones == {}
    assert rows[("::1", 631)].zones == {}


def test_bound_address_decides_the_zones():
    rows = {(r.listener.proto, r.listener.address, r.listener.port): r
            for r in surface.surface(_config(), surface.parse_ss(SS_OUTPUT), ADDRESSES)}
    assert set(rows[("tcp", "192.168.1.1", 443)].zones) == {"lan"}
    assert set(rows[("udp", "0.0.0.0", 67)].zones) == {"lan"}  # bound to eth1
    assert set(rows[("tcp", "0.0.0.0", 22)].zones) == {"lan", "wan"}  # every address


def test_nothing_open_by_default_and_management_never_from_the_wan():
    config = _config([{"name": "admin-from-lan", "action": "accept", "from_zone": "lan", "to_zone": "self",
                       "proto": "tcp", "dst_port": 443},
                      # An admin mistake the management drop overrides (security-lessons F2).
                      {"name": "oops", "action": "accept", "from_zone": "wan", "to_zone": "self",
                       "proto": "tcp", "dst_port": "20-30"}])
    assert surface.input_verdict(config, "lan", "tcp", 443).state == surface.OPEN
    ssh_from_wan = surface.input_verdict(config, "wan", "tcp", 22)
    assert ssh_from_wan.state == surface.CLOSED and "management" in ssh_from_wan.why
    assert surface.input_verdict(config, "wan", "tcp", 21).state == surface.OPEN  # the rule's range
    assert surface.input_verdict(config, "wan", "tcp", 8080).state == surface.CLOSED
    assert "policy drop" in surface.input_verdict(config, "wan", "udp", 500).why


def test_a_service_open_to_the_wan_is_flagged():
    config = _config([{"name": "http-from-anywhere", "action": "accept", "to_zone": "self",
                       "proto": "tcp", "dst_port": 8080}])
    rows = surface.surface(config, surface.parse_ss(SS_OUTPUT), ADDRESSES)
    assert rows[0].listener.port == 8080 and rows[0].internet  # listed first
    assert [r.listener.port for r in rows if r.internet] == [8080]


def test_conditions_make_it_restricted_not_open():
    config = _config([
        {"name": "vpn-admins", "action": "accept", "from_zone": "wan", "to_zone": "self", "proto": "tcp",
         "dst_port": 8080, "src_address": "198.51.100.0/24"},
        {"name": "ztna", "action": "accept", "from_zone": "lan", "to_zone": "self", "proto": "tcp",
         "dst_port": 8080, "require_ztna": True},
    ], ztna={"enabled": True, "users": [{"username": "alice", "password_hash": "scrypt$32768$8$3$00$00"}]})
    wan = surface.input_verdict(config, "wan", "tcp", 8080)
    assert wan.state == surface.RESTRICTED and "198.51.100.0/24" in wan.why
    assert surface.input_verdict(config, "lan", "tcp", 8080).state == surface.RESTRICTED
    # `ip saddr` never matches IPv6: for an IPv6 socket the rule opens nothing.
    assert surface.input_verdict(config, "wan", "tcp", 8080, family=6).state == surface.CLOSED


def test_rules_are_evaluated_in_order():
    config = _config([
        {"name": "block-first", "action": "drop", "from_zone": "lan", "to_zone": "self", "proto": "tcp",
         "dst_port": 8080},
        {"name": "allow-later", "action": "accept", "from_zone": "lan", "to_zone": "self", "proto": "tcp",
         "dst_port": 8080},
    ])
    verdict = surface.input_verdict(config, "lan", "tcp", 8080)
    assert verdict.state == surface.CLOSED and "block-first" in verdict.why


def test_the_dns_filter_and_iot_extras():
    config = _config([], dhcp={"lan": {"range_start": "192.168.1.100", "range_end": "192.168.1.200",
                                    "dns_servers": ["192.168.1.1"]}},
                     adblocker={"enabled": True, "serve_lan": True,
                                "source_urls": ["https://example.test/hosts"]},
                     iot={"enabled": True, "zones": ["lan"]})
    assert surface.input_verdict(config, "lan", "udp", 53).state == surface.OPEN
    # Isolated IoT devices always get DNS/DHCP, from whichever zone.
    assert surface.input_verdict(config, "wan", "udp", 67).state == surface.RESTRICTED
    assert surface.input_verdict(config, "lan", "udp", builder.IOT_MDNS_REPLY_PORT).state == surface.RESTRICTED


def test_wan_addresses_for_the_outside_scan_hint():
    assert surface.wan_addresses(_config(), ADDRESSES) == ["203.0.113.7"]


@pytest.mark.skipif(not shutil.which("ss") or not shutil.which("ip"), reason="needs ss and ip")
def test_the_real_ss_and_ip_output_parse():
    listeners, addresses = surface.collect()
    assert "lo" in addresses
    assert all(0 < l.port < 65536 for l in listeners)
    raw = subprocess.run(["ss", "-Hlntu"], capture_output=True, text=True).stdout
    assert len(listeners) == len({line.split()[4] + line.split()[0] for line in raw.splitlines() if line.strip()})


# -- the webUI screen and the helper command --------------------------------------------------


def test_only_the_webui_may_ask_the_helper_for_the_sockets():
    from frfw.helper import peer

    assert "listening_sockets" not in peer.SENSOR_COMMANDS
    policy = peer.PeerPolicy(full_uids=frozenset({1000}), sensor_uids=frozenset({2000}))
    assert not policy.allows(2000, "listening_sockets")
    assert policy.allows(1000, "listening_sockets")


def test_the_helper_command_reports_sockets(monkeypatch):
    from frfw.helper import server

    monkeypatch.setattr(surface, "collect", lambda: (surface.parse_ss(SS_OUTPUT), ADDRESSES))
    reply = server._handle_listening_sockets()
    assert reply["ok"] and {"proto": "udp", "address": "0.0.0.0", "port": 67, "device": "eth1",
                            "process": None} in reply["listeners"]
    assert reply["addresses"]["eth0"] == ["203.0.113.7"]


def test_the_cli_exits_2_when_something_faces_the_internet(tmp_path, monkeypatch, capsys):
    from frfw import cli

    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump({
        "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"},
                       "lan": {"device": "eth1", "zone": "lan", "address": "192.168.1.1/24"}},
        "rules": [{"name": "http", "action": "accept", "to_zone": "self", "proto": "tcp", "dst_port": 8080}],
        "nat": {"masquerade": [{"out_zone": "wan"}]},
    }))
    monkeypatch.setattr(surface, "collect", lambda: (surface.parse_ss(SS_OUTPUT), ADDRESSES))
    assert cli.main(["surface", str(config)]) == 2
    out = capsys.readouterr()
    assert "tcp/8080" in out.out and "reachable from the internet side" in out.out
    assert "WARNING: 1 service(s) reachable from wan" in out.err


# -- security-lessons K7: nothing listening that isn't needed ----------------------------------


def test_each_socket_says_what_needs_it():
    config = _config(rules=[{"name": "any-in", "action": "accept", "from_zone": "lan", "to_zone": "self"}])
    rows = {(r.listener.proto, r.listener.port, r.listener.address): r
            for r in surface.surface(config, surface.parse_ss(SS_OUTPUT), ADDRESSES)}
    assert rows[("tcp", 443, "192.168.1.1")].needed == "the webUI"
    assert rows[("udp", 33863, "127.0.0.1")].needed == "local only"
    # dnsmasq and Kea listen, but the config asks for neither: not needed.
    assert rows[("udp", 53, "192.168.1.1")].unneeded
    assert rows[("udp", 67, "0.0.0.0")].unneeded
    # And a stray web server, reachable from the LAN, certainly isn't.
    assert rows[("tcp", 8080, "::")].unneeded and rows[("tcp", 8080, "::")].listener.label == "unknown"


def test_what_the_config_turns_on_is_needed():
    config = _config(
        dhcp={"lan": {"range_start": "192.168.1.100", "range_end": "192.168.1.199", "dns_servers": ["1.1.1.1"]}},
        adblocker={"enabled": True, "source_urls": ["https://example.com/hosts"]},
        zones={"wan": {}, "lan": {}, "vpn": {}},
        wireguard={"enabled": True, "address": "10.99.0.1/24"},
    )
    listeners = [surface.Listener("udp", "0.0.0.0", 67, device="eth1"), surface.Listener("udp", "192.168.1.1", 53),
                 surface.Listener("udp", "0.0.0.0", 51820)]
    assert [surface.needed_by(config, l) for l in listeners] == [
        "the DHCP server (dhcp)", "the DNS filter (adblocker)", "the WireGuard VPN (wireguard)"]


def test_a_closed_unneeded_socket_is_not_flagged():
    """Unneeded but unreachable (the firewall drops it everywhere) is not
    worth an alarm: it can't be attacked from any zone."""
    rows = surface.surface(_config(), [surface.Listener("tcp", "0.0.0.0", 8080)], ADDRESSES)
    assert rows[0].needed is None and not rows[0].reachable and not rows[0].unneeded


def test_the_cli_says_so(monkeypatch, tmp_path, capsys):
    from frfw import cli

    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({
        "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"},
                       "lan": {"device": "eth1", "zone": "lan", "address": "192.168.1.1/24"}},
        "rules": [{"name": "any-in", "action": "accept", "from_zone": "lan", "to_zone": "self"}],
        "nat": {"masquerade": [{"out_zone": "wan"}]}}))
    monkeypatch.setattr(surface, "collect", lambda: ([surface.Listener("tcp", "192.168.1.1", 8080)], ADDRESSES))
    assert cli.main(["surface", str(path)]) == 3
    assert "not needed by FR_OS, stop it: tcp/8080" in capsys.readouterr().err
