"""Security-lessons K2: the rule check and temporary rules.

- a rule can expire; the kernel stops matching it at that second by
  itself (tested for real in a network namespace), and later rulesets
  leave it out;
- every rule has a counter; the hourly job records when each last
  matched (the counters are read from a real ruleset);
- the check finds any-to-any and internet-wide accept rules, shadowed and
  redundant rules, rules unused for 90 days and expired ones -- and
  doesn't call a rule shadowed when it isn't.
"""

from __future__ import annotations

import datetime
import os
import shutil
import subprocess
import sys
import time
import uuid

import pytest
import yaml

from frfw import cli, paths, rule_hits, rule_lint
from frfw.config import ConfigError, parse_config
from frfw.nft import build_ruleset

DAY = 24 * 3600


def _config(rules, **extra) -> dict:
    return {
        "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}, "dmz": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"},
                       "lan": {"device": "eth1", "zone": "lan", "address": "192.168.1.1/24"},
                       "dmz": {"device": "eth2", "zone": "dmz", "address": "10.0.2.1/24"}},
        "rules": rules, "nat": {"masquerade": [{"out_zone": "wan"}]}, **extra,
    }


def _rule(name, **kw) -> dict:
    return {"name": name, "action": "accept", **kw}


def _findings(rules, hits=None, now=None, **extra) -> dict[str, tuple[str, str]]:
    config = parse_config(_config(rules, **extra))
    first: dict[str, tuple[str, str]] = {}
    for f in rule_lint.lint(config, hits=hits or {}, now=now):
        first.setdefault(f.rule, (f.kind, f.severity))  # a rule's most important finding comes first
    return first


# -- temporary rules ---------------------------------------------------------------------------


def test_expiry_formats():
    with_offset = parse_config(_config([_rule("a", expires="2026-10-01T18:00+02:00")])).rules[0]
    assert with_offset.expires == int(datetime.datetime(2026, 10, 1, 16, 0, tzinfo=datetime.timezone.utc).timestamp())
    in_zone = parse_config(_config([_rule("a", expires="2026-10-01T18:00")], timezone="Europe/Budapest")).rules[0]
    assert in_zone.expires == with_offset.expires  # CEST is +02:00
    from_yaml = parse_config(yaml.safe_load(yaml.safe_dump(
        _config([_rule("a", expires=datetime.datetime(2026, 10, 1, 16, 0, tzinfo=datetime.timezone.utc))]))))
    assert from_yaml.rules[0].expires == with_offset.expires
    with pytest.raises(ConfigError, match="expires"):
        parse_config(_config([_rule("a", expires="next tuesday")]))


def test_the_ruleset_expires_rules_itself():
    now = 1_790_000_000
    config = parse_config(_config([_rule("gone", from_zone="lan", to_zone="dmz", expires="2026-01-01T00:00Z"),
                                   _rule("soon", from_zone="lan", to_zone="dmz", proto="tcp", dst_port=22,
                                         expires=datetime.datetime.fromtimestamp(now + 3600, datetime.timezone.utc)
                                         .isoformat())]))
    ruleset = build_ruleset(config, now=now)
    assert "rule:gone" not in ruleset
    assert f'meta time < {now + 3600} iifname @lan_ifaces oifname @dmz_ifaces tcp dport 22 counter accept' in ruleset


def _sh(*args, ns=None, check=True, input=None):
    cmd = (["ip", "netns", "exec", ns] if ns else []) + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=check, input=input)


needs_netns = pytest.mark.skipif(os.geteuid() != 0 or not (shutil.which("ip") and shutil.which("nft")),
                                 reason="needs root, ip netns and nft")


@needs_netns
def test_the_kernel_stops_a_temporary_rule_on_time():
    """A client reaches a port on the router through a temporary rule,
    and doesn't any more once it expires -- with no reload in between."""
    tag = uuid.uuid4().hex[:6]
    router, client = f"k2r{tag}", f"k2c{tag}"
    listener = None
    try:
        for ns in (router, client):
            _sh("ip", "netns", "add", ns)
            _sh("ip", "link", "set", "lo", "up", ns=ns)
        _sh("ip", "link", "add", f"r{tag}", "type", "veth", "peer", "name", f"c{tag}")
        _sh("ip", "link", "set", f"r{tag}", "netns", router)
        _sh("ip", "link", "set", f"c{tag}", "netns", client)
        _sh("ip", "addr", "add", "10.93.0.1/24", "dev", f"r{tag}", ns=router)
        _sh("ip", "addr", "add", "10.93.0.2/24", "dev", f"c{tag}", ns=client)
        _sh("ip", "link", "set", f"r{tag}", "up", ns=router)
        _sh("ip", "link", "set", f"c{tag}", "up", ns=client)
        expires = int(time.time()) + 6
        raw = {"version": 1, "hostname": "router", "zones": {"lan": {}},
               "interfaces": {"lan": {"device": f"r{tag}", "zone": "lan", "address": "10.93.0.1/24"}},
               "rules": [{"name": "temp-access", "action": "accept", "from_zone": "lan", "to_zone": "self",
                          "proto": "tcp", "dst_port": 8099,
                          "expires": datetime.datetime.fromtimestamp(expires, datetime.timezone.utc).isoformat()}],
               "nat": {}}
        _sh("nft", "-f", "-", ns=router, input=build_ruleset(parse_config(raw)))
        listener = subprocess.Popen(
            ["ip", "netns", "exec", router, sys.executable, "-c",
             "import socket\ns = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
             "s.bind(('10.93.0.1', 8099)); s.listen()\n"
             "while True:\n    c, _ = s.accept(); c.sendall(b'hello'); c.close()\n"])

        def reaches() -> bool:
            probe = ("import socket, sys\n"
                     "try:\n    c = socket.create_connection(('10.93.0.1', 8099), timeout=1)\n"
                     "    sys.exit(0 if c.recv(5) == b'hello' else 1)\n"
                     "except OSError:\n    sys.exit(1)\n")
            return _sh(sys.executable, "-c", probe, ns=client, check=False).returncode == 0

        for _ in range(20):
            if reaches():
                break
            time.sleep(0.2)
        else:
            pytest.fail("the temporary rule never let the client in")
        # The counter saw it (K2's "unused" check reads these).
        counters = rule_hits.read_counters(lambda argv: _sh(*argv, ns=router).stdout)
        assert counters["temp-access"] > 0
        time.sleep(max(0.0, expires - time.time()) + 1)
        assert not reaches(), "still open after the rule expired"
    finally:
        if listener is not None:
            listener.kill()
            listener.wait()
        for ns in (router, client):
            _sh("ip", "netns", "del", ns, check=False)


# -- hit record ----------------------------------------------------------------------------------


def test_the_hit_record(tmp_path):
    path = tmp_path / "hits.json"
    t0 = 1_700_000_000
    rules = rule_hits.record({"a": 0, "b": 5}, ["a", "b", "c"], path=path, now=t0)
    assert rules["a"] == {"since": t0, "last_hit": None, "packets": 0}
    assert rules["b"]["last_hit"] == t0
    rules = rule_hits.record({"a": 0, "b": 5}, ["a", "b"], path=path, now=t0 + 3600)
    assert rules["b"]["last_hit"] == t0 and "c" not in rules  # no new packets; c left the config
    rules = rule_hits.record({"a": 0, "b": 2}, ["a", "b"], path=path, now=t0 + 7200)
    assert rules["b"]["last_hit"] == t0 + 7200  # lower than before: reloaded, and 2 since
    assert rule_hits.unused(rules["a"], now=t0 + 91 * DAY) and not rule_hits.unused(rules["a"], now=t0 + 89 * DAY)
    assert oct(path.stat().st_mode & 0o777) == "0o644"


def test_counters_from_nft_json():
    dump = {"nftables": [
        {"rule": {"comment": "rule:x", "expr": [{"counter": {"packets": 3, "bytes": 1}}, {"accept": None}]}},
        {"rule": {"comment": "rule:x", "expr": [{"counter": {"packets": 4, "bytes": 1}}, {"accept": None}]}},
        {"rule": {"comment": "no-management-from-wan", "expr": [{"drop": None}]}},
    ]}
    import json

    assert rule_hits.read_counters(lambda argv: json.dumps(dump)) == {"x": 7}


def test_the_hourly_job_records_hits(monkeypatch, tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump(_config([_rule("web", from_zone="wan", to_zone="dmz", proto="tcp",
                                                    dst_port=443)])))
    monkeypatch.setattr(rule_hits, "read_counters", lambda: {"web": 12})
    cli.main(["schedule-check", str(config)])
    assert rule_hits.load()["web"]["packets"] == 12 and paths.RULE_HITS_PATH.exists()


# -- the check --------------------------------------------------------------------------------------


def test_any_to_any_and_internet_wide_rules():
    # The catch-all last: before it, every other rule would be redundant.
    got = _findings([_rule("wan-web", from_zone="wan", to_zone="dmz", proto="tcp", dst_port=443),
                     _rule("partner", from_zone="wan", to_zone="dmz", src_address="203.0.113.0/24"),
                     _rule("lan-out", from_zone="lan", to_zone="wan"),
                     _rule("wan-to-dmz", from_zone="wan", to_zone="dmz"),
                     _rule("everything")])
    assert got["everything"] == ("any-to-any", "warning")
    assert got["wan-to-dmz"] == ("open-from-internet", "warning")
    assert "wan-web" not in got and "partner" not in got and "lan-out" not in got


def test_shadowed_and_redundant():
    got = _findings([
        _rule("block-dmz", action="drop", from_zone="lan", to_zone="dmz"),
        _rule("dmz-ssh", from_zone="lan", to_zone="dmz", proto="tcp", dst_port=22),  # never matches
        _rule("web-range", from_zone="lan", to_zone="wan", proto="tcp", dst_port="80-443"),
        _rule("web", from_zone="lan", to_zone="wan", proto="tcp", dst_port=443),  # redundant
        _rule("udp-443", from_zone="lan", to_zone="wan", proto="udp", dst_port=443),  # other protocol: fine
    ])
    assert got["dmz-ssh"] == ("shadowed", "warning")
    assert got["web"] == ("redundant", "info")
    assert "udp-443" not in got and "block-dmz" not in got


@pytest.mark.parametrize("earlier, later", [
    (_rule("a", from_zone="lan", to_zone="dmz", src_address="192.168.1.0/25"),
     _rule("b", action="drop", from_zone="lan", to_zone="dmz", src_address="192.168.1.0/24")),  # narrower first
    (_rule("a", from_zone="lan", to_zone="dmz", schedule={"days": ["mon"], "start": "08:00", "end": "17:00"}),
     _rule("b", action="drop", from_zone="lan", to_zone="dmz")),  # only part of the week
    (_rule("a", from_zone="lan", to_zone="dmz", expires="2099-01-01T00:00Z"),
     _rule("b", action="drop", from_zone="lan", to_zone="dmz")),  # only until then
    (_rule("a", from_zone="lan", to_zone="dmz", require_ztna=True),
     _rule("b", action="drop", from_zone="lan", to_zone="dmz")),  # only ZTNA users
    (_rule("a", from_zone="lan", to_zone="self"),
     _rule("b", action="drop", from_zone="lan", to_zone="dmz")),  # other chain
])
def test_not_shadowed(earlier, later):
    assert "b" not in _findings([earlier, later])


def test_unused_and_expired():
    now = 1_800_000_000
    hits = {"old": {"since": now - 100 * DAY, "last_hit": now - 95 * DAY, "packets": 0},
            "new": {"since": now - 10 * DAY, "last_hit": None, "packets": 0},
            "busy": {"since": now - 200 * DAY, "last_hit": now - DAY, "packets": 9}}
    got = _findings([_rule("old", from_zone="lan", to_zone="wan", proto="tcp", dst_port=21),
                     _rule("new", from_zone="lan", to_zone="wan", proto="tcp", dst_port=22),
                     _rule("busy", from_zone="lan", to_zone="wan", proto="tcp", dst_port=443),
                     _rule("done", from_zone="lan", to_zone="wan", proto="tcp", dst_port=25,
                           expires="2020-01-01T00:00Z")], hits=hits, now=now)
    assert got == {"old": ("unused", "info"), "done": ("expired", "info")}


def test_the_cli(tmp_path, capsys):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(_config([_rule("everything")])))
    assert cli.main(["rule-check", str(path)]) == 1
    assert "everything: accepts everything" in capsys.readouterr().out
    path.write_text(yaml.safe_dump(_config([_rule("lan-out", from_zone="lan", to_zone="wan")])))
    assert cli.main(["rule-check", str(path)]) == 0
