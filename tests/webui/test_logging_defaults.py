"""Security-lessons K6: logging on by default.

- the ruleset logs what the default-deny policy drops, rate-limited, on
  by default (`logging.drops`);
- the dashboard shows the latest drops, read from the kernel log;
- the journal has a size and age limit; the audit log (sign-ins and
  changes) is capped too.

The real drop, logged by a real kernel, is in the QEMU boot test (a
network namespace's log is muted by the kernel unless a host-wide sysctl
is changed, which tests don't do).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from frfw import firewall_log
from frfw.config import ConfigError, parse_config
from frfw.nft import build_ruleset
from frfw.webui import audit

ROOT = Path(__file__).resolve().parents[2]


def _config(**logging) -> dict:
    raw = {"version": 1, "hostname": "r", "zones": {"wan": {}, "lan": {}},
           "interfaces": {"wan": {"device": "eth0", "zone": "wan"}, "lan": {"device": "eth1", "zone": "lan"}},
           "rules": [], "nat": {"masquerade": [{"out_zone": "wan"}]}}
    if logging:
        raw["logging"] = logging
    return raw


def test_drops_are_logged_by_default():
    ruleset = build_ruleset(parse_config(_config()))
    for chain in ("input", "forward"):
        body = ruleset.split(f"chain {chain} {{")[1].split("\n\t}")[0]
        last = body.strip().splitlines()[-1].strip()
        assert last == (f'limit rate 10/minute burst 10 packets log prefix "fr_os/drop/{chain}: " '
                        'comment "log-default-drop"'), chain  # last: only what nothing accepted


def test_the_rate_and_the_switch():
    assert "limit rate 60/minute burst 60" in build_ruleset(parse_config(_config(drops_per_minute=60)))
    assert "fr_os/drop" not in build_ruleset(parse_config(_config(drops=False)))
    with pytest.raises(ConfigError, match="drops_per_minute"):
        parse_config(_config(drops_per_minute=0))


def test_reading_the_kernel_log():
    lines = [
        {"MESSAGE": "fr_os/drop/input: IN=eth0 OUT= MAC=52:54:00:00:00:01 SRC=203.0.113.9 DST=198.51.100.2 "
                    "LEN=60 TTL=51 PROTO=TCP SPT=40000 DPT=23 WINDOW=64240 SYN URGP=0",
         "__REALTIME_TIMESTAMP": "1790000000000000"},
        {"MESSAGE": "fr_os/drop/forward: IN=eth1 OUT=eth0 SRC=192.168.1.50 DST=8.8.8.8 PROTO=UDP SPT=5 DPT=53",
         "__REALTIME_TIMESTAMP": "1790000005000000"},
        {"MESSAGE": "some other kernel line", "__REALTIME_TIMESTAMP": "1790000006000000"},
    ]
    seen = []

    def run(argv):
        seen.append(argv)
        return "\n".join(json.dumps(line) for line in lines) + "\nnot json\n"

    drops = firewall_log.recent_drops(run=run)
    assert seen[0][:2] == ["journalctl", "-k"] and "fr_os/drop/" in seen[0]
    assert [d["chain"] for d in drops] == ["forward", "input"]  # newest first
    assert drops[1] == {"chain": "input", "in": "eth0", "out": "", "src": "203.0.113.9", "dst": "198.51.100.2",
                        "proto": "TCP", "sport": "40000", "dport": "23", "ts": 1790000000.0}


def test_the_dashboard_shows_them(logged_in_client, webui_env):
    import yaml

    webui_env["config_path"].write_text(yaml.safe_dump(_config()))
    webui_env["helper"].drops = [{"chain": "input", "src": "203.0.113.9", "dst": "198.51.100.2", "proto": "TCP",
                                  "dport": "23", "in": "eth0", "ts": 1790000000}]
    page = logged_in_client.get("/").text
    assert "Recently dropped" in page and "203.0.113.9" in page and "TCP/23" in page
    webui_env["config_path"].write_text(yaml.safe_dump(_config(drops=False)))
    assert "Recently dropped" not in logged_in_client.get("/").text


def test_retention_limits():
    journald = (ROOT / "systemd" / "journald-fr_os.conf").read_text()
    assert "SystemMaxUse=200M" in journald and "MaxRetentionSec=90day" in journald
    for installer in ("installer/live-build/config/hooks/0100-install-frfw.hook.chroot",
                      "scripts/install-system-integration.sh"):
        text = (ROOT / installer).read_text()
        assert "journald.conf.d/fr_os.conf" in text and "nf_log_syslog" in text, installer
    assert audit.MAX_BYTES <= 1024 * 1024  # the audit log rotates: one old generation kept
