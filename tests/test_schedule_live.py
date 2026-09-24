"""Scheduled rules evaluated by the real kernel (phase 17).

frfw renders a local-time schedule as `meta day`/`meta hour` matches in
the kernel's own clocks (frfw.nft.schedule). This loads such rules into a
private network namespace with `TZ=UTC nft`, as frfw.apply does, sends a
packet through each one right now, and checks the kernel's verdict (the
rule's counter) against the pure-Python reference `is_active` -- in
several time zones, including half- and quarter-hour offsets.

Skipped unless running as root with nft and iproute2.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from datetime import datetime, timezone

import pytest

from frfw.nft.schedule import (
    MINUTES_PER_DAY,
    current_clock,
    is_active,
    local_minute_of_week,
    segments,
)

NS = "frfw-sched"

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0 or shutil.which("nft") is None or shutil.which("ip") is None,
    reason="needs root, nft and iproute2",
)

ZONES = ["UTC", "Europe/Budapest", "America/Los_Angeles", "Asia/Kolkata", "Pacific/Chatham"]


def _in_ns(*cmd: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(["ip", "netns", "exec", NS, *cmd], capture_output=True, text=True, **kwargs)


@pytest.fixture
def netns():
    subprocess.run(["ip", "netns", "del", NS], capture_output=True)
    subprocess.run(["ip", "netns", "add", NS], check=True, capture_output=True)
    _in_ns("ip", "link", "set", "lo", "up")
    try:
        yield
    finally:
        subprocess.run(["ip", "netns", "del", NS], capture_output=True)


def _cases(tz: str, now: datetime) -> list[tuple[tuple[int, ...], int, int]]:
    """Schedules around the current local time, each boundary at least 30
    minutes away from now, so the few seconds this test takes can't cross
    one. Some are active now, some are not."""
    minute = local_minute_of_week(tz, now)
    today, t = divmod(minute, MINUTES_PER_DAY)
    before, after = (t - 30) % MINUTES_PER_DAY, (t + 30) % MINUTES_PER_DAY
    later, much_later = (t + 60) % MINUTES_PER_DAY, (t + 120) % MINUTES_PER_DAY
    yesterday, other = (today - 1) % 7, (today + 3) % 7
    return [
        ((today, yesterday), before, after),          # active (also when it wraps midnight)
        (tuple(range(7)), before, after),             # active, every day
        ((other,), before, after),                    # inactive: another day
        (tuple(range(7)), later, much_later),         # inactive: later today
        ((today, yesterday), much_later, before),     # active: long window wrapping round
    ]


@pytest.mark.parametrize("tz", ZONES)
def test_kernel_verdict_matches_reference(netns, tz):
    now = datetime.now(timezone.utc)
    clock = current_clock(tz, now)
    local_now = local_minute_of_week(tz, now)
    cases = _cases(tz, now)

    lines = ["table inet sched {", "\tchain out {", "\t\ttype filter hook output priority filter; policy accept;"]
    for i, (days, start, end) in enumerate(cases):
        for seg in segments(days, start, end, clock):
            lines.append(
                f'\t\t{seg.render()} ip daddr 127.0.0.1 udp dport {40000 + i} counter comment "case{i}"'
            )
    lines += ["\t}", "}", ""]
    loaded = _in_ns("nft", "-f", "-", input="\n".join(lines), env={**os.environ, "TZ": "UTC"})
    assert loaded.returncode == 0, loaded.stderr

    for i in range(len(cases)):
        _in_ns("python3", "-c",
               f"import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'x', ('127.0.0.1', {40000 + i}))")

    listing = json.loads(_in_ns("nft", "-j", "list", "table", "inet", "sched").stdout)
    hits = {i: 0 for i in range(len(cases))}
    for item in listing["nftables"]:
        rule = item.get("rule")
        if not rule:
            continue
        case = int(rule["comment"].removeprefix("case"))
        for expr in rule["expr"]:
            if "counter" in expr:
                hits[case] += expr["counter"]["packets"]

    expected = {i: is_active(days, start, end, local_now) for i, (days, start, end) in enumerate(cases)}
    assert {i: hits[i] > 0 for i in hits} == expected, (tz, clock, lines)
    assert any(expected.values()) and not all(expected.values())
