"""What the firewall dropped (security-lessons K6).

The ruleset logs every packet its default-deny policy drops, rate
limited (frfw.nft.builder, `logging.drops`), to the kernel log, which the
journal keeps within its size and age limits (the image's journald
drop-in). `recent_drops` reads the latest entries back for the
dashboard: the apply-helper runs it, as reading the kernel log needs
root.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable

from frfw.nft.builder import DROP_LOG_PREFIX

_FIELDS = {"IN": "in", "OUT": "out", "SRC": "src", "DST": "dst", "PROTO": "proto", "DPT": "dport", "SPT": "sport"}


def _run(argv: list[str]) -> str:
    return subprocess.run(argv, capture_output=True, text=True, timeout=30).stdout


def parse(message: str) -> dict | None:
    """One kernel log line: "fr_os/drop/input: IN=eth0 OUT= ... SRC=... DPT=22"."""
    start = message.find(DROP_LOG_PREFIX)
    if start < 0:
        return None
    head, _, rest = message[start + len(DROP_LOG_PREFIX):].partition(":")
    entry = {"chain": head.strip()}
    for token in rest.split():
        key, eq, value = token.partition("=")
        if eq and key in _FIELDS:
            entry[_FIELDS[key]] = value
    return entry


def recent_drops(limit: int = 50, run: Callable[[list[str]], str] = _run) -> list[dict]:
    """The newest `limit` default-deny drops, newest first."""
    out = run(["journalctl", "-k", "--no-pager", "-o", "json", "-n", str(limit), "-g", DROP_LOG_PREFIX])
    drops = []
    for line in out.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        entry = parse(str(record.get("MESSAGE", "")))
        if entry is None:
            continue
        try:
            entry["ts"] = int(record.get("__REALTIME_TIMESTAMP", 0)) / 1e6
        except (TypeError, ValueError):
            entry["ts"] = 0
        drops.append(entry)
    drops.sort(key=lambda e: e["ts"], reverse=True)
    return drops[:limit]
