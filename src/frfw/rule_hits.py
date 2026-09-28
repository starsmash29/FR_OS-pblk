"""When did each firewall rule last match? (security-lessons K2)

Every rule in the ruleset carries an nft `counter` (frfw.nft.builder).
The counters live in the kernel and start again from zero on every
apply, so `record` keeps what matters across reloads and reboots in a
small state file: when FR_OS first saw each rule and when its counter
last went up. fr-schedule-check.timer (root, hourly) calls it; the rule
check (frfw.rule_lint) reads the file and reports a rule that hasn't
matched anything for 90 days -- often a leftover nobody remembers, and
an open door nobody uses is still an open door.

A counter lower than last time means the ruleset was reloaded in
between; any packets since then count as a hit.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from frfw import paths
from frfw.nft.builder import FILTER_TABLE

#: A rule that hasn't matched for this long is reported (K2).
UNUSED_SECONDS = 90 * 24 * 3600


def _run(argv: list[str]) -> str:
    return subprocess.run(argv, capture_output=True, text=True, check=True, timeout=30).stdout


def read_counters(run: Callable[[list[str]], str] = _run) -> dict[str, int]:
    """Packets per rule name, summed over the rule's lines (a scheduled
    rule has one per time window). Needs root."""
    data = json.loads(run(["nft", "-j", "list", "table", "inet", FILTER_TABLE]))
    counts: dict[str, int] = {}
    for item in data.get("nftables", []):
        rule = item.get("rule")
        if not rule or not str(rule.get("comment", "")).startswith("rule:"):
            continue
        name = rule["comment"][len("rule:"):]
        for expr in rule.get("expr", []):
            if isinstance(expr, dict) and "counter" in expr:
                counts[name] = counts.get(name, 0) + int(expr["counter"].get("packets", 0))
    return counts


def load(path: Path | None = None) -> dict[str, dict]:
    path = path or paths.RULE_HITS_PATH
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    rules = data.get("rules") if isinstance(data, dict) else None
    return rules if isinstance(rules, dict) else {}


def record(counters: dict[str, int], rule_names: list[str], *, path: Path | None = None,
           now: float | None = None) -> dict[str, dict]:
    """Fold the kernel's current counters into the state file; rules no
    longer in the config are forgotten. 0644: rule names and times."""
    path = path or paths.RULE_HITS_PATH
    now = time.time() if now is None else now
    old = load(path)
    rules: dict[str, dict] = {}
    for name in rule_names:
        entry = dict(old.get(name) or {"since": now, "last_hit": None, "packets": 0})
        packets = counters.get(name)
        if packets is not None:
            before = int(entry.get("packets") or 0)
            if packets > before or (packets < before and packets > 0):
                entry["last_hit"] = now
            entry["packets"] = packets
        rules[name] = entry
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"rules": rules}))
    tmp.chmod(0o644)
    tmp.replace(path)
    return rules


def unused(entry: dict | None, now: float | None = None) -> bool:
    """Known for 90 days and never (or not for 90 days) matched."""
    if not entry:
        return False
    now = time.time() if now is None else now
    last = entry.get("last_hit") or entry.get("since") or now
    return now - float(last) >= UNUSED_SECONDS
