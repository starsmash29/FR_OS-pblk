"""The rule check (security-lessons K2): mistakes in the firewall rules
that a person reading them one by one easily misses.

- **any → any**: an accept rule that matches everything (no zone, port,
  protocol or address) -- the firewall is off for the traffic it covers;
- **open from the internet**: an accept rule from an internet-facing zone
  (or any zone) with neither a port nor a source address -- the whole
  destination is reachable from anywhere;
- **shadowed**: an earlier rule in the same chain matches everything this
  one does and decides differently, so this one never matches;
- **redundant**: the same, with the same decision -- harmless, but it
  hides what the rule set really does;
- **unused**: no match for 90 days (the per-rule counters, frfw.rule_hits);
- **expired**: a temporary rule past its expiry -- the kernel already
  ignores it, the entry just hasn't been removed yet.

"Matches everything the other does" is judged conservatively, field by
field (zones, protocol, ports, addresses, MAC, ZTNA, schedule, expiry):
the check never calls a rule shadowed when it isn't, but can miss one
that is shadowed by a combination of rules.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass

from frfw import rule_hits
from frfw.config.loader import internet_facing_zones
from frfw.config.schema import SELF_ZONE, Action, Config, Protocol, Rule

WARNING = "warning"
INFO = "info"


@dataclass(frozen=True)
class Finding:
    rule: str
    kind: str
    severity: str
    message: str


def _ports(spec: str) -> tuple[int, int]:
    lo, _, hi = spec.partition("-")
    return int(lo), int(hi or lo)


def _net_covers(outer: str | None, inner: str | None) -> bool:
    if outer is None:
        return True
    if inner is None:
        return False
    return ipaddress.ip_network(inner, strict=False).subnet_of(ipaddress.ip_network(outer, strict=False))


def covers(a: Rule, b: Rule) -> bool:
    """Does `a` match every packet `b` matches? (Both in the same chain.)"""
    if a.from_zone is not None and a.from_zone != b.from_zone:
        return False
    if a.to_zone is not None and a.to_zone != b.to_zone:
        return False
    if a.proto != Protocol.ANY and a.proto != b.proto:
        return False
    if a.dst_port is not None:
        if b.dst_port is None or b.proto != a.proto:
            return False
        (alo, ahi), (blo, bhi) = _ports(a.dst_port), _ports(b.dst_port)
        if not (alo <= blo and bhi <= ahi):
            return False
    if not (_net_covers(a.src_address, b.src_address) and _net_covers(a.dst_address, b.dst_address)):
        return False
    if a.src_mac is not None and a.src_mac != b.src_mac:
        return False
    if a.require_ztna and not b.require_ztna:
        return False
    if a.schedule is not None and a.schedule != b.schedule:
        return False
    if a.expires is not None and (b.expires is None or b.expires > a.expires):
        return False
    return True


def _chains(rules: list[Rule]) -> list[list[Rule]]:
    """The rules in the order each chain evaluates them (frfw.nft.builder:
    scheduled cut_established rules first)."""
    def cuts(r: Rule) -> bool:
        return r.schedule is not None and r.schedule.cut_established

    out = []
    for in_input in (True, False):
        chain = [r for r in rules if (r.to_zone == SELF_ZONE) == in_input]
        out.append([r for r in chain if cuts(r)] + [r for r in chain if not cuts(r)])
    return out


def _wide_open(rule: Rule) -> bool:
    return (rule.dst_port is None and rule.proto == Protocol.ANY and rule.src_address is None
            and rule.dst_address is None and rule.src_mac is None and not rule.require_ztna)


def lint(config: Config, *, hits: dict[str, dict] | None = None, now: float | None = None) -> list[Finding]:
    now = time.time() if now is None else now
    hits = rule_hits.load() if hits is None else hits
    internet = internet_facing_zones(config.zones, config.nat)
    findings: list[Finding] = []
    live = [r for r in config.rules if r.expires is None or r.expires > now]

    for rule in config.rules:
        if rule.expires is not None and rule.expires <= now:
            findings.append(Finding(rule.name, "expired", INFO,
                                    "expired: the firewall already ignores it; remove it to keep the list clean"))
            continue
        if rule.action == Action.ACCEPT and rule.schedule is None:
            if rule.from_zone is None and rule.to_zone is None and _wide_open(rule):
                findings.append(Finding(rule.name, "any-to-any", WARNING,
                                        "accepts everything from anywhere to anywhere: the firewall is off for it"))
            elif ((rule.from_zone is None or rule.from_zone in internet) and rule.dst_port is None
                  and rule.src_address is None and not rule.require_ztna):
                where = "the router itself" if rule.to_zone == SELF_ZONE else (
                    f"the {rule.to_zone} zone" if rule.to_zone else "every zone")
                origin = f"the internet ({rule.from_zone})" if rule.from_zone else "any zone, the internet included"
                findings.append(Finding(rule.name, "open-from-internet", WARNING,
                                        f"opens all of {where} to {origin}: limit it to a port or a source address"))

    for chain in _chains(live):
        for i, rule in enumerate(chain):
            earlier = next((e for e in chain[:i] if covers(e, rule)), None)
            if earlier is None:
                continue
            if earlier.action == rule.action:
                findings.append(Finding(rule.name, "redundant", INFO,
                                        f"redundant: {earlier.name!r} above already matches all of it the same way"))
            else:
                findings.append(Finding(rule.name, "shadowed", WARNING,
                                        f"never matches: {earlier.name!r} above matches all of it first "
                                        f"and {earlier.action.value}s it"))

    for rule in live:
        if rule_hits.unused(hits.get(rule.name), now):
            findings.append(Finding(rule.name, "unused", INFO,
                                    "no traffic has matched it for 90 days: is it still needed?"))
    return findings
