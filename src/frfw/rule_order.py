"""Where a rule sits in its chain (ROADMAP SEC-30).

The firewall takes the first matching rule, so a rule's position decides
whether it ever runs. The Rules screen used to append every new rule to
the end of the list, behind the first-boot `lan-to-wan` accept, so a deny
an admin added never matched -- a real hole the 1d-3 boot test surfaced,
and until now fixable only by hand-editing config.yaml.

This module answers two questions, from the same `rule_lint.covers` test
the rule check already uses:

- **placement**: when a new rule is saved, which existing rule (if any)
  would match everything it matches and decide the other way, so the new
  rule belongs just before it;
- **move**: swapping a rule with its neighbour, or putting it before a
  named rule, on the admin's list (the order they see and the order the
  chain evaluates within a group).

It works on the raw rule dicts (what config.yaml holds and the screen
edits), using the parsed `Config` only to reason about the chains.
"""

from __future__ import annotations

from frfw.config.schema import SELF_ZONE, Config, Rule
from frfw.rule_lint import covers


def _chain_group(rule: Rule) -> tuple[bool, bool]:
    """A rule only shadows another evaluated in the same chain and group.
    The builder (frfw.nft.builder) splits rules into the input chain
    (`to_zone == self`) and the forward chain, and within each puts
    scheduled `cut_established` rules first; inside one group the config
    order is the evaluation order."""
    cut = rule.schedule is not None and rule.schedule.cut_established
    return (rule.to_zone == SELF_ZONE, cut)


def _defeats(earlier: Rule, later: Rule) -> bool:
    """`earlier`, placed before `later` and matching everything `later`
    does, stops `later` from doing its job -- so `later` belongs in front.
    Either it decides the other way, or it is an un-gated accept that would
    let through what `later` only means to accept after a ZTNA sign-in, so
    the gate never applies (security-lessons K2, SEC-6)."""
    if earlier.action != later.action:
        return True
    return later.require_ztna and not earlier.require_ztna


def earliest_shadower(rules: list[Rule], new: Rule) -> Rule | None:
    """The first rule in `new`'s chain that matches everything `new` does
    and would stop it from taking effect -- so `new` placed after it would
    never do its job (security-lessons K2). Inserting `new` just before it
    makes `new` take effect. None when nothing shadows `new`."""
    for rule in rules:
        if rule.name == new.name:
            continue
        if _chain_group(rule) != _chain_group(new):
            continue
        if covers(rule, new) and _defeats(rule, new):
            return rule
    return None


def place(raw_rules: list[dict], new_name: str, config: Config) -> str | None:
    """Move the just-appended rule `new_name` in `raw_rules` to just before
    the rule that would otherwise shadow it, in place. Returns the name of
    that rule, or None when the rule stays at the end (nothing shadows it,
    or the name isn't found)."""
    new = next((r for r in config.rules if r.name == new_name), None)
    if new is None:
        return None
    shadower = earliest_shadower(config.rules, new)
    if shadower is None:
        return None
    names = [r.get("name") for r in raw_rules]
    try:
        src = names.index(new_name)
        dst = names.index(shadower.name)
    except ValueError:
        return None
    if src < dst:  # already ahead of the shadower
        return None
    entry = raw_rules.pop(src)  # src > dst, so dst does not shift
    raw_rules.insert(dst, entry)
    return shadower.name


def swap(raw_rules: list[dict], name: str, direction: str) -> tuple[list[dict] | None, str]:
    """Move `name` one step up or down the admin's list. Returns the new
    list and a message, or (None, reason) when it can't."""
    names = [r.get("name") for r in raw_rules]
    if name not in names:
        return None, f"No such rule {name!r}"
    i = names.index(name)
    j = i - 1 if direction == "up" else i + 1
    if j < 0 or j >= len(raw_rules):
        edge = "top" if direction == "up" else "bottom"
        return None, f"Rule {name!r} is already at the {edge} of the list"
    out = list(raw_rules)
    out[i], out[j] = out[j], out[i]
    return out, f"Rule {name!r} moved {direction}"


def move_before(raw_rules: list[dict], name: str, before: str) -> tuple[list[dict] | None, str]:
    """Put `name` immediately before `before` in the admin's list."""
    names = [r.get("name") for r in raw_rules]
    if name not in names:
        return None, f"No such rule {name!r}"
    if before not in names:
        return None, f"No such rule {before!r}"
    if name == before:
        return None, "a rule cannot be moved before itself"
    out = [r for r in raw_rules if r.get("name") != name]
    entry = next(r for r in raw_rules if r.get("name") == name)
    out.insert([r.get("name") for r in out].index(before), entry)
    return out, f"Rule {name!r} moved before {before!r}"
