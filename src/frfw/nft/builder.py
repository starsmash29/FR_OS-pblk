"""Translates a `frfw.config.Config` into an nftables ruleset (nft syntax).

The generated ruleset is meant to be loaded with `nft -f` (see
`frfw.apply`). It always starts with `flush ruleset`, so applying it fully
replaces whatever nftables state was previously loaded -- this keeps
"config file is the source of truth" simple, at the cost of not being able
to coexist with hand-written nftables rules outside of frfw. See
`BRUTEFORCE_JAIL_SET_NAME`'s and `ZTNA_SET_NAME`'s own comments below for
the two deliberate exceptions to "fully reproducible from YAML alone":
both sets hold runtime state by design (banned IPs; authorized ZTNA
clients), and surviving a `flush ruleset` for each is handled one layer
up, in `frfw.provision.apply_all`, not here.
"""

from __future__ import annotations

from frfw.config.schema import (
    SELF_ZONE,
    Config,
    Masquerade,
    PortForward,
    Protocol,
    Rule,
)

#: Single `inet` table holding both the filter and NAT chains. `inet`
#: supports `type nat` chains (nftables >= 0.9.7), which lets NAT rules
#: reference the same per-zone interface sets as the filter rules instead
#: of duplicating them in a separate `ip` table.
FILTER_TABLE = "fr_os"

#: Brute-force login jail (phase 10, see frfw.bruteforce): a source IP
#: added here by the privileged apply-helper (never by this module, and
#: never config-derived) is dropped by every subsequent packet for
#: however long its own element timeout has left. Unlike ZTNA_SET_NAME
#: below, this set is *always* declared, unconditionally -- brute-force
#: protection for the admin/ZTNA login endpoints isn't an optional
#: subsystem an admin opts into, it's baseline hygiene, the same way
#: `ct state invalid drop` isn't behind a config flag either.
#:
#: `flags timeout` alone (no `dynamic`) is enough for `nft add element
#: ... { <ip> timeout <n>s }` to carry its own per-element timeout,
#: confirmed directly against the real `nft` binary while writing this
#: (ZTNA_SET_NAME's `dynamic,timeout` combination also works, but
#: `dynamic` turned out not to be required for this use -- elements are
#: only ever added by an explicit `nft add element` call from
#: frfw.bruteforce, never by a rule adding to the set from the data
#: path, which is what `dynamic` is actually for).
#:
#: Same `flush ruleset` survival problem as ZTNA_SET_NAME (see that
#: constant's comment below for the full explanation) -- handled the
#: same way, one layer up in frfw.provision.apply_all, via
#: frfw.bruteforce.snapshot_before_reload/restore_after_reload.
BRUTEFORCE_JAIL_SET_NAME = "bruteforce_jail"

#: The ZTNA gate's kernel-resident set of currently-authorized source
#: IPs (see frfw.ztna and Rule.require_ztna). A `dynamic,timeout` set:
#: the kernel itself evicts an entry once its own `timeout` elapses, no
#: userspace polling/cron involved. Only ever rendered into the ruleset
#: when `config.ztna.enabled` -- an unused, always-empty set costs
#: nothing, but there's no reason to declare it when the feature is off.
#:
#: IMPORTANT: this set's *contents* do not survive a normal `apply`.
#: `flush ruleset` (this module's very first line) drops literally every
#: table, chain and set in the entire kernel nftables state, this one
#: included, and the reload below recreates it empty. That's normally
#: fine (a config's rules/sets are supposed to be fully reproducible from
#: the YAML alone) but would silently and abruptly log out every active
#: ZTNA session on the next unrelated firewall change -- so
#: frfw.provision.apply_all specifically snapshots this set's contents
#: (frfw.ztna.snapshot_before_reload) before calling apply_ruleset and
#: restores them (frfw.ztna.restore_after_reload) immediately after, each
#: with a fresh timeout equal to its previously-remaining time. See that
#: module's docstring for the full reasoning; this comment exists so
#: nobody "cleans up" that snapshot/restore call thinking it's dead code.
ZTNA_SET_NAME = "authenticated_ztna_users"


def build_ruleset(config: Config) -> str:
    zone_devices = _zone_devices(config)
    lines: list[str] = ["flush ruleset", "", f"table inet {FILTER_TABLE} {{"]

    for zone in sorted(zone_devices):
        lines.extend(_render_iface_set(zone, zone_devices[zone]))

    lines.append("")
    lines.extend(_render_bruteforce_jail_set())

    if config.ztna.enabled:
        lines.append("")
        lines.extend(_render_ztna_set(config))

    input_rules = [r for r in config.rules if r.to_zone == SELF_ZONE]
    forward_rules = [r for r in config.rules if r.to_zone != SELF_ZONE]

    lines.append("")
    lines.append("\tchain input {")
    lines.append("\t\ttype filter hook input priority filter; policy drop;")
    lines.append("")
    # Very top of the chain, before even the loopback accept: a source
    # IP the privileged helper has jailed is dropped outright, before
    # any other rule (including the config-derived ones below) gets a
    # chance to match it first.
    lines.append(f"\t\t{_render_bruteforce_drop_rule()}")
    lines.append('\t\tiifname "lo" accept')
    lines.append("\t\tct state established,related accept")
    lines.append("\t\tct state invalid drop")
    if input_rules:
        lines.append("")
        lines.extend(f"\t\t{_render_rule(r)}" for r in input_rules)
    lines.append("\t}")

    lines.append("")
    lines.append("\tchain forward {")
    lines.append("\t\ttype filter hook forward priority filter; policy drop;")
    lines.append("")
    lines.append("\t\tct state established,related accept")
    lines.append("\t\tct state invalid drop")
    if forward_rules:
        lines.append("")
        lines.extend(f"\t\t{_render_rule(r)}" for r in forward_rules)
    lines.append("\t}")

    lines.append("")
    lines.append("\tchain output {")
    lines.append("\t\ttype filter hook output priority filter; policy accept;")
    lines.append("\t}")

    if config.nat.masquerade or config.nat.port_forwards:
        lines.append("")
        lines.extend(_render_nat_chains(config))

    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _zone_devices(config: Config) -> dict[str, list[str]]:
    zones: dict[str, list[str]] = {name: [] for name in config.zones}
    for iface in config.interfaces.values():
        zones[iface.zone].append(iface.device)
    return zones


def _iface_set_name(zone: str) -> str:
    return f"{zone}_ifaces"


def _render_iface_set(zone: str, devices: list[str]) -> list[str]:
    elements = ", ".join(f'"{d}"' for d in devices)
    return [
        f"\tset {_iface_set_name(zone)} {{",
        "\t\ttype ifname",
        f"\t\telements = {{ {elements} }}",
        "\t}",
    ]


def _render_bruteforce_jail_set() -> list[str]:
    # No `elements = {...}` and no set-level default `timeout` line:
    # every element frfw.bruteforce.ban_ip adds carries its own explicit
    # `timeout <n>s`, since the ban duration is a per-call parameter
    # (from the socket request), not a single fixed value worth baking
    # into the set declaration the way ZTNA's session_ttl_seconds is.
    return [
        f"\tset {BRUTEFORCE_JAIL_SET_NAME} {{",
        "\t\ttype ipv4_addr",
        "\t\tflags timeout",
        "\t}",
    ]


def _render_bruteforce_drop_rule() -> str:
    return f"ip saddr @{BRUTEFORCE_JAIL_SET_NAME} drop {_comment('bruteforce-jail')}"


def _render_ztna_set(config: Config) -> list[str]:
    # No `elements = {...}` line, unlike _render_iface_set: this set's
    # membership is 100% runtime state (added by frfw.ztna.authorize_ip
    # via the privileged helper after a successful ZTNA login), never
    # config-derived -- an empty set here is the correct starting state
    # every time the ruleset is (re)loaded, restored from a pre-reload
    # snapshot immediately afterward when there's anything to restore
    # (see this module's ZTNA_SET_NAME comment).
    return [
        f"\tset {ZTNA_SET_NAME} {{",
        "\t\ttype ipv4_addr",
        "\t\tflags dynamic,timeout",
        f"\t\ttimeout {config.ztna.session_ttl_seconds}s",
        "\t}",
    ]


def _comment(text: str) -> str:
    return f'comment "{text.replace(chr(34), chr(39))}"'


def _render_rule(rule: Rule) -> str:
    exprs: list[str] = []

    if rule.from_zone is not None:
        exprs.append(f"iifname @{_iface_set_name(rule.from_zone)}")
    if rule.to_zone is not None and rule.to_zone != SELF_ZONE:
        exprs.append(f"oifname @{_iface_set_name(rule.to_zone)}")

    if rule.require_ztna:
        exprs.append(f"ip saddr @{ZTNA_SET_NAME}")

    if rule.dst_port is not None:
        exprs.append(f"{rule.proto.value} dport {rule.dst_port}")
    elif rule.proto != Protocol.ANY:
        exprs.append(f"ip protocol {rule.proto.value}")

    if rule.src_address is not None:
        exprs.append(f"ip saddr {rule.src_address}")
    if rule.dst_address is not None:
        exprs.append(f"ip daddr {rule.dst_address}")

    if rule.log:
        exprs.append(f'log prefix "fr_os/{rule.name}: "')

    exprs.append(rule.action.value)
    exprs.append(_comment(f"rule:{rule.name}"))
    return " ".join(exprs)


def _render_nat_chains(config: Config) -> list[str]:
    lines = ["\tchain prerouting {"]
    lines.append("\t\ttype nat hook prerouting priority dstnat; policy accept;")
    if config.nat.port_forwards:
        lines.append("")
        lines.extend(f"\t\t{_render_port_forward(pf)}" for pf in config.nat.port_forwards)
    lines.append("\t}")

    lines.append("")
    lines.append("\tchain postrouting {")
    lines.append("\t\ttype nat hook postrouting priority srcnat; policy accept;")
    if config.nat.masquerade:
        lines.append("")
        lines.extend(f"\t\t{_render_masquerade(m)}" for m in config.nat.masquerade)
    lines.append("\t}")
    return lines


def _render_masquerade(masq: Masquerade) -> str:
    return (
        f"oifname @{_iface_set_name(masq.out_zone)} masquerade "
        f"{_comment(f'nat:masquerade:{masq.out_zone}')}"
    )


def _render_port_forward(pf: PortForward) -> str:
    # `dnat ip to` (not plain `dnat to`): in an `inet` table dnat is
    # ambiguous between ip/ip6 families and nft requires it spelled out.
    # Phase 1 only supports IPv4 addresses (see config loader), so `ip`.
    return (
        f"iifname @{_iface_set_name(pf.in_zone)} {pf.proto.value} dport {pf.dst_port} "
        f"dnat ip to {pf.to_address}:{pf.to_port} {_comment(f'nat:portfwd:{pf.name}')}"
    )
