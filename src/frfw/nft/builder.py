"""Translates a `frfw.config.Config` into an nftables ruleset (nft syntax).

The generated ruleset is meant to be loaded with `nft -f` (see
`frfw.apply`). It always starts with `flush ruleset`, so applying it fully
replaces whatever nftables state was previously loaded -- this keeps
"config file is the source of truth" simple, at the cost of not being able
to coexist with hand-written nftables rules outside of frfw.
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


def build_ruleset(config: Config) -> str:
    zone_devices = _zone_devices(config)
    lines: list[str] = ["flush ruleset", "", f"table inet {FILTER_TABLE} {{"]

    for zone in sorted(zone_devices):
        lines.extend(_render_iface_set(zone, zone_devices[zone]))

    input_rules = [r for r in config.rules if r.to_zone == SELF_ZONE]
    forward_rules = [r for r in config.rules if r.to_zone != SELF_ZONE]

    lines.append("")
    lines.append("\tchain input {")
    lines.append("\t\ttype filter hook input priority filter; policy drop;")
    lines.append("")
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


def _comment(text: str) -> str:
    return f'comment "{text.replace(chr(34), chr(39))}"'


def _render_rule(rule: Rule) -> str:
    exprs: list[str] = []

    if rule.from_zone is not None:
        exprs.append(f"iifname @{_iface_set_name(rule.from_zone)}")
    if rule.to_zone is not None and rule.to_zone != SELF_ZONE:
        exprs.append(f"oifname @{_iface_set_name(rule.to_zone)}")

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
