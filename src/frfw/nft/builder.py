"""Translates a `frfw.config.Config` into an nftables ruleset (nft syntax).

The generated ruleset is meant to be loaded with `nft -f` (see
`frfw.apply`). It always starts with `flush ruleset`, so applying it fully
replaces whatever nftables state was previously loaded -- this keeps
"config file is the source of truth" simple, at the cost of not being able
to coexist with hand-written nftables rules outside of frfw. See
`BRUTEFORCE_JAIL_SET_NAME`'s, `IDS_QUARANTINE_SET_NAME`'s,
`ZTNA_SET_NAME`'s and `IOT_ISOLATED_SET_NAME`'s own comments below for
the four deliberate exceptions to "fully reproducible from YAML alone":
each set holds runtime state by design (banned IPs; IDS-quarantined IPs;
authorized ZTNA clients; isolated IoT MACs), and surviving a `flush
ruleset` for each is handled one layer up, in `frfw.provision.apply_all`,
not here.
"""

from __future__ import annotations

from frfw.config.schema import (
    SELF_ZONE,
    Config,
    IotIsolationMode,
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

#: AI IDS/IPS quarantine set (phase 11, see frfw.ids_quarantine and
#: frfw.ai_ids): a source IP the unprivileged `fr-ai-ids` daemon has
#: flagged as anomalous (connection-rate spike, destination-scan
#: pattern, or repeated SNI-blocklist hits -- see frfw.ai_ids.engine)
#: gets added here by the privileged apply-helper, never by this module.
#: Same reasoning as BRUTEFORCE_JAIL_SET_NAME immediately above: declared
#: unconditionally (IDS/IPS enforcement isn't something worth turning
#: off independently of the detection engine itself, and an unused,
#: empty set costs nothing), `flags timeout` alone is sufficient for the
#: same reason (every element is added by an explicit `nft add element`
#: call from frfw.ids_quarantine.quarantine_ip, never by a data-path rule
#: needing `dynamic`), and it has the same `flush ruleset` survival
#: problem, handled the same way in frfw.provision.apply_all via
#: frfw.ids_quarantine.snapshot_before_reload/restore_after_reload.
IDS_QUARANTINE_SET_NAME = "ids_quarantine"

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

#: IoT isolation set (phase 14, see frfw.iot_isolation and frfw.iot):
#: MAC addresses (not IPs -- a DHCP renewal must not let a device slip
#: out) the privileged apply-helper puts here, never this module.
#: Matched with `ether saddr`, confirmed against the real `nft` binary to
#: work in an `inet` table's input and forward hooks, and it matches IPv4
#: and IPv6 traffic alike since it never looks at the IP header. Rendered
#: only when `config.iot.enabled`, like ZTNA_SET_NAME, and with the same
#: `flush ruleset` survival problem, handled the same way in
#: frfw.provision.apply_all via frfw.iot_isolation's snapshot/restore
#: pair. No `flags timeout`: membership is recomputed wholesale on every
#: scan (frfw.iot_isolation.sync_isolated), not aged out.
IOT_ISOLATED_SET_NAME = "iot_isolated"

#: Fixed local UDP port the IoT scanner (frfw.iot.mdns) sends its mDNS
#: query from. RFC 6762 section 6.7: a query from a source port other
#: than 5353 is a "legacy unicast" query, answered by unicast straight
#: back to that port -- so the input chain needs exactly one narrow
#: accept (`udp sport 5353 udp dport <this>`, from the IoT zones only)
#: instead of opening 5353 or accepting anything *from* port 5353, which
#: would let any LAN host reach every UDP service on the router just by
#: choosing that source port.
IOT_MDNS_REPLY_PORT = 53530


def build_ruleset(config: Config) -> str:
    zone_devices = _zone_devices(config)
    lines: list[str] = ["flush ruleset", "", f"table inet {FILTER_TABLE} {{"]

    for zone in sorted(zone_devices):
        lines.extend(_render_iface_set(zone, zone_devices[zone]))

    lines.append("")
    lines.extend(_render_bruteforce_jail_set())

    lines.append("")
    lines.extend(_render_ids_quarantine_set())

    if config.ztna.enabled:
        lines.append("")
        lines.extend(_render_ztna_set(config))

    if config.iot.enabled:
        lines.append("")
        lines.extend(_render_iot_isolated_set())

    input_rules = [r for r in config.rules if r.to_zone == SELF_ZONE]
    forward_rules = [r for r in config.rules if r.to_zone != SELF_ZONE]

    lines.append("")
    lines.append("\tchain input {")
    lines.append("\t\ttype filter hook input priority filter; policy drop;")
    lines.append("")
    # Very top of the chain, before even the loopback accept: a source
    # IP the privileged helper has jailed or quarantined is dropped
    # outright, before any other rule (including the config-derived
    # ones below) gets a chance to match it first.
    lines.append(f"\t\t{_render_bruteforce_drop_rule()}")
    lines.append(f"\t\t{_render_ids_quarantine_drop_rule()}")
    if config.iot.enabled:
        # Ahead of `ct state established,related accept` on purpose: an
        # isolated device's already-open sessions to the router are cut
        # the moment it's isolated, not whenever they happen to close.
        lines.extend(f"\t\t{r}" for r in _render_iot_input_rules(config))
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
    if config.iot.enabled:
        # Same "before established" placement as the input chain above,
        # and before every config-derived rule: an admin rule can't
        # accidentally re-open an isolated device -- iot.trusted_macs is
        # the one way to exempt it.
        lines.extend(f"\t\t{r}" for r in _render_iot_forward_rules(config))
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


def _render_ids_quarantine_set() -> list[str]:
    # Same shape as _render_bruteforce_jail_set() and the same reasoning
    # for no `elements = {...}`/set-level `timeout` line -- see
    # IDS_QUARANTINE_SET_NAME's own comment above.
    return [
        f"\tset {IDS_QUARANTINE_SET_NAME} {{",
        "\t\ttype ipv4_addr",
        "\t\tflags timeout",
        "\t}",
    ]


def _render_ids_quarantine_drop_rule() -> str:
    return f"ip saddr @{IDS_QUARANTINE_SET_NAME} drop {_comment('ids-quarantine')}"


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


def _render_iot_isolated_set() -> list[str]:
    return [
        f"\tset {IOT_ISOLATED_SET_NAME} {{",
        "\t\ttype ether_addr",
        "\t}",
    ]


def _render_iot_input_rules(config: Config) -> list[str]:
    rules = [
        f"iifname @{_iface_set_name(zone)} udp sport 5353 udp dport {IOT_MDNS_REPLY_PORT} "
        f"accept {_comment('iot-mdns-replies')}"
        for zone in config.iot.zones
    ]
    isolated = f"ether saddr @{IOT_ISOLATED_SET_NAME}"
    rules.append(f"{isolated} udp dport {{ 53, 67 }} accept {_comment('iot-isolated-dhcp-dns')}")
    rules.append(f"{isolated} tcp dport 53 accept {_comment('iot-isolated-dns-tcp')}")
    rules.append(f"{isolated} drop {_comment('iot-isolated-input')}")
    return rules


def _render_iot_forward_rules(config: Config) -> list[str]:
    isolated = f"ether saddr @{IOT_ISOLATED_SET_NAME}"
    rules: list[str] = []
    if config.iot.isolation_mode == IotIsolationMode.INTERNET_ONLY:
        for zone in sorted({m.out_zone for m in config.nat.masquerade}):
            rules.append(
                f"{isolated} oifname @{_iface_set_name(zone)} accept "
                f"{_comment('iot-isolated-internet')}"
            )
    rules.append(f"{isolated} drop {_comment('iot-isolated-forward')}")
    return rules


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
