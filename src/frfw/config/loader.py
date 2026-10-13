"""Loads and validates a frfw YAML configuration into a `Config` object.

Kept dependency-free (stdlib `yaml` from PyYAML, which ships as the
`python3-yaml` Debian package) rather than pulling in a schema-validation
library, since this code is meant to run on the target router itself.
"""

from __future__ import annotations

import base64
import datetime
import ipaddress
import re
import zoneinfo
from pathlib import Path
from typing import Any

import yaml

from frfw import validate
from frfw.appid import blocking_names, known_app_ids
from frfw.config.errors import ConfigError
from frfw.config.schema import (
    SELF_ZONE,
    Action,
    AdblockerConfig,
    AiIdsConfig,
    AppControlConfig,
    Config,
    DhcpConfig,
    DhcpPool,
    DhcpReservation,
    Interface,
    IotConfig,
    IotIsolationMode,
    Ipv6Config,
    Ipv6Pinhole,
    LocalDnsConfig,
    LoggingConfig,
    ManagementConfig,
    Masquerade,
    MetricsConfig,
    NatConfig,
    PortForward,
    PqcConfig,
    Protocol,
    Rule,
    RuleSchedule,
    TlsFingerprintConfig,
    TlsFingerprintEntry,
    UpdateConfig,
    WireguardConfig,
    WireguardPeer,
    XdpSniFilterConfig,
    Zone,
    ZtnaConfig,
    ZtnaUser,
)

_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*\Z")
_PORT_RANGE_RE = re.compile(r"^(\d{1,5})-(\d{1,5})\Z")
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\Z")
_HOSTNAME_RE = re.compile(
    r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*$"
)
#: ZTNA gate usernames: deliberately looser than zone/interface/rule
#: names (_NAME_RE) since these are end-user account names, not
#: infrastructure identifiers -- but still tight enough to be a safe nft
#: comment string, so no whitespace/quotes/etc.
_ZTNA_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_SUPPORTED_VERSION = 1
#: Bounds for ztna.session_ttl_seconds: 1 minute minimum (long enough to
#: be meaningful, short enough to be useful for testing) to 30 days
#: maximum (nftables/the kernel timer wheel handles far longer, but a
#: month is already well past "temporary session" for this feature).
_ZTNA_MIN_TTL_SECONDS = 60
_ZTNA_MAX_TTL_SECONDS = 30 * 24 * 3600

#: Must match bpf/xdp_sni_filter.c's MAX_SNI_LEN #define -- kept in sync
#: by tests/test_xdp_sni_key.py rather than a shared import, since one
#: side is C and the other Python. A hostname of exactly this length or
#: longer can never match (the kernel program fails open on it, per
#: extract_sni's own comment), so it's rejected here at config-load time
#: with a clear error instead of silently never matching at runtime.
_MAX_SNI_LEN = 32


def read_config(path: str | Path) -> tuple[Config, str]:
    """`load_config`, also returning the text the config was parsed from
    -- read once, so the two always match (an apply records that text,
    ROADMAP SEC-5)."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")
    text = path.read_text()
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    return parse_config(raw), text


def load_config(path: str | Path) -> Config:
    """Read a YAML file from `path` and return a validated `Config`.

    Raises `ConfigError` (with a human-readable message) on any schema
    violation, and `FileNotFoundError` if `path` does not exist.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    return parse_config(raw)


def parse_config(raw: Any) -> Config:
    """Validate an already-parsed (dict) config and build a `Config`."""
    if not isinstance(raw, dict):
        raise ConfigError("Top-level config must be a mapping")

    version = raw.get("version")
    if version != _SUPPORTED_VERSION:
        raise ConfigError(
            f"Unsupported config version {version!r}; expected {_SUPPORTED_VERSION}"
        )

    hostname = raw.get("hostname")
    if not isinstance(hostname, str) or not hostname:
        raise ConfigError("'hostname' is required and must be a non-empty string")
    try:
        validate.hostname(hostname)  # it goes into the webUI certificate request
    except validate.ArgumentError as exc:
        raise ConfigError(str(exc)) from exc

    tz_name = raw.get("timezone")
    if tz_name is not None:
        if not isinstance(tz_name, str) or not _valid_timezone(tz_name):
            raise ConfigError(f"'timezone' must be an IANA time zone name (e.g. Europe/Budapest), got {tz_name!r}")

    zones = _parse_zones(raw.get("zones", {}))
    interfaces = _parse_interfaces(raw.get("interfaces", {}), zones, _tunnel_zones(raw.get("wireguard")))
    rules = _parse_rules(raw.get("rules", []), zones, tz_name)
    nat = _parse_nat(raw.get("nat", {}) or {}, zones)
    dhcp = _parse_dhcp(raw.get("dhcp", {}) or {}, zones, interfaces)
    ai_ids = _parse_ai_ids(raw.get("ai_ids", {}) or {})
    update = _parse_update(raw.get("update", {}) or {})
    xdp_sni_filter = _parse_xdp_sni_filter(raw.get("xdp_sni_filter", {}) or {}, interfaces)
    ztna = _parse_ztna(raw.get("ztna", {}) or {})
    pqc = _parse_pqc(raw.get("pqc", {}) or {})
    adblocker = _parse_adblocker(raw.get("adblocker", {}) or {}, dhcp)
    iot = _parse_iot(raw.get("iot", {}) or {}, zones, nat)
    app_control = _parse_app_control(
        raw.get("app_control", {}) or {}, adblocker, xdp_sni_filter
    )
    local_dns = _parse_local_dns(raw.get("local_dns", {}) or {}, adblocker, app_control)
    tls_fingerprint = _parse_tls_fingerprint(raw.get("tls_fingerprint", {}) or {}, xdp_sni_filter)
    metrics = _parse_metrics(raw.get("metrics", {}) or {})
    management = _parse_management(raw.get("management", {}) or {}, zones, nat)
    wireguard = _parse_wireguard(raw.get("wireguard", {}) or {}, zones, nat, interfaces)
    _check_management_addresses(management, zones, nat, interfaces, wireguard)
    logging_config = _parse_logging(raw.get("logging", {}) or {})
    ipv6 = _parse_ipv6(raw.get("ipv6", {}) or {}, interfaces, zones, nat, rules)
    _check_management_ipv6(management, ipv6, interfaces, zones, nat, rules)

    return Config(
        version=version,
        hostname=hostname,
        interfaces=interfaces,
        zones=zones,
        rules=rules,
        nat=nat,
        dhcp=dhcp,
        ai_ids=ai_ids,
        update=update,
        xdp_sni_filter=xdp_sni_filter,
        ztna=ztna,
        pqc=pqc,
        adblocker=adblocker,
        local_dns=local_dns,
        iot=iot,
        app_control=app_control,
        tls_fingerprint=tls_fingerprint,
        metrics=metrics,
        management=management,
        wireguard=wireguard,
        logging=logging_config,
        ipv6=ipv6,
        timezone=tz_name,
    )


def _require_name(name: Any, what: str) -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise ConfigError(
            f"Invalid {what} name {name!r}: must match {_NAME_RE.pattern} "
            "(lowercase letters, digits, '-'/'_', starting with a letter)"
        )
    return name


def _parse_zones(raw: Any) -> dict[str, Zone]:
    if not isinstance(raw, dict):
        raise ConfigError("'zones' must be a mapping of zone name -> settings")
    zones: dict[str, Zone] = {}
    for name, body in raw.items():
        _require_name(name, "zone")
        if name == SELF_ZONE:
            raise ConfigError(f"Zone name {SELF_ZONE!r} is reserved")
        body = body or {}
        if not isinstance(body, dict):
            raise ConfigError(f"Zone {name!r} settings must be a mapping")
        description = body.get("description", "")
        zones[name] = Zone(name=name, description=description)
    return zones


def _parse_interfaces(
    raw: Any, zones: dict[str, Zone], tunnel_zones: set[str] = frozenset()
) -> dict[str, Interface]:
    if not isinstance(raw, dict) or not raw:
        raise ConfigError("'interfaces' must be a non-empty mapping")
    interfaces: dict[str, Interface] = {}
    seen_devices: dict[str, str] = {}
    for name, body in raw.items():
        _require_name(name, "interface")
        if not isinstance(body, dict):
            raise ConfigError(f"Interface {name!r} settings must be a mapping")

        device = body.get("device")
        if not isinstance(device, str) or not device:
            raise ConfigError(f"Interface {name!r} is missing a 'device'")
        try:
            validate.ifname(device)  # security-lessons F1: it becomes an `ip`/`nft` argument
        except validate.ArgumentError as exc:
            raise ConfigError(f"Interface {name!r}: {exc}") from exc
        if device in seen_devices:
            raise ConfigError(
                f"Device {device!r} is assigned to both "
                f"{seen_devices[device]!r} and {name!r}"
            )
        seen_devices[device] = name

        zone = body.get("zone")
        if not isinstance(zone, str) or zone not in zones:
            raise ConfigError(
                f"Interface {name!r} references undefined zone {zone!r}; "
                f"declare it under 'zones' first"
            )

        address = body.get("address")
        if address is not None:
            address = _validate_interface_address(address, f"Interface {name!r} address")

        description = body.get("description", "")
        vlan_parent = vlan_id = None
        vlan = body.get("vlan")
        if vlan is not None:
            if not isinstance(vlan, dict):
                raise ConfigError(f"Interface {name!r}: vlan must be a mapping with parent and id")
            vlan_parent, vlan_id = vlan.get("parent"), vlan.get("id")
            try:
                validate.ifname(vlan_parent)
            except validate.ArgumentError as exc:
                raise ConfigError(f"Interface {name!r} vlan.parent: {exc}") from exc
            if not isinstance(vlan_id, int) or isinstance(vlan_id, bool) or not 1 <= vlan_id <= 4094:
                raise ConfigError(f"Interface {name!r}: vlan.id must be 1-4094")
            if vlan_parent == device:
                raise ConfigError(f"Interface {name!r}: a VLAN can't be its own parent")
        interfaces[name] = Interface(
            name=name, device=device, zone=zone, address=address, description=description,
            vlan_parent=vlan_parent, vlan_id=vlan_id,
        )

    used_zones = {iface.zone for iface in interfaces.values()} | set(tunnel_zones)
    for zone_name in zones:
        if zone_name not in used_zones:
            raise ConfigError(
                f"Zone {zone_name!r} is declared but not used by any interface"
            )
    return interfaces


def _valid_zone_ref(zone: Any, zones: dict[str, Zone]) -> bool:
    return zone is None or zone == SELF_ZONE or zone in zones


def _parse_rules(raw: Any, zones: dict[str, Zone], tz_name: str | None = None) -> list[Rule]:
    if not isinstance(raw, list):
        raise ConfigError("'rules' must be a list")
    rules: list[Rule] = []
    seen_names: set[str] = set()
    for i, body in enumerate(raw):
        if not isinstance(body, dict):
            raise ConfigError(f"rules[{i}] must be a mapping")

        name = body.get("name")
        _require_name(name, "rule")
        if name in seen_names:
            raise ConfigError(f"Duplicate rule name {name!r}")
        seen_names.add(name)

        try:
            action = Action(body.get("action"))
        except ValueError as exc:
            raise ConfigError(
                f"Rule {name!r}: invalid action {body.get('action')!r}; "
                f"expected one of {[a.value for a in Action]}"
            ) from exc

        from_zone = body.get("from_zone")
        if not _valid_zone_ref(from_zone, zones) or from_zone == SELF_ZONE:
            raise ConfigError(f"Rule {name!r}: invalid from_zone {from_zone!r}")

        to_zone = body.get("to_zone")
        if not _valid_zone_ref(to_zone, zones):
            raise ConfigError(f"Rule {name!r}: invalid to_zone {to_zone!r}")

        proto_raw = body.get("proto", Protocol.ANY.value)
        try:
            proto = Protocol(proto_raw)
        except ValueError as exc:
            raise ConfigError(
                f"Rule {name!r}: invalid proto {proto_raw!r}; "
                f"expected one of {[p.value for p in Protocol]}"
            ) from exc

        dst_port = body.get("dst_port")
        if dst_port is not None:
            if proto not in (Protocol.TCP, Protocol.UDP):
                raise ConfigError(
                    f"Rule {name!r}: dst_port requires proto tcp or udp, got {proto.value!r}"
                )
            dst_port = _validate_port_spec(dst_port, f"Rule {name!r} dst_port")

        src_address = _parse_networks(body.get("src_address"), f"Rule {name!r} src_address")
        dst_address = _parse_networks(body.get("dst_address"), f"Rule {name!r} dst_address")
        if src_address and dst_address and not (
                {ipaddress.ip_network(n).version for n in src_address}
                & {ipaddress.ip_network(n).version for n in dst_address}):
            raise ConfigError(
                f"Rule {name!r}: src_address and dst_address have no address family in common, "
                "so the rule could never match"
            )

        log = bool(body.get("log", False))
        require_ztna = bool(body.get("require_ztna", False))

        src_mac = body.get("src_mac")
        if src_mac is not None:
            if not isinstance(src_mac, str) or not _MAC_RE.match(src_mac):
                raise ConfigError(f"Rule {name!r}: invalid src_mac {src_mac!r}")
            src_mac = src_mac.lower()

        schedule = None
        if body.get("schedule") is not None:
            schedule = _parse_schedule(body["schedule"], f"Rule {name!r} schedule", action)

        expires = None
        if body.get("expires") is not None:
            expires = parse_expiry(body["expires"], tz_name, f"Rule {name!r} expires")

        rules.append(
            Rule(
                name=name,
                action=action,
                from_zone=from_zone,
                to_zone=to_zone,
                proto=proto,
                dst_port=dst_port,
                src_address=src_address,
                dst_address=dst_address,
                log=log,
                require_ztna=require_ztna,
                src_mac=src_mac,
                schedule=schedule,
                expires=expires,
            )
        )
    return rules


def parse_expiry(value: Any, tz_name: str | None, what: str = "expires") -> int:
    """A rule's expiry (security-lessons K2) as Unix time: an ISO 8601
    date and time ("2026-10-01T18:00", or YAML's own timestamp); without
    an offset it is read in the config's `timezone` (else the router's)."""
    if isinstance(value, datetime.datetime):
        moment = value
    elif isinstance(value, str):
        try:
            moment = datetime.datetime.fromisoformat(value.strip())
        except ValueError as exc:
            raise ConfigError(f"{what}: expected a date and time like 2026-10-01T18:00, got {value!r}") from exc
    else:
        raise ConfigError(f"{what}: expected a date and time like 2026-10-01T18:00, got {value!r}")
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=zoneinfo.ZoneInfo(tz_name)) if tz_name else moment.astimezone()
    return int(moment.timestamp())


def _validate_port_spec(value: Any, what: str) -> str:
    if isinstance(value, int):
        if not 1 <= value <= 65535:
            raise ConfigError(f"{what}: port {value} out of range 1-65535")
        return str(value)
    if isinstance(value, str):
        m = _PORT_RANGE_RE.match(value)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535 and lo <= hi):
                raise ConfigError(f"{what}: invalid port range {value!r}")
            return f"{lo}-{hi}"
    raise ConfigError(
        f"{what}: expected an integer port or 'start-end' range string, got {value!r}"
    )


def _parse_networks(value: Any, what: str) -> tuple[str, ...] | None:
    """A rule's address field (ROADMAP FND-1d): one network, or a list of
    them, of either family -- `10.0.0.5/32`, `[10.0.0.0/24,
    2001:db8:5::/48]`. Normalized and without repeats, in the order given."""
    if value is None:
        return None
    items = value if isinstance(value, list) else [value]
    if not items:
        raise ConfigError(f"{what}: an empty list matches nothing; leave the key out instead")
    out: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise ConfigError(f"{what}: expected an address/network string, got {item!r}")
        try:
            parsed = ipaddress.ip_network(item.strip(), strict=False)
        except ValueError as exc:
            raise ConfigError(f"{what}: invalid IPv4 or IPv6 address/network {item!r}: {exc}") from exc
        if _scoped(parsed):
            raise ConfigError(f"{what}: invalid IPv4 or IPv6 address/network {item!r}: no scope (%) allowed")
        network = str(parsed)
        if network not in out:
            out.append(network)
    return tuple(out)


def _validate_address(value: Any, what: str) -> None:
    if not isinstance(value, str):
        raise ConfigError(f"{what}: expected a string, got {value!r}")
    try:
        ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ConfigError(f"{what}: invalid IPv4 address {value!r}: {exc}") from exc


def _validate_interface_address(value: Any, what: str) -> str:
    # An interface address is a host address *with* a prefix length (e.g.
    # "10.0.0.1/24") -- IPv4Interface (unlike IPv4Network) keeps the host
    # bits, which is exactly what "the router's own address" means.
    if not isinstance(value, str):
        raise ConfigError(f"{what}: expected a string, got {value!r}")
    try:
        return str(ipaddress.IPv4Interface(value))
    except ValueError as exc:
        raise ConfigError(
            f"{what}: expected an IPv4 address with prefix length (e.g. "
            f"'10.0.0.1/24'), got {value!r}: {exc}"
        ) from exc


def _parse_nat(raw: Any, zones: dict[str, Zone]) -> NatConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'nat' must be a mapping")

    masquerade: list[Masquerade] = []
    for i, body in enumerate(raw.get("masquerade", []) or []):
        if not isinstance(body, dict):
            raise ConfigError(f"nat.masquerade[{i}] must be a mapping")
        out_zone = body.get("out_zone")
        if not _valid_zone_ref(out_zone, zones) or out_zone in (None, SELF_ZONE):
            raise ConfigError(f"nat.masquerade[{i}]: invalid out_zone {out_zone!r}")
        masquerade.append(Masquerade(out_zone=out_zone))

    port_forwards: list[PortForward] = []
    seen_names: set[str] = set()
    for i, body in enumerate(raw.get("port_forwards", []) or []):
        if not isinstance(body, dict):
            raise ConfigError(f"nat.port_forwards[{i}] must be a mapping")

        name = body.get("name")
        _require_name(name, "port_forward")
        if name in seen_names:
            raise ConfigError(f"Duplicate port_forward name {name!r}")
        seen_names.add(name)

        in_zone = body.get("in_zone")
        if not _valid_zone_ref(in_zone, zones) or in_zone in (None, SELF_ZONE):
            raise ConfigError(
                f"nat.port_forwards[{name!r}]: invalid in_zone {in_zone!r}"
            )

        try:
            proto = Protocol(body.get("proto"))
        except ValueError as exc:
            raise ConfigError(
                f"nat.port_forwards[{name!r}]: invalid proto {body.get('proto')!r}"
            ) from exc
        if proto not in (Protocol.TCP, Protocol.UDP):
            raise ConfigError(
                f"nat.port_forwards[{name!r}]: proto must be tcp or udp, got {proto.value!r}"
            )

        dst_port_raw = body.get("dst_port")
        if not isinstance(dst_port_raw, int) or not 1 <= dst_port_raw <= 65535:
            raise ConfigError(
                f"nat.port_forwards[{name!r}]: dst_port must be an integer 1-65535"
            )

        to_address = body.get("to_address")
        _validate_address(to_address, f"nat.port_forwards[{name!r}] to_address")

        to_port_raw = body.get("to_port", dst_port_raw)
        if not isinstance(to_port_raw, int) or not 1 <= to_port_raw <= 65535:
            raise ConfigError(
                f"nat.port_forwards[{name!r}]: to_port must be an integer 1-65535"
            )

        port_forwards.append(
            PortForward(
                name=name,
                in_zone=in_zone,
                proto=proto,
                dst_port=dst_port_raw,
                to_address=to_address,
                to_port=to_port_raw,
            )
        )

    return NatConfig(masquerade=masquerade, port_forwards=port_forwards)


def _parse_dhcp(
    raw: Any, zones: dict[str, Zone], interfaces: dict[str, Interface]
) -> DhcpConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'dhcp' must be a mapping of zone name -> pool settings")

    interfaces_by_zone: dict[str, list[Interface]] = {}
    for iface in interfaces.values():
        interfaces_by_zone.setdefault(iface.zone, []).append(iface)

    pools: dict[str, DhcpPool] = {}
    for zone_name, body in raw.items():
        if zone_name not in zones:
            raise ConfigError(f"dhcp: undefined zone {zone_name!r}")
        if not isinstance(body, dict):
            raise ConfigError(f"dhcp[{zone_name!r}] must be a mapping")

        zone_interfaces = interfaces_by_zone.get(zone_name, [])
        if len(zone_interfaces) != 1:
            raise ConfigError(
                f"dhcp[{zone_name!r}]: DHCP requires exactly one interface in "
                f"this zone, found {len(zone_interfaces)}"
            )
        iface = zone_interfaces[0]
        if iface.address is None:
            raise ConfigError(
                f"dhcp[{zone_name!r}]: interface {iface.name!r} needs a static "
                f"'address' before it can serve DHCP on this zone"
            )
        network = ipaddress.IPv4Interface(iface.address).network
        gateway = ipaddress.IPv4Interface(iface.address).ip

        what = f"dhcp[{zone_name!r}]"
        range_start = _validate_pool_address(body.get("range_start"), network, gateway, f"{what} range_start")
        range_end = _validate_pool_address(body.get("range_end"), network, gateway, f"{what} range_end")
        if range_start > range_end:
            raise ConfigError(f"{what}: range_start must not be after range_end")

        dns_servers = body.get("dns_servers")
        if not isinstance(dns_servers, list) or not dns_servers:
            raise ConfigError(f"{what}: 'dns_servers' must be a non-empty list of IPv4 addresses")
        for dns in dns_servers:
            _validate_address(dns, f"{what} dns_servers")

        lease_time = body.get("lease_time", 3600)
        if not isinstance(lease_time, int) or lease_time <= 0:
            raise ConfigError(f"{what}: 'lease_time' must be a positive integer (seconds)")

        reservations = _parse_dhcp_reservations(body.get("reservations", []), network, gateway, what)

        pools[zone_name] = DhcpPool(
            zone=zone_name,
            range_start=str(range_start),
            range_end=str(range_end),
            dns_servers=[str(ipaddress.IPv4Address(d)) for d in dns_servers],
            lease_time=lease_time,
            reservations=reservations,
        )

    return DhcpConfig(zones=pools)


def _validate_pool_address(
    value: Any, network: ipaddress.IPv4Network, gateway: ipaddress.IPv4Address, what: str
) -> ipaddress.IPv4Address:
    if not isinstance(value, str):
        raise ConfigError(f"{what}: expected a string, got {value!r}")
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ConfigError(f"{what}: invalid IPv4 address {value!r}: {exc}") from exc
    if address not in network:
        raise ConfigError(f"{what}: {address} is not inside subnet {network}")
    if address == gateway:
        raise ConfigError(f"{what}: {address} is the gateway address, cannot be in the pool")
    return address


def _parse_dhcp_reservations(
    raw: Any, network: ipaddress.IPv4Network, gateway: ipaddress.IPv4Address, what: str
) -> list[DhcpReservation]:
    if not isinstance(raw, list):
        raise ConfigError(f"{what}: 'reservations' must be a list")

    reservations: list[DhcpReservation] = []
    seen_macs: set[str] = set()
    seen_addresses: set[str] = set()
    for i, body in enumerate(raw):
        if not isinstance(body, dict):
            raise ConfigError(f"{what} reservations[{i}] must be a mapping")

        mac = body.get("mac")
        if not isinstance(mac, str) or not _MAC_RE.match(mac):
            raise ConfigError(
                f"{what} reservations[{i}]: invalid MAC address {mac!r} "
                "(expected aa:bb:cc:dd:ee:ff)"
            )
        mac = mac.lower()
        if mac in seen_macs:
            raise ConfigError(f"{what} reservations[{i}]: duplicate MAC address {mac!r}")
        seen_macs.add(mac)

        address = _validate_pool_address(body.get("address"), network, gateway, f"{what} reservations[{i}] address")
        if str(address) in seen_addresses:
            raise ConfigError(f"{what} reservations[{i}]: duplicate address {address}")
        seen_addresses.add(str(address))

        hostname = body.get("hostname", "")
        if not isinstance(hostname, str):
            raise ConfigError(f"{what} reservations[{i}]: 'hostname' must be a string")

        reservations.append(
            DhcpReservation(mac_address=mac, address=str(address), hostname=hostname)
        )

    return reservations


#: Mirrors frfw.ids_quarantine.MAX_DURATION_SECONDS (not imported: the
#: loader stays free of the kernel-facing modules).
_MAX_QUARANTINE_SECONDS = 7 * 24 * 3600


def _parse_ai_ids(raw: Any) -> AiIdsConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'ai_ids' must be a mapping")

    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError("ai_ids.enabled must be a boolean")

    excluded_raw = raw.get("excluded_macs", [])
    if not isinstance(excluded_raw, list):
        raise ConfigError("ai_ids.excluded_macs must be a list")
    excluded_macs = []
    for i, mac in enumerate(excluded_raw):
        if not isinstance(mac, str) or not _MAC_RE.match(mac):
            raise ConfigError(f"ai_ids.excluded_macs[{i}]: invalid MAC address {mac!r}")
        excluded_macs.append(mac.lower())

    quarantine_duration_seconds = raw.get("quarantine_duration_seconds", 2 * 3600)
    if (
        not isinstance(quarantine_duration_seconds, int)
        or isinstance(quarantine_duration_seconds, bool)
        or quarantine_duration_seconds <= 0
    ):
        raise ConfigError("ai_ids.quarantine_duration_seconds must be a positive integer")
    if quarantine_duration_seconds > _MAX_QUARANTINE_SECONDS:
        # The apply-helper refuses longer ones (frfw.ids_quarantine).
        raise ConfigError(
            f"ai_ids.quarantine_duration_seconds may be at most {_MAX_QUARANTINE_SECONDS} (7 days)"
        )

    return AiIdsConfig(
        enabled=enabled,
        excluded_macs=excluded_macs,
        quarantine_duration_seconds=quarantine_duration_seconds,
    )


def _parse_update(raw: Any) -> UpdateConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'update' must be a mapping")

    repo = raw.get("repo", "")
    if not isinstance(repo, str):
        raise ConfigError("update.repo must be a string")
    if repo:
        try:
            validate.github_repo(repo)
        except validate.ArgumentError as exc:
            raise ConfigError(f"update.repo: {exc}") from exc

    auto_install_security = raw.get("auto_install_security", False)
    if not isinstance(auto_install_security, bool):
        raise ConfigError("update.auto_install_security must be true or false")

    kernel_updates = raw.get("kernel_updates", True)
    if not isinstance(kernel_updates, bool):
        raise ConfigError("update.kernel_updates must be true or false")

    return UpdateConfig(repo=repo, auto_install_security=auto_install_security, kernel_updates=kernel_updates)


def internet_facing_zones(zones: dict[str, Zone], nat: NatConfig) -> set[str]:
    """Zones that face the internet: every nat.masquerade out_zone, and a
    zone called "wan" even without NAT."""
    return {m.out_zone for m in nat.masquerade} | ({"wan"} & set(zones))


def ipv6_lan_zones(ipv6: Ipv6Config, interfaces: dict[str, Interface], zones: dict[str, Zone],
                   nat: NatConfig, rules: list[Rule] = ()) -> list[str]:
    """The zones the delegated prefix goes to (ROADMAP FND-1b), in order:
    `ipv6.lan_zones`, or every zone with an interface that doesn't face
    the internet, in config order -- but those IPv6 would get around a
    protection of (ipv6_lan_exclusions). Empty while IPv6 is off."""
    if not ipv6.enabled:
        return []
    if ipv6.lan_zones is not None:
        return list(ipv6.lan_zones)
    facing = internet_facing_zones(zones, nat)
    with_interface = {i.zone for i in interfaces.values()}
    excluded = ipv6_lan_exclusions(zones, nat, rules)
    return [z for z in zones if z not in facing and z in with_interface and z not in excluded]


def ipv6_lan_exclusions(zones: dict[str, Zone], nat: NatConfig, rules: list[Rule] = ()) -> dict[str, str]:
    """Zone -> why it can't have IPv6 (ROADMAP FND-1b): something that
    protects it is IPv4-only, so IPv6 would quietly open what the admin
    closed -- the host blocked by its IPv4 address reaching the same place
    over IPv6. Left out of the default `lan_zones`, refused in an explicit
    one.

    - A forward drop/reject rule by IPv4 address only (`src_address`,
      `dst_address` naming no IPv6 network, rendered `ip saddr`/`ip
      daddr`) touching the zone -- naming it, or no zone at all. One whose
      traffic comes from the internet is no gap: nothing new comes in
      from the internet over IPv6. One that names IPv6 networks too
      (ROADMAP FND-1d) is rendered for IPv6 as well: the admin covered
      the other family.

    The XDP SNI filter (and with it app control) kept its zones off IPv6
    too, until it read IPv6 itself (ROADMAP FND-1d)."""
    facing = internet_facing_zones(zones, nat)
    out: dict[str, str] = {}
    for rule in rules:
        if rule.action == Action.ACCEPT or rule.to_zone == SELF_ZONE:
            continue
        if not rule.ipv4_addresses_only:
            continue
        if rule.from_zone is not None and rule.from_zone in facing:
            continue
        reason = (f"rule {rule.name!r} blocks by IPv4 address only, which IPv6 would get around "
                  "(block a LAN host by MAC, src_mac: it picks its IPv6 addresses itself; "
                  "or name the IPv6 networks in the rule too)")
        for zone in zones:
            if zone not in facing and (rule.from_zone in (None, zone) or rule.to_zone in (None, zone)):
                out.setdefault(zone, reason)
    return out


def _parse_ipv6(raw: Any, interfaces: dict[str, Interface], zones: dict[str, Zone], nat: NatConfig,
                rules: list[Rule] = ()) -> Ipv6Config:
    if not isinstance(raw, dict):
        raise ConfigError("'ipv6' must be a mapping")
    unknown = set(raw) - {"enabled", "lan_zones", "ula_prefix", "pinholes"}
    if unknown:
        raise ConfigError(f"ipv6: unknown key(s) {sorted(unknown)}")
    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError("ipv6.enabled must be true or false")
    facing = internet_facing_zones(zones, nat)
    lan_zones = raw.get("lan_zones")
    if lan_zones is not None:
        if not isinstance(lan_zones, list) or not all(isinstance(z, str) for z in lan_zones):
            raise ConfigError("ipv6.lan_zones must be a list of zone names")
        if len(set(lan_zones)) != len(lan_zones):
            raise ConfigError("ipv6.lan_zones names a zone more than once")
        with_interface = {i.zone for i in interfaces.values()}
        excluded = ipv6_lan_exclusions(zones, nat, rules) if enabled else {}
        for zone in lan_zones:
            if zone not in zones:
                raise ConfigError(f"ipv6.lan_zones: unknown zone {zone!r}")
            if zone in facing:
                raise ConfigError(f"ipv6.lan_zones: {zone!r} faces the internet; the prefix comes from there")
            if zone not in with_interface:
                raise ConfigError(f"ipv6.lan_zones: zone {zone!r} has no interface to give a prefix to")
            if zone in excluded:
                raise ConfigError(f"ipv6.lan_zones: zone {zone!r} can't have IPv6: {excluded[zone]}")
        lan_zones = tuple(lan_zones)
    if enabled and not any(i.zone in facing for i in interfaces.values()):
        raise ConfigError(
            "ipv6.enabled needs an internet-facing interface (a zone nat.masquerade points at, "
            "or a zone named wan): IPv6 is taken from the provider there"
        )
    ula_prefix = _parse_ula_prefix(raw.get("ula_prefix"))
    pinholes = _parse_pinholes(raw.get("pinholes", []), enabled, set(zones), facing, rules)
    return Ipv6Config(enabled=enabled, lan_zones=lan_zones, ula_prefix=ula_prefix, pinholes=pinholes)


#: RFC 4193: a ULA is fd00::/8 with a 40-bit random global ID -- a /48.
_ULA_LOCAL = ipaddress.IPv6Network("fd00::/8")


def _scoped(value: ipaddress.IPv6Address | ipaddress.IPv6Network | ipaddress.IPv4Network | None) -> bool:
    """An IPv6 address or network with a scope (`%...`). Python's ipaddress
    takes any text after the `%` as one and gives it back in str() -- so
    into the nft script, unchecked (security-lessons F1)."""
    address = value.network_address if isinstance(value, ipaddress.IPv6Network) else value
    return getattr(address, "scope_id", None) is not None


def _parse_ula_prefix(raw: Any) -> str | None:
    if raw is None:
        return None
    try:
        network = ipaddress.IPv6Network(raw) if isinstance(raw, str) else None
    except ValueError:
        network = None
    if _scoped(network):
        network = None
    if network is None or network.prefixlen != 48 or not network.subnet_of(_ULA_LOCAL):
        raise ConfigError(f"ipv6.ula_prefix must be a ULA /48 in fd00::/8 (RFC 4193), e.g. fd12:3456:789a::/48, "
                          f"got {raw!r}")
    if network == ipaddress.IPv6Network("fd00::/48"):
        # RFC 4193 3.2: the global ID is random, so two networks joined
        # later (a VPN, a merger) don't collide; all zeros is the one
        # everyone would pick.
        raise ConfigError("ipv6.ula_prefix: fd00::/48 is not a random global ID (RFC 4193 3.2); "
                          "leave ula_prefix out and the router picks one")
    return str(network)


#: The widest port range one pinhole may open: a pinhole is for a
#: service, not for a host's whole port space.
PINHOLE_MAX_PORTS = 1000

#: RFC 5453: reserved interface identifiers (the subnet's anycast ones).
_RESERVED_IID_FROM = 0xfdff_ffff_ffff_ff80


def _pinhole_host(raw: Any, what: str) -> str:
    """A host part a pinhole may point at: an interface identifier (the
    low 64 bits, `::…`) or a full global unicast address -- never one
    that means more than one host or the router itself."""
    try:
        address = ipaddress.IPv6Address(raw) if isinstance(raw, str) else None
    except ValueError:
        address = None
    if _scoped(address):
        address = None
    if address is None:
        raise ConfigError(f"{what}: host must be an IPv6 address or an interface identifier such as "
                          f"::5054:ff:fe12:3456, got {raw!r}")
    iid = int(address) & ((1 << 64) - 1)
    if iid == 0:
        raise ConfigError(f"{what}: host {raw!r} is the subnet-router anycast address (all hosts' router), not a host")
    if iid == 1:
        raise ConfigError(f"{what}: host {raw!r} is the router's own address on the LAN (::1), not a host")
    if iid >= _RESERVED_IID_FROM:
        raise ConfigError(f"{what}: host {raw!r} is a reserved anycast identifier (RFC 5453), not a host")
    if int(address) >> 64 and not (address in _GLOBAL_UNICAST and address not in _ULA):
        raise ConfigError(f"{what}: host {raw!r} must be a global unicast address (2000::/3), or an interface "
                          "identifier (::…) to follow the provider's prefix")
    return str(address)


_GLOBAL_UNICAST = ipaddress.IPv6Network("2000::/3")
#: RFC 4193: unique local addresses, never routed to or from the internet.
_ULA = ipaddress.IPv6Network("fc00::/7")


def _port_bounds(spec: str) -> tuple[int, int]:
    low, _, high = spec.partition("-")
    return int(low), int(high or low)


def _parse_pinholes(raw: Any, enabled: bool, zones: set[str], facing: set[str],
                    rules: list[Rule]) -> tuple[Ipv6Pinhole, ...]:
    """ipv6.pinholes (ROADMAP FND-1c). While IPv6 is off they are kept
    but not checked against the zones (the webUI's IPv6 switch keeps
    them), and nothing renders them. A LAN zone that has no IPv6 now --
    left out of `lan_zones`, or taken off it by an IPv4-only protection
    turned on later (the SNI filter) -- keeps its pinholes too, unused
    and shown as off: a pinhole must never stand in the way of a
    protection."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError("ipv6.pinholes must be a list")
    out: list[Ipv6Pinhole] = []
    for index, body in enumerate(raw):
        if not isinstance(body, dict):
            raise ConfigError(f"ipv6.pinholes[{index}] must be a mapping")
        name = _require_name(body.get("name"), f"ipv6.pinholes[{index}]")
        what = f"ipv6.pinholes[{name!r}]"
        unknown = set(body) - {"name", "zone", "host", "proto", "port", "from"}
        if unknown:
            raise ConfigError(f"{what}: unknown key(s) {sorted(unknown)}")
        if any(p.name == name for p in out):
            raise ConfigError(f"ipv6.pinholes: {name!r} is named twice")
        zone = body.get("zone")
        if not isinstance(zone, str):
            raise ConfigError(f"{what}: zone is required")
        if enabled and (zone not in zones or zone in facing):
            raise ConfigError(f"{what}: zone {zone!r} is not a LAN zone of this config")
        host = _pinhole_host(body.get("host"), what)
        proto_raw = body.get("proto")
        if proto_raw not in (Protocol.TCP.value, Protocol.UDP.value):
            raise ConfigError(f"{what}: proto must be tcp or udp, got {proto_raw!r}")
        proto = Protocol(proto_raw)
        if body.get("port") is None:
            raise ConfigError(f"{what}: port is required")
        port_from, port_to = _port_bounds(_validate_port_spec(body.get("port"), f"{what} port"))
        if port_to - port_from + 1 > PINHOLE_MAX_PORTS:
            raise ConfigError(f"{what}: {port_to - port_from + 1} ports is more than one pinhole may open "
                              f"({PINHOLE_MAX_PORTS})")
        source = body.get("from")
        if source is not None:
            try:
                network = ipaddress.IPv6Network(source, strict=False) if isinstance(source, str) else None
            except ValueError:
                network = None
            if _scoped(network):
                network = None
            if network is None:
                raise ConfigError(f"{what}: from must be an IPv6 network such as 2001:db8:42::/48, got {source!r}")
            if network.overlaps(_ULA) or network.is_link_local or network.is_multicast:
                raise ConfigError(f"{what}: from {source!r} can't come from the internet")
            source = str(network)
        pinhole = Ipv6Pinhole(name=name, zone=zone, host=host, proto=proto, port_from=port_from,
                              port_to=port_to, source=source)
        blocker = _rule_dropping_pinhole(pinhole, facing, rules)
        if blocker is not None:
            raise ConfigError(
                f"{what}: rule {blocker!r} drops this traffic, and a pinhole goes ahead of the rules "
                "(a drop rule would not hold). Remove the rule, or narrow the pinhole"
            )
        out.append(pinhole)
    return tuple(out)


def _rule_dropping_pinhole(pinhole: Ipv6Pinhole, facing: set[str], rules: list[Rule]) -> str | None:
    """A forward drop/reject rule that would match a pinhole's traffic --
    from the internet, to its zone, its protocol and a port of it. The
    pinholes are rendered ahead of every rule (after the "nothing new
    from the internet" drop, which they are the exceptions to), so such a
    rule would silently stop holding. A rule by IPv4 address only never
    matches IPv6: no conflict. One naming IPv6 networks is taken to match
    (ROADMAP FND-1d): a pinhole's host has whatever address its prefix
    gives it, which the config can't compare."""
    for rule in rules:
        if rule.action == Action.ACCEPT or rule.to_zone == SELF_ZONE:
            continue
        if 6 not in rule.families:
            continue
        if rule.from_zone is not None and rule.from_zone not in facing:
            continue
        if rule.to_zone not in (None, pinhole.zone):
            continue
        if rule.proto not in (Protocol.ANY, pinhole.proto):
            continue
        if rule.dst_port is not None:
            low, high = _port_bounds(rule.dst_port)
            if high < pinhole.port_from or low > pinhole.port_to:
                continue
        return rule.name
    return None


#: The management ports (frfw.management.MANAGEMENT_PORTS): sshd, the webUI.
_MANAGEMENT_PORTS = (22, 443)


def _check_management_ipv6(management: ManagementConfig, ipv6: Ipv6Config, interfaces: dict[str, Interface],
                           zones: dict[str, Zone], nat: NatConfig, rules: list[Rule]) -> None:
    """ROADMAP FND-1c: management over IPv6 goes through the same input
    rules as over IPv4 -- and a drop/reject rule by IPv4 address can't
    hold there. So with such a rule on the management ports from a zone
    that would be managed over IPv6, management.ipv6 is refused (the
    same reason a zone with such a forward rule gets no IPv6, FND-1b)."""
    if not (management.ipv6 and ipv6.enabled):
        return
    facing = internet_facing_zones(zones, nat)
    if management.zones:
        managed = set(management.zones)
    elif management.allow_wan:
        managed = set(zones)
    else:
        managed = {z for z in zones if z not in facing}
    over_ipv6 = managed & set(ipv6_lan_zones(ipv6, interfaces, zones, nat, rules))
    for rule in rules:
        if rule.action == Action.ACCEPT or rule.to_zone != SELF_ZONE:
            continue
        if not rule.ipv4_addresses_only:
            continue
        if rule.from_zone is not None and rule.from_zone not in over_ipv6:
            continue
        if rule.proto not in (Protocol.ANY, Protocol.TCP):
            continue
        if rule.dst_port is not None:
            low, high = _port_bounds(rule.dst_port)
            if not any(low <= port <= high for port in _MANAGEMENT_PORTS):
                continue
        raise ConfigError(
            f"management.ipv6: rule {rule.name!r} keeps hosts off the webUI or SSH by IPv4 address only, which "
            "IPv6 would get around. Block them by MAC (src_mac) instead, or leave management.ipv6 off"
        )


def _parse_management(raw: Any, zones: dict[str, Zone], nat: NatConfig) -> ManagementConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'management' must be a mapping")
    allow_wan = raw.get("allow_wan", False)
    if not isinstance(allow_wan, bool):
        raise ConfigError("management.allow_wan must be a boolean")
    zones_raw = raw.get("zones", []) or []
    if not isinstance(zones_raw, list):
        raise ConfigError("management.zones must be a list of zone names")
    internet = internet_facing_zones(zones, nat)
    chosen: list[str] = []
    for zone in zones_raw:
        if not isinstance(zone, str) or zone not in zones:
            raise ConfigError(f"management.zones: undefined zone {zone!r}")
        if zone in internet and not allow_wan:
            raise ConfigError(
                f"management.zones: {zone!r} faces the internet; managing the router from there "
                "needs management.allow_wan: true (not recommended -- use a VPN instead)"
            )
        if zone not in chosen:
            chosen.append(zone)
    confirm = raw.get("confirm_apply_seconds", CONFIRM_APPLY_DEFAULT)
    if (not isinstance(confirm, int) or isinstance(confirm, bool)
            or not (confirm == 0 or CONFIRM_APPLY_MIN <= confirm <= CONFIRM_APPLY_MAX)):
        raise ConfigError(
            f"management.confirm_apply_seconds must be 0 (off) or {CONFIRM_APPLY_MIN}-{CONFIRM_APPLY_MAX} seconds"
        )
    addresses_raw = raw.get("addresses", []) or []
    if not isinstance(addresses_raw, list):
        raise ConfigError("management.addresses must be a list of IPv4 addresses")
    addresses: list[str] = []
    for address in addresses_raw:
        try:
            parsed = str(ipaddress.IPv4Address(address))
        except (ipaddress.AddressValueError, ValueError, TypeError):
            raise ConfigError(f"management.addresses: {address!r} is not an IPv4 address") from None
        if parsed != address:
            raise ConfigError(f"management.addresses: {address!r} is not an IPv4 address")
        if address not in addresses:
            addresses.append(address)
    ipv6 = raw.get("ipv6", False)
    if not isinstance(ipv6, bool):
        raise ConfigError("management.ipv6 must be true or false")
    return ManagementConfig(zones=tuple(chosen), allow_wan=allow_wan, confirm_apply_seconds=confirm,
                            addresses=tuple(addresses), ipv6=ipv6)


def _check_management_addresses(management: ManagementConfig, zones: dict[str, Zone], nat: NatConfig,
                                 interfaces: dict[str, Interface], wireguard: WireguardConfig) -> None:
    """ROADMAP SEC-27: every address the webUI and SSH listen on must be on
    the router -- a management zone's interface, or the VPN's tunnel. So a
    change that would take one away (an interface's address changed or
    removed, the VPN turned off) is refused when it is saved: only the
    admin's "webUI address" action moves them."""
    if not management.addresses:
        return
    # The zones management is reachable from (frfw.management.management_zones).
    if management.zones:
        allowed_zones = set(management.zones)
    elif management.allow_wan:
        allowed_zones = set(zones)
    else:
        allowed_zones = {z for z in zones if z not in internet_facing_zones(zones, nat)}
    available = {str(ipaddress.IPv4Interface(i.address).ip) for i in interfaces.values()
                 if i.address and i.zone in allowed_zones}
    if wireguard.enabled and wireguard.address and wireguard.zone in allowed_zones:
        available.add(str(ipaddress.IPv4Interface(wireguard.address).ip))
    for address in management.addresses:
        if address not in available:
            raise ConfigError(
                f"{address} is where the webUI and SSH listen (management.addresses), and this change takes it "
                "off the router. Move them first: System -> webUI address"
            )


#: ROADMAP SEC-26: long enough to reach the router at a new address and
#: sign in there, short enough that a router an Apply cut off from its
#: admin comes back by itself before anyone drives to it.
CONFIRM_APPLY_DEFAULT = 300
CONFIRM_APPLY_MIN = 60
CONFIRM_APPLY_MAX = 3600


#: WireGuard peer names: like ZTNA usernames (a device, not
#: infrastructure), and safe inside a wg config comment.
_WG_PEER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}\Z")


def valid_wireguard_key(key: Any) -> bool:
    """A WireGuard key: 32 bytes, standard base64 (44 characters)."""
    if not isinstance(key, str) or len(key) != 44:
        return False
    try:
        return len(base64.b64decode(key, validate=True)) == 32
    except ValueError:
        return False


def _parse_logging(raw: Any) -> LoggingConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'logging' must be a mapping")
    drops = raw.get("drops", True)
    if not isinstance(drops, bool):
        raise ConfigError("logging.drops must be true or false")
    rate = raw.get("drops_per_minute", 10)
    if not isinstance(rate, int) or isinstance(rate, bool) or not 1 <= rate <= 10000:
        raise ConfigError("logging.drops_per_minute must be 1-10000")
    return LoggingConfig(drops=drops, drops_per_minute=rate)


def _tunnel_zones(raw: Any) -> set[str]:
    """The zone of a configured WireGuard tunnel counts as used, like an
    interface's (wg0 isn't under 'interfaces')."""
    if isinstance(raw, dict) and (raw.get("enabled") or raw.get("address")):
        zone = raw.get("zone", "vpn")
        return {zone} if isinstance(zone, str) else set()
    return set()


def _parse_wireguard(
    raw: Any, zones: dict[str, Zone], nat: NatConfig, interfaces: dict[str, Interface]
) -> WireguardConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'wireguard' must be a mapping")
    if "private_key" in raw:
        # config.yaml is readable by the webUI; the key stays root's
        # (frfw.wireguard keeps it in /etc/fr_os/wireguard).
        raise ConfigError("wireguard.private_key must not be in config.yaml; the router keeps its key itself")
    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError("wireguard.enabled must be a boolean")
    port = raw.get("listen_port", 51820)
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ConfigError("wireguard.listen_port must be a port number (1-65535)")

    address = raw.get("address", "") or ""
    network = None
    if address:
        try:
            iface = ipaddress.IPv4Interface(address)
        except (ValueError, TypeError) as exc:
            raise ConfigError(f"wireguard.address: {address!r} is not an IPv4 address with a prefix") from exc
        if "/" not in str(address) or iface.network.prefixlen > 30:
            raise ConfigError("wireguard.address needs the tunnel's prefix, /30 or wider (e.g. 10.99.0.1/24)")
        if iface.ip in (iface.network.network_address, iface.network.broadcast_address):
            raise ConfigError(f"wireguard.address: {address} is not a host address")
        network = iface.network
        for other in interfaces.values():
            if other.address and ipaddress.IPv4Interface(other.address).network.overlaps(network):
                raise ConfigError(
                    f"wireguard.address: the tunnel {network} overlaps interface {other.name!r} ({other.address})"
                )
        address = str(iface)

    zone = raw.get("zone", "vpn")
    if enabled or zone != "vpn":
        if not isinstance(zone, str) or zone not in zones:
            raise ConfigError(f"wireguard.zone: undefined zone {zone!r} (add it under 'zones')")
        if zone in internet_facing_zones(zones, nat):
            raise ConfigError(f"wireguard.zone: {zone!r} faces the internet; the tunnel needs a zone of its own")

    endpoint = raw.get("endpoint", "") or ""
    if endpoint:
        try:
            validate.hostname(endpoint)
        except validate.ArgumentError as exc:
            raise ConfigError(f"wireguard.endpoint: {exc}") from exc

    peers_raw = raw.get("peers", []) or []
    if not isinstance(peers_raw, list):
        raise ConfigError("wireguard.peers must be a list")
    peers: list[WireguardPeer] = []
    names: set[str] = set()
    keys: set[str] = set()
    addresses: set[ipaddress.IPv4Address] = set()
    for i, body in enumerate(peers_raw):
        if not isinstance(body, dict):
            raise ConfigError(f"wireguard.peers[{i}] must be a mapping")
        name = body.get("name")
        if not isinstance(name, str) or not _WG_PEER_NAME_RE.match(name):
            raise ConfigError(f"wireguard.peers[{i}]: invalid name {name!r}")
        if name in names:
            raise ConfigError(f"wireguard.peers[{i}]: duplicate name {name!r}")
        key = body.get("public_key")
        if not valid_wireguard_key(key):
            raise ConfigError(f"wireguard.peers[{i}] ({name}): public_key is not a WireGuard key")
        if key in keys:
            raise ConfigError(f"wireguard.peers[{i}] ({name}): the same public_key is used twice")
        if network is None:
            raise ConfigError("wireguard.peers need wireguard.address (the tunnel subnet)")
        peer_addr = body.get("address")
        try:
            peer_iface = ipaddress.IPv4Interface(peer_addr)
        except (ValueError, TypeError) as exc:
            raise ConfigError(f"wireguard.peers[{i}] ({name}): invalid address {peer_addr!r}") from exc
        if peer_iface.network.prefixlen != 32:
            raise ConfigError(f"wireguard.peers[{i}] ({name}): the address must be a single host (/32)")
        ip = peer_iface.ip
        if ip not in network or ip in (network.network_address, network.broadcast_address,
                                       ipaddress.IPv4Interface(address).ip):
            raise ConfigError(f"wireguard.peers[{i}] ({name}): {ip} is not a free host address in {network}")
        if ip in addresses:
            raise ConfigError(f"wireguard.peers[{i}] ({name}): address {ip} is used twice")
        dual_stack = body.get("dual_stack", False)
        if not isinstance(dual_stack, bool):
            raise ConfigError(f"wireguard.peers[{i}] ({name}): dual_stack must be true or false")
        names.add(name)
        keys.add(key)
        addresses.add(ip)
        peers.append(WireguardPeer(name=name, public_key=key, address=f"{ip}/32", dual_stack=dual_stack))

    if enabled and network is None:
        raise ConfigError("wireguard.enabled is true but wireguard.address (the tunnel subnet) is not set")
    return WireguardConfig(enabled=enabled, listen_port=port, address=address, zone=zone,
                           endpoint=endpoint, peers=peers)


def _parse_pqc(raw: Any) -> PqcConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'pqc' must be a mapping")

    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError("pqc.enabled must be a boolean")

    return PqcConfig(enabled=enabled)


def _parse_xdp_sni_filter(raw: Any, interfaces: dict[str, Interface]) -> XdpSniFilterConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'xdp_sni_filter' must be a mapping")

    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError("xdp_sni_filter.enabled must be a boolean")

    ifaces_raw = raw.get("interfaces", [])
    if not isinstance(ifaces_raw, list):
        raise ConfigError("xdp_sni_filter.interfaces must be a list")
    xdp_interfaces = []
    for i, name in enumerate(ifaces_raw):
        if not isinstance(name, str) or name not in interfaces:
            raise ConfigError(
                f"xdp_sni_filter.interfaces[{i}]: {name!r} is not a defined interface"
            )
        xdp_interfaces.append(name)
    if enabled and not xdp_interfaces:
        raise ConfigError("xdp_sni_filter.enabled is true but interfaces is empty")

    blocklist_raw = raw.get("blocklist", [])
    if not isinstance(blocklist_raw, list):
        raise ConfigError("xdp_sni_filter.blocklist must be a list")
    blocklist = []
    for i, hostname in enumerate(blocklist_raw):
        # A trailing dot just marks the name as already fully qualified
        # (RFC 1035 3.1) and is stripped before the syntax check, the same
        # way adblocker.allowlist is parsed below -- so "example.com." in
        # the config is the same entry as "example.com", not a config error.
        if not isinstance(hostname, str) or not _HOSTNAME_RE.match(hostname.rstrip(".")):
            raise ConfigError(
                f"xdp_sni_filter.blocklist[{i}]: invalid hostname {hostname!r}"
            )
        if len(hostname) >= _MAX_SNI_LEN:
            raise ConfigError(
                f"xdp_sni_filter.blocklist[{i}]: hostname {hostname!r} is "
                f"{len(hostname)} bytes, must be under {_MAX_SNI_LEN} "
                "(the kernel filter's MAX_SNI_LEN) or it is NOT blocked"
            )
        # Stored in the canonical form the LPM trie's key is built from,
        # and the one the kernel program produces for the name it extracts
        # from the wire -- see frfw.xdp.normalize_sni (the same rules as the
        # normalization block at the end of extract_sni() in
        # bpf/xdp_sni_filter.c). Spelled out here rather
        # than imported: frfw.xdp imports this package, so importing it back
        # would be a cycle. tests/test_xdp_schema.py pins the two copies
        # against each other instead of relying on this staying in step.
        blocklist.append("".join(
            chr(ord(c) | 0x20) if "A" <= c <= "Z" else c for c in hostname
        ).rstrip("."))

    return XdpSniFilterConfig(
        enabled=enabled,
        interfaces=xdp_interfaces,
        blocklist=blocklist,
    )


#: Deliberately loose (scheme + non-empty rest) -- this only guards
#: against an obviously-wrong value (a bare hostname, a typo missing
#: "http"), not a full RFC 3986 validator; a genuinely malformed URL
#: still just fails cleanly at fetch time (frfw.adblock.AdblockError),
#: the same way a bad update.repo or ztna username only fails at use.
_HTTP_URL_RE = re.compile(r"^https?://\S+\Z")


def _parse_url_list(raw: Any, what: str) -> list[str]:
    if not isinstance(raw, list):
        raise ConfigError(f"{what} must be a list")
    urls = []
    for i, url in enumerate(raw):
        if not isinstance(url, str) or not _HTTP_URL_RE.match(url):
            raise ConfigError(f"{what}[{i}]: invalid URL {url!r}")
        urls.append(url)
    return urls


def _parse_bool(raw: dict, key: str, what: str) -> bool:
    value = raw.get(key, False)
    if not isinstance(value, bool):
        raise ConfigError(f"{what}.{key} must be a boolean")
    return value


def _parse_adblocker(raw: Any, dhcp: DhcpConfig) -> AdblockerConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'adblocker' must be a mapping")

    enabled = _parse_bool(raw, "enabled", "adblocker")
    source_urls = _parse_url_list(raw.get("source_urls", []), "adblocker.source_urls")

    categories_raw = raw.get("categories", {}) or {}
    if not isinstance(categories_raw, dict):
        raise ConfigError("adblocker.categories must be a mapping of category name -> list of URLs")
    categories: dict[str, list[str]] = {}
    for name, urls in categories_raw.items():
        _require_name(name, "adblocker category")
        if name == "ads":
            raise ConfigError(
                "adblocker.categories: 'ads' is reserved for the base list (adblocker.source_urls)"
            )
        parsed = _parse_url_list(urls, f"adblocker.categories.{name}")
        if not parsed:
            raise ConfigError(f"adblocker.categories.{name} has no URLs")
        categories[name] = parsed

    if enabled and not source_urls and not categories:
        raise ConfigError("adblocker.enabled is true but source_urls and categories are both empty")

    xdp_critical_limit = raw.get("xdp_critical_limit", 0)
    if isinstance(xdp_critical_limit, bool) or not isinstance(xdp_critical_limit, int):
        raise ConfigError("adblocker.xdp_critical_limit must be an integer")
    if xdp_critical_limit < 0:
        raise ConfigError("adblocker.xdp_critical_limit must be >= 0")

    allowlist_raw = raw.get("allowlist", []) or []
    if not isinstance(allowlist_raw, list):
        raise ConfigError("adblocker.allowlist must be a list of domain names")
    allowlist: list[str] = []
    for i, domain in enumerate(allowlist_raw):
        if not isinstance(domain, str) or "." not in domain or not _HOSTNAME_RE.match(domain.rstrip(".")):
            raise ConfigError(f"adblocker.allowlist[{i}]: invalid domain name {domain!r}")
        domain = domain.lower().rstrip(".")
        if domain not in allowlist:
            allowlist.append(domain)

    serve_lan = _parse_bool(raw, "serve_lan", "adblocker")
    force_dns = _parse_bool(raw, "force_dns", "adblocker")
    query_logging = _parse_bool(raw, "query_logging", "adblocker")
    if force_dns and not serve_lan:
        raise ConfigError("adblocker.force_dns requires adblocker.serve_lan")
    if serve_lan and not dhcp.zones:
        raise ConfigError(
            "adblocker.serve_lan needs at least one DHCP pool -- the resolver is announced "
            "to, and listens on, the DHCP zones"
        )

    return AdblockerConfig(
        enabled=enabled,
        source_urls=source_urls,
        xdp_critical_limit=xdp_critical_limit,
        categories=categories,
        allowlist=allowlist,
        serve_lan=serve_lan,
        force_dns=force_dns,
        query_logging=query_logging,
    )


def _parse_mac_list(raw: Any, what: str) -> list[str]:
    if not isinstance(raw, list):
        raise ConfigError(f"{what} must be a list")
    macs: list[str] = []
    for i, mac in enumerate(raw):
        if not isinstance(mac, str) or not _MAC_RE.match(mac):
            raise ConfigError(f"{what}[{i}]: invalid MAC address {mac!r}")
        mac = mac.lower()
        if mac not in macs:
            macs.append(mac)
    return macs


def _parse_iot(raw: Any, zones: dict[str, Zone], nat: NatConfig) -> IotConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'iot' must be a mapping")

    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError("iot.enabled must be a boolean")

    zones_raw = raw.get("zones", [])
    if not isinstance(zones_raw, list):
        raise ConfigError("iot.zones must be a list of zone names")
    internet_zones = {m.out_zone for m in nat.masquerade}
    iot_zones: list[str] = []
    for zone in zones_raw:
        if not isinstance(zone, str) or zone not in zones:
            raise ConfigError(f"iot.zones: undefined zone {zone!r}")
        if zone in internet_zones:
            raise ConfigError(
                f"iot.zones: {zone!r} is an internet-facing (nat.masquerade) zone; "
                "list the LAN-side zone(s) your devices live in instead"
            )
        if zone not in iot_zones:
            iot_zones.append(zone)
    if enabled and not iot_zones:
        raise ConfigError("iot.enabled is true but iot.zones is empty")

    auto_isolate = raw.get("auto_isolate", False)
    if not isinstance(auto_isolate, bool):
        raise ConfigError("iot.auto_isolate must be a boolean")

    mode_raw = raw.get("isolation_mode", IotIsolationMode.INTERNET_ONLY.value)
    try:
        isolation_mode = IotIsolationMode(mode_raw)
    except ValueError as exc:
        raise ConfigError(
            f"iot.isolation_mode: invalid value {mode_raw!r}; "
            f"expected one of {[m.value for m in IotIsolationMode]}"
        ) from exc
    if enabled and isolation_mode == IotIsolationMode.INTERNET_ONLY and not internet_zones:
        raise ConfigError(
            "iot.isolation_mode 'internet_only' needs at least one nat.masquerade "
            "entry to know which zone is the internet; add one or use 'block'"
        )

    trusted = _parse_mac_list(raw.get("trusted_macs", []), "iot.trusted_macs")
    isolated = _parse_mac_list(raw.get("isolated_macs", []), "iot.isolated_macs")
    overlap = sorted(set(trusted) & set(isolated))
    if overlap:
        raise ConfigError(f"iot: MAC(s) listed as both trusted and isolated: {overlap}")

    return IotConfig(
        enabled=enabled,
        zones=iot_zones,
        auto_isolate=auto_isolate,
        isolation_mode=isolation_mode,
        trusted_macs=trusted,
        isolated_macs=isolated,
    )


def _parse_ztna(raw: Any) -> ZtnaConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'ztna' must be a mapping")

    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError("ztna.enabled must be a boolean")

    ttl = raw.get("session_ttl_seconds", 8 * 3600)
    if (
        not isinstance(ttl, int)
        or isinstance(ttl, bool)
        or not (_ZTNA_MIN_TTL_SECONDS <= ttl <= _ZTNA_MAX_TTL_SECONDS)
    ):
        raise ConfigError(
            "ztna.session_ttl_seconds must be an integer between "
            f"{_ZTNA_MIN_TTL_SECONDS} and {_ZTNA_MAX_TTL_SECONDS} (seconds)"
        )

    users_raw = raw.get("users", [])
    if not isinstance(users_raw, list):
        raise ConfigError("ztna.users must be a list")
    users: list[ZtnaUser] = []
    seen_usernames: set[str] = set()
    for i, body in enumerate(users_raw):
        if not isinstance(body, dict):
            raise ConfigError(f"ztna.users[{i}] must be a mapping")

        username = body.get("username")
        if not isinstance(username, str) or not _ZTNA_USERNAME_RE.match(username):
            raise ConfigError(f"ztna.users[{i}]: invalid username {username!r}")
        if username in seen_usernames:
            raise ConfigError(f"ztna.users[{i}]: duplicate username {username!r}")
        seen_usernames.add(username)

        # Always an already-hashed password by the time it reaches config
        # loading -- frfw.webui.routes.ztna hashes a submitted plaintext
        # password (via frfw.admin_account.hash_password, the same PBKDF2
        # implementation the single admin account uses) before it's ever
        # written to config.yaml. This loader doesn't re-validate the
        # hash's own format beyond "non-empty string": that's
        # frfw.admin_account.verify_password's job at login time, and it
        # already fails closed (returns False) on anything malformed.
        password_hash = body.get("password_hash")
        if not isinstance(password_hash, str) or not password_hash:
            raise ConfigError(f"ztna.users[{i}]: missing or invalid password_hash")

        users.append(ZtnaUser(username=username, password_hash=password_hash))

    if enabled and not users:
        raise ConfigError("ztna.enabled is true but no users are configured")

    return ZtnaConfig(enabled=enabled, session_ttl_seconds=ttl, users=users)


def _parse_app_control(
    raw: Any, adblocker: AdblockerConfig, xdp_sni_filter: XdpSniFilterConfig
) -> AppControlConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'app_control' must be a mapping")

    flags = {}
    for key in ("enabled", "block_via_xdp", "observe_sni"):
        value = raw.get(key, False)
        if not isinstance(value, bool):
            raise ConfigError(f"app_control.{key} must be a boolean")
        flags[key] = value

    blocked_raw = raw.get("blocked_apps", [])
    if not isinstance(blocked_raw, list):
        raise ConfigError("app_control.blocked_apps must be a list of app ids")
    known = known_app_ids()
    blocked: list[str] = []
    for i, app_id in enumerate(blocked_raw):
        if not isinstance(app_id, str) or app_id not in known:
            raise ConfigError(f"app_control.blocked_apps[{i}]: unknown app {app_id!r}")
        if app_id in blocked:
            raise ConfigError(f"app_control.blocked_apps: {app_id!r} is listed twice")
        blocked.append(app_id)

    # Cross-section requirements only matter while the feature is on, so
    # switching the resolver or XDP off never makes a disabled
    # app_control section invalid.
    if flags["enabled"]:
        if blocked and not (adblocker.enabled and adblocker.serve_lan):
            raise ConfigError(
                "app_control.blocked_apps needs adblocker.enabled and adblocker.serve_lan: "
                "apps are blocked by the router's DNS resolver"
            )
        for key in ("block_via_xdp", "observe_sni"):
            if flags[key] and not xdp_sni_filter.enabled:
                raise ConfigError(f"app_control.{key} requires xdp_sni_filter.enabled")

    return AppControlConfig(
        enabled=flags["enabled"],
        blocked_apps=blocked,
        block_via_xdp=flags["block_via_xdp"],
        observe_sni=flags["observe_sni"],
    )


#: Single-label local domains nobody delegates publicly: everything under
#: `local_dns.domain` is NXDOMAIN unless it is a host, so `com` there
#: would cut the network off. (`local` is mDNS's, not ours.)
_PRIVATE_TOP_LEVEL = frozenset({"lan", "home", "internal", "intranet", "corp", "private", "localdomain"})

#: Bound on `local_dns` entries: each is a line of the resolver's config.
_LOCAL_DNS_MAX_ENTRIES = 1024


def _local_dns_name(value: Any, what: str, *, dotted: bool = True) -> str:
    """A name for `local_dns`: lower case, no trailing dot, through
    frfw.validate (it goes into the resolver's config, security-lessons
    F1). `dotted`: at least two labels, so no entry covers a whole
    top-level domain."""
    if not isinstance(value, str):
        raise ConfigError(f"{what}: expected a domain name, got {value!r}")
    name = value.strip().lower().rstrip(".")
    try:
        validate.hostname(name)
    except validate.ArgumentError as exc:
        raise ConfigError(f"{what}: {exc}") from exc
    if dotted and "." not in name:
        raise ConfigError(f"{what}: {name!r} needs at least two labels (e.g. nas.lan)")
    return name


def _parse_local_dns(raw: Any, adblocker: AdblockerConfig, app_control: AppControlConfig) -> LocalDnsConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'local_dns' must be a mapping")
    unknown = set(raw) - {"domain", "hosts", "overrides"}
    if unknown:
        raise ConfigError(f"local_dns: unknown key(s) {sorted(unknown)}")

    domain = ""
    if raw.get("domain"):
        domain = _local_dns_name(raw["domain"], "local_dns.domain", dotted=False)
        if "." not in domain and domain not in _PRIVATE_TOP_LEVEL:
            raise ConfigError(
                f"local_dns.domain: {domain!r} could be a public top-level domain; use one of "
                f"{', '.join(sorted(_PRIVATE_TOP_LEVEL))} or a domain of your own (e.g. home.arpa)"
            )

    tables: dict[str, dict[str, str]] = {}
    for key in ("hosts", "overrides"):
        table_raw = raw.get(key) or {}
        if not isinstance(table_raw, dict):
            raise ConfigError(f"local_dns.{key} must be a mapping of name -> IPv4 address")
        table: dict[str, str] = {}
        for name_raw, address in table_raw.items():
            name = _local_dns_name(name_raw, f"local_dns.{key}")
            _validate_address(address, f"local_dns.{key}.{name}")
            if name in table:
                raise ConfigError(f"local_dns.{key}: {name!r} is listed twice")
            table[name] = str(ipaddress.IPv4Address(address))
        tables[key] = table
    hosts, overrides = tables["hosts"], tables["overrides"]

    for name in sorted(hosts.keys() & overrides.keys()):
        raise ConfigError(f"local_dns: {name!r} is both a host and an override")
    if len(hosts) + len(overrides) > _LOCAL_DNS_MAX_ENTRIES:
        raise ConfigError(f"local_dns: at most {_LOCAL_DNS_MAX_ENTRIES} hosts and overrides")

    if (hosts or overrides or domain) and not (adblocker.enabled and adblocker.serve_lan):
        raise ConfigError(
            "local_dns needs adblocker.enabled and adblocker.serve_lan: local names are "
            "answered by the router's DNS resolver"
        )

    # A blocked app's names are answered NXDOMAIN by the same resolver:
    # one name can't be both, whichever line dnsmasq happened to prefer.
    if app_control.enabled and app_control.blocked_apps:
        blocked = blocking_names(app_control.blocked_apps)
        for name in [*hosts, *overrides, *([domain] if domain else [])]:
            for b in blocked:
                if name == b or name.endswith("." + b) or b.endswith("." + name):
                    raise ConfigError(f"local_dns: {name!r} overlaps the blocked app name {b!r}")

    return LocalDnsConfig(domain=domain, hosts=hosts, overrides=overrides)


_HHMM_RE = re.compile(r"^([01][0-9]|2[0-3]):([0-5][0-9])\Z|^24:00\Z")

#: Shortcuts accepted in schedule.days besides mon..sun.
_DAY_GROUPS = {
    "daily": tuple(range(7)),
    "weekdays": (0, 1, 2, 3, 4),
    "weekend": (5, 6),
}
_DAY_KEYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def _valid_timezone(name: str) -> bool:
    try:
        zoneinfo.ZoneInfo(name)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        return False
    return True


def _parse_hhmm(value: Any, what: str) -> int:
    if not isinstance(value, str) or not _HHMM_RE.match(value):
        raise ConfigError(f"{what} must be a \"HH:MM\" time (00:00-24:00), got {value!r}")
    hours, minutes = value.split(":")
    return int(hours) * 60 + int(minutes)


def _parse_schedule(raw: Any, what: str, action: Action) -> RuleSchedule:
    if not isinstance(raw, dict):
        raise ConfigError(f"{what} must be a mapping")

    days_raw = raw.get("days", ["daily"])
    if isinstance(days_raw, str):
        days_raw = [days_raw]
    if not isinstance(days_raw, list) or not days_raw:
        raise ConfigError(f"{what}.days must be a non-empty list (mon..sun, weekdays, weekend, daily)")
    days: set[int] = set()
    for day in days_raw:
        key = day.lower() if isinstance(day, str) else day
        if key in _DAY_GROUPS:
            days.update(_DAY_GROUPS[key])
        elif key in _DAY_KEYS:
            days.add(_DAY_KEYS.index(key))
        else:
            raise ConfigError(f"{what}.days: unknown day {day!r} (mon..sun, weekdays, weekend, daily)")

    start = _parse_hhmm(raw.get("start"), f"{what}.start")
    end = _parse_hhmm(raw.get("end"), f"{what}.end")
    if start == 24 * 60:
        raise ConfigError(f"{what}.start cannot be 24:00")
    if start == end:
        raise ConfigError(f"{what}: start and end are both {raw.get('start')}; use 00:00-24:00 for a whole day")

    cut_established = raw.get("cut_established", False)
    if not isinstance(cut_established, bool):
        raise ConfigError(f"{what}.cut_established must be a boolean")
    if cut_established and action == Action.ACCEPT:
        raise ConfigError(f"{what}.cut_established only applies to drop/reject rules")

    return RuleSchedule(days=tuple(sorted(days)), start=start, end=end, cut_established=cut_established)


JA4_RE = re.compile(r"^[tqd][0-9ds][0-9d][di][0-9]{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}\Z")
JA3_RE = re.compile(r"^[0-9a-f]{32}\Z")


def _parse_tls_fingerprint(raw: Any, xdp_sni_filter: XdpSniFilterConfig) -> TlsFingerprintConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'tls_fingerprint' must be a mapping")
    flags = {}
    for key in ("enabled", "quarantine_on_match"):
        value = raw.get(key, False)
        if not isinstance(value, bool):
            raise ConfigError(f"tls_fingerprint.{key} must be a boolean")
        flags[key] = value

    blocklist_raw = raw.get("blocklist", [])
    if not isinstance(blocklist_raw, list):
        raise ConfigError("tls_fingerprint.blocklist must be a list")
    entries: list[TlsFingerprintEntry] = []
    seen: set[str] = set()
    for i, item in enumerate(blocklist_raw):
        if isinstance(item, str):
            item = {"fingerprint": item}
        if not isinstance(item, dict):
            raise ConfigError(f"tls_fingerprint.blocklist[{i}] must be a mapping or a string")
        fingerprint = item.get("fingerprint")
        if not isinstance(fingerprint, str):
            raise ConfigError(f"tls_fingerprint.blocklist[{i}].fingerprint is required")
        fingerprint = fingerprint.strip().lower()
        if not (JA4_RE.match(fingerprint) or JA3_RE.match(fingerprint)):
            raise ConfigError(
                f"tls_fingerprint.blocklist[{i}]: {fingerprint!r} is neither a JA4 fingerprint "
                "(e.g. t13d1516h2_8daaf6152771_e5627efa2ab1) nor a 32-hex-digit JA3 hash"
            )
        if fingerprint in seen:
            raise ConfigError(f"tls_fingerprint.blocklist: {fingerprint!r} is listed twice")
        seen.add(fingerprint)
        label = item.get("label", "")
        if not isinstance(label, str) or len(label) > 80:
            raise ConfigError(f"tls_fingerprint.blocklist[{i}].label must be a string of at most 80 characters")
        entries.append(TlsFingerprintEntry(fingerprint=fingerprint, label=label))

    if flags["enabled"] and not xdp_sni_filter.enabled:
        raise ConfigError(
            "tls_fingerprint.enabled requires xdp_sni_filter.enabled: the XDP program "
            "on the LAN-side interfaces is what hands over the ClientHellos"
        )
    return TlsFingerprintConfig(
        enabled=flags["enabled"], blocklist=entries, quarantine_on_match=flags["quarantine_on_match"]
    )


_SITE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}\Z")
TOKEN_SHA256_RE = re.compile(r"^[0-9a-f]{64}\Z")


def _parse_metrics(raw: Any) -> MetricsConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'metrics' must be a mapping")
    site = raw.get("site")
    if site is not None and (not isinstance(site, str) or not _SITE_RE.match(site)):
        raise ConfigError(
            "metrics.site must be lowercase letters, digits, '.', '_', '-' (max 63), e.g. budapest-office"
        )
    token_hash = raw.get("token_sha256")
    if token_hash is not None and (not isinstance(token_hash, str) or not TOKEN_SHA256_RE.match(token_hash)):
        raise ConfigError("metrics.token_sha256 must be a 64-character lowercase SHA-256 hex digest")
    return MetricsConfig(site=site, token_sha256=token_hash)
