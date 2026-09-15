"""Loads and validates a frfw YAML configuration into a `Config` object.

Kept dependency-free (stdlib `yaml` from PyYAML, which ships as the
`python3-yaml` Debian package) rather than pulling in a schema-validation
library, since this code is meant to run on the target router itself.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

import yaml

from frfw.config.errors import ConfigError
from frfw.config.schema import (
    SELF_ZONE,
    Action,
    AiIdsConfig,
    Config,
    DhcpConfig,
    DhcpPool,
    DhcpReservation,
    Interface,
    Masquerade,
    NatConfig,
    PortForward,
    Protocol,
    Rule,
    UpdateConfig,
    XdpSniFilterConfig,
    Zone,
    ZtnaConfig,
    ZtnaUser,
)

_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
_PORT_RANGE_RE = re.compile(r"^(\d{1,5})-(\d{1,5})$")
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_TIME_OF_DAY_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_HOSTNAME_RE = re.compile(
    r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*$"
)
#: ZTNA gate usernames: deliberately looser than zone/interface/rule
#: names (_NAME_RE) since these are end-user account names, not
#: infrastructure identifiers -- but still tight enough to be a safe nft
#: comment string, so no whitespace/quotes/etc.
_ZTNA_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
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

    zones = _parse_zones(raw.get("zones", {}))
    interfaces = _parse_interfaces(raw.get("interfaces", {}), zones)
    rules = _parse_rules(raw.get("rules", []), zones)
    nat = _parse_nat(raw.get("nat", {}) or {}, zones)
    dhcp = _parse_dhcp(raw.get("dhcp", {}) or {}, zones, interfaces)
    ai_ids = _parse_ai_ids(raw.get("ai_ids", {}) or {})
    update = _parse_update(raw.get("update", {}) or {})
    xdp_sni_filter = _parse_xdp_sni_filter(raw.get("xdp_sni_filter", {}) or {}, interfaces)
    ztna = _parse_ztna(raw.get("ztna", {}) or {})

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


def _parse_interfaces(raw: Any, zones: dict[str, Zone]) -> dict[str, Interface]:
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
        interfaces[name] = Interface(
            name=name, device=device, zone=zone, address=address, description=description
        )

    used_zones = {iface.zone for iface in interfaces.values()}
    for zone_name in zones:
        if zone_name not in used_zones:
            raise ConfigError(
                f"Zone {zone_name!r} is declared but not used by any interface"
            )
    return interfaces


def _valid_zone_ref(zone: Any, zones: dict[str, Zone]) -> bool:
    return zone is None or zone == SELF_ZONE or zone in zones


def _parse_rules(raw: Any, zones: dict[str, Zone]) -> list[Rule]:
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

        src_address = body.get("src_address")
        if src_address is not None:
            _validate_network(src_address, f"Rule {name!r} src_address")

        dst_address = body.get("dst_address")
        if dst_address is not None:
            _validate_network(dst_address, f"Rule {name!r} dst_address")

        log = bool(body.get("log", False))
        require_ztna = bool(body.get("require_ztna", False))

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
            )
        )
    return rules


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


def _validate_network(value: Any, what: str) -> None:
    # Phase 1 targets IPv4 homelab setups only; IPv6 is future work (see
    # ROADMAP.md) and would need family-aware nft matches (`ip6 saddr`).
    if not isinstance(value, str):
        raise ConfigError(f"{what}: expected a string, got {value!r}")
    try:
        ipaddress.IPv4Network(value, strict=False)
    except ValueError as exc:
        raise ConfigError(f"{what}: invalid IPv4 address/network {value!r}: {exc}") from exc


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


def _parse_ai_ids(raw: Any) -> AiIdsConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'ai_ids' must be a mapping")

    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError("ai_ids.enabled must be a boolean")

    learning_days = raw.get("learning_days", 7)
    if not isinstance(learning_days, int) or isinstance(learning_days, bool) or learning_days <= 0:
        raise ConfigError("ai_ids.learning_days must be a positive integer")

    retrain_time = raw.get("retrain_time", "03:30")
    if not isinstance(retrain_time, str) or not _TIME_OF_DAY_RE.match(retrain_time):
        raise ConfigError(
            f"ai_ids.retrain_time must be a 24h 'HH:MM' string, got {retrain_time!r}"
        )

    excluded_raw = raw.get("excluded_macs", [])
    if not isinstance(excluded_raw, list):
        raise ConfigError("ai_ids.excluded_macs must be a list")
    excluded_macs = []
    for i, mac in enumerate(excluded_raw):
        if not isinstance(mac, str) or not _MAC_RE.match(mac):
            raise ConfigError(f"ai_ids.excluded_macs[{i}]: invalid MAC address {mac!r}")
        excluded_macs.append(mac.lower())

    return AiIdsConfig(
        enabled=enabled,
        learning_days=learning_days,
        retrain_time=retrain_time,
        excluded_macs=excluded_macs,
    )


def _parse_update(raw: Any) -> UpdateConfig:
    if not isinstance(raw, dict):
        raise ConfigError("'update' must be a mapping")

    repo = raw.get("repo", "")
    if not isinstance(repo, str):
        raise ConfigError("update.repo must be a string")

    return UpdateConfig(repo=repo)


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
        if not isinstance(hostname, str) or not _HOSTNAME_RE.match(hostname):
            raise ConfigError(
                f"xdp_sni_filter.blocklist[{i}]: invalid hostname {hostname!r}"
            )
        if len(hostname) >= _MAX_SNI_LEN:
            raise ConfigError(
                f"xdp_sni_filter.blocklist[{i}]: hostname {hostname!r} is "
                f"{len(hostname)} bytes, must be under {_MAX_SNI_LEN} "
                "(the kernel filter's MAX_SNI_LEN)"
            )
        blocklist.append(hostname.lower())

    return XdpSniFilterConfig(
        enabled=enabled,
        interfaces=xdp_interfaces,
        blocklist=blocklist,
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
