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
    Config,
    Interface,
    Masquerade,
    NatConfig,
    PortForward,
    Protocol,
    Rule,
    Zone,
)

_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
_PORT_RANGE_RE = re.compile(r"^(\d{1,5})-(\d{1,5})$")
_SUPPORTED_VERSION = 1


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

    return Config(
        version=version,
        hostname=hostname,
        interfaces=interfaces,
        zones=zones,
        rules=rules,
        nat=nat,
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

        description = body.get("description", "")
        interfaces[name] = Interface(
            name=name, device=device, zone=zone, description=description
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
