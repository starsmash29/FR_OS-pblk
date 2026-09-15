"""Dataclass definitions for the frfw configuration model.

These are plain, dependency-free dataclasses (stdlib + nothing else) so the
engine can run on a minimal Debian install without pulling in extra Python
packages beyond PyYAML. Construction and validation happen in
`frfw.config.loader`; the dataclasses here intentionally do not validate
their own inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

#: Pseudo-zone meaning "traffic destined to the router itself" (input chain),
#: as opposed to traffic forwarded between real zones.
SELF_ZONE = "self"


class Action(str, Enum):
    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"


class Protocol(str, Enum):
    ANY = "any"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


@dataclass(frozen=True)
class Interface:
    """A logical interface: a name used elsewhere in the config, mapped to
    a physical/logical Linux device name and a zone.

    `address` (a CIDR string like "10.0.0.1/24") is optional: it is the
    router's own static IPv4 address on that interface, applied via
    `frfw.ifaddr`. It is required for a zone to have a DHCP pool (see
    `DhcpPool`), since the pool's subnet and gateway are derived from it.
    Leave it unset for an interface whose address is managed elsewhere
    (e.g. a WAN interface using DHCP from the ISP).
    """

    name: str
    device: str
    zone: str
    address: str | None = None
    description: str = ""


@dataclass(frozen=True)
class Zone:
    name: str
    description: str = ""


@dataclass(frozen=True)
class Rule:
    """A filter rule. `from_zone`/`to_zone` of `None` mean "any zone".

    `to_zone == SELF_ZONE` targets traffic addressed to the router itself
    (nftables `input` chain) rather than forwarded traffic.
    """

    name: str
    action: Action
    from_zone: str | None = None
    to_zone: str | None = None
    proto: Protocol = Protocol.ANY
    dst_port: str | None = None
    src_address: str | None = None
    dst_address: str | None = None
    log: bool = False


@dataclass(frozen=True)
class Masquerade:
    out_zone: str


@dataclass(frozen=True)
class PortForward:
    name: str
    in_zone: str
    proto: Protocol
    dst_port: int
    to_address: str
    to_port: int


@dataclass(frozen=True)
class NatConfig:
    masquerade: list[Masquerade] = field(default_factory=list)
    port_forwards: list[PortForward] = field(default_factory=list)


@dataclass(frozen=True)
class DhcpReservation:
    mac_address: str
    address: str
    hostname: str = ""


@dataclass(frozen=True)
class DhcpPool:
    """A DHCPv4 pool for one zone, served by Kea (see `frfw.kea`).

    The zone's subnet and gateway come from its (single) interface's
    static `address`, not repeated here.
    """

    zone: str
    range_start: str
    range_end: str
    dns_servers: list[str]
    lease_time: int = 3600
    reservations: list[DhcpReservation] = field(default_factory=list)


@dataclass(frozen=True)
class DhcpConfig:
    zones: dict[str, DhcpPool] = field(default_factory=dict)


@dataclass(frozen=True)
class AiIdsConfig:
    """Settings for the (currently mock -- see frfw.ai_ids) anomaly
    detection engine. `excluded_macs` are devices never profiled (e.g. the
    router's own interfaces, or noisy IoT devices the admin doesn't want
    flagged)."""

    enabled: bool = False
    learning_days: int = 7
    retrain_time: str = "03:30"
    excluded_macs: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class UpdateConfig:
    """Which GitHub repo to check for new FR_OS releases against (phase 6,
    see frfw.update). Empty string means "use the built-in default"
    (`frfw.update.DEFAULT_REPO`) -- override only for a fork/community
    edition mirror that publishes its own releases."""

    repo: str = ""


@dataclass(frozen=True)
class Config:
    version: int
    hostname: str
    interfaces: dict[str, Interface]
    zones: dict[str, Zone]
    rules: list[Rule]
    nat: NatConfig
    dhcp: DhcpConfig = field(default_factory=DhcpConfig)
    ai_ids: AiIdsConfig = field(default_factory=AiIdsConfig)
    update: UpdateConfig = field(default_factory=UpdateConfig)
