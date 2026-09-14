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
    a physical/logical Linux device name and a zone."""

    name: str
    device: str
    zone: str
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
class Config:
    version: int
    hostname: str
    interfaces: dict[str, Interface]
    zones: dict[str, Zone]
    rules: list[Rule]
    nat: NatConfig
