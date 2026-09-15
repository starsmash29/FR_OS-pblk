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

    `require_ztna`, if set, additionally requires the source address to
    currently be a member of the kernel-resident ZTNA authorized-clients
    set (see `ZtnaConfig`/`frfw.ztna`/`frfw.nft.builder.ZTNA_SET_NAME`)
    for this rule to match at all -- deliberately reusing the existing
    rule engine (from_zone/to_zone/proto/port/address all still apply
    normally) rather than inventing a separate "protected zones" concept
    alongside it: "accept this specific zone/port combination, but only
    from ZTNA-authorized sources" is just one more match condition on an
    ordinary rule, not a different kind of rule.
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
    require_ztna: bool = False


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
class XdpSniFilterConfig:
    """Settings for the kernel-space TLS SNI filter (phase 4, see
    frfw.xdp and bpf/xdp_sni_filter.c).

    `interfaces` names logical interfaces (keys of `Config.interfaces`,
    not raw device names) to attach the XDP program to -- almost always
    just the WAN interface, since inspecting LAN-side traffic for
    outbound-to-the-internet SNIs is rarely useful and doubles the
    attach/detach and per-packet cost for no benefit.

    `blocklist` is a list of hostnames (e.g. "ads.example.com"); the
    kernel program also blocks every subdomain of a listed name (see
    this module's header comment... actually see bpf/xdp_sni_filter.c's
    "LPM trie key construction" comment for why and how). A hostname
    must be shorter than MAX_SNI_LEN (32) bytes in the compiled BPF
    program -- see frfw.xdp.MAX_SNI_LEN, kept in sync with the .c file's
    #define by a test, not by importing across the Python/C boundary.
    """

    enabled: bool = False
    interfaces: list[str] = field(default_factory=list)
    blocklist: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ZtnaUser:
    """One local ZTNA gate account. `password_hash` is always already a
    PBKDF2 hash (frfw.admin_account.hash_password's format) by the time
    it reaches this dataclass -- never a plaintext password; the webUI's
    ZTNA settings screen hashes a submitted password before it's ever
    written to config.yaml, exactly like the single admin account."""

    username: str
    password_hash: str


@dataclass(frozen=True)
class ZtnaConfig:
    """Settings for the local Zero Trust Network Access gate (see
    frfw.ztna, frfw.webui.routes.ztna, and this rule's `require_ztna`
    flag above).

    This is deliberately *not* a general-purpose identity provider: it
    authorizes a *source IP address* for `session_ttl_seconds`, via a
    kernel-resident nftables set with its own native timeout -- there is
    no per-request/per-connection identity check, no cloud IdP, and no
    userspace session tracking. A device's IP is either currently a
    member of the set or it isn't; the kernel evicts it on expiry with
    zero help from userspace (frfw.ztna's module docstring has the full
    design rationale, including the one real wrinkle: a full firewall
    `apply` reloads the entire nftables ruleset -- see
    frfw.nft.builder's own docstring on `flush ruleset` -- which would
    otherwise silently log every active session out; frfw.provision
    special-cases exactly this by snapshotting and restoring the set's
    contents around that reload).
    """

    enabled: bool = False
    session_ttl_seconds: int = 8 * 3600
    users: list[ZtnaUser] = field(default_factory=list)


@dataclass(frozen=True)
class UpdateConfig:
    """Which GitHub repo to check for new FR_OS releases against (phase 6,
    see frfw.update). Empty string means "use the built-in default"
    (`frfw.update.DEFAULT_REPO`) -- override only for a fork/community
    edition mirror that publishes its own releases."""

    repo: str = ""


@dataclass(frozen=True)
class PqcConfig:
    """Toggles hybrid (classical + post-quantum) key exchange for the
    management layer -- the webUI's own HTTPS listener and, if this host
    also runs sshd, its SSH KexAlgorithms -- see frfw.pqc for the full
    design writeup and the two hard version floors this depends on
    (OpenSSL 3.5 for TLS's X25519MLKEM768 group, OpenSSH 9.9 for SSH's
    mlkem768x25519-sha256). Both are capability-gated at apply time: if
    the installed OpenSSL/OpenSSH build is older than that, enabling
    this has no effect beyond restricting the webUI to TLS 1.3-only --
    it never breaks either service by requesting an algorithm the host
    doesn't actually have."""

    enabled: bool = False


@dataclass(frozen=True)
class AdblockerConfig:
    """Settings for the local DNS-level ad/tracker blocker (phase 9, see
    frfw.adblock).

    `source_urls` are hosts-format blocklists (e.g. StevenBlack's unified
    hosts list) `firewall-cli adblock-refresh` downloads, parses and
    dedupes into a local hosts-format file (`frfw.paths.ADBLOCK_HOSTS_PATH`)
    that a dedicated, frfw-managed dnsmasq instance serves from -- this is
    the "bulk" tier: tens of thousands of domains is cheap in a text file
    and a userspace hash table, and would not be cheap as kernel memory.

    `xdp_critical_limit`, if > 0, additionally feeds up to that many of
    the same domains into the existing Phase 4 XDP LPM trie
    (`frfw.xdp.sync_blocklist`) as a small, kernel-enforced "critical"
    subset -- reusing that one shared trie rather than adding a second
    kernel-side map, per the explicit "don't bloat the kernel stack"
    design constraint. Defaults to 0 (off): XDP requires its own compiled
    program and interface attachment, which is a bigger commitment than
    "block ads" alone should silently trigger -- an admin who already has
    xdp_sni_filter enabled opts in explicitly by raising this above 0.
    """

    enabled: bool = False
    source_urls: list[str] = field(default_factory=list)
    xdp_critical_limit: int = 0


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
    xdp_sni_filter: XdpSniFilterConfig = field(default_factory=XdpSniFilterConfig)
    ztna: ZtnaConfig = field(default_factory=ZtnaConfig)
    pqc: PqcConfig = field(default_factory=PqcConfig)
    adblocker: AdblockerConfig = field(default_factory=AdblockerConfig)
