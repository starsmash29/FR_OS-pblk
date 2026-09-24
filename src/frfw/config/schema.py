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
class RuleSchedule:
    """When a rule applies (phase 17, see frfw.nft.schedule), in the
    config's `timezone`.

    `days` are weekday indexes, 0 = Monday. `start`/`end` are minutes
    after local midnight; `end` may be 1440 (24:00). An `end` at or
    before `start` means the window runs past midnight into the next
    day: Friday 22:00-06:00 ends Saturday 06:00.

    `cut_established` (drop/reject rules only) moves the rule ahead of
    the chain's `ct state established,related accept`, so connections
    opened before the window started are cut too, not only new ones.
    Such rules are evaluated before every ordinary rule.
    """

    days: tuple[int, ...]
    start: int
    end: int
    cut_established: bool = False


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
    #: Source MAC address (lowercase aa:bb:cc:dd:ee:ff), phase 17 -- names
    #: a device regardless of the address DHCP gave it.
    src_mac: str | None = None
    schedule: RuleSchedule | None = None


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
    """Settings for the real-time, kernel-assisted anomaly detection
    engine (phase 11, see frfw.ai_ids). `enabled` controls the config
    flag the webUI/CLI show and validate; the actual `fr-ai-ids` daemon
    is a separate systemd service that reads this flag itself (it is not
    started/stopped by `firewall-cli apply` the way nftables/Kea/XDP
    are -- see frfw.ai_ids's module docstring for why detection stays
    fully out-of-band from the config-apply pipeline).

    `excluded_macs` are devices never flagged or quarantined (e.g. the
    router's own interfaces, a backup server or NAS that legitimately
    opens many connections, or a noisy IoT device). Since the engine
    scores *source IP addresses* (drawn from live connection-tracking
    and XDP SNI-filter data, which have no concept of a MAC address once
    traffic has been routed), a configured MAC is resolved against the
    current DHCP static reservations (`dhcp.<zone>.reservations`) at
    daemon startup to build the actual excluded-IP set -- the same
    "known device" source the earlier mock engine used, kept for
    continuity, now feeding real exclusion logic instead of a mock
    profile lookup. A MAC with no matching reservation currently excludes
    nothing (there is no IP to resolve it to yet); this is a known
    limitation, not silently ignored -- see ARCHITECTURE.md.

    `quarantine_duration_seconds` is how long a flagged IP is dropped by
    the kernel (`frfw.ids_quarantine`) once quarantined, mirroring
    `frfw.bruteforce`'s BAN_DURATION_SECONDS -- 2 hours by default, long
    enough to actually interrupt an ongoing scan/beacon, short enough
    that a false positive self-heals without needing a manual unquarantine
    (which this phase does not yet implement -- see ARCHITECTURE.md's
    open issues).
    """

    enabled: bool = False
    excluded_macs: list[str] = field(default_factory=list)
    quarantine_duration_seconds: int = 2 * 3600


@dataclass(frozen=True)
class XdpSniFilterConfig:
    """Settings for the kernel-space TLS SNI filter (phase 4, see
    frfw.xdp and bpf/xdp_sni_filter.c).

    `interfaces` names logical interfaces (keys of `Config.interfaces`,
    not raw device names) to attach the XDP program to. XDP only sees
    packets an interface *receives*, so to filter what LAN clients
    connect to, list the LAN-side interfaces their ClientHellos arrive
    on. On the WAN interface the program only sees connections coming in
    from the internet (e.g. to a port-forwarded HTTPS server). The phase 4
    docs recommended the WAN interface for outbound filtering, which
    never worked -- see ARCHITECTURE.md's phase 16 section.

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
    #: Phase 15. Extra, separately-reported blocklists: category name ->
    #: source URLs (hosts format or plain domain lists). See
    #: frfw.adblock.categories for the verified presets the webUI offers.
    categories: dict[str, list[str]] = field(default_factory=dict)
    #: Domains (and their subdomains) never blocked, whatever list they're on.
    allowlist: list[str] = field(default_factory=list)
    #: Make the resolver actually used: hand out the router's own address
    #: as the DNS server in every DHCP pool (the pool's `dns_servers`
    #: become the resolver's upstreams instead) and accept DNS from those
    #: zones in the input chain. Off by default, as in phase 9 -- changing
    #: what every client's DNS is must be a deliberate choice.
    serve_lan: bool = False
    #: Requires serve_lan. Redirect every plain-DNS (port 53) query from
    #: the DHCP zones to this resolver, drop DNS-over-TLS (port 853), and
    #: answer Firefox's DoH canary domain with NXDOMAIN so it keeps using
    #: the system resolver.
    force_dns: bool = False
    #: Log every query (dnsmasq `log-queries=extra`) to the journal --
    #: needed for the AI IDS's NXDOMAIN/DGA and threat-lookup signals.
    #: Off by default: it records which client looked up which name.
    query_logging: bool = False


class IotIsolationMode(str, Enum):
    #: An isolated device may still reach the internet (every zone a
    #: `nat.masquerade` entry points at), but nothing else routed through
    #: this box -- no other zone, and no service on the router itself
    #: beyond DHCP and DNS.
    INTERNET_ONLY = "internet_only"
    #: An isolated device gets DHCP and DNS from the router and nothing
    #: else routed at all.
    BLOCK = "block"


@dataclass(frozen=True)
class IotConfig:
    """Settings for light-weight IoT device discovery and isolation
    (phase 14, see frfw.iot and frfw.iot_isolation).

    `zones` lists the zones whose devices are inventoried: DHCP leases
    and ARP entries inside those zones, plus an active mDNS service query
    on each of their interfaces that has a static `address`. Every device
    found is classified (OUI vendor, mDNS service types, DHCP hostname,
    randomized-MAC bit -- see frfw.iot.classify) as "iot", "general" or
    "unknown".

    Isolation is enforced by the router's own nftables ruleset on the
    device's MAC address (`frfw.nft.builder.IOT_ISOLATED_SET_NAME`), so it
    covers everything *routed through this box* -- other zones, the
    router's own services, and (in `block` mode) the internet. It cannot
    see traffic two devices exchange directly on the same switch/Wi-Fi
    segment; real layer-2 separation needs a dedicated IoT zone (its own
    VLAN interface, e.g. `eth1.30`), which this project already supports
    as an ordinary interface/zone -- see ARCHITECTURE.md's phase 14
    section.

    `auto_isolate` is off by default: enabling the feature alone only
    discovers and classifies devices, so an admin can review the
    inventory before anything is cut off. With it on, every device
    classified "iot" that is not in `trusted_macs` is isolated.
    `isolated_macs` are always isolated regardless of classification;
    `trusted_macs` are never isolated (a MAC may not appear in both).
    """

    enabled: bool = False
    zones: list[str] = field(default_factory=list)
    auto_isolate: bool = False
    isolation_mode: IotIsolationMode = IotIsolationMode.INTERNET_ONLY
    trusted_macs: list[str] = field(default_factory=list)
    isolated_macs: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AppControlConfig:
    """Coarse application identification and blocking (phase 16, see
    frfw.appid).

    `enabled` runs the fr-appid daemon, which attributes the names clients
    look up (resolver query log, needs `adblocker.query_logging`) and the
    TLS SNIs they send (needs `observe_sni`) to the apps of the bundled
    catalog, and turns on blocking of `blocked_apps`.

    `blocked_apps` (catalog app ids) are blocked by the router's resolver,
    which answers NXDOMAIN for every catalog name of those apps and their
    subdomains -- so it needs `adblocker.enabled` and `serve_lan`, and
    `adblocker.force_dns` to stop clients from simply using another DNS
    server. `block_via_xdp` additionally puts those names (the ones
    shorter than the XDP program's 32-byte limit) on the kernel SNI
    blocklist, which also catches clients that resolved the name some
    other way (DNS-over-HTTPS, hard-coded addresses).

    `observe_sni` makes the XDP program report every SNI it sees, not
    only blocklist hits (one journal line per TLS connection).
    """

    enabled: bool = False
    blocked_apps: list[str] = field(default_factory=list)
    block_via_xdp: bool = False
    observe_sni: bool = False


@dataclass(frozen=True)
class TlsFingerprintEntry:
    fingerprint: str  # a JA4 string or a 32-hex-digit JA3 hash, lowercase
    label: str = ""


@dataclass(frozen=True)
class TlsFingerprintConfig:
    """TLS client fingerprinting without decryption (phase 19, see
    frfw.tlsfp).

    `enabled` makes the XDP program copy every ClientHello it sees (so
    `xdp_sni_filter` must be enabled, on the LAN-side interfaces) and runs
    the fr-tls-fp daemon, which computes JA3 and JA4 per client, keeps an
    inventory, and reports fingerprints never seen on the network before.

    `blocklist` entries are reported when seen; with `quarantine_on_match`
    the client is also put in the AI IDS quarantine set for
    `ai_ids.quarantine_duration_seconds` (the kernel set exists whether or
    not the AI IDS daemon itself runs).
    """

    enabled: bool = False
    blocklist: list[TlsFingerprintEntry] = field(default_factory=list)
    quarantine_on_match: bool = False


@dataclass(frozen=True)
class MetricsConfig:
    """GET /metrics for multi-site monitoring (phase 20, see frfw.metrics).

    `site` names this router in a fleet (exported as fros_info's
    `site_name` label; the hostname when unset). `token_sha256` is the
    SHA-256 hex digest of a bearer token: when set, /metrics answers only
    requests with `Authorization: Bearer <token>`. Only the digest is ever
    stored -- the token is shown once when generated (webUI System screen
    or `firewall-cli metrics-token`).
    """

    site: str | None = None
    token_sha256: str | None = None


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
    iot: IotConfig = field(default_factory=IotConfig)
    app_control: AppControlConfig = field(default_factory=AppControlConfig)
    tls_fingerprint: TlsFingerprintConfig = field(default_factory=TlsFingerprintConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    #: IANA time zone rule schedules are written in (phase 17); None =
    #: the router's own local zone.
    timezone: str | None = None
