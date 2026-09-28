"""The router's attack surface: what listens, and from which zone it can
be reached (security-lessons I3).

Two facts are put together, both taken from the running system:

1. every listening socket (`ss -Hlntup`, run as root by the apply-helper
   so it also names the processes it can), with the address and, for
   device-bound sockets, the interface it is bound to;
2. which zone's traffic the input chain lets through to that port --
   worked out from the same config the ruleset is built from, in the
   same order as frfw.nft.builder's input chain: the ad-block resolver's
   DNS accept, the management drop, then the admin's rules to "self",
   then the chain's `policy drop`.

A socket bound to loopback is reachable from no zone; one bound to an
address is reachable from the zones whose interfaces carry it; a
wildcard one from every zone -- and then the firewall decides. Anything
that comes out reachable from an internet-facing zone is flagged.

What this can't see, and says so on the page: a port forward to another
host (that is forwarded, not listened on), and what an outside scanner
really gets through (upstream NAT/CGNAT, the ISP). For that, scan the
WAN address from outside.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass, field

from frfw import management
from frfw.config.schema import SELF_ZONE, Action, Config, Protocol, Rule
from frfw.nft import builder

#: What usually listens on these ports on an FR_OS box -- for sockets
#: whose process `ss` couldn't name.
KNOWN_PORTS = {
    ("tcp", 22): "sshd",
    ("tcp", 443): "webUI (fr-webui)",
    ("udp", 53): "DNS filter (dnsmasq)",
    ("tcp", 53): "DNS filter (dnsmasq)",
    ("udp", 67): "DHCP server (Kea)",
    ("udp", 68): "DHCP client",
    ("udp", 5353): "mDNS",
    ("udp", builder.IOT_MDNS_REPLY_PORT): "IoT scan (mDNS replies)",
}

OPEN = "open"
RESTRICTED = "restricted"
CLOSED = "closed"


class SurfaceError(Exception):
    pass


@dataclass(frozen=True)
class Listener:
    proto: str  # "tcp" | "udp"
    address: str  # "0.0.0.0", "::", "192.168.1.1", ...
    port: int
    device: str | None = None  # bound to one interface (SO_BINDTODEVICE)
    process: str | None = None

    @property
    def family(self) -> int:
        return ipaddress.ip_address(self.address).version

    @property
    def wildcard(self) -> bool:
        return ipaddress.ip_address(self.address).is_unspecified

    @property
    def loopback(self) -> bool:
        return ipaddress.ip_address(self.address).is_loopback

    @property
    def label(self) -> str:
        return self.process or KNOWN_PORTS.get((self.proto, self.port), "unknown")


@dataclass(frozen=True)
class Verdict:
    state: str  # OPEN | RESTRICTED | CLOSED
    why: str


@dataclass
class Row:
    listener: Listener
    zones: dict[str, Verdict] = field(default_factory=dict)
    internet: bool = False  # reachable (at all) from an internet-facing zone
    #: What in the config needs this socket (security-lessons K7); None:
    #: nothing does.
    needed: str | None = None

    @property
    def reachable(self) -> bool:
        return any(v.state != CLOSED for v in self.zones.values())

    @property
    def unneeded(self) -> bool:
        """Reachable from some zone, and nothing FR_OS runs needs it."""
        return self.reachable and self.needed is None


def needed_by(config: Config, listener: Listener) -> str | None:
    """Why this socket is expected on an FR_OS router with this config
    (security-lessons K7), or None: a service nothing here asked for."""
    if listener.loopback:
        return "local only"
    key = (listener.proto, listener.port)
    if key == ("tcp", management.WEBUI_PORT):
        return "the webUI"
    if key == ("tcp", management.SSH_PORT):
        return "SSH (runs only while someone has a key)"
    if key == ("udp", 68):
        return "the WAN's DHCP client"
    if listener.port == 53 and config.adblocker.enabled:
        return "the DNS filter (adblocker)"
    if key == ("udp", 67) and config.dhcp.zones:
        return "the DHCP server (dhcp)"
    if key in (("udp", 5353), ("udp", builder.IOT_MDNS_REPLY_PORT)) and config.iot.enabled:
        return "the IoT scan (iot)"
    if key == ("udp", config.wireguard.listen_port) and config.wireguard.enabled:
        return "the WireGuard VPN (wireguard)"
    return None


# -- the sockets --------------------------------------------------------------------

_USERS_RE = re.compile(r'users:\(\("([^"]+)"')


def _split_host_port(local: str) -> tuple[str, str | None, int]:
    host, _, port = local.rpartition(":")
    device = None
    if "%" in host:
        host, _, device = host.partition("%")
    host = host.strip("[]")
    if host == "*":
        host = "::"
    return host, device, int(port)


def parse_ss(text: str) -> list[Listener]:
    """Listening sockets from `ss -Hlntup` output (tcp LISTEN, udp UNCONN)."""
    listeners = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] not in ("tcp", "udp"):
            continue
        try:
            host, device, port = _split_host_port(fields[4])
            ipaddress.ip_address(host)
        except ValueError:
            continue
        match = _USERS_RE.search(line)
        listeners.append(Listener(fields[0], host, port, device, match.group(1) if match else None))
    return sorted(set(listeners), key=lambda l: (l.proto, l.port, l.address, l.device or ""))


def parse_ip_addr(text: str) -> dict[str, list[str]]:
    """Interface -> its addresses, from `ip -j addr show`."""
    out: dict[str, list[str]] = {}
    for iface in json.loads(text or "[]"):
        out[iface["ifname"]] = [a["local"] for a in iface.get("addr_info", []) if "local" in a]
    return out


def collect() -> tuple[list[Listener], dict[str, list[str]]]:
    """Read both off the running system (root for the process names)."""
    try:
        ss = subprocess.run(["ss", "-Hlntup"], capture_output=True, text=True, timeout=10)
        ip = subprocess.run(["ip", "-j", "addr", "show"], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise SurfaceError(f"cannot list sockets: {exc}") from exc
    if ss.returncode != 0:
        raise SurfaceError(ss.stderr.strip() or "ss failed")
    if ip.returncode != 0:
        raise SurfaceError(ip.stderr.strip() or "ip addr failed")
    return parse_ss(ss.stdout), parse_ip_addr(ip.stdout)


# -- what the firewall lets through ------------------------------------------------------


def _port_matches(spec: str, port: int) -> bool:
    lo, _, hi = spec.partition("-")
    return int(lo) <= port <= int(hi or lo)


def _rule_matches(rule: Rule, zone: str, proto: str, port: int, family: int) -> bool:
    if rule.from_zone is not None and rule.from_zone != zone:
        return False
    if rule.proto not in (Protocol.ANY, Protocol(proto)):
        return False
    if rule.dst_port is not None and not _port_matches(rule.dst_port, port):
        return False
    # `ip saddr`/`ip daddr` matches (addresses, the ZTNA set) never match IPv6.
    if family == 6 and (rule.src_address or rule.dst_address or rule.require_ztna):
        return False
    return True


def _conditions(rule: Rule) -> list[str]:
    out = []
    if rule.src_address:
        out.append(f"from {rule.src_address}")
    if rule.src_mac:
        out.append(f"from device {rule.src_mac}")
    if rule.require_ztna:
        out.append("ZTNA-signed-in clients")
    if rule.dst_address:
        out.append(f"to {rule.dst_address}")
    if rule.schedule is not None:
        out.append("on a schedule")
    return out


def input_verdict(config: Config, zone: str, proto: str, port: int, family: int = 4) -> Verdict:
    """What the input chain does with a new connection from `zone` to
    `proto`/`port` on the router, step by step in frfw.nft.builder's order."""
    verdict = _chain_verdict(config, zone, proto, port, family)
    # The isolated-IoT accepts come first in the chain and aren't tied to a
    # zone: whatever else happens, those devices still get DNS and DHCP.
    isolated_dns_dhcp = (proto == "udp" and port in (53, 67)) or (proto == "tcp" and port == 53)
    if verdict.state == CLOSED and config.iot.enabled and isolated_dns_dhcp:
        return Verdict(RESTRICTED, "only isolated IoT devices (DNS/DHCP)")
    return verdict


def _chain_verdict(config: Config, zone: str, proto: str, port: int, family: int) -> Verdict:
    if config.iot.enabled and zone in config.iot.zones and proto == "udp" and port == builder.IOT_MDNS_REPLY_PORT:
        return Verdict(RESTRICTED, "only mDNS replies from port 5353 (IoT scan)")
    input_rules = [r for r in config.rules if r.to_zone == SELF_ZONE]
    cut = [r for r in input_rules if r.schedule is not None and r.schedule.cut_established]
    rest = [r for r in input_rules if r not in cut]
    restricted_by: list[str] = []

    def decide(rules: list[Rule]) -> Verdict | None:
        for rule in rules:
            if not _rule_matches(rule, zone, proto, port, family):
                continue
            conditions = _conditions(rule)
            if conditions:
                if rule.action == Action.ACCEPT:
                    restricted_by.append(f"rule {rule.name!r}: {', '.join(conditions)}")
                continue  # a conditional drop leaves the rest to the next rules
            if rule.action == Action.ACCEPT:
                return Verdict(OPEN, f"rule {rule.name!r}")
            if restricted_by:
                return Verdict(RESTRICTED, "; ".join(restricted_by))
            return Verdict(CLOSED, f"rule {rule.name!r} ({rule.action.value})")
        return None

    found = decide(cut)
    if found:
        return found
    if zone in builder._dns_resolver_zones(config) and port == 53:
        return Verdict(OPEN, "the ad-block DNS resolver serves this zone")
    if (proto == "tcp" and port in management.MANAGEMENT_PORTS
            and zone in management.blocked_zones(config)):
        if restricted_by:
            return Verdict(RESTRICTED, "; ".join(restricted_by))
        return Verdict(CLOSED, "management is off this zone (management.zones)")
    found = decide(rest)
    if found:
        return found
    if restricted_by:
        return Verdict(RESTRICTED, "; ".join(restricted_by))
    return Verdict(CLOSED, "no rule allows it (policy drop)")


# -- putting it together ---------------------------------------------------------------


def _zones_by_device(config: Config) -> dict[str, str]:
    return {iface.device: iface.zone for iface in config.interfaces.values()}


def reachable_zones(listener: Listener, config: Config, addresses: dict[str, list[str]]) -> list[str]:
    """The zones whose traffic can reach the socket at all (before the
    firewall): by what it is bound to."""
    if listener.loopback:
        return []
    by_device = _zones_by_device(config)
    if listener.device is not None:
        zone = by_device.get(listener.device)
        return [zone] if zone else []
    if listener.wildcard:
        return sorted({z for d, z in by_device.items()} & set(config.zones))
    zones = set()
    for device, addrs in addresses.items():
        if listener.address in addrs and device in by_device:
            zones.add(by_device[device])
    for iface in config.interfaces.values():  # a static address not up yet
        if iface.address and str(ipaddress.ip_interface(iface.address).ip) == listener.address:
            zones.add(iface.zone)
    return sorted(zones)


def surface(config: Config, listeners: list[Listener], addresses: dict[str, list[str]]) -> list[Row]:
    internet = management.internet_zones(config)
    rows = []
    for listener in listeners:
        row = Row(listener)
        for zone in reachable_zones(listener, config, addresses):
            row.zones[zone] = input_verdict(config, zone, listener.proto, listener.port, listener.family)
        row.internet = any(z in internet and v.state != CLOSED for z, v in row.zones.items())
        row.needed = needed_by(config, listener)
        rows.append(row)
    return sorted(rows, key=lambda r: (not r.internet, not r.reachable, r.listener.port, r.listener.proto))


def wan_addresses(config: Config, addresses: dict[str, list[str]]) -> list[str]:
    """The internet-facing interfaces' addresses, for the outside-scan hint."""
    internet = management.internet_zones(config)
    out = []
    for iface in config.interfaces.values():
        if iface.zone in internet:
            out += [a for a in addresses.get(iface.device, []) if not ipaddress.ip_address(a).is_link_local]
    return out
