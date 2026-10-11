"""IPv6 (ROADMAP FND-1): on the WAN for the router itself (FND-1a), and on
the LAN (FND-1b).

FR_OS was IPv4-only: the ruleset dropped every IPv6 packet, neighbour
discovery included. With `ipv6.enabled`:

- **dhcpcd** (`fr-dhcp6.service`, Debian's dhcpcd-base, IPv6 only) takes
  the WAN's address from the provider's Router Advertisement (SLAAC, RFC
  7217 stable addresses: not derived from the MAC) and asks DHCPv6 for an
  address and a delegated prefix (`wan_devices`). It hands a /64 of that
  prefix to each device of the LAN zones (`lan_devices`, FND-1b), in a
  fixed order: the first device gets the prefix's first /64 ("sla_id"
  0), so a provider's /64 still serves the first LAN. dhcpcd adds the
  router's address `<network>::1` there, follows the provider's
  renumbering, and installs an `unreachable` route for the rest of the
  prefix. It runs on the LAN devices only to do that: no Router
  Advertisement is read there (`noipv6rs`: a LAN must never configure
  the router) and nothing is asked for. It runs no hook script (`script
  /bin/true`), so nothing the provider sends reaches the router's own
  files (resolv.conf, its hostname, NTP), and it sends no hostname. It
  drops to its own account itself (privilege separation) inside a
  systemd sandbox.
- **dnsmasq, RA only** (`fr-ra.service`, FND-1b): a dedicated instance
  that advertises each LAN device's /64 for SLAAC (`constructor:`, so a
  renumbered prefix is advertised as it changes) and does nothing else --
  no DNS (`port=0`, which also leaves the RA without a DNS server option:
  the LAN keeps the router's IPv4 resolver, FND-1c), no DHCPv4, no DHCPv6
  (`ra-only`). It runs as a dynamic account with CAP_NET_RAW alone.
- **The kernel** takes no Router Advertisement on any interface
  (`accept_ra=0`: dhcpcd reads the WAN's itself), follows no redirect,
  and routes IPv6 (`forwarding=1`) only while a LAN zone gets it.
- **The firewall** (frfw.nft.builder) accepts the ICMPv6 the WAN needs,
  and on the LAN neighbour discovery, router solicitations and ping; every
  other IPv6 packet to the router is dropped, before any rule written for
  IPv4 -- the router's services come with FND-1c. Forwarded IPv6 goes only
  between the WAN and the LAN zones' devices, nothing new comes in from
  the internet, and a LAN host may only send from its own network.

`status()` says what the provider gave and what that means: a delegated
prefix and the LAN networks made of it, an address only (a single /64 on
the WAN: not enough for a LAN), or nothing. FR_OS is a community edition:
every outcome is a state to explain, never an error.

Off (the default), the ruleset drops all IPv6 to and through the router,
and an apply stops dhcpcd -- which takes its addresses and routes with it
-- and the RA instance if they were running.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from frfw import paths, svc, validate
from frfw.config.loader import internet_facing_zones, ipv6_lan_exclusions, ipv6_lan_zones
from frfw.config.schema import Config

#: The kernel's network settings (net.ipv6.*, and the one net.ipv4 one
#: dhcpcd needs).
PROC_NET = Path("/proc/sys/net")


class Ipv6Error(Exception):
    pass


def wan_devices(config: Config) -> list[str]:
    """The internet-facing interfaces' devices: where IPv6 comes from."""
    facing = internet_facing_zones(config.zones, config.nat)
    devices: list[str] = []
    for iface in config.interfaces.values():
        if iface.zone in facing and iface.device not in devices:
            devices.append(validate.ifname(iface.device))
    return devices


def lan_devices(config: Config) -> list[tuple[str, str]]:
    """(zone, device) for every device the delegated prefix is handed to
    (ROADMAP FND-1b): the LAN zones' devices, zone by zone in
    `ipv6.lan_zones` order, then in config order. The position is the
    device's /64 in the prefix ("sla_id"), so an added zone or device
    goes last and renumbers nobody. Not the VPN tunnel: its clients are
    IPv4-only. Empty while IPv6 is off."""
    zones = ipv6_lan_zones(config.ipv6, config.interfaces, config.zones, config.nat, config.rules,
                           config.xdp_sni_filter)
    out: list[tuple[str, str]] = []
    for zone in zones:
        for iface in config.interfaces.values():
            if iface.zone == zone and iface.device not in [d for _, d in out]:
                out.append((zone, validate.ifname(iface.device)))
    return out


def excluded_zones(config: Config) -> list[tuple[str, str]]:
    """(zone, why) for each zone left out of the default `lan_zones`
    because IPv6 would get around an IPv4-only protection of it
    (frfw.config.loader.ipv6_lan_exclusions). None with an explicit list,
    which the loader refuses such a zone in."""
    if not config.ipv6.enabled or config.ipv6.lan_zones is not None:
        return []
    with_interface = {i.zone for i in config.interfaces.values()}
    return [(zone, why) for zone, why in ipv6_lan_exclusions(
        config.interfaces, config.zones, config.nat, config.rules, config.xdp_sni_filter).items()
        if zone in with_interface]


_DHCPCD_TEMPLATE = """\
# Managed by FR_OS (frfw.ipv6) -- regenerated on every `apply`, do not edit.
# IPv6 (ROADMAP FND-1): SLAAC from the provider's Router Advertisement,
# DHCPv6 for an address and a delegated prefix on the WAN; a /64 of the
# prefix for each LAN device (FND-1b), with an unreachable route installed
# for the rest of it.
ipv6only
noipv4
noipv4ll
# Router Advertisements are read on the WAN only (its block below): never
# on a LAN, which must not configure the router -- and dhcpcd.conf(5)
# advises it when asking for a delegated prefix.
noipv6rs
# No hostname and no FQDN option: the router doesn't name itself to the
# provider.
fqdn disable
# No hook script: nothing the provider sends is written to the router's
# own files (resolv.conf, its hostname, NTP servers).
script /bin/true
# Stable addresses that don't carry the MAC (RFC 7217).
slaac private
# The LAN devices too: dhcpcd only assigns a prefix to an interface it
# runs on.
allowinterfaces {devices}
{interfaces}"""


def _delegation(config: Config, first: bool) -> str:
    """ia_pd's interfaces: `<device>/<sla_id>/64` for each LAN device, on
    the first WAN device only -- two WANs delegating to the same LAN would
    give it two prefixes from two providers. sla_id 0 is the prefix's
    first /64 and, from a provider that delegates just a /64, the whole
    prefix (dhcpcd.conf(5)); a device whose sla_id doesn't fit the prefix
    gets nothing, which status() explains. "-": to no interface."""
    lan = lan_devices(config) if first else []
    if not lan:
        return "-"
    return " ".join(f"{device}/{sla}/64" for sla, (_, device) in enumerate(lan))


def render_dhcpcd_conf(config: Config) -> str:
    wan = wan_devices(config)
    blocks = "".join(
        f"\ninterface {device}\n"
        "\tipv6rs\n"
        # Asking for these explicitly also makes dhcpcd start DHCPv6
        # when the provider's RA sets neither the M nor the O flag. With
        # no interface named, dhcpcd would give every other interface a
        # prefix: it is always named, or "-".
        f"\tia_na {n}\n"
        f"\tia_pd {n + 100} {_delegation(config, n == 1)}\n"
        for n, device in enumerate(wan, start=1)
    )
    devices = wan + [d for _, d in lan_devices(config) if d not in wan]
    return _DHCPCD_TEMPLATE.format(devices=" ".join(devices), interfaces=blocks)


#: Debian's dnsmasq-base (fr-adblock-dns uses the same binary).
DNSMASQ_BINARY = "/usr/sbin/dnsmasq"

_RA_TEMPLATE = """\
# Managed by FR_OS (frfw.ipv6) -- regenerated on every `apply`, do not edit.
# Router Advertisements on the LAN (ROADMAP FND-1b), and nothing else: the
# /64 dhcpcd gave each device, for SLAAC.
# No DNS: this also leaves the RA without a DNS server option, so the LAN
# keeps using the router's IPv4 resolver (FND-1c).
port=0
no-resolv
no-hosts
# Nothing is written: /run is read-only in fr-ra's sandbox, and there are
# no leases to keep.
pid-file=
leasefile-ro
# No log line for every advertisement sent.
quiet-ra
enable-ra
{interfaces}"""


def render_ra_conf(config: Config) -> str:
    """dnsmasq's config: an RA-only context per LAN device. `constructor:`
    takes the prefix from the device's own address, as dhcpcd set it, and
    follows it when the provider renumbers; `ra-only`: SLAAC with no
    DHCPv6 server (no M or O flag)."""
    lines = []
    for _, device in lan_devices(config):
        lines.append(f"interface={device}\ndhcp-range=::,constructor:{device},ra-only\n")
    return _RA_TEMPLATE.format(interfaces="".join(lines))


def sysctl_settings(config: Config) -> dict[str, str]:
    """`ipv6/conf/<device>/<key>` (under /proc/sys/net) -> value, for every
    configured device (not VPN tunnels, which never carry an RA) and the
    defaults new ones get.

    These are also every value dhcpcd would otherwise write itself:
    fr-dhcp6's sandbox keeps /proc/sys read-only, and dhcpcd leaves a
    setting alone that already has the value it wants -- the IPv4
    `promote_secondaries` among them, which it insists on, even with
    `ipv6only`, on every interface it runs on (an interface it can't set
    it on is "not valid"): the WAN's and the LAN's."""
    wan = wan_devices(config)
    lan = [d for _, d in lan_devices(config)]
    # Routing only while there is a LAN to route to (FND-1b).
    settings: dict[str, str] = {"ipv6/conf/all/forwarding": "1" if lan else "0"}
    devices = sorted({validate.ifname(i.device) for i in config.interfaces.values()})
    for device in ["all", "default", *devices]:
        settings[f"ipv6/conf/{device}/accept_ra"] = "0"
        settings[f"ipv6/conf/{device}/accept_redirects"] = "0"
        settings[f"ipv6/conf/{device}/accept_source_route"] = "0"
        # dhcpcd does SLAAC on the WAN, nothing does elsewhere.
        settings[f"ipv6/conf/{device}/autoconf"] = "0"
    for device in [*wan, *lan]:
        settings[f"ipv6/conf/{device}/disable_ipv6"] = "0"
        settings[f"ipv4/conf/{device}/promote_secondaries"] = "1"
    return settings


def read_sysctls(keys, proc_root: Path | None = None) -> dict[str, str | None]:
    """The current values (None: no such device), to restore on undo."""
    proc_root = proc_root or PROC_NET
    out: dict[str, str | None] = {}
    for key in keys:
        try:
            out[key] = (proc_root / key).read_text().strip()
        except OSError:
            out[key] = None
    return out


def write_sysctls(settings: dict[str, str | None], proc_root: Path | None = None) -> None:
    """Write each value; a device that isn't there (yet) is skipped."""
    proc_root = proc_root or PROC_NET
    for key, value in settings.items():
        if value is None:
            continue
        path = proc_root / key
        if not path.parent.is_dir():
            continue
        try:
            if path.read_text().strip() != value:
                path.write_text(value + "\n")
        except OSError as exc:
            raise Ipv6Error(f"cannot set net.{key.replace('/', '.')} = {value}: {exc}") from exc


def kernel_has_ipv6(proc_root: Path | None = None) -> bool:
    """False with `ipv6.disable=1` on the kernel command line."""
    return ((proc_root or PROC_NET) / "ipv6" / "conf").is_dir()


#: Debian's dhcpcd-base.
DHCPCD_BINARY = "/usr/sbin/dhcpcd"


def check_available(proc_root: Path | None = None, dhcpcd_binary: str | None = None,
                    dnsmasq_binary: str | None = None, config: Config | None = None) -> None:
    """An apply's preflight (ROADMAP SEC-5): what turning IPv6 on needs --
    and dnsmasq for the LAN's RAs, when `config` hands the prefix to one."""
    dhcpcd_binary = dhcpcd_binary or DHCPCD_BINARY
    dnsmasq_binary = dnsmasq_binary or DNSMASQ_BINARY
    if not kernel_has_ipv6(proc_root):
        raise Ipv6Error("this kernel runs without IPv6 (ipv6.disable=1 on its command line)")
    if not Path(dhcpcd_binary).is_file():
        raise Ipv6Error(f"{dhcpcd_binary} is not installed (Debian's dhcpcd-base)")
    if config is not None and lan_devices(config) and not Path(dnsmasq_binary).is_file():
        raise Ipv6Error(f"{dnsmasq_binary} is not installed (Debian's dnsmasq-base), and the LAN's "
                        "Router Advertisements need it")


@dataclass(frozen=True)
class SyncResult:
    active: bool
    message: str


def sync(config: Config, *, dry_run: bool = False, conf_path: Path | None = None,
         proc_root: Path | None = None, ra_conf_path: Path | None = None) -> SyncResult:
    """Reconcile the kernel's IPv6 settings, dhcpcd and the LAN's RA
    instance with `config.ipv6` (an apply's step, frfw.provision)."""
    conf_path = conf_path or paths.IPV6_DHCPCD_CONF_PATH
    ra_conf_path = ra_conf_path or paths.IPV6_RA_CONF_PATH
    lan = lan_devices(config)
    if not config.ipv6.enabled:
        # Nothing to do -- not even a systemctl call -- unless an earlier
        # apply turned it on: tests and machines without dhcpcd apply too.
        if not (conf_path.exists() or ra_conf_path.exists() or service_active()
                or service_active(paths.IPV6_RA_SERVICE_NAME)):
            return SyncResult(False, "IPv6 off")
        if dry_run:
            return SyncResult(False, "Would turn IPv6 off (dry-run)")
        _require_root()
        _stop_ra(ra_conf_path)
        _systemctl("stop")
        conf_path.unlink(missing_ok=True)
        # Routing off with it; the kernel's other settings stay as safe as
        # they are.
        write_sysctls({"ipv6/conf/all/forwarding": "0"}, proc_root)
        return SyncResult(False, "IPv6 turned off")

    devices = wan_devices(config)
    if not kernel_has_ipv6(proc_root):
        raise Ipv6Error("this kernel runs without IPv6 (ipv6.disable=1 on its command line)")
    where = (f"; the LAN gets a /64 each on {', '.join(d for _, d in lan)} (Router Advertisements, SLAAC)"
             if lan else "; no LAN zone gets IPv6")
    if dry_run:
        return SyncResult(True, f"Would take IPv6 from the provider on {', '.join(devices)}{where} (dry-run)")
    _require_root()
    ra_text = render_ra_conf(config) if lan else None
    if ra_text is not None:
        _test_ra_conf(ra_text, ra_conf_path)
    write_sysctls(sysctl_settings(config), proc_root)
    text = render_dhcpcd_conf(config)
    changed = not conf_path.exists() or conf_path.read_text() != text
    if changed:
        conf_path.parent.mkdir(parents=True, exist_ok=True)
        conf_path.write_text(text)
    # A restart drops the addresses (the LAN's too) and asks the provider
    # again: only for a new config, not on every apply.
    _systemctl("restart" if changed else "start")
    if ra_text is None:
        _stop_ra(ra_conf_path)
    else:
        ra_changed = not ra_conf_path.exists() or ra_conf_path.read_text() != ra_text
        if ra_changed:
            ra_conf_path.write_text(ra_text)
        _systemctl("restart" if ra_changed else "start", paths.IPV6_RA_SERVICE_NAME)
    return SyncResult(True, f"IPv6: dhcpcd on {', '.join(devices)} (SLAAC, DHCPv6 address and prefix "
                            f"delegation){where}")


def _stop_ra(ra_conf_path: Path) -> None:
    if ra_conf_path.exists() or service_active(paths.IPV6_RA_SERVICE_NAME):
        _systemctl("stop", paths.IPV6_RA_SERVICE_NAME)
        ra_conf_path.unlink(missing_ok=True)


def _test_ra_conf(text: str, ra_conf_path: Path) -> None:
    """`dnsmasq --test` of the new config before it replaces the old one."""
    ra_conf_path.parent.mkdir(parents=True, exist_ok=True)
    candidate = ra_conf_path.with_name(ra_conf_path.name + ".new")
    candidate.write_text(text)
    try:
        proc = subprocess.run([DNSMASQ_BINARY, "--test", f"--conf-file={candidate}"],
                              capture_output=True, text=True, timeout=30)
    except FileNotFoundError as exc:
        raise Ipv6Error(f"{DNSMASQ_BINARY} is not installed (Debian's dnsmasq-base)") from exc
    finally:
        candidate.unlink(missing_ok=True)
    if proc.returncode != 0:
        raise Ipv6Error(f"dnsmasq rejected the Router Advertisement config: "
                        f"{(proc.stderr or proc.stdout).strip()}")


def service_active(unit: str | None = None) -> bool:
    try:
        proc = svc.systemctl("is-active", unit or paths.IPV6_SERVICE_NAME, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return proc.stdout.strip() in ("active", "activating", "reloading")


def _systemctl(action: str, unit: str | None = None) -> None:
    unit = unit or paths.IPV6_SERVICE_NAME
    try:
        proc = svc.systemctl(action, unit, timeout=60)
    except FileNotFoundError as exc:
        raise Ipv6Error("'systemctl' not found") from exc
    if proc.returncode != 0:
        raise Ipv6Error(f"systemctl {action} {unit} failed: "
                        f"{(proc.stderr or proc.stdout).strip()} (see journalctl -u {unit})")


def _require_root() -> None:
    if os.geteuid() != 0:
        raise Ipv6Error("Setting up IPv6 requires root privileges.")


# --- what the provider gave ---------------------------------------------------


#: status()'s verdicts.
OFF = "off"
NO_KERNEL = "no-kernel-ipv6"
NOTHING = "nothing"
ADDRESS_ONLY = "address-only"
PREFIX = "prefix"


@dataclass
class Ipv6Status:
    state: str
    devices: list[str] = field(default_factory=list)
    #: (device, address/prefixlen, "SLAAC" or "DHCPv6")
    addresses: list[tuple[str, str, str]] = field(default_factory=list)
    #: (device, gateway)
    default_routes: list[tuple[str, str]] = field(default_factory=list)
    #: delegated prefixes, e.g. "2001:db8:100::/56"
    prefixes: list[str] = field(default_factory=list)
    service_active: bool = False
    #: (zone, device, its network, e.g. "2001:db8:100::/64", or "" for none
    #: yet) for every LAN device the prefix is handed to (FND-1b).
    lan: list[tuple[str, str, str]] = field(default_factory=list)
    ra_active: bool = False
    #: (zone, why) for the zones left out (excluded_zones).
    excluded: list[tuple[str, str]] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.state == OFF:
            return "IPv6 is off."
        if self.state == NO_KERNEL:
            return "This router's kernel runs without IPv6."
        if self.state == NOTHING:
            return ("Nothing from the provider (yet): no IPv6 address on the WAN. Either the network "
                    "upstream has no IPv6, or it hasn't answered yet; the router keeps using IPv4.")
        if self.state == ADDRESS_ONLY:
            return ("The WAN has an IPv6 address, but no prefix was delegated: the router itself has IPv6, "
                    "the LAN can't get it from this upstream. Turn on prefix delegation (DHCPv6-PD) on the "
                    "router in front of this one, or ask the provider for it.")
        sizes = ", ".join(f"{p} ({lan_networks(p)} LAN networks)" for p in self.prefixes)
        text = f"A prefix was delegated: {sizes}."
        left_out = "".join(f" Zone {zone} gets no IPv6: {why}." for zone, why in self.excluded)
        if not self.lan:
            return text + " No LAN zone gets IPv6, so only the router uses it." + left_out
        served = [f"{zone} ({device}) {network}" for zone, device, network in self.lan if network]
        waiting = [f"{zone} ({device})" for zone, device, network in self.lan if not network]
        if served:
            text += " The LAN has IPv6: " + ", ".join(served) + "."
        if waiting:
            room = sum(lan_networks(p) for p in self.prefixes)
            if room and room < len(self.lan):
                text += (f" No network on {', '.join(waiting)}: the prefix holds {room} LAN network(s) and "
                         f"{len(self.lan)} are needed. Ask the provider for a larger prefix (a /56 or /60), "
                         "or leave zones out of ipv6.lan_zones.")
            else:
                text += f" No network on {', '.join(waiting)} yet."
        return text + left_out

    def as_dict(self) -> dict:
        return {"state": self.state, "summary": self.summary, "devices": self.devices,
                "addresses": [list(a) for a in self.addresses],
                "default_routes": [list(r) for r in self.default_routes],
                "prefixes": self.prefixes, "service_active": self.service_active,
                "lan": [list(n) for n in self.lan], "ra_active": self.ra_active,
                "excluded": [list(e) for e in self.excluded]}


def lan_networks(prefix: str) -> int:
    """How many /64 LAN networks a delegated prefix holds."""
    return 2 ** max(0, 64 - ipaddress.IPv6Network(prefix).prefixlen)


def _ip_json(*args: str) -> list:
    proc = subprocess.run(["ip", "-j", "-6", *args], capture_output=True, text=True, timeout=10)
    if proc.returncode != 0:
        raise Ipv6Error(f"ip -6 {' '.join(args)} failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout or "[]")


def status(config: Config, *, proc_root: Path | None = None, ip_json=None) -> Ipv6Status:
    """What the provider gave the WAN, read from the kernel: its global
    addresses, its default route, the unreachable routes dhcpcd installs
    for a delegated prefix, and the networks it made of it on the LAN."""
    ip_json = ip_json or _ip_json
    devices = wan_devices(config)
    if not config.ipv6.enabled:
        return Ipv6Status(OFF, devices)
    if not kernel_has_ipv6(proc_root):
        return Ipv6Status(NO_KERNEL, devices)
    lan = lan_devices(config)
    result = Ipv6Status(NOTHING, devices, service_active=service_active(),
                        ra_active=bool(lan) and service_active(paths.IPV6_RA_SERVICE_NAME),
                        excluded=excluded_zones(config))
    lan_network: dict[str, str] = {}
    for link in ip_json("addr", "show"):
        device = link.get("ifname")
        for info in link.get("addr_info", []):
            if info.get("family") != "inet6" or info.get("scope") != "global":
                continue
            address = ipaddress.IPv6Interface(f"{info['local']}/{int(info['prefixlen'])}")
            if device in devices:
                # dhcpcd adds a DHCPv6 (IA_NA) address as a /128, a SLAAC
                # one with its prefix's length.
                source = "DHCPv6" if address.network.prefixlen == 128 else "SLAAC"
                result.addresses.append((device, str(address), source))
            elif any(device == d for _, d in lan) and address.network.prefixlen == 64:
                lan_network.setdefault(device, str(address.network))
    result.lan = [(zone, device, lan_network.get(device, "")) for zone, device in lan]
    for route in ip_json("route", "show", "table", "main"):
        dst = route.get("dst")
        if dst == "default" and route.get("dev") in devices and route.get("gateway"):
            result.default_routes.append((route["dev"], str(ipaddress.IPv6Address(route["gateway"]))))
        elif route.get("type") == "unreachable" and route.get("protocol") == "dhcp" and dst:
            network = ipaddress.IPv6Network(dst)
            if network.prefixlen <= 64 and not (network.is_link_local or network.is_multicast or network.is_loopback):
                result.prefixes.append(str(network))
    if not result.prefixes and lan_network:
        # A delegated /64 given whole to the first LAN device: dhcpcd
        # installs no unreachable route for it (dhcpcd.conf(5), ia_pd).
        result.prefixes = sorted(set(lan_network.values()))
    if result.prefixes:
        result.state = PREFIX
    elif result.addresses:
        result.state = ADDRESS_ONLY
    return result
