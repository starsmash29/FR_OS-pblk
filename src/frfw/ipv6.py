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
- **A stable network per LAN zone** (FND-1c): the provider may renumber
  the delegated prefix at any time, and may delegate none. So each LAN
  device also gets a /64 of a ULA /48 (RFC 4193: `fdXX:XXXX:XXXX::/48`,
  40 random bits the router picks once, `ula_prefix`) at the same
  position ("sla_id"), and the router's address `<network>::1` there
  (`ula_addresses`). The router's services answer on it: DNS, and the
  webUI and SSH with `management.ipv6` (frfw.management) -- never on the
  provider's addresses. It is added without duplicate address detection
  (`nodad`: a tentative address can't be bound, and no SLAAC host takes
  `::1`), and kept when the link goes down (`keep_addr_on_down`). ULA is
  never routed to or from the internet (frfw.nft.builder).
- **dnsmasq, RA only** (`fr-ra.service`, FND-1b): a dedicated instance
  that advertises each LAN device's /64s for SLAAC (`constructor:`, so a
  renumbered prefix is advertised as it changes; it takes every permanent
  address on the device, the ULA one too) and does nothing else -- no
  DNS (`port=0`), no DHCPv4, no DHCPv6 (`ra-only`). Where the router's
  resolver serves the zone, the RA names it (RDNSS, RFC 8106): the
  router's ULA address there (FND-1c). It runs as a dynamic account with
  CAP_NET_RAW and the CAP_NET_ADMIN dnsmasq insists on for RA, nothing
  else.
- **The kernel** takes no Router Advertisement on any interface
  (`accept_ra=0`: dhcpcd reads the WAN's itself), follows no redirect,
  and routes IPv6 (`forwarding=1`) only while a LAN zone gets it.
- **The firewall** (frfw.nft.builder) accepts the ICMPv6 the WAN needs,
  and on the LAN neighbour discovery, router solicitations and ping, DNS
  where the resolver serves the zone, and with `management.ipv6` the
  webUI and SSH on the ULA address -- through the same rules as over
  IPv4; every other IPv6 packet to the router is dropped. Forwarded IPv6
  goes only between the WAN and the LAN zones' devices, nothing new comes
  in from the internet but through a pinhole (`ipv6.pinholes`, FND-1c),
  and a LAN host may only send from its own network.

`status()` says what the provider gave and what that means: a delegated
prefix and the LAN networks made of it, an address only (a single /64 on
the WAN: not enough for a LAN), or nothing. FR_OS is a community edition:
every outcome is a state to explain, never an error.

Off (the default), the ruleset drops all IPv6 to and through the router,
and an apply stops dhcpcd -- which takes its addresses and routes with it
-- and the RA instance if they were running, and takes the ULA addresses
off.
"""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
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
# Router Advertisements on the LAN (ROADMAP FND-1b/1c), and nothing else:
# each device's /64s, for SLAAC -- the one dhcpcd gave it from the
# provider's prefix and the stable ULA one -- and, where the router's
# resolver serves the zone, the resolver's address (RDNSS).
# No DNS here: the ad-block resolver (fr-adblock-dns) answers it.
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


def render_ra_conf(config: Config, ula: ipaddress.IPv6Network | None = None) -> str:
    """dnsmasq's config: an RA-only context per LAN device. `constructor:`
    takes the prefixes from the device's own permanent addresses -- the
    provider's, as dhcpcd set it and following it when the provider
    renumbers, and the ULA one -- `ra-only`: SLAAC with no DHCPv6 server
    (no M or O flag). With `ula`, the router's ULA address goes in the RA
    as the DNS server (RDNSS) on the devices of the zones the resolver
    serves: dnsmasq takes it from `option6:dns-server`, tagged with the
    device's name (radv.c), even with its own DNS off (`port=0`)."""
    from frfw.nft.builder import dns_resolver_zones

    served = set(dns_resolver_zones(config))
    addresses = {device: address for _, device, address in ula_addresses(config, ula)} if ula else {}
    lines = []
    for zone, device in lan_devices(config):
        lines.append(f"interface={device}\ndhcp-range=::,constructor:{device},ra-only\n")
        if zone in served and device in addresses:
            server = ipaddress.IPv6Interface(addresses[device]).ip
            lines.append(f"dhcp-option=tag:{device},option6:dns-server,[{server}]\n")
    return _RA_TEMPLATE.format(interfaces="".join(lines))


# --- the stable (ULA) networks ------------------------------------------------

#: RFC 4193: locally assigned ULAs, fd00::/8.
ULA_LOCAL = ipaddress.IPv6Network("fd00::/8")
#: RFC 4193: every unique local address, fc00::/7.
ULA = ipaddress.IPv6Network("fc00::/7")


def generate_ula_prefix() -> ipaddress.IPv6Network:
    """A ULA /48 with a 40-bit random global ID (RFC 4193 3.2), from the
    OS's CSPRNG -- not the RFC's SHA-1 of a timestamp and an EUI-64, which
    is only a way to get random bits without a good generator."""
    global_id = secrets.randbits(40) or 1  # never fd00::/48, the one everyone would pick
    return ipaddress.IPv6Network(((0xfd << 120) | (global_id << 80), 48))


def _read_ula_state(state_path: Path | None = None) -> dict:
    state_path = state_path or paths.IPV6_ULA_STATE_PATH
    try:
        data = json.loads(state_path.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_ula_state(state: dict, state_path: Path | None = None) -> None:
    state_path = state_path or paths.IPV6_ULA_STATE_PATH
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_name(f".{state_path.name}.tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True) + "\n")
    tmp.chmod(0o644)
    tmp.replace(state_path)


def _valid_ula(value) -> ipaddress.IPv6Network | None:
    try:
        network = ipaddress.IPv6Network(value)
    except (TypeError, ValueError):
        return None
    return network if network.prefixlen == 48 and network.subnet_of(ULA_LOCAL) else None


def ula_prefix(config: Config, state_path: Path | None = None) -> ipaddress.IPv6Network | None:
    """The ULA /48 of the LAN's stable networks: `ipv6.ula_prefix`, or
    the one the router generated (None until an apply generated it)."""
    if config.ipv6.ula_prefix:
        return ipaddress.IPv6Network(config.ipv6.ula_prefix)
    return _valid_ula(_read_ula_state(state_path).get("generated"))


def ensure_ula_prefix(config: Config, state_path: Path | None = None) -> ipaddress.IPv6Network:
    """ula_prefix(), generating and keeping one the first time. The
    generated one is kept even while `ipv6.ula_prefix` overrides it, so
    taking the override out doesn't renumber the LAN again."""
    state = _read_ula_state(state_path)
    if _valid_ula(state.get("generated")) is None:
        state["generated"] = str(generate_ula_prefix())
        _write_ula_state(state, state_path)
    return ula_prefix(config, state_path)


def ula_addresses(config: Config, prefix: ipaddress.IPv6Network | None) -> list[tuple[str, str, str]]:
    """(zone, device, "<network>::1/64") for every LAN device: its /64 of
    the ULA /48 at the same position ("sla_id") as in the provider's
    prefix. Empty without a prefix."""
    if prefix is None:
        return []
    out = []
    for sla, (zone, device) in enumerate(lan_devices(config)):
        network = ipaddress.IPv6Network((int(prefix.network_address) | (sla << 64), 64))
        out.append((zone, device, f"{network.network_address + 1}/64"))
    return out


def _run_ip(args: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["ip", "-6", *args], capture_output=True, text=True, timeout=10)
    except FileNotFoundError as exc:
        raise Ipv6Error("'ip' binary not found; install the iproute2 package") from exc


#: iproute2's answers when there is nothing to take off: no such address
#: on the device, no such device.
_GONE = ("Cannot assign requested address", "Cannot find device")


def _set_ula_addresses(wanted: list[tuple[str, str]], before: list[tuple[str, str]]) -> None:
    """Take off the ULA addresses an earlier apply put on and this one
    doesn't want (gone already is fine: a device unplugged), then put on
    the wanted ones. Security-lessons F1: every value validated, the
    device always after `dev` (iproute2 takes what follows it as the
    name, never as an option)."""
    for device, address in before:
        if (device, address) in wanted:
            continue
        device, address = validate.ifname(device), str(ipaddress.IPv6Interface(address))
        proc = _run_ip(["addr", "del", address, "dev", device])
        if proc.returncode != 0 and not any(gone in proc.stderr for gone in _GONE):
            raise Ipv6Error(f"cannot take {address} off {device}: {proc.stderr.strip()}")
    for device, address in wanted:
        device, address = validate.ifname(device), str(ipaddress.IPv6Interface(address))
        proc = _run_ip(["addr", "replace", address, "dev", device, "nodad"])
        if proc.returncode != 0:
            raise Ipv6Error(f"cannot put {address} on {device}: {proc.stderr.strip()}")


def _applied(state: dict) -> list[tuple[str, str]]:
    pairs = []
    for item in state.get("addresses") or []:
        if not (isinstance(item, list) and len(item) == 2 and all(isinstance(v, str) for v in item)):
            continue
        try:
            validate.ifname(item[0])
            if ipaddress.IPv6Interface(item[1]).ip in ULA:
                pairs.append((item[0], item[1]))
        except (validate.ArgumentError, ValueError):
            continue
    return pairs


def sync_ula(config: Config, *, state_path: Path | None = None) -> list[tuple[str, str, str]]:
    """Put the LAN devices' ULA addresses on, take the stale ones off, and
    record what is on (the IPv6 step of an apply, after dhcpcd)."""
    lan = lan_devices(config)
    prefix = ensure_ula_prefix(config, state_path) if lan else ula_prefix(config, state_path)
    addresses = ula_addresses(config, prefix) if lan else []
    state = _read_ula_state(state_path)
    wanted = [(device, address) for _, device, address in addresses]
    _set_ula_addresses(wanted, _applied(state))
    state["addresses"] = [list(pair) for pair in wanted]
    _write_ula_state(state, state_path)
    return addresses


@dataclass(frozen=True)
class UlaState:
    """The ULA addresses an apply's IPv6 step may change, as they were:
    on undo the step's own additions come off and its removals go back
    (frfw.provision)."""

    text: str | None

    @classmethod
    def capture(cls, state_path: Path | None = None) -> "UlaState":
        try:
            return cls((state_path or paths.IPV6_ULA_STATE_PATH).read_text())
        except OSError:
            return cls(None)

    def restore(self, state_path: Path | None = None) -> None:
        state_path = state_path or paths.IPV6_ULA_STATE_PATH
        before = _applied(json.loads(self.text)) if self.text else []
        _set_ula_addresses(before, _applied(_read_ula_state(state_path)))
        if self.text is None:
            state_path.unlink(missing_ok=True)
        else:
            state_path.write_text(self.text)


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
    for device in lan:
        # FND-1c: the router's ULA address stays when the link is set
        # down, as an IPv4 address does -- the kernel drops even static
        # IPv6 addresses then, and the webUI and SSH listen on it.
        settings[f"ipv6/conf/{device}/keep_addr_on_down"] = "1"
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
         proc_root: Path | None = None, ra_conf_path: Path | None = None,
         ula_state_path: Path | None = None) -> SyncResult:
    """Reconcile the kernel's IPv6 settings, dhcpcd, the LAN's ULA
    addresses and its RA instance with `config.ipv6` (an apply's step,
    frfw.provision)."""
    conf_path = conf_path or paths.IPV6_DHCPCD_CONF_PATH
    ra_conf_path = ra_conf_path or paths.IPV6_RA_CONF_PATH
    lan = lan_devices(config)
    if not config.ipv6.enabled:
        # Nothing to do -- not even a systemctl call -- unless an earlier
        # apply turned it on: tests and machines without dhcpcd apply too.
        if not (conf_path.exists() or ra_conf_path.exists() or _applied(_read_ula_state(ula_state_path))
                or service_active() or service_active(paths.IPV6_RA_SERVICE_NAME)):
            return SyncResult(False, "IPv6 off")
        if dry_run:
            return SyncResult(False, "Would turn IPv6 off (dry-run)")
        _require_root()
        _stop_ra(ra_conf_path)
        sync_ula(config, state_path=ula_state_path)
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
    ula = ensure_ula_prefix(config, ula_state_path) if lan else None
    ra_text = render_ra_conf(config, ula) if lan else None
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
    # FND-1c: the stable addresses, after dhcpcd (which takes off only
    # what it put on) and before the RA instance advertises them.
    stable = sync_ula(config, state_path=ula_state_path)
    if stable:
        where += "; stable addresses " + ", ".join(f"{device} {address}" for _, device, address in stable)
    if ra_text is None:
        _stop_ra(ra_conf_path)
    else:
        ra_changed = not ra_conf_path.exists() or ra_conf_path.read_text() != ra_text
        if ra_changed:
            ra_conf_path.write_text(ra_text)
            # fr-ra's dynamic account reads it; it holds device names only.
            ra_conf_path.chmod(0o644)
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
    #: The ULA /48 of the stable networks (FND-1c), "" before one exists.
    ula_prefix: str = ""
    #: (zone, device, the router's ULA address/64) on each LAN device that
    #: has it now.
    ula: list[tuple[str, str, str]] = field(default_factory=list)
    #: (name, zone, "tcp 443", [the addresses it opens now]) per pinhole:
    #: an interface identifier in every network its zone has now.
    pinholes: list[tuple[str, str, str, list[str]]] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.state == OFF:
            return "IPv6 is off."
        if self.state == NO_KERNEL:
            return "This router's kernel runs without IPv6."
        return self._provider_summary() + self._stable_summary()

    def _stable_summary(self) -> str:
        """FND-1c: the LAN's own networks, whatever the provider gives."""
        if not self.ula:
            return ""
        return (f" The LAN's stable networks come from {self.ula_prefix} (ULA, never routed to the internet): "
                "the router answers there whatever the provider gives.")

    def _provider_summary(self) -> str:
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
                "excluded": [list(e) for e in self.excluded], "ula_prefix": self.ula_prefix,
                "ula": [list(u) for u in self.ula],
                "pinholes": [[name, zone, what, None if targets is None else list(targets)]
                             for name, zone, what, targets in self.pinholes]}


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
    ula = ula_prefix(config)
    result.ula_prefix = str(ula) if ula and lan else ""
    stable = {(device, address) for _, device, address in ula_addresses(config, ula)}
    present: set[tuple[str, str]] = set()
    for link in ip_json("addr", "show"):
        device = link.get("ifname")
        for info in link.get("addr_info", []):
            if info.get("family") != "inet6" or info.get("scope") != "global":
                continue
            address = ipaddress.IPv6Interface(f"{info['local']}/{int(info['prefixlen'])}")
            if address.ip in ULA:
                # FND-1c: the router's own stable addresses, not the provider's.
                present.add((device, str(address)))
                continue
            if device in devices:
                # dhcpcd adds a DHCPv6 (IA_NA) address as a /128, a SLAAC
                # one with its prefix's length.
                source = "DHCPv6" if address.network.prefixlen == 128 else "SLAAC"
                result.addresses.append((device, str(address), source))
            elif any(device == d for _, d in lan) and address.network.prefixlen == 64:
                lan_network.setdefault(device, str(address.network))
    result.lan = [(zone, device, lan_network.get(device, "")) for zone, device in lan]
    result.ula = [(zone, device, address) for zone, device, address in ula_addresses(config, ula)
                  if (device, address) in present & stable]
    result.pinholes = pinhole_targets(config, result.lan)
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


def pinhole_targets(config: Config, lan: list[tuple[str, str, str]]
                    ) -> list[tuple[str, str, str, list[str] | None]]:
    """(name, zone, "tcp 443", addresses) per pinhole (FND-1c): an
    interface identifier in each network its zone has now (`lan`, from
    status()), a full address as it is -- None when the zone has no IPv6
    now, so the pinhole is off."""
    served = {zone for zone, _ in lan_devices(config)}
    out = []
    for pinhole in config.ipv6.pinholes:
        if pinhole.zone not in served:
            targets = None
        elif pinhole.is_suffix:
            suffix = int(ipaddress.IPv6Address(pinhole.host))
            targets = [str(ipaddress.IPv6Network(network).network_address + suffix)
                       for zone, _, network in lan if zone == pinhole.zone and network]
        else:
            targets = [pinhole.host]
        out.append((pinhole.name, pinhole.zone, f"{pinhole.proto.value} {pinhole.port}", targets))
    return out
