"""IPv6 on the WAN, for the router itself (ROADMAP FND-1a).

FR_OS was IPv4-only: the ruleset dropped every IPv6 packet, neighbour
discovery included, so the router had no IPv6 at all. With
`ipv6.enabled` it takes IPv6 from the provider on its internet-facing
interfaces (`wan_devices`):

- **dhcpcd** (`fr-dhcp6.service`, Debian's dhcpcd-base, IPv6 only, on
  those interfaces only) takes an address from the provider's Router
  Advertisement (SLAAC, RFC 7217 stable addresses: not derived from the
  MAC) and asks DHCPv6 for an address and a delegated prefix. The prefix
  is only recorded: dhcpcd installs an `unreachable` route for it and
  assigns it to no interface -- handing it to the LAN is FND-1b. dhcpcd
  runs no hook script (`script /bin/true`), so nothing the provider sends
  reaches the router's own files (resolv.conf, its hostname, NTP), and it
  sends no hostname. It drops to its own account itself (privilege
  separation) inside a systemd sandbox.
- **The kernel** takes no Router Advertisement on any interface
  (`accept_ra=0`: dhcpcd reads the WAN's itself; a LAN must never be
  configured by one), follows no redirect, and routes nothing over IPv6
  (`forwarding=0`).
- **The firewall** (frfw.nft.builder) accepts the ICMPv6 the WAN needs
  -- neighbour discovery and the provider's RA only with hop limit 255
  (RFC 4861: they never cross a router), the errors path MTU discovery
  needs, a rate-limited ping -- and DHCPv6 replies from a link-local
  address; every other IPv6 packet to the router is dropped, before any
  rule written for IPv4. Services on IPv6 come with FND-1c.

`status()` says what the provider gave and what that means: a delegated
prefix (the LAN can have IPv6, FND-1b), an address only (a single /64 on
the WAN: not enough for a LAN), or nothing. FR_OS is a community edition:
every outcome is a state to explain, never an error.

Off (the default), the ruleset drops all IPv6 to and through the router,
and an apply stops dhcpcd -- which takes its addresses and routes with it
-- if it was running.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from frfw import paths, svc, validate
from frfw.config.loader import internet_facing_zones
from frfw.config.schema import Config

#: The kernel's per-interface IPv6 settings.
PROC_IPV6 = Path("/proc/sys/net/ipv6")


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


_DHCPCD_TEMPLATE = """\
# Managed by FR_OS (frfw.ipv6) -- regenerated on every `apply`, do not edit.
# IPv6 on the WAN for the router itself (ROADMAP FND-1a): SLAAC from the
# provider's Router Advertisement, DHCPv6 for an address and a delegated
# prefix. The prefix is assigned to no interface yet (an unreachable
# route is installed for it); handing it to the LAN is FND-1b.
ipv6only
noipv4
noipv4ll
# Router solicitations on the WAN only (its block below), as dhcpcd.conf(5)
# advises when asking for a delegated prefix.
noipv6rs
# No hostname and no FQDN option: the router doesn't name itself to the
# provider.
fqdn disable
# No hook script: nothing the provider sends is written to the router's
# own files (resolv.conf, its hostname, NTP servers).
script /bin/true
# Stable addresses that don't carry the MAC (RFC 7217).
slaac private
allowinterfaces {devices}
{interfaces}"""


def render_dhcpcd_conf(config: Config) -> str:
    blocks = "".join(
        f"\ninterface {device}\n"
        "\tipv6rs\n"
        # Asking for these explicitly also makes dhcpcd start DHCPv6
        # when the provider's RA sets neither the M nor the O flag. The
        # prefix goes to no interface ("-"; with none named, dhcpcd would
        # give every other interface one), and dhcpcd installs a reject
        # route for it.
        f"\tia_na {n}\n"
        f"\tia_pd {n + 100} -\n"
        for n, device in enumerate(wan_devices(config), start=1)
    )
    return _DHCPCD_TEMPLATE.format(devices=" ".join(wan_devices(config)), interfaces=blocks)


def sysctl_settings(config: Config) -> dict[str, str]:
    """`conf/<device>/<key>` -> value, for every configured device (not
    VPN tunnels, which never carry an RA) and the defaults new ones get."""
    wan = set(wan_devices(config))
    settings: dict[str, str] = {"conf/all/forwarding": "0"}
    devices = sorted({validate.ifname(i.device) for i in config.interfaces.values()})
    for device in ["all", "default", *devices]:
        settings[f"conf/{device}/accept_ra"] = "0"
        settings[f"conf/{device}/accept_redirects"] = "0"
        settings[f"conf/{device}/accept_source_route"] = "0"
        if device not in wan:
            settings[f"conf/{device}/autoconf"] = "0"
    for device in wan:
        settings[f"conf/{device}/disable_ipv6"] = "0"
    return settings


def read_sysctls(keys, proc_root: Path | None = None) -> dict[str, str | None]:
    """The current values (None: no such device), to restore on undo."""
    proc_root = proc_root or PROC_IPV6
    out: dict[str, str | None] = {}
    for key in keys:
        try:
            out[key] = (proc_root / key).read_text().strip()
        except OSError:
            out[key] = None
    return out


def write_sysctls(settings: dict[str, str | None], proc_root: Path | None = None) -> None:
    """Write each value; a device that isn't there (yet) is skipped."""
    proc_root = proc_root or PROC_IPV6
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
            raise Ipv6Error(f"cannot set net.ipv6.{key.replace('/', '.')} = {value}: {exc}") from exc


def kernel_has_ipv6(proc_root: Path | None = None) -> bool:
    """False with `ipv6.disable=1` on the kernel command line."""
    return ((proc_root or PROC_IPV6) / "conf").is_dir()


#: Debian's dhcpcd-base.
DHCPCD_BINARY = "/usr/sbin/dhcpcd"


def check_available(proc_root: Path | None = None, dhcpcd_binary: str | None = None) -> None:
    """An apply's preflight (ROADMAP SEC-5): what turning IPv6 on needs."""
    dhcpcd_binary = dhcpcd_binary or DHCPCD_BINARY
    if not kernel_has_ipv6(proc_root):
        raise Ipv6Error("this kernel runs without IPv6 (ipv6.disable=1 on its command line)")
    if not Path(dhcpcd_binary).is_file():
        raise Ipv6Error(f"{dhcpcd_binary} is not installed (Debian's dhcpcd-base)")


@dataclass(frozen=True)
class SyncResult:
    active: bool
    message: str


def sync(config: Config, *, dry_run: bool = False, conf_path: Path | None = None,
         proc_root: Path | None = None) -> SyncResult:
    """Reconcile the kernel's IPv6 settings and dhcpcd with `config.ipv6`
    (an apply's step, frfw.provision)."""
    conf_path = conf_path or paths.IPV6_DHCPCD_CONF_PATH
    if not config.ipv6.enabled:
        # Nothing to do -- not even a systemctl call -- unless an earlier
        # apply turned it on: tests and machines without dhcpcd apply too.
        if not conf_path.exists() and not service_active():
            return SyncResult(False, "IPv6 off")
        if dry_run:
            return SyncResult(False, "Would turn IPv6 on the WAN off (dry-run)")
        _require_root()
        _systemctl("stop")
        conf_path.unlink(missing_ok=True)
        return SyncResult(False, "IPv6 on the WAN turned off")

    devices = wan_devices(config)
    if not kernel_has_ipv6(proc_root):
        raise Ipv6Error("this kernel runs without IPv6 (ipv6.disable=1 on its command line)")
    if dry_run:
        return SyncResult(True, f"Would take IPv6 from the provider on {', '.join(devices)} (dry-run)")
    _require_root()
    write_sysctls(sysctl_settings(config), proc_root)
    text = render_dhcpcd_conf(config)
    changed = not conf_path.exists() or conf_path.read_text() != text
    if changed:
        conf_path.parent.mkdir(parents=True, exist_ok=True)
        conf_path.write_text(text)
    # A restart drops the addresses and asks the provider again: only for
    # a new config, not on every apply.
    _systemctl("restart" if changed else "start")
    return SyncResult(True, f"IPv6 on the WAN: dhcpcd on {', '.join(devices)} (SLAAC, DHCPv6 address "
                            "and prefix delegation)")


def service_active() -> bool:
    try:
        proc = svc.systemctl("is-active", paths.IPV6_SERVICE_NAME, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return proc.stdout.strip() in ("active", "activating", "reloading")


def _systemctl(action: str) -> None:
    try:
        proc = svc.systemctl(action, paths.IPV6_SERVICE_NAME, timeout=60)
    except FileNotFoundError as exc:
        raise Ipv6Error("'systemctl' not found") from exc
    if proc.returncode != 0:
        raise Ipv6Error(f"systemctl {action} {paths.IPV6_SERVICE_NAME} failed: "
                        f"{(proc.stderr or proc.stdout).strip()} (see journalctl -u {paths.IPV6_SERVICE_NAME})")


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
        return (f"A prefix was delegated: {sizes}. The router has IPv6; handing it to the LAN is the next "
                "step (ROADMAP FND-1b).")

    def as_dict(self) -> dict:
        return {"state": self.state, "summary": self.summary, "devices": self.devices,
                "addresses": [list(a) for a in self.addresses],
                "default_routes": [list(r) for r in self.default_routes],
                "prefixes": self.prefixes, "service_active": self.service_active}


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
    addresses, its default route, and the unreachable routes dhcpcd
    installs for a delegated prefix it assigns nowhere."""
    ip_json = ip_json or _ip_json
    devices = wan_devices(config)
    if not config.ipv6.enabled:
        return Ipv6Status(OFF, devices)
    if not kernel_has_ipv6(proc_root):
        return Ipv6Status(NO_KERNEL, devices)
    result = Ipv6Status(NOTHING, devices, service_active=service_active())
    for link in ip_json("addr", "show"):
        device = link.get("ifname")
        if device not in devices:
            continue
        for info in link.get("addr_info", []):
            if info.get("family") != "inet6" or info.get("scope") != "global":
                continue
            address = ipaddress.IPv6Interface(f"{info['local']}/{int(info['prefixlen'])}")
            # dhcpcd adds a DHCPv6 (IA_NA) address as a /128, a SLAAC one
            # with its prefix's length.
            source = "DHCPv6" if address.network.prefixlen == 128 else "SLAAC"
            result.addresses.append((device, str(address), source))
    for route in ip_json("route", "show", "table", "main"):
        dst = route.get("dst")
        if dst == "default" and route.get("dev") in devices and route.get("gateway"):
            result.default_routes.append((route["dev"], str(ipaddress.IPv6Address(route["gateway"]))))
        elif route.get("type") == "unreachable" and route.get("protocol") == "dhcp" and dst:
            network = ipaddress.IPv6Network(dst)
            if network.prefixlen <= 64 and not (network.is_link_local or network.is_multicast or network.is_loopback):
                result.prefixes.append(str(network))
    if result.prefixes:
        result.state = PREFIX
    elif result.addresses:
        result.state = ADDRESS_ONLY
    return result
