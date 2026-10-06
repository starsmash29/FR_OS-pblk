"""Network interface discovery, read straight from sysfs.

Deliberately avoids shelling out to `ip`/`ethtool`: everything needed
(MAC address, driver, link state, negotiated speed) is already exposed as
plain files under `/sys/class/net/<iface>/`, so reading it directly is
both dependency-free and trivially testable (point `sysfs_net` at a fake
directory tree in tests instead of the real `/sys`). The one exception
is first boot's WAN/LAN choice (`choose_wan_lan`, ROADMAP SEC-8), which
asks each port whether a DHCP server answers there.
"""

from __future__ import annotations

import ipaddress

import random
import socket
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from frfw import validate

DEFAULT_SYSFS_NET = Path("/sys/class/net")

#: Interface name prefixes that are virtual/software devices, never a real
#: WAN/LAN/OPT uplink -- excluded from detection results by default.
_IGNORED_EXACT = {"lo"}
_IGNORED_PREFIXES = (
    "veth",
    "docker",
    "br-",
    "virbr",
    "tun",
    "tap",
    "ifb",
    "bond",
    "wg",
)


@dataclass(frozen=True)
class DetectedInterface:
    name: str
    mac_address: str | None
    driver: str | None
    link_up: bool | None
    speed_mbps: int | None


def list_interfaces(
    sysfs_net: Path = DEFAULT_SYSFS_NET, *, include_virtual: bool = False
) -> list[DetectedInterface]:
    """List network interfaces found under `sysfs_net`, sorted by name."""
    if not sysfs_net.is_dir():
        return []

    interfaces = []
    for entry in sorted(sysfs_net.iterdir(), key=lambda p: p.name):
        if not include_virtual and _is_ignored(entry.name):
            continue
        interfaces.append(_read_interface(entry))
    return interfaces


def _is_ignored(name: str) -> bool:
    return name in _IGNORED_EXACT or name.startswith(_IGNORED_PREFIXES)


def _read_interface(iface_dir: Path) -> DetectedInterface:
    return DetectedInterface(
        name=iface_dir.name,
        mac_address=_read_text(iface_dir / "address"),
        driver=_read_driver(iface_dir),
        link_up=_read_carrier(iface_dir),
        speed_mbps=_read_speed(iface_dir),
    )


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _read_driver(iface_dir: Path) -> str | None:
    driver_link = iface_dir / "device" / "driver"
    # Path.resolve() does not raise for a non-existent target (it resolves
    # lexically), so an explicit existence check is needed first -- an ifb
    # or other driverless virtual interface has no "device" symlink at all.
    if not driver_link.exists():
        return None
    try:
        return driver_link.resolve().name
    except OSError:
        return None


def _read_carrier(iface_dir: Path) -> bool | None:
    raw = _read_text(iface_dir / "carrier")
    return None if raw is None else raw == "1"


def _read_speed(iface_dir: Path) -> int | None:
    raw = _read_text(iface_dir / "speed")
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    # The kernel reports -1 (or occasionally 0) when speed is unknown, e.g.
    # link down or a virtual device that doesn't negotiate a speed.
    return value if value > 0 else None


# --- WAN/LAN choice at first boot (ROADMAP SEC-8, review v0.2.0 R14) --------
#
# First boot used to make the first NIC the WAN and the second the LAN.
# Cabled the other way round, the router then served DHCP -- as the LAN's
# gateway -- onto the upstream network, and took its own
# address from whatever answered on the LAN. The upstream side is the one
# where a DHCP server already answers, and the LAN must never be a port
# that already has one: so first boot asks each port, before anything is
# configured on it.

_ETH_P_IP = 0x0800
_BOOTP_MAGIC = b"\x63\x82\x53\x63"
_DHCPDISCOVER, _DHCPOFFER = 1, 2


def _checksum(header: bytes) -> int:
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _discover_frame(mac: bytes, xid: int) -> bytes:
    """A broadcast DHCPDISCOVER from `mac`, Ethernet header included: the
    port has no address yet, so it goes out on a packet socket."""
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0, 0x8000,
                        bytes(4), bytes(4), bytes(4), bytes(4), mac.ljust(16, b"\0"), b"", b"")
    options = _BOOTP_MAGIC + bytes([53, 1, _DHCPDISCOVER, 55, 3, 1, 3, 6, 255])
    payload = bootp + options
    udp = struct.pack("!HHHH", 68, 67, 8 + len(payload), 0) + payload
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), random.randrange(65536), 0, 64, 17, 0,
                               bytes(4), b"\xff\xff\xff\xff"))
    ip[10:12] = struct.pack("!H", _checksum(bytes(ip)))
    return b"\xff" * 6 + mac + struct.pack("!H", _ETH_P_IP) + bytes(ip) + udp


def _offered_network(frame: bytes, xid: int) -> ipaddress.IPv4Network | None:
    """The network a DHCPOFFER answering our DISCOVER `xid` offers an
    address in -- the address and its subnet mask (option 1; a /24 when
    the server sends none) -- or None when `frame` is no such offer."""
    if len(frame) < 14 + 20 + 8 + 240 or frame[12:14] != struct.pack("!H", _ETH_P_IP):
        return None
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 17 or len(ip) < ihl + 8 + 240:
        return None
    udp = ip[ihl:]
    if struct.unpack("!H", udp[2:4])[0] != 68:
        return None
    bootp = udp[8:]
    if bootp[0] != 2 or struct.unpack("!I", bootp[4:8])[0] != xid or bootp[236:240] != _BOOTP_MAGIC:
        return None
    options, i = bootp[240:], 0
    is_offer, mask = False, "255.255.255.0"
    while i < len(options) and options[i] != 255:
        if options[i] == 0:
            i += 1
            continue
        if i + 1 >= len(options):
            return None
        code, length = options[i], options[i + 1]
        value = options[i + 2:i + 2 + length]
        if len(value) != length:
            return None
        if code == 53 and length == 1:
            is_offer = value[0] == _DHCPOFFER
        elif code == 1 and length == 4:
            mask = str(ipaddress.IPv4Address(value))
        i += 2 + length
    if not is_offer:
        return None
    try:
        return ipaddress.IPv4Network(f"{ipaddress.IPv4Address(bootp[16:20])}/{mask}", strict=False)
    except ValueError:  # a mask that isn't one
        return ipaddress.IPv4Network(f"{ipaddress.IPv4Address(bootp[16:20])}/24", strict=False)


def _is_offer(frame: bytes, xid: int) -> bool:
    """Whether `frame` is a DHCPOFFER answering our DISCOVER `xid`."""
    return _offered_network(frame, xid) is not None


def _bring_up(device: str, sysfs_net: Path, *, carrier_wait: float) -> None:
    """Set the port up (it may still be down this early in first boot)
    and give its link a moment to come up."""
    subprocess.run(["ip", "link", "set", "dev", device, "up"], capture_output=True, check=False)
    deadline = time.monotonic() + carrier_wait
    while time.monotonic() < deadline and _read_carrier(sysfs_net / device) is not True:
        time.sleep(0.2)


def dhcp_offer(
    device: str,
    *,
    timeout: float = 3.0,
    attempts: int = 3,
    carrier_wait: float = 5.0,
    sysfs_net: Path = DEFAULT_SYSFS_NET,
) -> ipaddress.IPv4Network | None:
    """The network a DHCP server on `device` offers an address in, or None
    when none answers a DISCOVER -- sent and heard on a packet socket, so
    the port needs no address and nothing is configured on it; no REQUEST
    follows, so no lease is taken. Needs root (CAP_NET_RAW). Any failure
    counts as "no answer"."""
    device = validate.ifname(device)
    mac_text = _read_text(sysfs_net / device / "address") or ""
    try:
        mac = bytes.fromhex(mac_text.replace(":", ""))
    except ValueError:
        return None
    if len(mac) != 6:
        return None
    _bring_up(device, sysfs_net, carrier_wait=carrier_wait)
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_IP))
    except OSError:
        return None
    with sock:
        try:
            sock.bind((device, _ETH_P_IP))
            for _ in range(attempts):
                xid = random.getrandbits(32)
                sock.send(_discover_frame(mac, xid))
                deadline = time.monotonic() + timeout
                while (remaining := deadline - time.monotonic()) > 0:
                    sock.settimeout(remaining)
                    try:
                        frame = sock.recv(4096)
                    except socket.timeout:
                        break
                    if (offered := _offered_network(frame, xid)) is not None:
                        return offered
        except OSError:
            return None
    return None


def dhcp_server_answers(device: str, **kwargs) -> bool:
    """Whether a DHCP server answers a DISCOVER on `device` (`dhcp_offer`)."""
    return dhcp_offer(device, **kwargs) is not None


@dataclass(frozen=True)
class WanLanChoice:
    wan: str | None
    lan: str | None
    #: Why, in a sentence the console and the first-boot log show.
    basis: str
    #: The network the WAN's DHCP server offered an address in, when it
    #: did: the LAN must not overlap it (ROADMAP NET-12).
    wan_network: ipaddress.IPv4Network | None = None


def choose_wan_lan(
    interfaces: list[DetectedInterface], answers: Callable[[str], object]
) -> WanLanChoice:
    """Which port is the WAN and which the LAN, for first boot.

    - Exactly one port has a DHCP server answering: that one is the WAN
      (the upstream network hands out addresses); the LAN is another
      port, one with a link if there is one.
    - Several do: no choice. FR_OS serves DHCP on its LAN, and doing so
      on a network that already has a server is the mistake this exists
      to prevent; the admin assigns the ports.
    - None does (a static or PPPoE upstream, a modem still booting): the
      old order, first port WAN, second LAN -- said plainly, so the
      console tells the admin to check the cabling.

    `answers` says whether a DHCP server answers on a port: anything
    true, ideally the offered network (`dhcp_offer`), which the choice
    keeps for the WAN."""
    names = [iface.name for iface in interfaces]
    if len(names) < 2:
        return WanLanChoice(None, None, f"{len(names)} network port(s): nothing to choose")
    with ThreadPoolExecutor(max_workers=len(names)) as pool:
        answered = dict(zip(names, pool.map(answers, names)))
    offering = [name for name in names if answered[name]]
    if len(offering) == 1:
        wan = offering[0]
        others = [iface for iface in interfaces if iface.name != wan]
        lan = next((iface.name for iface in others if iface.link_up), others[0].name)
        offered = answered[wan] if isinstance(answered[wan], ipaddress.IPv4Network) else None
        return WanLanChoice(wan, lan, f"a DHCP server answered on {wan} only", offered)
    if offering:
        return WanLanChoice(None, None, f"DHCP servers answered on {', '.join(offering)}: "
                                        "not putting the LAN where one already runs")
    return WanLanChoice(names[0], names[1],
                        "no DHCP server answered on any port: chosen by port order -- check the cabling")
