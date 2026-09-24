"""The kernel's IPv4 neighbour table, `/proc/net/arp` -- world-readable
(no privilege needed, unlike conntrack), and the only inventory source
for devices with a static IP that never talk to the DHCP server."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from frfw.iot.oui import normalize_mac

ARP_PATH = Path("/proc/net/arp")

#: ATF_COM: the entry is resolved. Incomplete entries have flags 0x0 and
#: an all-zero hardware address.
_ATF_COM = 0x2


@dataclass(frozen=True)
class ArpEntry:
    ip: str
    mac: str
    device: str


def read_arp_table(path: Path = ARP_PATH) -> list[ArpEntry]:
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    entries: list[ArpEntry] = []
    for line in lines[1:]:  # header row
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, _hw_type, flags, hw_addr, _mask, device = parts[:6]
        try:
            if not int(flags, 16) & _ATF_COM:
                continue
        except ValueError:
            continue
        mac = normalize_mac(hw_addr)
        if mac is None or mac == "00:00:00:00:00:00":
            continue
        entries.append(ArpEntry(ip=ip, mac=mac, device=device))
    return entries
