"""Network interface discovery, read straight from sysfs.

Deliberately avoids shelling out to `ip`/`ethtool`: everything needed
(MAC address, driver, link state, negotiated speed) is already exposed as
plain files under `/sys/class/net/<iface>/`, so reading it directly is
both dependency-free and trivially testable (point `sysfs_net` at a fake
directory tree in tests instead of the real `/sys`).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

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
