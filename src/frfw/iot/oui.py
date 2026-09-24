"""MAC address -> hardware vendor lookup, from the IEEE's own MA-L
(24-bit OUI) registry as shipped by Debian's `ieee-data` package
(`/usr/share/ieee-data/oui.csv`, columns `Registry,Assignment,
Organization Name,Organization Address`, confirmed against the real
file). Nothing is bundled into this project: the registry is ~3 MB and
updated by the distribution, not by us. If the package isn't installed
the lookup simply returns no vendor and classification leans on the
other signals.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

OUI_CSV_PATH = Path("/usr/share/ieee-data/oui.csv")

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def normalize_mac(mac: str) -> str | None:
    """`AA-BB-CC-DD-EE-FF` / `aa:bb:...` -> `aa:bb:cc:dd:ee:ff`, or None
    if it isn't a MAC address at all."""
    if not isinstance(mac, str):
        return None
    mac = mac.strip().lower().replace("-", ":")
    return mac if _MAC_RE.match(mac) else None


def is_locally_administered(mac: str) -> bool:
    """Bit 1 of the first octet: set on randomized/"private" addresses
    (modern phones and laptops per Wi-Fi network), and on virtual NICs --
    almost never on an embedded IoT device's burned-in address."""
    return bool(int(mac[:2], 16) & 0x02)


def load_vendor_db(path: Path = OUI_CSV_PATH) -> dict[str, str]:
    """{"AABBCC": "Vendor Name"} for every MA-L assignment; {} if the
    file is missing or unreadable."""
    db: dict[str, str] = {}
    try:
        with path.open(newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.reader(f):
                if len(row) < 3 or row[0] != "MA-L":
                    continue
                prefix = row[1].strip().upper()
                if len(prefix) == 6:
                    db[prefix] = row[2].strip()
    except OSError:
        return {}
    return db


def vendor_for(mac: str, db: dict[str, str]) -> str | None:
    if is_locally_administered(mac):
        return None  # a randomized address carries no real vendor prefix
    return db.get(mac.replace(":", "")[:6].upper())
