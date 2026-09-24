"""Active DHCPv4 leases from Kea's memfile lease database.

frfw.kea configures `"lease-database": {"type": "memfile"}`, which Kea
writes as an append-only CSV (Debian path `/var/lib/kea/kea-leases4.csv`,
header `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,
fqdn_fwd,fqdn_rev,hostname,state,user_context[,pool_id]`). Append-only
means a renewed lease shows up as a *new* row for the same address, so
the last row wins; `state` 0 is a live lease (1 = declined, 2 =
expired-reclaimed). Columns are looked up by header name, so a Kea
version adding trailing columns (pool_id arrived in 2.4) doesn't matter.

Only read by the privileged apply-helper's `dhcp_leases` command --
Kea's state directory belongs to the `_kea` user, not to frfw's
unprivileged webUI/scanner account.
"""

from __future__ import annotations

import csv
import ipaddress
import time
from dataclasses import dataclass
from pathlib import Path

from frfw.iot.oui import normalize_mac

KEA_LEASES_PATH = Path("/var/lib/kea/kea-leases4.csv")

_MAX_HOSTNAME = 253


@dataclass(frozen=True)
class Lease:
    ip: str
    mac: str
    hostname: str
    expire: int


def _clean_hostname(raw: str) -> str:
    # Option 12 comes straight from the client -- untrusted. Kea escapes
    # a literal comma as "&#x2c"; keep only printable ASCII and cap the
    # length so it's safe to show in the webUI and log.
    raw = raw.replace("&#x2c", ",").strip().rstrip(".")
    cleaned = "".join(ch for ch in raw if 32 < ord(ch) < 127)
    return cleaned[:_MAX_HOSTNAME]


def read_leases(path: Path = KEA_LEASES_PATH, *, now: float | None = None) -> list[Lease]:
    """Currently valid leases, one per address. A missing file just means
    no DHCP server has handed anything out yet -- not an error."""
    now = time.time() if now is None else now
    try:
        f = path.open(newline="", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return []
    by_address: dict[str, Lease | None] = {}
    with f:
        for row in csv.DictReader(f):
            address = (row.get("address") or "").strip()
            try:
                ipaddress.IPv4Address(address)
            except ValueError:
                continue
            mac = normalize_mac(row.get("hwaddr") or "")
            try:
                expire = int(row.get("expire") or 0)
                state = int(row.get("state") or 0)
            except ValueError:
                continue
            if mac is None or state != 0 or expire <= now:
                by_address[address] = None  # a later row can retire an earlier one
                continue
            by_address[address] = Lease(
                ip=address, mac=mac, hostname=_clean_hostname(row.get("hostname") or ""), expire=expire
            )
    return sorted((lease for lease in by_address.values() if lease), key=lambda l: l.ip)
