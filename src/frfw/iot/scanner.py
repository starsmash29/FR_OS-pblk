"""The IoT scan: inventory -> classify -> decide -> enforce -> record.

Runs unprivileged (as fr_os-webui, from `fr-iot-scan.timer` or the
webUI's "Scan now" button). It is the process that parses untrusted
network data (mDNS responses, DHCP-supplied hostnames), which is exactly
why it must not run as root; the two privileged steps go through the
apply-helper socket:

- `dhcp_leases`: Kea's lease file belongs to the `_kea` user;
- `iot_sync_isolation`: replacing the kernel `iot_isolated` set.

Order matters in one place: mDNS discovery runs *before* the ARP table
is read. A device answering the query had to ARP-resolve the router
first, and Linux records the requester of an ARP request in its own
neighbour table -- so devices with a static IP that only showed up via
mDNS are in /proc/net/arp by the time it's read.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from frfw import paths
from frfw.config import load_config
from frfw.config.schema import Config
from frfw.helper import client as helper_client
from frfw.helper.client import HelperError
from frfw.iot import mdns
from frfw.iot.arp import ARP_PATH, read_arp_table
from frfw.iot.classify import CATEGORY_IOT, Classification, Observation, classify
from frfw.iot.oui import OUI_CSV_PATH, load_vendor_db, normalize_mac, vendor_for


@dataclass
class ScanResult:
    devices: list[dict] = field(default_factory=list)
    isolated: list[str] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)


def _iot_interfaces(config: Config):
    return [i for i in config.interfaces.values() if i.zone in config.iot.zones]


def iot_networks(config: Config) -> list[tuple[str, ipaddress.IPv4Network]]:
    """(device name, subnet) for every IoT-zone interface with a static
    address -- the only interfaces a lease can be attributed to, and the
    only ones an mDNS query can be sent from."""
    result = []
    for iface in _iot_interfaces(config):
        if iface.address:
            result.append((iface.device, ipaddress.IPv4Interface(iface.address).network))
    return result


def gather_observations(
    config: Config,
    *,
    leases: list[dict],
    arp_entries,
    vendor_db: dict[str, str],
    mdns_results: dict[str, set[str]],
) -> list[Observation]:
    """Merge every source into one Observation per MAC, restricted to the
    configured IoT zones. Pure -- no I/O -- so it's tested directly."""
    zone_devices = {i.device for i in _iot_interfaces(config)}
    networks = iot_networks(config)

    def interface_for(ip: str) -> str | None:
        addr = ipaddress.IPv4Address(ip)
        for device, network in networks:
            if addr in network:
                return device
        return None

    merged: dict[str, dict] = {}
    for lease in leases:
        mac = normalize_mac(lease.get("mac", ""))
        ip = lease.get("ip")
        if mac is None or not isinstance(ip, str):
            continue
        try:
            device = interface_for(ip)
        except ValueError:
            continue
        if device is None:
            continue
        merged[mac] = {"ip": ip, "hostname": str(lease.get("hostname") or ""), "interface": device}

    for entry in arp_entries:
        if entry.device not in zone_devices:
            continue
        record = merged.setdefault(entry.mac, {"ip": entry.ip, "hostname": "", "interface": entry.device})
        record.setdefault("ip", entry.ip)

    observations = []
    for mac, rec in sorted(merged.items()):
        services = tuple(sorted(mdns_results.get(rec.get("ip") or "", set())))
        observations.append(
            Observation(
                mac=mac,
                ip=rec.get("ip"),
                hostname=rec.get("hostname", ""),
                interface=rec.get("interface", ""),
                vendor=vendor_for(mac, vendor_db),
                services=services,
            )
        )
    return observations


def decide_isolation(config: Config, classified: list[tuple[Observation, Classification]]) -> list[str]:
    """Which MACs end up in the kernel set: every `iot.isolated_macs`
    entry, plus (only with `auto_isolate`) every device classified "iot",
    minus anything in `iot.trusted_macs` -- trusted always wins."""
    trusted = set(config.iot.trusted_macs)
    isolated = set(config.iot.isolated_macs)
    if config.iot.auto_isolate:
        isolated |= {obs.mac for obs, cls in classified if cls.category == CATEGORY_IOT}
    return sorted(isolated - trusted)


def _device_record(obs: Observation, cls: Classification, config: Config, isolated: set[str]) -> dict:
    record = asdict(obs)
    record["services"] = list(obs.services)
    record.update(
        category=cls.category,
        score=cls.score,
        reasons=list(cls.reasons),
        isolated=obs.mac in isolated,
        trusted=obs.mac in config.iot.trusted_macs,
    )
    return record


def _write_state(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
    tmp.replace(path)


def load_inventory(path: Path = paths.IOT_INVENTORY_PATH) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def run_scan(
    config: Config,
    *,
    leases_fn: Callable[[], dict] = helper_client.dhcp_leases,
    sync_fn: Callable[[list[str]], dict] = helper_client.iot_sync_isolation,
    mdns_fn: Callable[..., dict[str, set[str]]] = mdns.discover,
    arp_path: Path = ARP_PATH,
    oui_path: Path = OUI_CSV_PATH,
    state_path: Path = paths.IOT_INVENTORY_PATH,
    now: float | None = None,
) -> ScanResult:
    result = ScanResult()
    if not config.iot.enabled:
        result.messages.append("IoT discovery is disabled (iot.enabled: false)")
        return result

    leases: list[dict] = []
    try:
        response = leases_fn()
        if response.get("ok"):
            leases = list(response.get("leases") or [])
        else:
            result.messages.append(f"warning: DHCP leases unavailable: {response.get('message')}")
    except HelperError as exc:
        result.messages.append(f"warning: DHCP leases unavailable: {exc}")

    addresses = [str(ipaddress.IPv4Interface(i.address).ip) for i in _iot_interfaces(config) if i.address]
    mdns_results: dict[str, set[str]] = {}
    if addresses:
        try:
            mdns_results = mdns_fn(addresses)
        except mdns.MdnsError as exc:
            result.messages.append(f"warning: mDNS discovery skipped: {exc}")
    else:
        result.messages.append(
            "warning: no IoT-zone interface has a static address; mDNS discovery skipped"
        )

    arp_entries = read_arp_table(arp_path)
    vendor_db = load_vendor_db(oui_path)
    if not vendor_db:
        result.messages.append(
            f"note: no OUI vendor database at {oui_path} (install the 'ieee-data' package)"
        )

    observations = gather_observations(
        config, leases=leases, arp_entries=arp_entries, vendor_db=vendor_db, mdns_results=mdns_results
    )
    known_ips = {o.ip for o in observations}
    orphans = sorted(ip for ip in mdns_results if ip not in known_ips)
    if orphans:
        result.messages.append(
            f"note: {len(orphans)} mDNS responder(s) with no known MAC, not enforceable: {orphans}"
        )

    classified = [(obs, classify(obs)) for obs in observations]
    wanted = decide_isolation(config, classified)

    isolated = wanted
    try:
        response = sync_fn(wanted)
        if response.get("ok"):
            isolated = list(response.get("isolated") or [])
            result.messages.append(f"{len(isolated)} device(s) isolated ({config.iot.isolation_mode.value})")
        else:
            result.messages.append(f"error: isolation not applied: {response.get('message')}")
            isolated = []
    except HelperError as exc:
        result.messages.append(f"error: isolation not applied: {exc}")
        isolated = []

    isolated_set = set(isolated)
    result.devices = [_device_record(o, c, config, isolated_set) for o, c in classified]
    result.isolated = isolated
    counts: dict[str, int] = {}
    for d in result.devices:
        counts[d["category"]] = counts.get(d["category"], 0) + 1
    if result.devices:
        summary = ", ".join(f"{n} {cat}" for cat, n in sorted(counts.items()))
        result.messages.insert(0, f"{len(result.devices)} device(s) found: {summary}")
    else:
        result.messages.insert(0, "0 device(s) found in the IoT zones")

    _write_state(
        state_path,
        {
            "scanned_at": int(time.time() if now is None else now),
            "auto_isolate": config.iot.auto_isolate,
            "isolation_mode": config.iot.isolation_mode.value,
            "devices": result.devices,
            "isolated": result.isolated,
            "messages": result.messages,
        },
    )
    return result


def resync_from_inventory(
    config: Config,
    inventory: dict | None,
    *,
    sync_fn: Callable[[list[str]], dict] = helper_client.iot_sync_isolation,
) -> dict:
    """Re-apply the isolation decision to the last scan's classifications
    without rescanning -- used right after an admin trusts/isolates a
    device in the webUI, so the change takes effect immediately instead
    of at the next timer run."""
    classified = []
    for d in (inventory or {}).get("devices", []):
        mac = normalize_mac(d.get("mac", ""))
        if mac is None:
            continue
        classified.append(
            (Observation(mac=mac), Classification(category=str(d.get("category")), score=0))
        )
    return sync_fn(decide_isolation(config, classified))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fr-iot-scan", description="Scan the IoT zones once.")
    parser.add_argument("--config", default=str(paths.CONFIG_PATH))
    parser.add_argument("--state", default=str(paths.IOT_INVENTORY_PATH))
    args = parser.parse_args(argv)

    config = load_config(args.config)
    result = run_scan(config, state_path=Path(args.state))
    for message in result.messages:
        print(message)
    return 1 if any(m.startswith("error:") for m in result.messages) else 0


if __name__ == "__main__":
    sys.exit(main())
