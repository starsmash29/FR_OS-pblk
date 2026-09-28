"""Segmentation by default (security-lessons K4).

One flat LAN lets a compromised camera or a guest's laptop reach every
other device. `add_segments` gives a router its IoT and/or guest segment
in one step: each is a VLAN on the LAN port (802.1Q; the switch or access
point tags the IoT/guest SSIDs or ports), with its own subnet, DHCP and
zone, and rules that let it reach the internet and nothing else:

- **iot** (VLAN 30, 192.168.30.0/24): the devices are inventoried and
  isolated (IoT isolation, phase 14): internet only, never the LAN or
  the router's management;
- **guest** (VLAN 40, 192.168.40.0/24): internet only.

Neither becomes a management zone: `management.zones` is pinned to the
zones that manage the router now, before the new ones are added.

It edits the raw config dict; the caller validates and saves it.
"""

from __future__ import annotations

import ipaddress

from frfw.config.loader import internet_facing_zones
from frfw.config.schema import Config

SEGMENTS = {
    "iot": {"vlan": 30, "address": "192.168.30.1/24", "label": "IoT devices"},
    "guest": {"vlan": 40, "address": "192.168.40.1/24", "label": "Guests"},
}
PUBLIC_DNS = ["1.1.1.1", "9.9.9.9"]


class SegmentError(Exception):
    pass


def lan_device(raw: dict) -> str:
    lan = (raw.get("interfaces") or {}).get("lan")
    if not isinstance(lan, dict) or not lan.get("device"):
        raise SegmentError("No 'lan' interface to put the segments on")
    return str(lan["device"])


def add_segments(raw: dict, config: Config, names: list[str]) -> list[str]:
    """Add the chosen segments (`iot`, `guest`) to `raw`; returns what was
    added. Segments that already exist are left as they are."""
    parent = lan_device(raw)
    zones = raw.setdefault("zones", {})
    interfaces = raw.setdefault("interfaces", {})
    rules = raw.setdefault("rules", [])
    rule_names = {r.get("name") for r in rules if isinstance(r, dict)}
    wan = sorted(internet_facing_zones(config.zones, config.nat))
    added = []
    for name in names:
        spec = SEGMENTS.get(name)
        if spec is None:
            raise SegmentError(f"unknown segment {name!r}")
        if name in zones or name in interfaces:
            continue
        net = ipaddress.IPv4Interface(spec["address"]).network
        for other in config.interfaces.values():
            if other.address and ipaddress.IPv4Interface(other.address).network.overlaps(net):
                raise SegmentError(f"{net} is already used by interface {other.name!r}")
        management = raw.setdefault("management", {})
        if not management.get("zones") and not management.get("allow_wan"):
            # Pin management to today's zones: the new segment isn't one.
            from frfw import management as management_mod

            management["zones"] = management_mod.management_zones(config)
        device = f"{parent}.{spec['vlan']}"
        zones[name] = {"description": spec["label"]}
        interfaces[name] = {"device": device, "zone": name, "address": spec["address"],
                            "vlan": {"parent": parent, "id": spec["vlan"]}}
        hosts = list(net.hosts())
        raw.setdefault("dhcp", {})[name] = {"range_start": str(hosts[99]), "range_end": str(hosts[198]),
                                           "dns_servers": list(PUBLIC_DNS)}
        for out in wan:
            rule = f"{name}-to-{out}"
            if rule not in rule_names:
                rules.append({"name": rule, "action": "accept", "from_zone": name, "to_zone": out})
        if name == "iot":
            iot = raw.setdefault("iot", {})
            iot["enabled"] = True
            iot["zones"] = sorted(set(iot.get("zones") or []) | {"iot"})
            iot.setdefault("auto_isolate", True)
            iot.setdefault("isolation_mode", "internet_only")
        added.append(name)
    return added
