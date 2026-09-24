"""Generates a minimal, valid frfw config from a WAN/LAN/OPT role assignment.

This is the non-interactive engine behind `firewall-cli assign-interfaces`
(the pfSense-style "which NIC is WAN, which is LAN" install step). A real
interactive wizard / webUI form (phase 3) can build on the same function.
"""

from __future__ import annotations

import yaml

#: Rules and NAT every skeleton config ships with: SSH access to the
#: router from the LAN, LAN can reach the internet, and outbound NAT on
#: the WAN interface. Deliberately minimal and safe-by-default -- nothing
#: is exposed from WAN. Adjust further via the config file or, later, the
#: webUI.
_BASE_RULES = [
    {
        "name": "allow-mgmt-from-lan",
        "action": "accept",
        "from_zone": "lan",
        "to_zone": "self",
        "proto": "tcp",
        "dst_port": 22,
    },
    {
        "name": "lan-to-wan",
        "action": "accept",
        "from_zone": "lan",
        "to_zone": "wan",
    },
]


def build_skeleton_config(
    wan_device: str,
    lan_device: str,
    opt_devices: dict[str, str] | None = None,
    *,
    hostname: str = "fr-router",
) -> str:
    """Return YAML text for a minimal config assigning `wan_device` to the
    `wan` zone, `lan_device` to `lan`, and each `opt_devices` entry to a
    same-named zone. LAN<->OPT traffic is not pre-authorized; add rules
    for it explicitly once the OPT zone's purpose is decided.
    """
    opt_devices = opt_devices or {}

    interfaces = {
        "wan": {"device": wan_device, "zone": "wan"},
        "lan": {"device": lan_device, "zone": "lan"},
    }
    zones = {"wan": {}, "lan": {}}
    rules = list(_BASE_RULES)

    for opt_name, opt_device in opt_devices.items():
        interfaces[opt_name] = {"device": opt_device, "zone": opt_name}
        zones[opt_name] = {}

    config = {
        "version": 1,
        "hostname": hostname,
        "interfaces": interfaces,
        "zones": zones,
        "rules": rules,
        "nat": {"masquerade": [{"out_zone": "wan"}]},
    }
    return yaml.safe_dump(config, sort_keys=False, default_flow_style=False)
