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
        # The webUI (HTTPS). Without it a freshly booted router drops the
        # admin's browser on its own LAN (input policy is drop) -- found by
        # booting the ISO for real.
        "name": "webui-from-lan",
        "action": "accept",
        "from_zone": "lan",
        "to_zone": "self",
        "proto": "tcp",
        "dst_port": 443,
    },
    {
        "name": "lan-to-wan",
        "action": "accept",
        "from_zone": "lan",
        "to_zone": "wan",
    },
]

#: Out-of-the-box LAN: the router at .1, DHCP for .100-.199 (the common
#: home-router layout, so a laptop plugged in gets an address and can
#: open https://192.168.1.1/ without any manual step).
DEFAULT_LAN_ADDRESS = "192.168.1.1/24"
DEFAULT_LAN_DHCP = {
    "range_start": "192.168.1.100",
    "range_end": "192.168.1.199",
    # The router runs no resolver until DNS filtering is turned on, so
    # hand out public resolvers; the Ad-Block screen switches clients to
    # the router's own when enabled.
    "dns_servers": ["1.1.1.1", "9.9.9.9"],
}


def build_skeleton_config(
    wan_device: str,
    lan_device: str,
    opt_devices: dict[str, str] | None = None,
    *,
    hostname: str = "fr-router",
    lan_address: str | None = DEFAULT_LAN_ADDRESS,
) -> str:
    """Return YAML text for a minimal config assigning `wan_device` to the
    `wan` zone, `lan_device` to `lan`, and each `opt_devices` entry to a
    same-named zone. LAN<->OPT traffic is not pre-authorized; add rules
    for it explicitly once the OPT zone's purpose is decided.

    With `lan_address` (default 192.168.1.1/24) the LAN also gets that
    static address and a DHCP pool in its .100-.199 range (only for a /24
    as it is, the common case; any other prefix gets the address alone).
    The WAN is left to DHCP from the upstream network.
    """
    opt_devices = opt_devices or {}

    interfaces = {
        "wan": {"device": wan_device, "zone": "wan"},
        "lan": {"device": lan_device, "zone": "lan"},
    }
    dhcp = {}
    if lan_address:
        interfaces["lan"]["address"] = lan_address
        if lan_address == DEFAULT_LAN_ADDRESS:
            dhcp["lan"] = dict(DEFAULT_LAN_DHCP)
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
    if dhcp:
        config["dhcp"] = dhcp
    return yaml.safe_dump(config, sort_keys=False, default_flow_style=False)
