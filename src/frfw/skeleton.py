"""Generates a minimal, valid frfw config from a WAN/LAN/OPT role assignment.

This is the non-interactive engine behind `firewall-cli assign-interfaces`
(the pfSense-style "which NIC is WAN, which is LAN" install step). A real
interactive wizard / webUI form (phase 3) can build on the same function.
"""

from __future__ import annotations

import ipaddress

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

#: Out-of-the-box LAN: the router at .1, DHCP for .100-.199, so a laptop
#: plugged in gets an address and can open the webUI without any manual
#: step. Not 192.168.0.x/1.x or the other ranges home routers and ISP
#: boxes hand out (ROADMAP NET-12): FR_OS's WAN is usually such a box's
#: LAN, and a LAN in the same range as the WAN leaves the router unable to
#: tell the two apart -- found on a real Telekom line, whose router is
#: 192.168.1.1.
DEFAULT_LAN_ADDRESS = "10.73.1.1/24"
#: Where the LAN goes when the upstream network overlaps the default, in
#: order: three different private blocks, so a WAN in any one of them (a
#: whole 10.0.0.0/8 included) leaves another (`lan_address_avoiding`).
LAN_ADDRESS_CHOICES = ("10.73.1.1/24", "172.29.73.1/24", "192.168.173.1/24")
#: The router runs no resolver until DNS filtering is turned on, so hand
#: out public resolvers; the Ad-Block screen switches clients to the
#: router's own when enabled.
DEFAULT_LAN_DNS = ["1.1.1.1", "9.9.9.9"]


def lan_address_avoiding(networks) -> str:
    """The first of LAN_ADDRESS_CHOICES whose network overlaps none of
    `networks` (the upstream networks first boot saw offered)."""
    for choice in LAN_ADDRESS_CHOICES:
        lan = ipaddress.IPv4Interface(choice).network
        if not any(lan.overlaps(net) for net in networks):
            return choice
    raise ValueError("every LAN address choice overlaps the upstream network")


def _dhcp_pool(lan_address: str) -> dict | None:
    """.100-.199 of a /24 LAN, for the LAN's DHCP server; None for any
    other prefix, which gets the address alone."""
    lan = ipaddress.IPv4Interface(lan_address)
    if lan.network.prefixlen != 24:
        return None
    base = lan.network.network_address
    return {"range_start": str(base + 100), "range_end": str(base + 199), "dns_servers": list(DEFAULT_LAN_DNS)}


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

    With `lan_address` (default DEFAULT_LAN_ADDRESS) the LAN also gets
    that static address and a DHCP pool in its .100-.199 range (only for a
    /24, the common case; any other prefix gets the address alone).
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
        pool = _dhcp_pool(lan_address)
        if pool:
            dhcp["lan"] = pool
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
    if lan_address:
        # ROADMAP SEC-27: where the webUI and SSH listen is the admin's
        # choice from the start, not a side effect of the LAN's address.
        config["management"] = {"addresses": [str(ipaddress.IPv4Interface(lan_address).ip)]}
    # Security-lessons K4: IoT isolation on from the start. Devices the
    # scanner classifies as IoT reach the internet but not the rest of
    # the LAN or the router's management; the IoT Devices screen trusts
    # one back with a click.
    config["iot"] = {"enabled": True, "zones": ["lan"], "auto_isolate": True, "isolation_mode": "internet_only"}
    return yaml.safe_dump(config, sort_keys=False, default_flow_style=False)
