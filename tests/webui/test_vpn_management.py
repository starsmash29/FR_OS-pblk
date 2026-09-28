"""Security-lessons K5: manage the router from outside through the
WireGuard VPN, not by opening the webUI and SSH to the internet.

- the tunnel's zone is a management zone by default (it doesn't face the
  internet), so the firewall doesn't drop the webUI/SSH from it;
- the webUI and sshd listen on the router's tunnel address too;
- the System screen points to the VPN, and says so plainly when the WAN
  is opened while the VPN is already on.
"""

from __future__ import annotations

import pytest
import yaml
from fastapi.testclient import TestClient

from frfw import management
from frfw.admin_account import ROLE_ADMIN
from frfw.config import parse_config
from frfw.nft import build_ruleset


def _config(wg_enabled=True, **management_section) -> dict:
    return {
        "version": 1, "hostname": "router",
        "zones": {"wan": {}, "lan": {}, "vpn": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"},
                       "lan": {"device": "eth1", "zone": "lan", "address": "192.168.1.1/24"}},
        "rules": [], "nat": {"masquerade": [{"out_zone": "wan"}]},
        "wireguard": {"enabled": wg_enabled, "address": "10.99.0.1/24"},
        "management": management_section,
    }


def test_management_listens_on_the_tunnel_address():
    config = parse_config(_config())
    assert management.listen_addresses(config) == ["127.0.0.1", "192.168.1.1", "10.99.0.1"]
    assert "ListenAddress 10.99.0.1" in management.sshd_dropin(config)


def test_the_vpn_zone_is_not_blocked_from_management():
    config = parse_config(_config())
    assert management.blocked_zones(config) == ["wan"]
    ruleset = build_ruleset(config)
    assert "no-management-from-wan" in ruleset and "no-management-from-vpn" not in ruleset


def test_nothing_on_the_tunnel_while_it_is_off():
    assert "10.99.0.1" not in management.listen_addresses(parse_config(_config(wg_enabled=False)))


def test_an_admin_can_keep_the_vpn_out_of_management():
    config = parse_config(_config(zones=["lan"]))
    assert "10.99.0.1" not in management.listen_addresses(config)
    assert "no-management-from-vpn" in build_ruleset(config)


@pytest.fixture
def system_page(webui_env):
    webui_env["admin_store"].set_password("boss", "orchid-lamp-7", ROLE_ADMIN)
    from frfw.webui.app import create_app

    def page(**raw_overrides) -> str:
        webui_env["config_path"].write_text(yaml.safe_dump({**_config(), **raw_overrides}))
        client = TestClient(create_app(**webui_env), follow_redirects=False)
        client.post("/login", data={"username": "boss", "password": "orchid-lamp-7"})
        return client.get("/system").text

    return page


def test_the_system_screen_points_to_the_vpn(system_page):
    off = system_page(wireguard={"enabled": False, "address": "10.99.0.1/24"})
    assert 'turn on the <a href="/vpn">VPN</a>' in off
    on = system_page()
    assert 'through the <a href="/vpn">VPN</a>' in on and "10.99.0.1" in on
    both = system_page(management={"allow_wan": True})
    assert "There is no need to open them to the" in both
    assert "Use the WireGuard VPN (VPN screen)" in both
