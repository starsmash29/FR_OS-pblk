"""Security-lessons G8/K5: the VPN screen.

- turning the VPN on adds the zone and the rules that make it useful
  (webUI/SSH/LAN from the VPN) and is a security alert;
- a device with its own public key: only that key is stored;
- a device the router makes a key pair for: its configuration (with the
  private key) is shown once, as text and QR code, never stored, never
  cached, never in the audit log;
- a new device is a security alert; removing one is plain;
- viewers see the screen but change nothing.
"""

from __future__ import annotations

import base64

import pytest
import yaml
from fastapi.testclient import TestClient

from frfw import wireguard
from frfw.admin_account import ROLE_ADMIN, ROLE_VIEWER
from frfw.config import load_config
from frfw.webui import audit
from frfw.webui.app import create_app

GOOD = "orchid-lamp-7"
DEVICE_KEY = base64.b64encode(b"d" * 32).decode()


@pytest.fixture
def env(webui_env):
    webui_env["admin_store"].set_password("boss", GOOD, ROLE_ADMIN)
    webui_env["admin_store"].add_user("guest", "violet-anchor-9", ROLE_VIEWER)
    webui_env["config_path"].write_text(yaml.safe_dump({
        "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"},
                       "lan": {"device": "eth1", "zone": "lan", "address": "192.168.1.1/24"}},
        "rules": [], "nat": {"masquerade": [{"out_zone": "wan"}]},
    }))
    return webui_env


def _signed_in(env, username="boss", password=GOOD) -> TestClient:
    client = TestClient(create_app(**env), follow_redirects=False)
    assert client.post("/login", data={"username": username, "password": password}).headers["location"] == "/"
    return client


def _turn_on(client, **extra):
    return client.post("/vpn/settings", data={"enabled": "true", "address": "10.99.0.1/24", "listen_port": 51820,
                                              "endpoint": "vpn.example.net", **extra})


def _alerts(env) -> list[str]:
    return [e["alert"] for e in audit.read_recent(env["audit_log_path"]) if e.get("alert")]


def test_the_screen_is_in_the_sidebar(env):
    page = _signed_in(env).get("/vpn")
    assert page.status_code == 200 and 'href="/vpn"' in page.text and "VPN (WireGuard)" in page.text


def test_turning_it_on_makes_it_useful(env):
    response = _turn_on(_signed_in(env))
    assert "success" in response.headers["location"]
    config = load_config(env["config_path"])
    assert config.wireguard.enabled and "vpn" in config.zones
    rules = {r.name: r for r in config.rules}
    assert rules["webui-from-vpn"].dst_port == "443" and rules["ssh-from-vpn"].dst_port == "22"
    assert rules["vpn-to-lan"].to_zone == "lan"
    assert _alerts(env) == ["WireGuard VPN turned on by 'boss'"]
    # Saving again adds nothing twice and is no new alert.
    _turn_on(_signed_in(env))
    assert len(load_config(env["config_path"]).rules) == 3 and len(_alerts(env)) == 1


def test_a_device_with_its_own_key(env):
    client = _signed_in(env)
    _turn_on(client)
    response = client.post("/vpn/peers/add", data={"name": "laptop", "public_key": DEVICE_KEY})
    assert "success" in response.headers["location"]
    peer = load_config(env["config_path"]).wireguard.peers[0]
    assert (peer.name, peer.public_key, peer.address) == ("laptop", DEVICE_KEY, "10.99.0.2/32")
    assert "new VPN device 'laptop' added by 'boss'" in _alerts(env)


def test_a_device_the_router_makes_keys_for(env):
    client = _signed_in(env)
    _turn_on(client)
    router_priv, router_pub = wireguard.generate_keypair()
    env["helper"].wireguard = {"public_key": router_pub, "up": True, "peers": {}}
    page = client.post("/vpn/peers/add", data={"name": "phone"})
    assert page.status_code == 200 and page.headers["cache-control"] == "no-store"
    text = page.text
    private = text.split("PrivateKey = ")[1].split("\n")[0]
    public = load_config(env["config_path"]).wireguard.peers[0].public_key
    assert wireguard.public_key_of(private) == public  # the pair belongs together
    assert f"PublicKey = {router_pub}" in text and "Endpoint = vpn.example.net:51820" in text
    assert "AllowedIPs = 10.99.0.0/24, 192.168.1.0/24" in text
    assert "<svg" in text and "the router doesn't keep it" in text
    # The private key is nowhere the router keeps things.
    assert private not in env["config_path"].read_text()
    assert private not in env["audit_log_path"].read_text()
    # A second look is not possible.
    assert private not in client.get("/vpn").text


def test_generated_keys_need_the_router_key_first(env):
    client = _signed_in(env)
    _turn_on(client)
    env["helper"].wireguard = {"public_key": None, "up": False, "peers": {}}
    response = client.post("/vpn/peers/add", data={"name": "phone"})
    assert "Apply+first" in response.headers["location"]
    assert load_config(env["config_path"]).wireguard.peers == []


def test_full_tunnel_devices(env):
    client = _signed_in(env)
    _turn_on(client)
    _, router_pub = wireguard.generate_keypair()
    env["helper"].wireguard = {"public_key": router_pub, "up": True, "peers": {}}
    text = client.post("/vpn/peers/add", data={"name": "phone", "full_tunnel": "true"}).text
    assert "AllowedIPs = 0.0.0.0/0" in text


def test_bad_devices_are_refused(env):
    client = _signed_in(env)
    _turn_on(client)
    assert "error" in client.post("/vpn/peers/add", data={"name": "x", "public_key": "nope"}).headers["location"]
    client.post("/vpn/peers/add", data={"name": "laptop", "public_key": DEVICE_KEY})
    assert "error" in client.post("/vpn/peers/add",
                                  data={"name": "laptop2", "public_key": DEVICE_KEY}).headers["location"]
    assert [p.name for p in load_config(env["config_path"]).wireguard.peers] == ["laptop"]


def test_removing_a_device(env):
    client = _signed_in(env)
    _turn_on(client)
    client.post("/vpn/peers/add", data={"name": "laptop", "public_key": DEVICE_KEY})
    assert "success" in client.post("/vpn/peers/remove/laptop").headers["location"]
    assert load_config(env["config_path"]).wireguard.peers == []
    assert "error" in client.post("/vpn/peers/remove/laptop").headers["location"]


def test_the_status_shows_handshakes(env):
    client = _signed_in(env)
    _turn_on(client)
    client.post("/vpn/peers/add", data={"name": "laptop", "public_key": DEVICE_KEY})
    env["helper"].wireguard = {"public_key": "R" * 43 + "=", "up": True, "peers": {
        DEVICE_KEY: {"endpoint": "203.0.113.7:40000", "latest_handshake": 1790000000, "rx_bytes": 1, "tx_bytes": 2}}}
    page = client.get("/vpn").text
    assert "from 203.0.113.7:40000" in page and "R" * 43 in page


def test_viewers_change_nothing(env):
    _turn_on(_signed_in(env))
    before = env["config_path"].read_text()
    viewer = _signed_in(env, "guest", "violet-anchor-9")
    assert viewer.get("/vpn").status_code == 200
    assert viewer.post("/vpn/peers/add", data={"name": "evil", "public_key": DEVICE_KEY}).status_code == 403
    assert viewer.post("/vpn/settings", data={}).status_code == 403
    assert env["config_path"].read_text() == before
