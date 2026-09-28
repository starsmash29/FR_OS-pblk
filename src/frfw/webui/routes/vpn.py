"""The WireGuard VPN screen (security-lessons G8/K5; see frfw.wireguard).

- `GET /vpn`: the tunnel's settings, the router's public key and each
  device's last handshake (from the apply-helper: the key and `wg show`
  are root's).
- `POST /vpn/settings`: turn the tunnel on or off, its address, port and
  the address clients reach the router at. Turning it on also adds what
  makes it useful, if it isn't there yet: the `vpn` zone, and rules that
  let the VPN reach the webUI, SSH and the LAN -- so managing the router
  from outside works through the tunnel, not by opening the webUI to the
  internet (K5).
- `POST /vpn/peers/add`: a new device. Either its own public key is
  pasted (the private key never leaves the device), or the router makes
  a key pair and shows the device's configuration -- as text and as a QR
  code for the WireGuard app -- once. That private key is not stored
  anywhere; the page says so.
- `POST /vpn/peers/remove/{name}`.

A new device, and turning the VPN on, are security alerts (G9): each is
a way into the network.
"""

from __future__ import annotations

import io
import time
from pathlib import Path

import segno
from fastapi import APIRouter, Depends, Form, Request

from frfw import wireguard
from frfw.config import ConfigError, parse_config
from frfw.webui import audit
from frfw.webui.actions import try_save
from frfw.webui.client_ip import client_ip
from frfw.webui.deps import get_audit_log_path, get_helper, get_raw_config, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()

DEFAULT_ADDRESS = "10.99.0.1/24"

#: Added when the VPN is turned on, if missing: without them the tunnel
#: comes up but leads nowhere (the input and forward chains drop by
#: default).
_VPN_RULES = (
    {"name": "webui-from-vpn", "action": "accept", "from_zone": "vpn", "to_zone": "self",
     "proto": "tcp", "dst_port": 443},
    {"name": "ssh-from-vpn", "action": "accept", "from_zone": "vpn", "to_zone": "self",
     "proto": "tcp", "dst_port": 22},
    {"name": "vpn-to-lan", "action": "accept", "from_zone": "vpn", "to_zone": "lan"},
)


def _status(helper: HelperClient) -> dict:
    try:
        reply = helper.wireguard_status()
    except OSError:
        return {}
    return reply if reply.get("ok") else {}


def _peers(raw: dict) -> list[dict]:
    return [p for p in (raw.get("wireguard") or {}).get("peers") or [] if isinstance(p, dict)]


@router.get("/vpn")
def show_vpn(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    section = raw.get("wireguard") or {}
    status = _status(helper)
    handshakes = status.get("peers") or {}
    peers = []
    for peer in _peers(raw):
        live = handshakes.get(peer.get("public_key"), {})
        ts = live.get("latest_handshake") or 0
        peers.append({**peer, "endpoint_seen": live.get("endpoint", ""),
                      "handshake": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else ""})
    return templates.TemplateResponse(request, "vpn.html", {
        "username": username,
        "enabled": bool(section.get("enabled")),
        "address": section.get("address") or DEFAULT_ADDRESS,
        "listen_port": section.get("listen_port", 51820),
        "endpoint": section.get("endpoint", ""),
        "peers": peers,
        "router_key": status.get("public_key"),
        "up": status.get("up", False),
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
    })


@router.post("/vpn/settings")
def save_settings(
    request: Request,
    enabled: bool = Form(False),
    address: str = Form(DEFAULT_ADDRESS),
    listen_port: int = Form(51820),
    endpoint: str = Form(""),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
    audit_log_path: Path = Depends(get_audit_log_path),
):
    section = raw.setdefault("wireguard", {})
    was_enabled = bool(section.get("enabled"))
    section.update(enabled=enabled, address=address.strip(), listen_port=listen_port, endpoint=endpoint.strip())
    section.setdefault("peers", [])
    if enabled:
        zone = section.setdefault("zone", "vpn")
        raw.setdefault("zones", {}).setdefault(zone, {})
        rules = raw.setdefault("rules", [])
        names = {r.get("name") for r in rules if isinstance(r, dict)}
        for rule in _VPN_RULES:
            if rule["name"] not in names and rule["to_zone"] in {"self", *raw["zones"]}:
                rules.append({**rule, "from_zone": zone})
    ok, message = try_save(raw, helper)
    if not ok:
        return redirect_with("/vpn", error=message)
    if enabled and not was_enabled:
        audit.alert(audit_log_path, f"WireGuard VPN turned on by {username!r}",
                    user=username, client=client_ip(request))
    state = "on" if enabled else "off"
    return redirect_with("/vpn", success=f"VPN settings saved ({state}) -- click Apply on the dashboard to load them")


@router.post("/vpn/peers/add")
def add_peer(
    request: Request,
    name: str = Form(...),
    public_key: str = Form(""),
    full_tunnel: bool = Form(False),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
    audit_log_path: Path = Depends(get_audit_log_path),
):
    try:
        config = parse_config(raw)
    except ConfigError as exc:
        return redirect_with("/vpn", error=str(exc))
    if not config.wireguard.address:
        return redirect_with("/vpn", error="Set the VPN's address and save the settings first")
    public_key = public_key.strip()
    private_key = None
    router_key = None
    if not public_key:
        router_key = _status(helper).get("public_key")
        if not router_key:
            return redirect_with("/vpn", error="Turn the VPN on and click Apply first: the router makes its key then")
        private_key, public_key = wireguard.generate_keypair()
    try:
        address = wireguard.next_free_address(config.wireguard)
    except wireguard.WireguardError as exc:
        return redirect_with("/vpn", error=str(exc))
    raw["wireguard"].setdefault("peers", []).append(
        {"name": name.strip(), "public_key": public_key, "address": address})
    ok, message = try_save(raw, helper)
    if not ok:
        return redirect_with("/vpn", error=message)
    audit.alert(audit_log_path, f"new VPN device {name.strip()!r} added by {username!r}",
                user=username, client=client_ip(request))
    if private_key is None:
        return redirect_with("/vpn", success=f"VPN device {name.strip()!r} added -- click Apply to load it")
    text = wireguard.client_config(parse_config(raw), private_key=private_key, address=address,
                                   router_key=router_key, full_tunnel=full_tunnel)
    svg = io.BytesIO()
    segno.make(text, error="m").save(svg, kind="svg", scale=4, dark="#0C141F", light="#FFFFFF", xmldecl=False)
    response = templates.TemplateResponse(request, "vpn_peer.html", {
        "username": username, "name": name.strip(), "config_text": text, "qr_svg": svg.getvalue().decode(),
    })
    # The device's private key is on this page and nowhere else.
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/vpn/peers/remove/{peer_name}")
def remove_peer(
    peer_name: str,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    section = raw.setdefault("wireguard", {})
    peers = _peers(raw)
    remaining = [p for p in peers if p.get("name") != peer_name]
    if len(remaining) == len(peers):
        return redirect_with("/vpn", error=f"No such VPN device {peer_name!r}")
    section["peers"] = remaining
    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/vpn", success=f"VPN device {peer_name!r} removed -- click Apply to cut it off")
    return redirect_with("/vpn", error=message)
