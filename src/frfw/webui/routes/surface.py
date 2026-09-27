"""The attack-surface screen (security-lessons I3; see frfw.surface).

Read-only: every listening socket, which zones can reach it and why, with
anything reachable from an internet-facing zone flagged at the top. The
socket list comes from the apply-helper (root, so `ss` can name the
processes); the verdicts are computed here from the saved config.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from frfw import management, surface
from frfw.config import ConfigError, parse_config
from frfw.helper.client import HelperError
from frfw.webui.deps import get_helper, get_raw_config, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.templating import templates

router = APIRouter()


@router.get("/surface")
def show_surface(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    error = None
    rows: list[surface.Row] = []
    zones: list[str] = []
    internet: set[str] = set()
    wan_addresses: list[str] = []
    try:
        config = parse_config(raw)
    except ConfigError as exc:
        config, error = None, f"The saved config doesn't parse: {exc}"
    if config is not None:
        try:
            reply = helper.listening_sockets()
        except (HelperError, OSError) as exc:
            reply = {"ok": False, "message": str(exc)}
        if not reply.get("ok"):
            error = f"Can't list the listening sockets: {reply.get('message') or 'no answer'}"
        else:
            listeners = [surface.Listener(**l) for l in reply.get("listeners", [])]
            addresses = reply.get("addresses") or {}
            rows = surface.surface(config, listeners, addresses)
            zones = sorted(config.zones)
            internet = management.internet_zones(config)
            wan_addresses = surface.wan_addresses(config, addresses)
    exposed = [r for r in rows if r.internet]
    return templates.TemplateResponse(request, "surface.html", {
        "username": username,
        "rows": rows,
        "zones": zones,
        "internet": internet,
        "exposed": exposed,
        "wan_addresses": wan_addresses,
        "allow_wan": bool(config and config.management.allow_wan),
        "error": error,
    })
