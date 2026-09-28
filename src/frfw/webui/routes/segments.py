"""The network segments screen (security-lessons K4, see frfw.segments):
IoT and guest segments in one step. First-run setup brings the admin
here right after the account is theirs; it stays reachable from the
sidebar."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request

from frfw import segments
from frfw.config import ConfigError, parse_config
from frfw.webui.actions import try_save
from frfw.webui.deps import get_helper, get_raw_config, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


@router.get("/segments")
def show_segments(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
):
    zones = raw.get("zones") or {}
    try:
        parent = segments.lan_device(raw)
    except segments.SegmentError:
        parent = None
    return templates.TemplateResponse(request, "segments.html", {
        "username": username,
        "segments": [{"name": name, **spec, "present": name in zones,
                      "device": f"{parent}.{spec['vlan']}" if parent else None}
                     for name, spec in segments.SEGMENTS.items()],
        "parent": parent,
        "first_run": request.query_params.get("first_run") == "1",
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
    })


@router.post("/segments")
def add_segments(
    chosen: list[str] = Form([], alias="segment"),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    if not chosen:
        return redirect_with("/", success="No segments added -- you can add them later on the Segments screen")
    try:
        added = segments.add_segments(raw, parse_config(raw), chosen)
    except (ConfigError, segments.SegmentError) as exc:
        return redirect_with("/segments", error=str(exc))
    if not added:
        return redirect_with("/segments", success="Those segments are already there")
    ok, message = try_save(raw, helper)
    if not ok:
        return redirect_with("/segments", error=message)
    return redirect_with("/segments", success=f"Added: {', '.join(added)} -- click Apply on the dashboard to load them")
