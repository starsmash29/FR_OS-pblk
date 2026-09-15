from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request

from frfw.webui.actions import try_save
from frfw.webui.deps import get_helper, get_raw_config, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


@router.get("/nat")
def show_nat(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
):
    nat = raw.get("nat") or {}
    return templates.TemplateResponse(
        request,
        "nat.html",
        {
            "username": username,
            "masquerade": nat.get("masquerade") or [],
            "port_forwards": nat.get("port_forwards") or [],
            "zones": sorted((raw.get("zones") or {}).keys()),
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/nat/masquerade/add")
def add_masquerade(
    out_zone: str = Form(...),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    nat = raw.setdefault("nat", {})
    masquerade = nat.setdefault("masquerade", [])
    if not any(m.get("out_zone") == out_zone for m in masquerade):
        masquerade.append({"out_zone": out_zone})

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/nat", success=f"Masquerade on {out_zone!r} added")
    return redirect_with("/nat", error=message)


@router.post("/nat/masquerade/delete/{out_zone}")
def delete_masquerade(
    out_zone: str,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    nat = raw.setdefault("nat", {})
    nat["masquerade"] = [m for m in nat.get("masquerade") or [] if m.get("out_zone") != out_zone]

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/nat", success=f"Masquerade on {out_zone!r} removed")
    return redirect_with("/nat", error=message)


@router.post("/nat/portforward/add")
def add_port_forward(
    name: str = Form(...),
    in_zone: str = Form(...),
    proto: str = Form(...),
    dst_port: int = Form(...),
    to_address: str = Form(...),
    to_port: int | None = Form(None),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    entry = {
        "name": name,
        "in_zone": in_zone,
        "proto": proto,
        "dst_port": dst_port,
        "to_address": to_address,
        "to_port": to_port if to_port else dst_port,
    }
    nat = raw.setdefault("nat", {})
    port_forwards = nat.setdefault("port_forwards", [])
    port_forwards[:] = [p for p in port_forwards if p.get("name") != name]
    port_forwards.append(entry)

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/nat", success=f"Port forward {name!r} saved")
    return redirect_with("/nat", error=message)


@router.post("/nat/portforward/delete/{name}")
def delete_port_forward(
    name: str,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    nat = raw.setdefault("nat", {})
    nat["port_forwards"] = [p for p in nat.get("port_forwards") or [] if p.get("name") != name]

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/nat", success=f"Port forward {name!r} deleted")
    return redirect_with("/nat", error=message)
