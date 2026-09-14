from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request

from frfw import netdetect
from frfw.webui.actions import try_save
from frfw.webui.deps import get_helper, get_raw_config, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


@router.get("/interfaces")
def list_interfaces(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
):
    interfaces = [
        {"name": name, **body} for name, body in sorted((raw.get("interfaces") or {}).items())
    ]

    edit_name = request.query_params.get("edit")
    edit = next((i for i in interfaces if i["name"] == edit_name), None)

    return templates.TemplateResponse(
        request,
        "interfaces.html",
        {
            "username": username,
            "interfaces": interfaces,
            "edit": edit,
            "detected": netdetect.list_interfaces(include_virtual=True),
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/interfaces/save")
def save_interface(
    name: str = Form(...),
    device: str = Form(...),
    zone: str = Form(...),
    address: str = Form(""),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    interfaces = raw.setdefault("interfaces", {})
    zones = raw.setdefault("zones", {})

    entry = {"device": device, "zone": zone}
    if address.strip():
        entry["address"] = address.strip()
    interfaces[name] = entry
    zones.setdefault(zone, {})

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/interfaces", success=f"Interface {name!r} saved")
    return redirect_with("/interfaces", error=message)


@router.post("/interfaces/delete/{name}")
def delete_interface(
    name: str,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    interfaces = raw.get("interfaces") or {}
    removed = interfaces.pop(name, None)
    if removed is None:
        return redirect_with("/interfaces", error=f"No such interface {name!r}")

    # A zone left with no interfaces is always invalid -- drop it too so
    # the common case (deleting the only interface in a zone) just works;
    # if rules/NAT/DHCP still reference that zone, validation below will
    # still catch it and nothing gets saved.
    remaining_zones = {i["zone"] for i in interfaces.values()}
    zones = raw.get("zones") or {}
    if removed["zone"] not in remaining_zones:
        zones.pop(removed["zone"], None)

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/interfaces", success=f"Interface {name!r} deleted")
    return redirect_with("/interfaces", error=message)
