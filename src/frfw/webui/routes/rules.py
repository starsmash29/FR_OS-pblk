from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request

from frfw.webui.actions import try_save
from frfw.webui.deps import get_helper, get_raw_config, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


@router.get("/rules")
def list_rules(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
):
    return templates.TemplateResponse(
        request,
        "rules.html",
        {
            "username": username,
            "rules": raw.get("rules") or [],
            "zones": sorted((raw.get("zones") or {}).keys()),
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/rules/add")
def add_rule(
    name: str = Form(...),
    action: str = Form(...),
    from_zone: str = Form(""),
    to_zone: str = Form(""),
    proto: str = Form("any"),
    dst_port: str = Form(""),
    src_address: str = Form(""),
    dst_address: str = Form(""),
    log: bool = Form(False),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    rule: dict = {"name": name, "action": action}
    if from_zone.strip():
        rule["from_zone"] = from_zone.strip()
    if to_zone.strip():
        rule["to_zone"] = to_zone.strip()
    if proto and proto != "any":
        rule["proto"] = proto
    if dst_port.strip():
        rule["dst_port"] = int(dst_port) if dst_port.strip().isdigit() else dst_port.strip()
    if src_address.strip():
        rule["src_address"] = src_address.strip()
    if dst_address.strip():
        rule["dst_address"] = dst_address.strip()
    if log:
        rule["log"] = True

    rules = raw.setdefault("rules", [])
    rules[:] = [r for r in rules if r.get("name") != name]  # replace if it already existed
    rules.append(rule)

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/rules", success=f"Rule {name!r} saved")
    return redirect_with("/rules", error=message)


@router.post("/rules/delete/{name}")
def delete_rule(
    name: str,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    rules = raw.get("rules") or []
    remaining = [r for r in rules if r.get("name") != name]
    if len(remaining) == len(rules):
        return redirect_with("/rules", error=f"No such rule {name!r}")
    raw["rules"] = remaining

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/rules", success=f"Rule {name!r} deleted")
    return redirect_with("/rules", error=message)
