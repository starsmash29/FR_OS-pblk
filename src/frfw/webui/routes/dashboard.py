from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request

from frfw import netdetect
from frfw import pqc as pqc_mod
from frfw.adblock import count_blocked_domains
from frfw.ai_ids import is_daemon_active
from frfw.apply import list_backups
from frfw.config import ConfigError, parse_config
from frfw.webui.deps import (
    get_adblock_hosts_path,
    get_helper,
    get_raw_config,
    require_login,
)
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


@router.get("/")
def dashboard(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
    adblock_hosts_path: Path = Depends(get_adblock_hosts_path),
):
    try:
        config = parse_config(raw)
    except ConfigError:
        config = None

    ai_ids_enabled = bool(config is not None and config.ai_ids.enabled)
    ai_ids_quarantined_count = None
    if ai_ids_enabled:
        status = helper.ids_quarantine_status()
        ai_ids_quarantined_count = status.get("count") if status.get("ok") else None

    pqc_status = pqc_mod.get_status(config) if config is not None else None

    adblocker_enabled = bool(config is not None and config.adblocker.enabled)
    adblock_domain_count = count_blocked_domains(adblock_hosts_path) if adblocker_enabled else None

    interface_rows = []
    if config is not None:
        detected = {d.name: d for d in netdetect.list_interfaces(include_virtual=True)}
        for iface in config.interfaces.values():
            nic = detected.get(iface.device)
            if nic is None or nic.link_up is None:
                link = "?"
            else:
                link = "up" if nic.link_up else "down"
            interface_rows.append(
                {"zone": iface.zone, "device": iface.device, "address": iface.address, "link": link}
            )

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "username": username,
            "hostname": raw.get("hostname") or "?",
            "config_valid": config is not None,
            "zone_count": len(raw.get("zones") or {}),
            "interface_count": len(raw.get("interfaces") or {}),
            "rule_count": len(raw.get("rules") or []),
            "port_forward_count": len((raw.get("nat") or {}).get("port_forwards") or []),
            "dhcp_zone_count": len(raw.get("dhcp") or {}),
            "backup_count": len(list_backups()),
            "interface_rows": interface_rows,
            "ai_ids_enabled": ai_ids_enabled,
            "ai_ids_daemon_active": is_daemon_active(),
            "ai_ids_quarantined_count": ai_ids_quarantined_count,
            "pqc_status": pqc_status,
            "adblocker_enabled": adblocker_enabled,
            "adblock_domain_count": adblock_domain_count,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/apply")
def apply_now(
    request: Request,
    username: str = Depends(require_login),
    helper: HelperClient = Depends(get_helper),
):
    dry_run = request.query_params.get("dry_run") == "1"
    result = helper.apply(dry_run=dry_run)
    message = result.get("message", "")
    if result.get("ok"):
        return redirect_with("/", success=message or "Applied")
    return redirect_with("/", error=message or "Apply failed")


@router.post("/rollback")
def rollback_now(
    username: str = Depends(require_login), helper: HelperClient = Depends(get_helper)
):
    result = helper.rollback()
    message = result.get("message", "")
    if result.get("ok"):
        return redirect_with("/", success=message or "Rolled back")
    return redirect_with("/", error=message or "Rollback failed")
