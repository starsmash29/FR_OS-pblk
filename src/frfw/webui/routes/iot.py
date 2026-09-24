"""IoT devices screen (phase 14, see frfw.iot and frfw.iot_isolation).

- The inventory table is the last scan's display-only state file
  (frfw.iot.scanner.load_inventory) -- written by the unprivileged
  scanner, read back here without any privilege.
- "Currently isolated" is a live kernel-state query through the
  apply-helper (`iot_isolation_status`), the authority on who is
  actually cut off right now.
- "Scan now" runs the scanner in this (unprivileged) process -- it is
  the same fr_os-webui account the timer-driven `fr-iot-scan.service`
  uses, and its two privileged steps go through the helper either way.
- Trust / isolate / clear edit `iot.trusted_macs`/`iot.isolated_macs`
  through the normal validated `save_config` path, then immediately
  re-apply the isolation decision to the last scan's classifications
  (frfw.iot.scanner.resync_from_inventory), so trusting a device frees
  it right away instead of at the next scheduled scan.
"""

from __future__ import annotations

import time
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request

from frfw.config import ConfigError, parse_config
from frfw.helper.client import HelperError
from frfw.iot.scanner import load_inventory, resync_from_inventory, run_scan
from frfw.webui.actions import try_save
from frfw.webui.deps import (
    get_helper,
    get_iot_inventory_path,
    get_iot_scan_options,
    get_raw_config,
    require_login,
)
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()

_DEVICE_ACTIONS = ("trust", "isolate", "clear")


def _format_ts(ts) -> str | None:
    if not isinstance(ts, (int, float)):
        return None
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


@router.get("/iot")
def show_iot(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
    inventory_path: Path = Depends(get_iot_inventory_path),
):
    iot_raw = raw.get("iot") or {}
    config_error = None
    try:
        parse_config(raw)
    except ConfigError as exc:
        config_error = str(exc)

    enabled = bool(iot_raw.get("enabled", False))
    live_isolated: list[str] = []
    isolation_error = None
    if enabled:
        try:
            status = helper.iot_isolation_status()
            if status.get("ok"):
                live_isolated = list(status.get("isolated") or [])
            else:
                isolation_error = status.get("message")
        except HelperError as exc:
            isolation_error = str(exc)

    inventory = load_inventory(inventory_path) or {}
    devices = sorted(
        inventory.get("devices", []),
        key=lambda d: ({"iot": 0, "unknown": 1, "general": 2}.get(d.get("category"), 3), d.get("ip") or ""),
    )
    live_set = set(live_isolated)
    for device in devices:
        device["live_isolated"] = device.get("mac") in live_set

    return templates.TemplateResponse(
        request,
        "iot.html",
        {
            "username": username,
            "enabled": enabled,
            "selected_zones": list(iot_raw.get("zones") or []),
            "all_zones": sorted((raw.get("zones") or {}).keys()),
            "auto_isolate": bool(iot_raw.get("auto_isolate", False)),
            "isolation_mode": iot_raw.get("isolation_mode", "internet_only"),
            "trusted_macs": list(iot_raw.get("trusted_macs") or []),
            "isolated_macs": list(iot_raw.get("isolated_macs") or []),
            "devices": devices,
            "scanned_at": _format_ts(inventory.get("scanned_at")),
            "scan_messages": inventory.get("messages", []),
            "live_isolated": live_isolated,
            "isolation_error": isolation_error,
            "config_error": config_error,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/iot/settings")
def save_settings(
    enabled: bool = Form(False),
    zones: list[str] = Form([]),
    auto_isolate: bool = Form(False),
    isolation_mode: str = Form("internet_only"),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    previous = raw.get("iot") or {}
    raw["iot"] = {
        "enabled": enabled,
        "zones": zones,
        "auto_isolate": auto_isolate,
        "isolation_mode": isolation_mode,
        "trusted_macs": list(previous.get("trusted_macs") or []),
        "isolated_macs": list(previous.get("isolated_macs") or []),
    }
    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with(
            "/iot", success="IoT settings saved -- click Apply on the dashboard to load the isolation rules"
        )
    return redirect_with("/iot", error=message)


@router.post("/iot/scan")
def scan_now(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
    inventory_path: Path = Depends(get_iot_inventory_path),
    scan_options: dict = Depends(get_iot_scan_options),
):
    try:
        config = parse_config(raw)
    except ConfigError as exc:
        return redirect_with("/iot", error=f"Config does not pass validation: {exc}")
    if not config.iot.enabled:
        return redirect_with("/iot", error="IoT discovery is disabled -- enable it and save first")

    result = run_scan(
        config,
        leases_fn=helper.dhcp_leases,
        sync_fn=helper.iot_sync_isolation,
        state_path=inventory_path,
        **scan_options,
    )
    summary = "; ".join(result.messages)
    if any(m.startswith("error:") for m in result.messages):
        return redirect_with("/iot", error=summary)
    return redirect_with("/iot", success=summary)


@router.post("/iot/device")
def device_action(
    mac: str = Form(...),
    action: str = Form(...),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
    inventory_path: Path = Depends(get_iot_inventory_path),
):
    if action not in _DEVICE_ACTIONS:
        return redirect_with("/iot", error=f"unknown action {action!r}")
    mac = mac.strip().lower()

    iot_raw = dict(raw.get("iot") or {})
    trusted = [m for m in (iot_raw.get("trusted_macs") or []) if m.lower() != mac]
    isolated = [m for m in (iot_raw.get("isolated_macs") or []) if m.lower() != mac]
    if action == "trust":
        trusted.append(mac)
    elif action == "isolate":
        isolated.append(mac)
    iot_raw["trusted_macs"] = trusted
    iot_raw["isolated_macs"] = isolated
    raw["iot"] = iot_raw

    ok, message = try_save(raw, helper)
    if not ok:
        return redirect_with("/iot", error=message)

    config = parse_config(raw)
    if not config.iot.enabled:
        return redirect_with("/iot", success=f"{mac}: saved ({action})")
    try:
        response = resync_from_inventory(
            config, load_inventory(inventory_path), sync_fn=helper.iot_sync_isolation
        )
    except HelperError as exc:
        return redirect_with("/iot", error=f"{mac}: saved, but isolation not re-applied: {exc}")
    if not response.get("ok"):
        return redirect_with(
            "/iot", error=f"{mac}: saved, but isolation not re-applied: {response.get('message')}"
        )
    return redirect_with(
        "/iot", success=f"{mac}: {action} saved; {response.get('count', 0)} device(s) now isolated"
    )
