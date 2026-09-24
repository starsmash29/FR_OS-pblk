"""TLS fingerprints screen (phase 19, see frfw.tlsfp).

The inventory and events are fr-tls-fp's display-only state file; the
settings and blocklist are `tls_fingerprint` in config.yaml, saved through
the normal validated path. Client addresses are labelled from the last
IoT scan when possible, like the Applications screen.
"""

from __future__ import annotations

import time
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request

from frfw.config import ConfigError, parse_config
from frfw.iot.scanner import load_inventory
from frfw.tlsfp.daemon import is_daemon_active, load_state
from frfw.webui.actions import try_save
from frfw.webui.deps import (
    get_helper,
    get_iot_inventory_path,
    get_raw_config,
    get_tlsfp_state_path,
    require_login,
)
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


def _ts(value) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(value)) if isinstance(value, (int, float)) else "-"


@router.get("/tls")
def show_tls(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    state_path: Path = Depends(get_tlsfp_state_path),
    inventory_path: Path = Depends(get_iot_inventory_path),
):
    tls_raw = raw.get("tls_fingerprint") or {}
    config_error = None
    try:
        parse_config(raw)
    except ConfigError as exc:
        config_error = str(exc)

    labels = {}
    for device in (load_inventory(inventory_path) or {}).get("devices", []):
        if device.get("ip"):
            labels[device["ip"]] = device.get("hostname") or device.get("vendor") or device.get("mac")

    state = load_state(state_path)
    blocked = {
        (e.get("fingerprint") if isinstance(e, dict) else str(e)).lower()
        for e in tls_raw.get("blocklist") or []
    }
    rows = []
    for client, fingerprints in (state.get("clients") or {}).items():
        for ja4, seen in fingerprints.items():
            rows.append({
                "client": client,
                "label": labels.get(client),
                "ja4": ja4,
                "ja3": seen.get("ja3", []),
                "sni": seen.get("sni", []),
                "count": seen.get("count", 0),
                "last_seen": _ts(seen.get("last_seen")),
                "last_seen_raw": seen.get("last_seen", 0),
                "blocked": ja4 in blocked or any(j in blocked for j in seen.get("ja3", [])),
            })
    rows.sort(key=lambda r: -r["last_seen_raw"])

    # How many clients share each JA4 -- a fingerprint on one device only
    # is more interesting than one every phone presents.
    sharing: dict[str, int] = {}
    for row in rows:
        sharing[row["ja4"]] = sharing.get(row["ja4"], 0) + 1
    for row in rows:
        row["clients_with_it"] = sharing[row["ja4"]]

    events = list(reversed(state.get("events") or []))[:100]
    for event in events:
        event["when"] = _ts(event.get("ts"))

    xdp_raw = raw.get("xdp_sni_filter") or {}
    return templates.TemplateResponse(
        request,
        "tls.html",
        {
            "username": username,
            "enabled": bool(tls_raw.get("enabled", False)),
            "quarantine_on_match": bool(tls_raw.get("quarantine_on_match", False)),
            "blocklist": [
                e if isinstance(e, dict) else {"fingerprint": str(e)} for e in tls_raw.get("blocklist") or []
            ],
            "xdp_enabled": bool(xdp_raw.get("enabled")),
            "xdp_interfaces": list(xdp_raw.get("interfaces") or []),
            "daemon_active": is_daemon_active(),
            "learning": state.get("learning", True),
            "generated": _ts(state.get("generated")),
            "stats": state.get("stats") or {},
            "rows": rows[:500],
            "events": events,
            "config_error": config_error,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/tls/settings")
def save_settings(
    enabled: bool = Form(False),
    quarantine_on_match: bool = Form(False),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    tls_raw = dict(raw.get("tls_fingerprint") or {})
    tls_raw["enabled"] = enabled
    tls_raw["quarantine_on_match"] = quarantine_on_match
    tls_raw.setdefault("blocklist", [])
    raw["tls_fingerprint"] = tls_raw
    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/tls", success="TLS fingerprinting settings saved -- click Apply on the dashboard")
    return redirect_with("/tls", error=message)


@router.post("/tls/block")
def block_fingerprint(
    fingerprint: str = Form(...),
    label: str = Form(""),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    tls_raw = dict(raw.get("tls_fingerprint") or {})
    fingerprint = fingerprint.strip().lower()
    entries = [
        e for e in tls_raw.get("blocklist") or []
        if (e.get("fingerprint") if isinstance(e, dict) else str(e)).lower() != fingerprint
    ]
    entries.append({"fingerprint": fingerprint, "label": label.strip()})
    tls_raw["blocklist"] = entries
    raw["tls_fingerprint"] = tls_raw
    ok, message = try_save(raw, helper)
    if ok:
        # The running daemon re-reads the blocklist within 30 seconds; no Apply needed.
        return redirect_with("/tls", success=f"{fingerprint} added to the blocklist")
    return redirect_with("/tls", error=message)


@router.post("/tls/unblock")
def unblock_fingerprint(
    fingerprint: str = Form(...),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    tls_raw = dict(raw.get("tls_fingerprint") or {})
    fingerprint = fingerprint.strip().lower()
    tls_raw["blocklist"] = [
        e for e in tls_raw.get("blocklist") or []
        if (e.get("fingerprint") if isinstance(e, dict) else str(e)).lower() != fingerprint
    ]
    raw["tls_fingerprint"] = tls_raw
    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/tls", success=f"{fingerprint} removed from the blocklist")
    return redirect_with("/tls", error=message)
