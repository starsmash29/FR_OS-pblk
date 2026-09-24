"""Applications screen (phase 16, see frfw.appid).

- The usage table is fr-appid's display-only summary file
  (frfw.appid.daemon.load_usage), read without any privilege.
- Client addresses are labelled with the hostname/vendor the last IoT
  scan found for them, when there is one (frfw.iot.scanner's inventory).
- Settings and the blocked-app list go through the normal validated
  `save_config` path; blocking takes effect on the next Apply, which
  rewrites the resolver config (and the XDP blocklist with
  `block_via_xdp`).
"""

from __future__ import annotations

import time
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request

from frfw.appid import load_catalog
from frfw.appid.daemon import is_daemon_active, load_usage
from frfw.config import ConfigError, parse_config
from frfw.iot.scanner import load_inventory
from frfw.webui.actions import try_save
from frfw.webui.deps import (
    get_appid_usage_path,
    get_helper,
    get_iot_inventory_path,
    get_raw_config,
    require_login,
)
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


def _format_ts(ts) -> str | None:
    if not isinstance(ts, (int, float)):
        return None
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _client_labels(inventory_path: Path) -> dict[str, str]:
    inventory = load_inventory(inventory_path) or {}
    labels = {}
    for device in inventory.get("devices", []):
        ip = device.get("ip")
        label = device.get("hostname") or device.get("vendor") or device.get("mac")
        if ip and label:
            labels[ip] = label
    return labels


def _prerequisites(raw: dict) -> list[tuple[bool, str]]:
    adblocker = raw.get("adblocker") or {}
    xdp = raw.get("xdp_sni_filter") or {}
    app_control = raw.get("app_control") or {}
    return [
        (
            bool(adblocker.get("enabled") and adblocker.get("query_logging")),
            "DNS observation: Ad-Block resolver enabled with query logging",
        ),
        (
            bool(adblocker.get("enabled") and adblocker.get("serve_lan")),
            "DNS blocking: Ad-Block resolver announced to LAN clients (serve_lan)",
        ),
        (
            bool(adblocker.get("force_dns")),
            "Clients cannot bypass the resolver with their own DNS server (force_dns)",
        ),
        (
            bool(xdp.get("enabled") and app_control.get("observe_sni")),
            "SNI observation: XDP filter enabled on the LAN-side interfaces with observe_sni",
        ),
    ]


@router.get("/apps")
def show_apps(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    usage_path: Path = Depends(get_appid_usage_path),
    inventory_path: Path = Depends(get_iot_inventory_path),
):
    app_raw = raw.get("app_control") or {}
    config_error = None
    try:
        parse_config(raw)
    except ConfigError as exc:
        config_error = str(exc)

    catalog = load_catalog()
    usage = load_usage(usage_path)
    labels = _client_labels(inventory_path)
    blocked = set(app_raw.get("blocked_apps") or [])

    rows = []
    for app in catalog.apps:
        stats = usage["apps"].get(app.id) or {}
        clients = [
            {
                "ip": ip,
                "label": labels.get(ip),
                "hits": row.get("hits_24h", 0),
                "last_seen": _format_ts(row.get("last_seen")),
                "active": bool(row.get("active")),
                "sources": ", ".join(row.get("sources", [])),
            }
            for ip, row in (stats.get("clients") or {}).items()
        ]
        clients.sort(key=lambda c: -c["hits"])
        rows.append(
            {
                "id": app.id,
                "name": app.name,
                "category": app.category,
                "names": len(app.all_names()),
                "hits": stats.get("hits_24h", 0),
                "active_clients": stats.get("active_clients", 0),
                "last_seen": _format_ts(stats.get("last_seen")),
                "clients": clients,
                "blocked": app.id in blocked,
            }
        )
    rows.sort(key=lambda r: (-r["active_clients"], -r["hits"], r["category"], r["name"]))

    return templates.TemplateResponse(
        request,
        "apps.html",
        {
            "username": username,
            "enabled": bool(app_raw.get("enabled", False)),
            "observe_sni": bool(app_raw.get("observe_sni", False)),
            "block_via_xdp": bool(app_raw.get("block_via_xdp", False)),
            "prerequisites": _prerequisites(raw),
            "daemon_active": is_daemon_active(),
            "rows": rows,
            "usage_generated": _format_ts(usage.get("generated")),
            "catalog": catalog,
            "config_error": config_error,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/apps/settings")
def save_settings(
    enabled: bool = Form(False),
    observe_sni: bool = Form(False),
    block_via_xdp: bool = Form(False),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    previous = raw.get("app_control") or {}
    raw["app_control"] = {
        "enabled": enabled,
        "observe_sni": observe_sni,
        "block_via_xdp": block_via_xdp,
        "blocked_apps": list(previous.get("blocked_apps") or []),
    }
    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with(
            "/apps", success="Application settings saved -- click Apply on the dashboard to load them"
        )
    return redirect_with("/apps", error=message)


@router.post("/apps/block")
def save_blocked(
    blocked_apps: list[str] = Form([]),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    app_raw = dict(raw.get("app_control") or {})
    # Keep the catalog's order so config.yaml diffs stay stable.
    order = [app.id for app in load_catalog().apps]
    chosen = set(blocked_apps)
    app_raw["blocked_apps"] = [a for a in order if a in chosen] + sorted(chosen - set(order))
    raw["app_control"] = app_raw
    ok, message = try_save(raw, helper)
    if ok:
        count = len(app_raw["blocked_apps"])
        return redirect_with(
            "/apps", success=f"{count} app(s) blocked -- click Apply on the dashboard to enforce"
        )
    return redirect_with("/apps", error=message)
