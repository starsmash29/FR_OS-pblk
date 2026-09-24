"""Ad-block / DNS filtering screen (phase 9, extended in phase 15 -- see
frfw.adblock, frfw.adblock.categories and frfw.adblock.dns_service).

Settings follow the same "edit the raw YAML dict, validate, save through
the privileged helper" pattern as every other screen (see
frfw.webui.actions.try_save) -- saving here never fetches anything or
touches the resolver directly; that happens either on the next `apply`
(which only reconciles the resolver's running state, see
frfw.provision's docstring) or when an admin clicks "Refresh now" (which
goes through the apply-helper's `refresh_adblock` socket command, since
downloading megabytes of third-party blocklist data and writing under
/etc/fr_os is exactly the kind of privileged operation this webUI
process must never do itself).

Categories: the verified presets (frfw.adblock.categories.PRESETS) are
checkboxes; any other category an admin added to config.yaml by hand is
shown and kept as-is, never silently dropped by a save from this form.

The live per-category domain counts and resolver-active badge are read
directly, unprivileged, in this process -- counting lines in
world-readable hosts files and `systemctl is-active` need no elevated
access.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request

from frfw.adblock import BASE_CATEGORY, DEFAULT_SOURCE_URLS, category_counts
from frfw.adblock.categories import PRESETS, PRESETS_BY_NAME
from frfw.adblock.dns_service import is_resolver_active
from frfw.webui.actions import try_save
from frfw.webui.deps import (
    get_adblock_category_dir,
    get_adblock_hosts_path,
    get_helper,
    get_raw_config,
    require_login,
)
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


def _lines(text: str) -> list[str]:
    items: list[str] = []
    for line in text.replace(",", "\n").splitlines():
        item = line.strip()
        if item and item not in items:
            items.append(item)
    return items


@router.get("/adblock")
def show_adblock(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    adblock_hosts_path: Path = Depends(get_adblock_hosts_path),
    category_dir: Path = Depends(get_adblock_category_dir),
):
    adblock_raw = raw.get("adblocker") or {}
    enabled = bool(adblock_raw.get("enabled", False))
    source_urls = list(adblock_raw.get("source_urls") or [])
    xdp_critical_limit = int(adblock_raw.get("xdp_critical_limit", 0) or 0)
    categories = dict(adblock_raw.get("categories") or {})

    counts = category_counts(list(categories), hosts_path=adblock_hosts_path, category_dir=category_dir)
    resolver_active = is_resolver_active()

    if resolver_active:
        status_label, badge_class = "Active", "badge-green"
    elif enabled:
        status_label, badge_class = "Enabled, not yet applied -- run Apply", "badge-yellow"
    else:
        status_label, badge_class = "Disabled", "badge-red"

    custom_categories = {
        name: urls for name, urls in categories.items() if name not in PRESETS_BY_NAME
    }

    return templates.TemplateResponse(
        request,
        "adblock.html",
        {
            "username": username,
            "enabled": enabled,
            "source_urls": source_urls,
            "source_urls_text": "\n".join(source_urls),
            "default_source_url": DEFAULT_SOURCE_URLS[0],
            "xdp_critical_limit": xdp_critical_limit,
            "domain_count": sum(counts.values()),
            "counts": counts,
            "base_category": BASE_CATEGORY,
            "presets": PRESETS,
            "selected_categories": set(categories),
            "custom_categories": custom_categories,
            "allowlist_text": "\n".join(adblock_raw.get("allowlist") or []),
            "serve_lan": bool(adblock_raw.get("serve_lan", False)),
            "force_dns": bool(adblock_raw.get("force_dns", False)),
            "query_logging": bool(adblock_raw.get("query_logging", False)),
            "status_label": status_label,
            "badge_class": badge_class,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/adblock/settings")
def save_settings(
    enabled: bool = Form(False),
    source_urls: str = Form(""),
    xdp_critical_limit: int = Form(0),
    categories: list[str] = Form([]),
    allowlist: str = Form(""),
    serve_lan: bool = Form(False),
    force_dns: bool = Form(False),
    query_logging: bool = Form(False),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    previous = raw.get("adblocker") or {}
    previous_categories = dict(previous.get("categories") or {})

    # Presets come from the form; hand-added categories are carried over.
    new_categories = {
        name: urls for name, urls in previous_categories.items() if name not in PRESETS_BY_NAME
    }
    for name in categories:
        preset = PRESETS_BY_NAME.get(name)
        if preset is None:
            return redirect_with("/adblock", error=f"unknown category {name!r}")
        # Keep an admin's own edited URL list for a preset they already had.
        new_categories[name] = previous_categories.get(name) or list(preset.urls)

    raw["adblocker"] = {
        "enabled": enabled,
        "source_urls": _lines(source_urls),
        "xdp_critical_limit": xdp_critical_limit,
        "categories": new_categories,
        "allowlist": [d.lower() for d in _lines(allowlist)],
        "serve_lan": serve_lan,
        "force_dns": force_dns,
        "query_logging": query_logging,
    }

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with(
            "/adblock",
            success="Ad-block settings saved -- click Refresh now to download new categories, "
            "then Apply on the dashboard",
        )
    return redirect_with("/adblock", error=message)


@router.post("/adblock/refresh")
def refresh_now(
    username: str = Depends(require_login),
    helper: HelperClient = Depends(get_helper),
):
    result = helper.refresh_adblock()
    if result.get("ok"):
        return redirect_with("/adblock", success=result.get("message", "Refreshed"))
    return redirect_with("/adblock", error=result.get("message") or "Refresh failed")
