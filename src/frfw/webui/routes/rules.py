from __future__ import annotations

import zoneinfo
from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request

from frfw import rule_hits, rule_lint
from frfw.config import ConfigError, parse_config
from frfw.nft.schedule import WEEKDAY_KEYS, describe, is_active, local_minute_of_week
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
    # Schedule text and "active now" come from the parsed config, so they
    # show exactly what the ruleset renders; an invalid config just shows
    # the raw rules without them.
    tz_name = raw.get("timezone")
    schedules: dict[str, dict] = {}
    findings: list[rule_lint.Finding] = []
    expiry: dict[str, dict] = {}
    hits = rule_hits.load()
    try:
        config = parse_config(raw)
        # Security-lessons K2: the rule check, and temporary rules.
        findings = rule_lint.lint(config, hits=hits)
        for rule in config.rules:
            if rule.expires is not None:
                expiry[rule.name] = {"text": _local(rule.expires, config.timezone),
                                     "past": rule.expires <= datetime.now().timestamp()}
        now_minute = local_minute_of_week(config.timezone)
        for rule in config.rules:
            if rule.schedule is not None:
                sched = rule.schedule
                schedules[rule.name] = {
                    "text": describe(sched.days, sched.start, sched.end),
                    "active": is_active(sched.days, sched.start, sched.end, now_minute),
                    "cut": sched.cut_established,
                }
    except (ConfigError, zoneinfo.ZoneInfoNotFoundError, ValueError):
        pass
    try:
        now = datetime.now(zoneinfo.ZoneInfo(tz_name)) if tz_name else datetime.now().astimezone()
        router_time = now.strftime("%a %Y-%m-%d %H:%M %Z")
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        router_time = None
    return templates.TemplateResponse(
        request,
        "rules.html",
        {
            "username": username,
            "rules": raw.get("rules") or [],
            "schedules": schedules,
            "timezone": tz_name or "",
            "router_time": router_time,
            "weekdays": WEEKDAY_KEYS,
            "findings": findings,
            "flagged": {f.rule: f for f in findings},
            "expiry": expiry,
            "last_hit": {name: _local(e["last_hit"], tz_name) if e.get("last_hit") else None
                         for name, e in hits.items()},
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
    require_ztna: bool = Form(False),
    src_mac: str = Form(""),
    schedule_days: list[str] = Form([]),
    schedule_start: str = Form(""),
    schedule_end: str = Form(""),
    cut_established: bool = Form(False),
    expires: str = Form(""),
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
    if require_ztna:
        rule["require_ztna"] = True
    if src_mac.strip():
        rule["src_mac"] = src_mac.strip().lower()
    if schedule_start.strip() or schedule_end.strip():
        schedule: dict = {
            "days": schedule_days or ["daily"],
            "start": schedule_start.strip(),
            "end": schedule_end.strip(),
        }
        if cut_established:
            schedule["cut_established"] = True
        rule["schedule"] = schedule
    if expires.strip():
        rule["expires"] = expires.strip()

    rules = raw.setdefault("rules", [])
    rules[:] = [r for r in rules if r.get("name") != name]  # replace if it already existed
    rules.append(rule)

    ok, message = try_save(raw, helper)
    if not ok:
        return redirect_with("/rules", error=message)
    # Say it right away if the new rule trips the rule check (K2).
    warnings = [f.message for f in rule_lint.lint(parse_config(raw), hits={})
                if f.rule == name and f.severity == rule_lint.WARNING]
    if warnings:
        return redirect_with("/rules", error=f"Rule {name!r} saved, but it " + "; ".join(warnings))
    return redirect_with("/rules", success=f"Rule {name!r} saved")


@router.post("/rules/remove-expired")
def remove_expired(
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    """Temporary rules past their expiry (K2): the kernel already ignores
    them; this tidies config.yaml."""
    try:
        config = parse_config(raw)
    except ConfigError as exc:
        return redirect_with("/rules", error=str(exc))
    now = datetime.now().timestamp()
    gone = {r.name for r in config.rules if r.expires is not None and r.expires <= now}
    if not gone:
        return redirect_with("/rules", success="No expired rules")
    raw["rules"] = [r for r in raw.get("rules") or [] if r.get("name") not in gone]
    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/rules", success=f"Removed {len(gone)} expired rule(s): {', '.join(sorted(gone))}")
    return redirect_with("/rules", error=message)


def _local(ts: float, tz_name: str | None) -> str:
    try:
        zone = zoneinfo.ZoneInfo(tz_name) if tz_name else None
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        zone = None
    moment = datetime.fromtimestamp(ts, zone) if zone else datetime.fromtimestamp(ts).astimezone()
    return moment.strftime("%Y-%m-%d %H:%M")


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


@router.post("/rules/timezone")
def set_timezone(
    timezone: str = Form(""),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    if timezone.strip():
        raw["timezone"] = timezone.strip()
    else:
        raw.pop("timezone", None)
    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with(
            "/rules", success="Time zone saved -- click Apply on the dashboard to re-render scheduled rules"
        )
    return redirect_with("/rules", error=message)
