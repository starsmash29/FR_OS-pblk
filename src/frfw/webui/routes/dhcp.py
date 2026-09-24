from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request

from frfw.webui.actions import try_save
from frfw.webui.deps import get_helper, get_raw_config, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


def _eligible_zones(raw: dict) -> dict[str, dict]:
    """zone -> its interface, for zones with exactly one addressed interface

    (a DHCP pool's subnet/gateway come from that interface's address --
    see frfw.config.loader._parse_dhcp).
    """
    by_zone: dict[str, list[dict]] = {}
    for iface in (raw.get("interfaces") or {}).values():
        by_zone.setdefault(iface.get("zone"), []).append(iface)
    return {
        zone: ifaces[0]
        for zone, ifaces in by_zone.items()
        if len(ifaces) == 1 and ifaces[0].get("address")
    }


@router.get("/dhcp")
def show_dhcp(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
):
    eligible = _eligible_zones(raw)
    dhcp = raw.get("dhcp") or {}
    zones = [
        {"zone": zone, "interface_address": iface["address"], "pool": dhcp.get(zone)}
        for zone, iface in sorted(eligible.items())
    ]

    return templates.TemplateResponse(
        request,
        "dhcp.html",
        {
            "username": username,
            "zones": zones,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/dhcp/{zone}/save")
def save_pool(
    zone: str,
    range_start: str = Form(...),
    range_end: str = Form(...),
    dns_servers: str = Form(...),
    lease_time: int = Form(3600),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    dhcp = raw.setdefault("dhcp", {})
    existing = dhcp.get(zone) or {}
    dhcp[zone] = {
        "range_start": range_start,
        "range_end": range_end,
        "dns_servers": [s.strip() for s in dns_servers.split(",") if s.strip()],
        "lease_time": lease_time,
        "reservations": existing.get("reservations", []),
    }

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/dhcp", success=f"DHCP pool for {zone!r} saved")
    return redirect_with("/dhcp", error=message)


@router.post("/dhcp/{zone}/delete")
def delete_pool(
    zone: str,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    (raw.get("dhcp") or {}).pop(zone, None)

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/dhcp", success=f"DHCP pool for {zone!r} removed")
    return redirect_with("/dhcp", error=message)


@router.post("/dhcp/{zone}/reservations/add")
def add_reservation(
    zone: str,
    mac: str = Form(...),
    address: str = Form(...),
    hostname: str = Form(""),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    pool = (raw.get("dhcp") or {}).get(zone)
    if pool is None:
        return redirect_with("/dhcp", error=f"No DHCP pool configured for zone {zone!r} yet")

    reservations = pool.setdefault("reservations", [])
    reservations[:] = [r for r in reservations if r.get("mac") != mac]
    entry = {"mac": mac, "address": address}
    if hostname.strip():
        entry["hostname"] = hostname.strip()
    reservations.append(entry)

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/dhcp", success=f"Reservation for {mac!r} saved")
    return redirect_with("/dhcp", error=message)


@router.post("/dhcp/{zone}/reservations/delete/{mac}")
def delete_reservation(
    zone: str,
    mac: str,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    pool = (raw.get("dhcp") or {}).get(zone)
    if pool is None:
        return redirect_with("/dhcp", error=f"No DHCP pool configured for zone {zone!r}")

    pool["reservations"] = [r for r in pool.get("reservations") or [] if r.get("mac") != mac]

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/dhcp", success="Reservation deleted")
    return redirect_with("/dhcp", error=message)
