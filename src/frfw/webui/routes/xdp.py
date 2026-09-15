"""XDP TLS SNI filter screen (phase 4, see frfw.xdp and bpf/xdp_sni_filter.c).

Settings (enabled/interfaces/blocklist) follow the same "edit the raw
YAML dict, validate, save through the privileged helper" pattern as
every other screen (see frfw.webui.actions.try_save) -- attaching or
detaching the actual XDP program never happens from this process
directly; it happens the next time `apply` runs (CLI or the "Apply"
button on the dashboard), exactly like an nftables ruleset or Kea config
change. This page's status card reflects live kernel state
(`frfw.xdp.get_attached`/`get_stats`, both read-only, root-optional --
they return empty/zero rather than raising when the filter has never
been loaded), which is deliberately allowed to disagree with the
*configured* state shown in the settings form and blocklist table until
the next apply -- the same "config vs. running state can drift until
you apply" reality every other screen already lives with.

The live log stream (`GET /xdp/logs/stream`) is the one part of this
screen that isn't config-editing: it tails the fr-xdp-sni-logger
systemd unit's own journal via `journalctl -f`, not the kernel ring
buffer directly. The ring buffer's pinned map is root-only (see
frfw.xdp.RingBufferReader's docstring), and this webUI process
deliberately runs as an unprivileged user (see systemd/fr-webui.service)
-- reading already-logged, already-decoded JSON lines back out of the
journal (systemd/fr-webui.service grants read-only journal access via
`SupplementaryGroups=systemd-journal`, the standard low-privilege way to
do this) avoids needing to widen that at all.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import StreamingResponse

from frfw import xdp as xdp_mod
from frfw.webui.actions import try_save
from frfw.webui.deps import get_helper, get_raw_config, get_xdp_state_path, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()

#: The unit fr-xdp-sni-logger.service runs as (see that file) -- `-o cat`
#: strips journald's own prefix (timestamp/hostname/unit), leaving
#: exactly the JSON line frfw.xdp.format_event_json wrote; `-n 50` seeds
#: the stream with recent history before following live.
_JOURNALCTL_CMD = [
    "journalctl",
    "-u", "fr-xdp-sni-logger.service",
    "-o", "cat",
    "-f",
    "-n", "50",
]


def _device_to_name(raw: dict) -> dict[str, str]:
    """device (e.g. "eth0") -> logical interface name (e.g. "wan")."""
    return {
        iface.get("device"): name
        for name, iface in (raw.get("interfaces") or {}).items()
        if iface.get("device")
    }


def _status_for(mode: str) -> tuple[str, str]:
    """AttachMode value -> (display label, badge CSS class)."""
    if mode == xdp_mod.AttachMode.NATIVE.value:
        return "Native / Driver (xdpdrv)", "badge-green"
    return "Generic / SKB (xdpgeneric)", "badge-yellow"


@router.get("/xdp")
def show_xdp(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    xdp_state_path: Path = Depends(get_xdp_state_path),
):
    xdp_raw = raw.get("xdp_sni_filter") or {}
    enabled = bool(xdp_raw.get("enabled", False))
    configured_interfaces = list(xdp_raw.get("interfaces") or [])
    blocked_domains = list(xdp_raw.get("blocklist") or [])
    available_interfaces = sorted(raw.get("interfaces") or {})

    device_to_name = _device_to_name(raw)
    try:
        attached = xdp_mod.get_attached(state_path=xdp_state_path)
    except xdp_mod.XdpError:
        attached = {}
    try:
        stats = xdp_mod.get_stats()
    except xdp_mod.XdpError:
        stats = {name: 0 for name in xdp_mod.STAT_NAMES}

    interfaces_status = [
        {
            "name": device_to_name.get(device, device),
            "device": device,
            "label": _status_for(mode)[0],
            "badge_class": _status_for(mode)[1],
        }
        for device, mode in sorted(attached.items())
    ]

    if interfaces_status:
        primary = interfaces_status[0]
        interface = primary["name"]
        xdp_status = primary["label"]
        badge_class = primary["badge_class"]
    elif enabled:
        interface = ", ".join(configured_interfaces) or "(none configured)"
        xdp_status = "Not attached yet -- run Apply"
        badge_class = "badge-red"
    else:
        interface = configured_interfaces[0] if configured_interfaces else "-"
        xdp_status = "Disabled"
        badge_class = "badge-red"

    return templates.TemplateResponse(
        request,
        "xdp.html",
        {
            "username": username,
            "enabled": enabled,
            "configured_interfaces": configured_interfaces,
            "available_interfaces": available_interfaces,
            "blocked_domains": blocked_domains,
            "blocklist_text": "\n".join(blocked_domains),
            "interface": interface,
            "xdp_status": xdp_status,
            "badge_class": badge_class,
            "interfaces_status": interfaces_status,
            "stats": stats,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/xdp/settings")
def save_settings(
    enabled: bool = Form(False),
    interfaces: list[str] = Form([]),
    blocklist: str = Form(""),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    domains = []
    for line in blocklist.replace(",", "\n").splitlines():
        domain = line.strip()
        if domain and domain not in domains:
            domains.append(domain)

    raw["xdp_sni_filter"] = {
        "enabled": enabled,
        "interfaces": interfaces,
        "blocklist": domains,
    }

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with(
            "/xdp",
            success="XDP SNI filter settings saved -- click Apply on the "
            "dashboard to load them into the kernel",
        )
    return redirect_with("/xdp", error=message)


@router.post("/xdp/blocklist/remove")
def remove_domain(
    domain: str = Form(...),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    xdp_raw = raw.setdefault("xdp_sni_filter", {})
    xdp_raw["blocklist"] = [d for d in (xdp_raw.get("blocklist") or []) if d != domain]

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/xdp", success=f"Removed {domain!r} from the blocklist")
    return redirect_with("/xdp", error=message)


def _iter_journal_lines(cmd: list[str]) -> Iterator[str]:
    """Runs `cmd` (a `journalctl -f ...` invocation) and yields its
    stdout line by line as it's produced, forever (until the process
    ends or the generator is closed by the client disconnecting).
    Separated out from the route so tests can monkeypatch this one
    function with a fake, finite line source instead of needing a real
    systemd journal."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, bufsize=1)
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            yield line.rstrip("\n")
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@router.get("/xdp/logs/stream")
def stream_logs(username: str = Depends(require_login)):
    def event_source() -> Iterator[str]:
        try:
            for line in _iter_journal_lines(_JOURNALCTL_CMD):
                if not line:
                    continue
                # Each line is already a JSON object (frfw.xdp.
                # format_event_json); forward it verbatim as the SSE
                # payload rather than re-encoding, but validate it
                # parses so a corrupt/partial line can't break the
                # browser-side JSON.parse().
                try:
                    json.loads(line)
                except ValueError:
                    continue
                yield f"data: {line}\n\n"
        except FileNotFoundError:
            yield (
                'data: {"error": "journalctl not found -- is systemd installed?"}\n\n'
            )

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # nginx: don't buffer an SSE stream
        },
    )
