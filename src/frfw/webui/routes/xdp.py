"""XDP TLS SNI filter screen (phase 4, see frfw.xdp and bpf/xdp_sni_filter.c).

Settings (enabled/interfaces/blocklist) follow the same "edit the raw
YAML dict, validate, save through the privileged helper" pattern as
every other screen (see frfw.webui.actions.try_save) -- attaching or
detaching the actual XDP program never happens from this process
directly; it happens the next time `apply` runs (CLI or the "Apply"
button on the dashboard), exactly like an nftables ruleset or Kea config
change. This page's status card reflects live kernel state -- which
interfaces run the program (`frfw.xdp.get_attached`, `ip -j link`, no
privilege needed) and its packet counters, which come through the
apply-helper's read-only `xdp_stats` (ROADMAP P4-1: they live on bpffs,
root's) -- and is deliberately allowed to disagree with the
*configured* state shown in the settings form and blocklist table until
the next apply -- the same "config vs. running state can drift until
you apply" reality every other screen already lives with.

The live log stream (`GET /xdp/logs/stream`) is the one part of this
screen that isn't config-editing: it follows the fr-xdp-sni-logger
unit's event file (paths.SNI_EVENTS_PATH) with `tail -F`, not the kernel
ring buffer directly. The ring buffer's pinned map is root-only (see
frfw.xdp.RingBufferReader's docstring), and this webUI process
deliberately runs as an unprivileged user (see systemd/fr-webui.service).
The event file is the logger's own, readable by the fr_os-webui group:
this process needs no journal access at all, so it can't read every
other unit's log either (ROADMAP SEC-4, review v0.2.0 R10).

Each stream is a child process, so the route bounds them: one per webUI
session (every live-log tab of a session reads the same child, see
`_LogStream`) and `LOG_STREAM_LIMIT` of them per webUI process (review
v0.2.0 R19). The child is terminated when the session's last tab
disconnects.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from frfw import paths
from frfw import xdp as xdp_mod
from frfw.helper.client import HelperError
from frfw.webui.actions import try_save
from frfw.webui.auth import COOKIE_NAME
from frfw.webui.deps import get_helper, get_raw_config, get_xdp_state_path, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()

#: Follow the SNI event file: `-n 50` seeds the stream with recent
#: history, `-F` follows on through the logger emptying it at its size
#: cap and waits for it if it doesn't exist yet. Each line is already the
#: JSON frfw.xdp.format_event_json wrote.
_EVENTS_CMD = ["tail", "-n", "50", "-F", "--", str(paths.SNI_EVENTS_PATH)]


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
    helper: HelperClient = Depends(get_helper),
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
    # The counters live on bpffs, root's: the apply-helper reads them
    # (ROADMAP P4-1). If it can't, say so rather than show zeros that
    # look like "nothing dropped".
    try:
        result = helper.xdp_stats()
    except HelperError:
        result = {}
    stats = result.get("stats") if result.get("ok") else None

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


#: Ceiling on live log streams per webUI process, across all
#: sessions (review v0.2.0 R19). Every stream is one `tail`
#: child, so this bounds how many an admin can leave running; a tab
#: past the cap gets a clear error frame instead of a stream. 8 leaves
#: room for an admin with a few live-log tabs on more than one device
#: while keeping the worst case far below any process limit a router
#: hits. A module constant, not a config key: it bounds a resource,
#: it is not a preference.
LOG_STREAM_LIMIT = 8

#: Frames a tab's queue may hold. A tab that stops reading loses the
#: oldest frames rather than blocking the session's stream or growing
#: the webUI's memory without bound (the viewer trims its own DOM to
#: 300 lines anyway).
_LOG_QUEUE_MAX = 256

#: Seconds between SSE keep-alive comments while the log is quiet.
#: It is also the bound on noticing a gone browser: a tab checks for a
#: disconnect at least this often, so a quiet log can't keep a
#: closed tab's `tail` alive (and its cap slot taken) forever.
LOG_HEARTBEAT_SECONDS = 15.0

_KEEPALIVE = ": keepalive\n\n"


def _sse_frame(line: str) -> str | None:
    """One event-log line as an SSE frame, or None if it must be dropped.

    Each line is already a JSON object (frfw.xdp.format_event_json);
    forward it verbatim as the SSE payload rather than re-encoding, but
    validate it parses so a corrupt/partial line can't break the
    browser-side JSON.parse()."""
    if not line:
        return None
    try:
        json.loads(line)
    except ValueError:
        return None
    return f"data: {line}\n\n"


def _sse_error(message: str) -> str:
    return f"data: {json.dumps({'error': message})}\n\n"


def _session_stream_key(request: Request) -> str:
    """The webUI session behind this request, as a registry key.

    `require_login` has already validated the cookie by the time the
    route runs. The cookie value is a bearer secret: only its digest is
    kept. A missing cookie fails closed rather than digesting to the
    hash of the empty string, a key every such caller would share."""
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return hashlib.sha256(cookie.encode()).hexdigest()


def _offer(subscriber: asyncio.Queue, frame: str | None) -> None:
    """Queue a frame without blocking: a tab that stopped reading loses
    its oldest frame. The end marker (None) is never the one dropped."""
    while True:
        try:
            subscriber.put_nowait(frame)
            return
        except asyncio.QueueFull:
            try:
                subscriber.get_nowait()
            except asyncio.QueueEmpty:
                pass


class _LogStream:
    """One `tail -F` child per webUI session, fanned out to every
    live-log tab of that session (review v0.2.0 R19).

    A single asyncio task (`_pump`) owns the child: it reads the log
    and puts each frame into every tab's queue. The last tab to leave
    cancels the task, and the task's own `finally` ends the child -- the
    cleanup runs in the pump's task, not in the cancelled request's, so
    a client disconnect can't interrupt it halfway. Everything here runs
    on the event loop, so no lock is needed.
    """

    def __init__(self, session_key: str) -> None:
        self.session_key = session_key
        self.subscribers: set[asyncio.Queue] = set()
        self.finished = False
        self._task: asyncio.Task | None = None

    def subscribe(self) -> asyncio.Queue:
        subscriber: asyncio.Queue = asyncio.Queue(maxsize=_LOG_QUEUE_MAX)
        self.subscribers.add(subscriber)
        if self._task is None:
            self._task = asyncio.get_running_loop().create_task(self._pump())
        return subscriber

    def unsubscribe(self, subscriber: asyncio.Queue) -> None:
        """One tab went away; the last one ends the session's stream."""
        self.subscribers.discard(subscriber)
        if self.subscribers or self.finished:
            return
        if self._task is not None and not self._task.done():
            self._task.cancel()  # the pump's `finally` ends the child
        else:
            self._end()

    def _broadcast(self, frame: str) -> None:
        for subscriber in list(self.subscribers):
            _offer(subscriber, frame)

    def _end(self) -> None:
        """No tab may stream from this object any more: wake every tab
        with the end marker and give the session's cap slot back."""
        if self.finished:
            return
        self.finished = True
        for subscriber in list(self.subscribers):
            _offer(subscriber, None)
        if _log_streams.get(self.session_key) is self:
            del _log_streams[self.session_key]

    async def _watch_errors(self, stderr: asyncio.StreamReader) -> None:
        """`tail -F` keeps retrying a file it can't open and says why on
        stderr. A missing file is normal before the logger first starts;
        one this process may not read is a broken install, and the
        stream says so once instead of staying silent."""
        reported = False
        while True:
            raw = await stderr.readline()
            if not raw:
                return
            if not reported and b"Permission denied" in raw:
                self._broadcast(_sse_error("cannot read the SNI event log (permission denied)"))
                reported = True

    async def _pump(self) -> None:
        proc: asyncio.subprocess.Process | None = None
        watcher: asyncio.Task | None = None
        try:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *_EVENTS_CMD,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    stdin=asyncio.subprocess.DEVNULL,
                )
            except FileNotFoundError:
                self._broadcast(_sse_error("tail not found -- is coreutils installed?"))
                return
            assert proc.stderr is not None
            watcher = asyncio.get_running_loop().create_task(self._watch_errors(proc.stderr))
            assert proc.stdout is not None
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    return  # the child died
                frame = _sse_frame(raw.decode("utf-8", "replace").rstrip("\n"))
                if frame is not None:
                    self._broadcast(frame)
        finally:
            if watcher is not None:
                watcher.cancel()
            if proc is not None and proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    proc.kill()
            self._end()


_log_streams: dict[str, _LogStream] = {}


def _acquire_stream(session_key: str) -> _LogStream | None:
    """The session's stream, creating it when there is none. None means
    the process-wide cap (`LOG_STREAM_LIMIT`) is reached: the caller
    sends one error frame and spawns nothing."""
    stream = _log_streams.get(session_key)
    if stream is not None and not stream.finished:
        return stream
    if len(_log_streams) >= LOG_STREAM_LIMIT:
        return None
    stream = _LogStream(session_key)
    _log_streams[session_key] = stream
    return stream


async def _tab(session_key: str, request: Request) -> AsyncIterator[str]:
    """One browser tab's view of its session's stream.

    The stream is looked up (or started) and subscribed to here, in the
    body Starlette iterates, not in the route: a response that is never
    started -- the client gone before the first byte -- then holds no
    cap slot and no subscription. Lookup and subscribe run with no
    `await` between them, so the stream can't finish in the gap.

    Between frames -- and at least every LOG_HEARTBEAT_SECONDS on a
    quiet log, when it sends a keep-alive comment -- the tab asks
    whether its client is still there. That check is what ends a closed
    tab: a server writing to a gone client is not told so, and a quiet
    log gives it nothing to write."""
    stream = _acquire_stream(session_key)
    if stream is None:
        # At the cap (review v0.2.0 R19): one clear frame, no process.
        yield _sse_error(
            f"live log stream limit reached ({LOG_STREAM_LIMIT}) -- "
            "close a stream and reconnect"
        )
        return
    subscriber = stream.subscribe()
    try:
        while True:
            try:
                frame = await asyncio.wait_for(subscriber.get(), timeout=LOG_HEARTBEAT_SECONDS)
            except asyncio.TimeoutError:
                frame = _KEEPALIVE
            if frame is None or await request.is_disconnected():
                return
            yield frame
    finally:
        # Synchronous on purpose: a cancelled request can't run an
        # `await` here, so the child's shutdown belongs to the pump task.
        stream.unsubscribe(subscriber)


_SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",  # nginx: don't buffer an SSE stream
}


@router.get("/xdp/logs/stream")
async def stream_logs(request: Request, username: str = Depends(require_login)):
    return StreamingResponse(
        _tab(_session_stream_key(request), request),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )
