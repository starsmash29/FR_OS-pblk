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

Each stream is a child process, so the route bounds them: one per webUI
session (every live-log tab of a session reads the same child, see
`_LogStream`) and `LOG_STREAM_LIMIT` of them per webUI process (review
v0.2.0 R19). The child is terminated when the session's last tab
disconnects.
"""

from __future__ import annotations

import hashlib
import json
import queue
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import StreamingResponse

from frfw import xdp as xdp_mod
from frfw.webui.actions import try_save
from frfw.webui.auth import COOKIE_NAME
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


#: Ceiling on live journal streams per webUI process, across all
#: sessions (review v0.2.0 R19). Every stream is one `journalctl`
#: child, so this bounds how many an admin can leave running; a tab
#: past the cap gets a clear error frame instead of a stream. The value
#: is a proposal (see "Not done" in the roadmap note), not a measured
#: limit.
LOG_STREAM_LIMIT = 8

#: Frames a tab's queue may hold. A tab that stops reading loses the
#: oldest frames rather than blocking the stream or growing the
#: webUI's memory without bound (the viewer trims its own DOM to 300
#: lines anyway).
_LOG_QUEUE_MAX = 256

#: `Condition.wait` bound while a tab holds out for a frame. The driver
#: notifies on every line, so this only fires when the stream died
#: without its wake-up -- a last-resort re-check, not a poll loop.
_LOG_DRIVE_WAIT_SECONDS = 1.0


def _sse_frame(line: str) -> str | None:
    """One journal line as an SSE frame, or None if it must be dropped.

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
    route runs, so it is present and bound to this browser's session.
    The cookie value itself is a bearer secret: it is never stored or
    logged, only its digest is kept."""
    cookie = request.cookies.get(COOKIE_NAME) or ""
    return hashlib.sha256(cookie.encode()).hexdigest()


class _LogStream:
    """One `journalctl -f` child, shared by every live-log tab of one
    session (review v0.2.0 R19).

    `main` started a child per HTTP request, so N tabs meant N children
    for the same lines. Here the first tab of a session pulls the
    journal and hands every frame to all of its tabs; later tabs read
    from the running stream and start no process of their own. There is
    no background thread: the tab that finds nobody driving takes the
    wheel and pulls the next line in its own request thread. When the
    last tab leaves, its `release` closes the generator -- whose own
    `finally` terminates the child -- so "process ended on
    disconnect" keeps working with one stream per session.
    """

    def __init__(self, session_key: str) -> None:
        self.session_key = session_key
        self._cond = threading.Condition()
        self._subscribers: list[queue.Queue] = []
        self._source: Iterator[str] | None = None
        self._driving = False
        self._finished = False

    @property
    def finished(self) -> bool:
        """No tab may stream from this object any more. Read without this
        object's own lock: the only reader is the registry lookup, which
        holds the registry lock and is what drops a finished stream's
        entry anyway."""
        return self._finished

    def subscribe(self) -> Iterator[str]:
        """This tab's view of the shared stream: already-formatted SSE
        frames, ending when the journal does."""
        subscriber: queue.Queue = queue.Queue(maxsize=_LOG_QUEUE_MAX)
        with self._cond:
            if self._finished:
                subscriber.put_nowait(None)
            else:
                if self._source is None:
                    # The generator body does not run yet, so this
                    # starts no process: the child spawns on the first
                    # pull further below.
                    self._source = _iter_journal_lines(_JOURNALCTL_CMD)
                self._subscribers.append(subscriber)
        try:
            while True:
                frame = self._next_frame(subscriber)
                if frame is None:
                    return
                yield frame
        finally:
            self._release(subscriber)

    def _next_frame(self, subscriber: queue.Queue) -> str | None:
        """The next frame for one tab. Takes the wheel (pulls one line
        out of the journal for everybody) when nobody is driving."""
        while True:
            with self._cond:
                if not subscriber.empty():
                    return subscriber.get()
                if self._finished:
                    return None
                if self._driving or self._source is None:
                    # Another tab is inside the blocking read, or the
                    # stream died between subscribe and now: wait for
                    # its wake-up (or the timeout) and look again.
                    self._cond.wait(timeout=_LOG_DRIVE_WAIT_SECONDS)
                    continue
                self._driving = True
                source = self._source
            self._drive(source)

    def _drive(self, source: Iterator[str]) -> None:
        """Pull one line from the shared source and hand it to every
        tab. Runs in the driving tab's own request thread -- never in a
        background thread and never while holding the lock -- so
        closing that request is what closes the generator."""
        frame: str | None = None
        finished = False
        try:
            try:
                line = next(source)
            except StopIteration:
                self._finish()
                finished = True
            except FileNotFoundError:
                # Same frame `main` sent: the route is unprivileged and
                # the journal is simply absent here. Queued before
                # `_finish`, which ends every tab.
                with self._cond:
                    self._broadcast(
                        _sse_error("journalctl not found -- is systemd installed?")
                    )
                self._finish()
                finished = True
            else:
                frame = _sse_frame(line)
        finally:
            with self._cond:
                if frame is not None:
                    self._broadcast(frame)
                self._driving = False
                self._cond.notify_all()
            if finished:
                self._close_source()

    def _broadcast(self, frame: str) -> None:
        """Put one frame in every tab's queue and wake them. Called with
        `_cond` held, and only ever from the tab that is driving: another
        tab may not take the wheel until the line it just pulled is in
        every queue, so two tabs can't see two lines out of order. It
        only queues (dropping the oldest frame of a tab that stopped
        reading), so it never blocks."""
        subscribers = list(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber.put_nowait(frame)
            except queue.Full:
                # A tab that stopped reading loses the oldest frame
                # rather than blocking the rest of the session.
                try:
                    subscriber.get_nowait()
                except queue.Empty:
                    pass
                try:
                    subscriber.put_nowait(frame)
                except queue.Full:
                    pass
        self._cond.notify_all()

    def _release(self, subscriber: queue.Queue) -> None:
        """One tab went away. The last one ends the stream for the
        session: that is what removes the registry entry and frees the
        cap slot, and what terminates the child."""
        with self._cond:
            if subscriber in self._subscribers:
                self._subscribers.remove(subscriber)
            last = not self._subscribers
        if last:
            self._finish()

    def _finish(self) -> None:
        """End the stream for every tab: marker into every queue, the
        child closed, the registry entry dropped."""
        with self._cond:
            if self._finished:
                return
            self._finished = True
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            _offer_end(subscriber)
        with self._cond:
            self._cond.notify_all()
        self._close_source()
        with _log_streams_lock:
            if _log_streams.get(self.session_key) is self:
                del _log_streams[self.session_key]

    def _close_source(self) -> None:
        """Close the journal generator, which runs its `finally` (`proc.
        terminate()` + `proc.wait(timeout=5)`), unless a tab is inside
        the blocking `next()` on it right now -- then that tab's own
        `_drive`/`_finish` path closes it instead. Never closing from
        outside the driving thread is what makes the child shutdown
        deterministic (no cross-thread `close()`)."""
        with self._cond:
            if self._driving:
                return
            source, self._source = self._source, None
        close = getattr(source, "close", None)
        if close is not None:
            close()


def _offer_end(subscriber: queue.Queue) -> None:
    """The end-of-stream marker must never be dropped for a full queue
    -- a slow tab would otherwise hang behind a finished stream."""
    while True:
        try:
            subscriber.put_nowait(None)
            return
        except queue.Full:
            try:
                subscriber.get_nowait()
            except queue.Empty:
                pass


_log_streams_lock = threading.Lock()
_log_streams: dict[str, _LogStream] = {}


def _acquire_stream(session_key: str) -> _LogStream | None:
    """The session's stream, creating it when there is none. None means
    the process-wide cap (`LOG_STREAM_LIMIT`) is reached: the caller
    sends one error frame and spawns nothing."""
    with _log_streams_lock:
        stream = _log_streams.get(session_key)
        if stream is not None and not stream.finished:
            return stream
        if len(_log_streams) >= LOG_STREAM_LIMIT:
            return None
        stream = _LogStream(session_key)
        _log_streams[session_key] = stream
        return stream


_SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",  # nginx: don't buffer an SSE stream
}


@router.get("/xdp/logs/stream")
def stream_logs(request: Request, username: str = Depends(require_login)):
    stream = _acquire_stream(_session_stream_key(request))
    if stream is None:
        # At the cap (review v0.2.0 R19): one clear frame, no process.
        return StreamingResponse(
            iter([
                _sse_error(
                    f"live log stream limit reached ({LOG_STREAM_LIMIT}) -- "
                    "close a stream and reconnect"
                )
            ]),
            media_type="text/event-stream",
            headers=_SSE_HEADERS,
        )

    return StreamingResponse(
        stream.subscribe(),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )
