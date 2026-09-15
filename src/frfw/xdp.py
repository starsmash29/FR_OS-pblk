"""Kernel-space TLS SNI filter orchestrator (phase 4).

Everything here is userspace glue around the real work, which happens
entirely in the kernel in bpf/xdp_sni_filter.c (read that file's header
comment first -- it documents the packet-parsing design, the LPM key
scheme, and real, deliberate limitations this module inherits and does
not try to work around). This module's job is narrow and stays that way
on purpose:

1. Compile the BPF C source if needed (`ensure_compiled`).
2. Load it once and pin the program + its maps under /sys/fs/bpf, so
   attaching to *multiple* interfaces (a WAN and a guest-WiFi uplink,
   say) shares one blocklist and one set of stats/events rather than
   creating an independent copy per interface (`load_and_pin`).
3. Attach the pinned program to each configured interface, preferring
   native driver mode (`xdpdrv`) for wire-speed hardware offload on NICs
   that support it (Intel XL710/ixgbe, Mellanox ConnectX-4/5 and
   similar), falling back to generic/SKB mode (`xdpgeneric`) -- slower
   (a software path, packet already past the driver) but works
   everywhere, including this project's own loopback-based integration
   testing (`attach`).
4. Reconcile the pinned LPM trie's contents with `config.xdp_sni_filter.
   blocklist` (`sync_blocklist`) -- add what's missing, remove what's no
   longer wanted, leave everything else alone (so re-running `apply`
   never has to tear down and rebuild the whole blocklist).
5. Read match events off the ring buffer (`RingBufferReader`,
   `run_event_logger`) entirely decoupled from the kernel's drop
   decision: nothing in this module runs anywhere near the packet path,
   consistent with the C program's own design (it never blocks on
   anything user space does).

Why CLI tools (`ip`, `bpftool`) instead of a Python eBPF library like
bcc or a full libbpf-python binding: this matches every other privileged
operation in frfw (frfw.ifaddr, frfw.apply, frfw.kea all shell out to
the standard system tool rather than binding to a library), keeps the
runtime dependency footprint to "iproute2 and linux-tools for this
kernel", and avoids bcc's much heavier footprint (it embeds a full
clang/LLVM at runtime to JIT-compile BPF C source on every load, whereas
this project compiles once, ahead of time, exactly like a real C
program would be built). The one piece that has no sane CLI equivalent
-- polling the ring buffer without either busy-waiting or shelling out
to a helper program per event -- goes through a small, direct ctypes
binding to libbpf's `ring_buffer__new`/`ring_buffer__poll` instead
(see `RingBufferReader`); this is the one place a real library call
saves real complexity, and it's advisory/read-only (it can never affect
the drop decision), not a broader dependency the way bcc would be.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable

from frfw import __version__, paths
from frfw.config.schema import Config

# --- constants ------------------------------------------------------------

#: Must match bpf/xdp_sni_filter.c's #define exactly. Kept in sync by
#: tests/test_xdp_sni_key.py (which computes keys with this value and
#: compares against known-good bytes worked out by hand), not a shared
#: import, since one side is C and the other Python.
MAX_SNI_LEN = 32
LPM_KEY_LEN = MAX_SNI_LEN + 1

#: struct lpm_sni_key { u32 prefixlen; unsigned char reversed[LPM_KEY_LEN]; }
#: -- 4 + 33 = 37, rounded up to 8-byte alignment by the compiler, and
#: confirmed against the running kernel's own report of the map's key
#: size (`bpftool map show` prints "key 40B") during manual testing.
_KEY_STRUCT_SIZE = ((4 + LPM_KEY_LEN + 7) // 8) * 8

#: struct sni_event's field offsets and total size, confirmed against a
#: real compiled instance of that exact struct definition (see the
#: xdp.py commit message / session notes for how) rather than assumed:
#: saddr(4)@0, daddr(4)@4, sport(2)@8, dport(2)@10, action(1)@12,
#: sni_len(2)@14 (one padding byte at 13 for its 2-byte alignment),
#: sni[MAX_SNI_LEN]@16 -- total 48 bytes for MAX_SNI_LEN=32.
_EVENT_SIZE = 16 + MAX_SNI_LEN

#: Where the compiled program and its maps are pinned once loaded, so
#: multiple interfaces (and multiple frfw processes -- the CLI, the
#: webUI, the event logger daemon) all see and share the same instance
#: rather than each `ip link ... obj file.o` creating an independent
#: copy of the maps.
_PIN_DIR = Path("/sys/fs/bpf/fr_os_xdp")
_PIN_PROG_DIR = _PIN_DIR / "prog"
_PIN_MAPS_DIR = _PIN_DIR / "maps"
PIN_PROG_PATH = _PIN_PROG_DIR / "xdp_sni_filter"
PIN_BLOCKLIST_PATH = _PIN_MAPS_DIR / "sni_blocklist"
PIN_STATS_PATH = _PIN_MAPS_DIR / "stats"
PIN_EVENTS_PATH = _PIN_MAPS_DIR / "events"

#: Index order must match bpf/xdp_sni_filter.c's `enum { STAT_... }`.
STAT_NAMES = ["pass_not_tls", "pass_truncated", "pass_no_sni", "pass_no_match", "drop_match"]


class XdpError(Exception):
    """Raised when compiling, loading, attaching, or configuring the XDP
    SNI filter fails."""


class AttachMode(str, Enum):
    NATIVE = "xdpdrv"
    GENERIC = "xdpgeneric"


@dataclass(frozen=True)
class SyncResult:
    applied: bool
    message: str


@dataclass(frozen=True)
class SniEvent:
    """One decoded record from the kernel's `events` ring buffer --
    always a drop (the kernel program never logs a pass), see
    bpf/xdp_sni_filter.c's `struct sni_event`."""

    saddr: str
    daddr: str
    sport: int
    dport: int
    hostname: str

    @classmethod
    def from_bytes(cls, raw: bytes) -> "SniEvent":
        if len(raw) < _EVENT_SIZE:
            raise XdpError(f"short ring buffer record: {len(raw)} < {_EVENT_SIZE} bytes")
        saddr = socket.inet_ntoa(raw[0:4])
        daddr = socket.inet_ntoa(raw[4:8])
        sport, dport = struct.unpack_from("<HH", raw, 8)
        sni_len = min(struct.unpack_from("<H", raw, 14)[0], MAX_SNI_LEN)
        hostname = raw[16 : 16 + sni_len].decode("ascii", errors="replace")
        return cls(saddr=saddr, daddr=daddr, sport=sport, dport=dport, hostname=hostname)


# --- LPM key construction ---------------------------------------------------


def build_lpm_key(hostname: str) -> bytes:
    """Python port of build_lpm_key() in xdp_sni_filter.c: the LPM trie
    lookup/insert key for `hostname`, matching the kernel program's
    reverse("." + hostname) scheme exactly (see that file's "LPM trie key
    construction" header comment for why this blocks subdomains
    correctly without also matching unrelated domains that merely share
    trailing characters).

    Confirmed byte-for-byte against the kernel's own computed key for a
    real extracted SNI via a temporary bpf_printk during development,
    not derived from the C source by inspection alone -- an earlier
    version of this function (matching an intermediate step of
    build_lpm_key()'s two-phase construction, before its post-barrel-
    shift result) produced a right-aligned key that silently never
    matched anything.
    """
    sni_len = len(hostname)
    if not (0 < sni_len < MAX_SNI_LEN):
        raise XdpError(
            f"hostname length must be in (0, {MAX_SNI_LEN}): {hostname!r} is {sni_len}"
        )
    content = ("." + hostname)[::-1].encode("ascii")
    reversed_buf = content + b"\x00" * (LPM_KEY_LEN - len(content))
    prefixlen = (sni_len + 1) * 8
    key = struct.pack("<I", prefixlen) + reversed_buf
    return key + b"\x00" * (_KEY_STRUCT_SIZE - len(key))


# --- compiling ---------------------------------------------------------------


def _candidate_source_paths() -> list[Path]:
    # Dev/sandbox convenience: running from a git checkout, bpf/ is a
    # sibling of src/. (src/frfw/xdp.py -> parents[2] is the repo root.)
    checkout_src = Path(__file__).resolve().parents[2] / "bpf" / "xdp_sni_filter.c"
    # A real installed deployment: frfw.update keeps each installed
    # release's extracted source tree under RELEASES_DIR permanently
    # (see frfw.update's module docstring), so the exact version
    # currently `pip install`ed has its bpf/ sitting right there too.
    release_src = paths.RELEASES_DIR / f"v{__version__}" / "bpf" / "xdp_sni_filter.c"
    return [checkout_src, release_src]


def ensure_compiled(*, obj_path: Path = paths.XDP_BPF_OBJ_PATH) -> Path:
    """Return a path to a compiled xdp_sni_filter.o, compiling it with
    clang if `obj_path` is missing or older than the source it can find.

    A production image (installer/live-build) ships `obj_path`
    precompiled, so this is normally a same-mtime no-op that never shells
    out to clang at all -- a router appliance image has no business
    assuming a C compiler is installed. Compiling here is what this
    project's own manual verification of the kernel program used, and is
    a reasonable fallback for a from-source dev checkout.
    """
    source = next((p for p in _candidate_source_paths() if p.is_file()), None)

    if obj_path.is_file() and (source is None or obj_path.stat().st_mtime >= source.stat().st_mtime):
        return obj_path

    if source is None:
        raise XdpError(
            f"No compiled XDP object at {obj_path} and no bpf/xdp_sni_filter.c "
            "source found to compile it from."
        )

    obj_path.parent.mkdir(parents=True, exist_ok=True)
    arch = os.uname().machine
    cmd = [
        "clang", "-O2", "-g", "-target", "bpf",
        "-I", f"/usr/include/{arch}-linux-gnu",
        "-c", str(source), "-o", str(obj_path),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise XdpError(f"Compiling {source} failed:\n{proc.stderr}")
    return obj_path


# --- loading / pinning -------------------------------------------------------


def is_loaded() -> bool:
    return PIN_PROG_PATH.exists()


def load_and_pin(obj_path: Path) -> None:
    """Load the compiled program once, pinning it and every one of its
    maps under /sys/fs/bpf so later attach() calls (possibly from a
    different process entirely) can reuse the same instance. Idempotent:
    if already pinned, does nothing -- in particular, this never resets
    an already-populated blocklist map."""
    if is_loaded():
        return
    _PIN_PROG_DIR.mkdir(parents=True, exist_ok=True)
    _PIN_MAPS_DIR.mkdir(parents=True, exist_ok=True)
    proc = _bpftool([
        "prog", "loadall", str(obj_path), str(_PIN_PROG_DIR),
        "type", "xdp", "pinmaps", str(_PIN_MAPS_DIR),
    ])
    if proc.returncode != 0:
        raise XdpError(f"Loading {obj_path} failed:\n{proc.stderr}")


def unload() -> None:
    """Remove the pinned program and maps. Only call once nothing is
    still attached to the program (detach() every interface first) --
    this does not itself detach anything."""
    for p in (PIN_PROG_PATH, PIN_BLOCKLIST_PATH, PIN_STATS_PATH, PIN_EVENTS_PATH):
        p.unlink(missing_ok=True)
    for d in (_PIN_PROG_DIR, _PIN_MAPS_DIR, _PIN_DIR):
        try:
            d.rmdir()
        except OSError:
            pass


# --- attach / detach ---------------------------------------------------------


def attach(device: str) -> AttachMode:
    """Attach the pinned program to `device`, trying native (driver)
    mode first, falling back to generic mode. Raises XdpError if both
    fail (e.g. the interface doesn't exist)."""
    last_stderr = ""
    for mode in (AttachMode.NATIVE, AttachMode.GENERIC):
        proc = _run_ip(["link", "set", "dev", device, mode.value, "pinned", str(PIN_PROG_PATH)])
        if proc.returncode == 0:
            return mode
        last_stderr = proc.stderr
    raise XdpError(
        f"Failed to attach XDP program to {device} in either native or "
        f"generic mode: {last_stderr.strip()}"
    )


def detach(device: str, mode: AttachMode) -> None:
    proc = _run_ip(["link", "set", "dev", device, mode.value, "off"])
    if proc.returncode != 0:
        raise XdpError(f"Failed to detach XDP program from {device}: {proc.stderr.strip()}")


# --- blocklist reconciliation -------------------------------------------------


def sync_blocklist(hostnames: list[str]) -> None:
    """Make the pinned LPM trie's contents exactly match `hostnames`:
    add whatever's missing, remove whatever's no longer wanted, touch
    nothing else. Safe to call repeatedly (e.g. on every `apply`)."""
    desired = {build_lpm_key(h) for h in hostnames}
    existing = _dump_lpm_keys(PIN_BLOCKLIST_PATH)
    for key in existing - desired:
        _map_delete(PIN_BLOCKLIST_PATH, key)
    for key in desired - existing:
        _map_update(PIN_BLOCKLIST_PATH, key, b"\x01")


def _dump_lpm_keys(map_path: Path) -> set[bytes]:
    # Deliberately no `-j`/`-p`: bpftool's default (non-JSON-flag) `map
    # dump` output is *also* JSON, but only the BTF-decoded view (e.g.
    # `{"key": {"prefixlen": 160, "reversed": [...]}, "value": 1}`);
    # passing -j/-p additionally wraps that same view inside a top-level
    # "formatted" key alongside the raw hex-byte arrays, which changes
    # this function's parsing entirely depending on which flag was used
    # -- confirmed against the real installed bpftool binary during
    # development, not assumed from documentation.
    proc = _bpftool(["map", "dump", "pinned", str(map_path)])
    if proc.returncode != 0:
        raise XdpError(f"Dumping {map_path} failed:\n{proc.stderr}")
    entries = json.loads(proc.stdout or "[]")
    keys = set()
    for entry in entries:
        prefixlen = entry["key"]["prefixlen"]
        reversed_bytes = bytes(entry["key"]["reversed"])
        raw = struct.pack("<I", prefixlen) + reversed_bytes
        keys.add(raw + b"\x00" * (_KEY_STRUCT_SIZE - len(raw)))
    return keys


def _key_hex_args(data: bytes) -> list[str]:
    return [f"0x{b:02x}" for b in data]


def _map_update(map_path: Path, key: bytes, value: bytes) -> None:
    proc = _bpftool([
        "map", "update", "pinned", str(map_path),
        "key", *_key_hex_args(key), "value", *_key_hex_args(value),
    ])
    if proc.returncode != 0:
        raise XdpError(f"Updating {map_path} failed:\n{proc.stderr}")


def _map_delete(map_path: Path, key: bytes) -> None:
    proc = _bpftool(["map", "delete", "pinned", str(map_path), "key", *_key_hex_args(key)])
    if proc.returncode != 0:
        raise XdpError(f"Deleting from {map_path} failed:\n{proc.stderr}")


def get_stats() -> dict[str, int]:
    """Read the cheap per-category packet counters (see STAT_NAMES),
    for the webUI/CLI status display. All zero if the filter has never
    been loaded."""
    counts = {name: 0 for name in STAT_NAMES}
    if not PIN_STATS_PATH.exists():
        return counts
    proc = _bpftool(["map", "dump", "pinned", str(PIN_STATS_PATH)])  # see _dump_lpm_keys re: no -j
    if proc.returncode != 0:
        raise XdpError(f"Dumping stats failed:\n{proc.stderr}")
    for entry in json.loads(proc.stdout or "[]"):
        idx, value = entry["key"], entry["value"]
        if 0 <= idx < len(STAT_NAMES):
            counts[STAT_NAMES[idx]] = value
    return counts


# --- state persistence (which interfaces are currently attached, in which mode) --


@dataclass
class XdpState:
    attached: dict[str, str] = field(default_factory=dict)  # device -> AttachMode.value


def get_attached(state_path: Path = paths.XDP_STATE_PATH) -> dict[str, str]:
    """Public read-only view of which interfaces are currently attached
    and in which mode, for the CLI/webUI status display."""
    return dict(_load_state(state_path).attached)


def _load_state(state_path: Path) -> XdpState:
    if not state_path.is_file():
        return XdpState()
    try:
        data = json.loads(state_path.read_text())
    except (json.JSONDecodeError, OSError):
        return XdpState()
    return XdpState(attached=dict(data.get("attached", {})))


def _save_state(state: XdpState, state_path: Path) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps({"attached": state.attached}))


# --- top-level sync (the frfw.provision.apply_all entry point) --------------


def sync_sni_filter(
    config: Config,
    *,
    dry_run: bool = False,
    state_path: Path = paths.XDP_STATE_PATH,
) -> SyncResult:
    """Reconcile the running system's XDP SNI filter state with
    `config.xdp_sni_filter`: attach/detach interfaces and sync the
    blocklist as needed. This is the one function frfw.provision calls;
    everything else in this module is a building block for it (or for
    the separate event-logger daemon, which never touches attach state).

    `state_path` defaults to the real system path (paths.XDP_STATE_PATH)
    but is overridable, the same way frfw.provision.apply_all's
    backup_dir/kea_config_path are, so tests never touch it."""
    cfg = config.xdp_sni_filter
    state = _load_state(state_path)

    if not cfg.enabled:
        if not state.attached:
            return SyncResult(applied=False, message="XDP SNI filter disabled; nothing to do")
        devices = sorted(state.attached)
        if dry_run:
            return SyncResult(
                applied=False,
                message=f"Would detach XDP SNI filter from: {', '.join(devices)}",
            )
        _require_root()
        for device, mode in state.attached.items():
            detach(device, AttachMode(mode))
        unload()
        _save_state(XdpState(), state_path)
        return SyncResult(applied=True, message=f"Detached XDP SNI filter from: {', '.join(devices)}")

    devices = [config.interfaces[name].device for name in cfg.interfaces]
    if dry_run:
        return SyncResult(
            applied=False,
            message=(
                f"Would attach XDP SNI filter to: {', '.join(devices)} "
                f"({len(cfg.blocklist)} blocked hostnames)"
            ),
        )

    _require_root()
    obj_path = ensure_compiled()
    load_and_pin(obj_path)

    new_attached: dict[str, str] = {}
    modes_used = []
    for device in devices:
        if device in state.attached:
            new_attached[device] = state.attached[device]
            continue
        mode = attach(device)
        new_attached[device] = mode.value
        modes_used.append(f"{device}={mode.value}")

    for device, mode in state.attached.items():
        if device not in new_attached:
            detach(device, AttachMode(mode))

    sync_blocklist(cfg.blocklist)
    _save_state(XdpState(attached=new_attached), state_path)

    detail = f" ({', '.join(modes_used)})" if modes_used else ""
    return SyncResult(
        applied=True,
        message=(
            f"XDP SNI filter attached to: {', '.join(devices)}{detail}, "
            f"{len(cfg.blocklist)} blocked hostnames"
        ),
    )


# --- ring buffer reader -------------------------------------------------------

_RINGBUF_CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)


def _load_libbpf() -> ctypes.CDLL:
    name = ctypes.util.find_library("bpf")
    if not name:
        raise XdpError("libbpf shared library not found; install libbpf1 (or equivalent)")
    lib = ctypes.CDLL(name)
    lib.bpf_obj_get.restype = ctypes.c_int
    lib.bpf_obj_get.argtypes = [ctypes.c_char_p]
    lib.ring_buffer__new.restype = ctypes.c_void_p
    lib.ring_buffer__new.argtypes = [ctypes.c_int, _RINGBUF_CB, ctypes.c_void_p, ctypes.c_void_p]
    lib.ring_buffer__poll.restype = ctypes.c_int
    lib.ring_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ring_buffer__free.restype = None
    lib.ring_buffer__free.argtypes = [ctypes.c_void_p]
    return lib


class RingBufferReader:
    """Reads `SniEvent`s off the kernel's pinned ring buffer map via a
    direct ctypes binding to libbpf's `ring_buffer__new`/`__poll`/
    `__free` -- no polling loop busy-waiting: `ring_buffer__poll` blocks
    inside libbpf (via epoll on the ring buffer's underlying fd) up to
    its timeout, waking immediately when a new record is submitted, so
    an idle filter costs essentially no CPU here. This is the only piece
    of this module built on a direct C library call rather than a CLI
    tool -- see this module's docstring for why.

    Usage: `with RingBufferReader(on_event) as r: while True: r.poll()`.
    """

    def __init__(self, on_event: Callable[[SniEvent], None], map_path: Path = PIN_EVENTS_PATH):
        if not map_path.exists():
            raise XdpError(
                f"Ring buffer map not found at {map_path} -- is the XDP SNI "
                "filter loaded (frfw.xdp.sync_sni_filter with enabled: true)?"
            )
        self._on_event = on_event
        self._libbpf = _load_libbpf()
        fd = self._libbpf.bpf_obj_get(str(map_path).encode())
        if fd < 0:
            raise XdpError(f"bpf_obj_get({map_path}) failed")
        self._cb = _RINGBUF_CB(self._handle_sample)
        self._rb = self._libbpf.ring_buffer__new(fd, self._cb, None, None)
        if not self._rb:
            raise XdpError("ring_buffer__new() failed")

    def _handle_sample(self, _ctx, data, size) -> int:
        raw = ctypes.string_at(data, size)
        try:
            event = SniEvent.from_bytes(raw)
        except XdpError:
            return 0
        self._on_event(event)
        return 0

    def poll(self, timeout_ms: int = 200) -> int:
        """Blocks up to `timeout_ms` waiting for at least one record;
        returns the number of records processed (0 on timeout)."""
        return self._libbpf.ring_buffer__poll(self._rb, timeout_ms)

    def close(self) -> None:
        if self._rb is not None:
            self._libbpf.ring_buffer__free(self._rb)
            self._rb = None

    def __enter__(self) -> "RingBufferReader":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def run_event_logger(*, poll_timeout_ms: int = 500) -> None:
    """Blocking entry point for the event-logger daemon (see
    systemd/fr-xdp-sni-logger.service): waits for the pinned events map
    to exist (created only once `sync_sni_filter` has run with
    `enabled: true`, which may not have happened yet on first boot, or
    ever, if the feature is off), then logs every match to stdout
    (captured by journald under that unit) forever. Runs as an
    unprivileged, read-only consumer of a map it did not create --
    reading a ring buffer needs no special privilege beyond being able
    to open the pinned path."""
    while not PIN_EVENTS_PATH.exists():
        time.sleep(2)

    def _log(event: SniEvent) -> None:
        print(
            f"XDP SNI DROP {event.saddr}:{event.sport} -> "
            f"{event.daddr}:{event.dport} sni={event.hostname!r}",
            flush=True,
        )

    with RingBufferReader(_log) as reader:
        while True:
            reader.poll(poll_timeout_ms)


def main() -> None:
    run_event_logger()


# --- small subprocess helpers -------------------------------------------------


def _require_root() -> None:
    if os.geteuid() != 0:
        raise XdpError("This operation requires root privileges.")


def _run_ip(args: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["ip", *args], capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise XdpError("'ip' binary not found; install the iproute2 package") from exc


def _bpftool(args: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["bpftool", *args], capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise XdpError(
            "'bpftool' not found; install the linux-tools package matching this kernel"
        ) from exc


if __name__ == "__main__":
    main()
