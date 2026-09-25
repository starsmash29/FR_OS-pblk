"""A cheap snapshot of this router's resources for the webUI dashboard.

Everything here is unprivileged and non-blocking: /proc and statvfs reads,
no sampling interval (the load average stands in for CPU usage, unlike
frfw.metrics' 100 ms /proc/stat sample, so the dashboard never waits).
Every figure is None when its source can't be read -- the dashboard then
shows "-" instead of a made-up number.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from frfw.metrics import _read_cpu_model, _read_ram_totals

_PROC_UPTIME_PATH = Path("/proc/uptime")
_PROC_LOADAVG_PATH = Path("/proc/loadavg")


@dataclass(frozen=True)
class SystemSnapshot:
    kernel: str | None
    cpu_model: str | None
    cpu_count: int | None
    load: tuple[float, float, float] | None
    uptime_seconds: float | None
    ram_used: int | None
    ram_total: int | None
    disk_used: int | None
    disk_total: int | None

    @property
    def load_ratio(self) -> float | None:
        """1-minute load per CPU, capped at 1 -- a rough "how busy" figure."""
        if self.load is None or not self.cpu_count:
            return None
        return min(1.0, self.load[0] / self.cpu_count)

    @property
    def ram_ratio(self) -> float | None:
        return self.ram_used / self.ram_total if self.ram_used is not None and self.ram_total else None

    @property
    def disk_ratio(self) -> float | None:
        return self.disk_used / self.disk_total if self.disk_used is not None and self.disk_total else None


def _read_uptime() -> float | None:
    try:
        return float(_PROC_UPTIME_PATH.read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def _read_load() -> tuple[float, float, float] | None:
    try:
        parts = _PROC_LOADAVG_PATH.read_text().split()
        return float(parts[0]), float(parts[1]), float(parts[2])
    except (OSError, ValueError, IndexError):
        return None


def _read_disk(path: str = "/") -> tuple[int, int] | None:
    try:
        st = os.statvfs(path)
    except OSError:
        return None
    return st.f_frsize * (st.f_blocks - st.f_bfree), st.f_frsize * st.f_blocks


def snapshot() -> SystemSnapshot:
    ram = _read_ram_totals()
    disk = _read_disk()
    return SystemSnapshot(
        kernel=os.uname().release,
        cpu_model=_read_cpu_model(),
        cpu_count=os.cpu_count(),
        load=_read_load(),
        uptime_seconds=_read_uptime(),
        ram_used=ram[0] if ram else None,
        ram_total=ram[1] if ram else None,
        disk_used=disk[0] if disk else None,
        disk_total=disk[1] if disk else None,
    )


def format_bytes(value: int | None) -> str:
    if value is None:
        return "-"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"  # pragma: no cover -- loop always returns


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    minutes = int(seconds // 60)
    days, minutes = divmod(minutes, 24 * 60)
    hours, minutes = divmod(minutes, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"
