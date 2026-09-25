"""frfw.sysinfo: the dashboard's resource snapshot."""

from __future__ import annotations

from frfw import sysinfo
from frfw.sysinfo import SystemSnapshot, format_bytes, format_duration


def test_snapshot_reads_this_machine():
    snap = sysinfo.snapshot()
    assert snap.kernel
    assert snap.cpu_count and snap.cpu_count >= 1
    assert snap.uptime_seconds and snap.uptime_seconds > 0
    assert snap.ram_total and 0 < snap.ram_ratio <= 1
    assert snap.disk_total and 0 <= snap.disk_ratio <= 1
    assert snap.load is not None and 0 <= snap.load_ratio <= 1


def test_unreadable_sources_give_none_not_numbers(monkeypatch, tmp_path):
    monkeypatch.setattr(sysinfo, "_PROC_UPTIME_PATH", tmp_path / "missing")
    monkeypatch.setattr(sysinfo, "_PROC_LOADAVG_PATH", tmp_path / "missing")
    monkeypatch.setattr(sysinfo, "_read_ram_totals", lambda: None)
    monkeypatch.setattr(sysinfo, "_read_disk", lambda path="/": None)
    snap = sysinfo.snapshot()
    assert snap.uptime_seconds is None and snap.load is None
    assert snap.load_ratio is None and snap.ram_ratio is None and snap.disk_ratio is None


def test_load_ratio_is_per_cpu_and_capped():
    base = dict(kernel="k", cpu_model=None, uptime_seconds=1.0, ram_used=None, ram_total=None,
                disk_used=None, disk_total=None)
    assert SystemSnapshot(cpu_count=4, load=(1.0, 0.0, 0.0), **base).load_ratio == 0.25
    assert SystemSnapshot(cpu_count=2, load=(9.0, 0.0, 0.0), **base).load_ratio == 1.0


def test_format_bytes():
    assert format_bytes(None) == "-"
    assert format_bytes(512) == "512 B"
    assert format_bytes(1536) == "1.5 KiB"
    assert format_bytes(16 * 2**30) == "16.0 GiB"


def test_format_duration():
    assert format_duration(None) == "-"
    assert format_duration(59) == "0m"
    assert format_duration(3 * 3600 + 120) == "3h 2m"
    assert format_duration(2 * 86400 + 3600 + 60) == "2d 1h 1m"
