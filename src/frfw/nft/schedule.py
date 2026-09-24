"""Time-based rule schedules rendered as nftables `meta day` / `meta hour`
matches (phase 17).

An admin writes a schedule in *local* time ("weekdays 22:00-06:00"). Two
facts about how the kernel evaluates nftables time matches, both checked
against the real `nft` 1.0.9 binary and net/netfilter/nft_meta.c, make a
literal translation wrong:

1. `meta hour` is compared against **UTC** seconds since midnight. The
   `nft` tool converts a written "22:00" to UTC *when the ruleset is
   loaded*, using the nft process's own time zone -- so the result
   depends on who ran nft, and it silently goes an hour off after every
   daylight-saving change until the ruleset is reloaded.
2. `meta day` is computed from UTC shifted by the kernel's own time zone
   (`sys_tz`, set with settimeofday -- normally 0, but systemd sets it to
   the local offset when the RTC keeps local time). It is **not** the
   same clock as `meta hour`, so near midnight the two disagree about
   which day it is.

So frfw does the conversion itself: every local weekly interval is moved
to UTC with the configured zone's current offset, cut wherever either
clock crosses midnight, and each piece is rendered with the kernel's day
name and a UTC hour range. The ruleset is then loaded with `TZ=UTC`
(frfw.apply) so nft leaves those hour values alone. When the offset
changes (DST) or the kernel's zone does, `firewall-cli schedule-check`
(hourly timer) notices and re-applies.
"""

from __future__ import annotations

import ctypes
import time
import zoneinfo
from dataclasses import dataclass
from datetime import datetime, timezone

MINUTES_PER_DAY = 24 * 60
MINUTES_PER_WEEK = 7 * MINUTES_PER_DAY

#: Index 0 = Monday, the order used everywhere in frfw (config and clock).
WEEKDAY_KEYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
WEEKDAY_NAMES = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")


@dataclass(frozen=True)
class ScheduleClock:
    """What rendering needs to know about "now": the configured zone's
    offset from UTC, and the kernel's own zone (settimeofday's
    tz_minuteswest -- minutes *west* of Greenwich, so UTC+2 is -120)."""

    utc_offset_minutes: int
    kernel_minuteswest: int = 0

    def describe(self) -> str:
        sign = "+" if self.utc_offset_minutes >= 0 else "-"
        hours, minutes = divmod(abs(self.utc_offset_minutes), 60)
        return f"UTC{sign}{hours:02d}:{minutes:02d}"

    def as_dict(self) -> dict:
        return {
            "utc_offset_minutes": self.utc_offset_minutes,
            "kernel_minuteswest": self.kernel_minuteswest,
        }


@dataclass(frozen=True)
class Segment:
    """One rendered piece: the kernel day names it applies to (None = every
    day) and a UTC seconds-of-day range, inclusive (None = the whole day)."""

    days: tuple[str, ...] | None
    hours: tuple[int, int] | None

    def render(self) -> str:
        parts = []
        if self.days is not None:
            names = [f'"{d}"' for d in self.days]
            parts.append(f"meta day {names[0]}" if len(names) == 1 else f"meta day {{ {', '.join(names)} }}")
        if self.hours is not None:
            parts.append(f'meta hour "{_hms(self.hours[0])}"-"{_hms(self.hours[1])}"')
        return " ".join(parts)


def _hms(seconds: int) -> str:
    h, rest = divmod(seconds, 3600)
    m, s = divmod(rest, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def kernel_minuteswest() -> int:
    """The kernel's sys_tz.tz_minuteswest, via gettimeofday(2) -- the value
    nft_meta_weekday() subtracts. 0 if it can't be read."""
    class _Timeval(ctypes.Structure):
        _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]

    class _Timezone(ctypes.Structure):
        _fields_ = [("tz_minuteswest", ctypes.c_int), ("tz_dsttime", ctypes.c_int)]

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        tv, tz = _Timeval(), _Timezone()
        if libc.gettimeofday(ctypes.byref(tv), ctypes.byref(tz)) != 0:
            return 0
        return int(tz.tz_minuteswest)
    except (OSError, AttributeError):
        return 0


def utc_offset_minutes(tz_name: str | None, now: datetime | None = None) -> int:
    """The zone's current offset; the system's local zone when unset."""
    now = now or datetime.now(timezone.utc)
    if tz_name:
        offset = now.astimezone(zoneinfo.ZoneInfo(tz_name)).utcoffset()
        return int(offset.total_seconds() // 60) if offset is not None else 0
    return int(time.localtime(now.timestamp()).tm_gmtoff // 60)


def current_clock(tz_name: str | None, now: datetime | None = None) -> ScheduleClock:
    return ScheduleClock(utc_offset_minutes(tz_name, now), kernel_minuteswest())


def local_intervals(days: tuple[int, ...], start: int, end: int) -> list[tuple[int, int]]:
    """The schedule as [a, b) minutes-of-week intervals in local time
    (Monday 00:00 = 0). `end <= start` means the window runs past
    midnight into the next day, e.g. Fri 22:00-06:00 ends Sat 06:00."""
    length = end - start if end > start else MINUTES_PER_DAY - start + end
    return [(d * MINUTES_PER_DAY + start, d * MINUTES_PER_DAY + start + length) for d in sorted(days)]


def is_active(days: tuple[int, ...], start: int, end: int, local_minute_of_week: int) -> bool:
    """Whether the schedule covers a local minute-of-week -- the reference
    semantics the rendered segments are tested against."""
    t = local_minute_of_week % MINUTES_PER_WEEK
    for a, b in local_intervals(days, start, end):
        if a <= t < b or a <= t + MINUTES_PER_WEEK < b:
            return True
    return False


def segments(days: tuple[int, ...], start: int, end: int, clock: ScheduleClock) -> list[Segment]:
    """Render a schedule for `clock` (see the module docstring)."""
    kernel_shift = -clock.kernel_minuteswest  # kernel-day clock = UTC + shift

    pieces: list[tuple[int, int]] = []
    for a, b in local_intervals(days, start, end):
        a -= clock.utc_offset_minutes
        b -= clock.utc_offset_minutes
        # Cut at every UTC midnight and every kernel-day midnight.
        cuts = sorted(set(_midnights(a, b, 0)) | set(_midnights(a, b, kernel_shift)))
        bounds = [a, *cuts, b]
        pieces.extend(zip(bounds, bounds[1:]))

    # Group identical UTC hour ranges by kernel day, then merge adjacent
    # ranges that apply to the same days (e.g. a whole-day schedule cut at
    # UTC midnight comes back together).
    by_hours: dict[tuple[int, int], set[int]] = {}
    for p, q in pieces:
        kernel_day = ((p + kernel_shift) // MINUTES_PER_DAY) % 7
        day_start = p - (p % MINUTES_PER_DAY)
        hours = ((p - day_start) * 60, (q - day_start) * 60 - 1)
        by_hours.setdefault(hours, set()).add(kernel_day)
    by_days: dict[frozenset[int], list[tuple[int, int]]] = {}
    for hours, day_set in by_hours.items():
        by_days.setdefault(frozenset(day_set), []).append(hours)

    out = []
    for day_set, ranges in by_days.items():
        merged: list[list[int]] = []
        for lo, hi in sorted(ranges):
            if merged and lo <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        day_names = None if len(day_set) == 7 else tuple(WEEKDAY_NAMES[d] for d in sorted(day_set))
        for lo, hi in merged:
            whole_day = (lo, hi) == (0, MINUTES_PER_DAY * 60 - 1)
            out.append(Segment(day_names, None if whole_day else (lo, hi)))
    out.sort(key=lambda seg: (seg.hours or (0, 0), seg.days or ()))
    return out


def _midnights(a: int, b: int, shift: int) -> list[int]:
    """Minutes t with a < t < b where the clock `UTC + shift` reads 00:00."""
    first = ((a + shift) // MINUTES_PER_DAY + 1) * MINUTES_PER_DAY - shift
    return list(range(first, b, MINUTES_PER_DAY))


def segment_matches(segment: Segment, utc_minute_of_week: int, clock: ScheduleClock) -> bool:
    """What the kernel would decide for one segment at a UTC minute-of-week
    -- mirrors nft_meta_weekday()/nft_meta_hour(). For tests."""
    t = utc_minute_of_week % MINUTES_PER_WEEK
    if segment.days is not None:
        kernel_day = ((t - clock.kernel_minuteswest) // MINUTES_PER_DAY) % 7
        if WEEKDAY_NAMES[kernel_day] not in segment.days:
            return False
    if segment.hours is not None:
        second = (t % MINUTES_PER_DAY) * 60
        if not segment.hours[0] <= second <= segment.hours[1]:
            return False
    return True


def local_minute_of_week(tz_name: str | None, now: datetime | None = None) -> int:
    """Minutes since Monday 00:00 in `tz_name` (system local zone if None)."""
    now = now or datetime.now(timezone.utc)
    local = now.astimezone(zoneinfo.ZoneInfo(tz_name)) if tz_name else now.astimezone()
    return local.weekday() * MINUTES_PER_DAY + local.hour * 60 + local.minute


def describe(days: tuple[int, ...], start: int, end: int) -> str:
    """Human-readable form for the webUI/CLI, e.g. "Mon-Fri 21:30-06:30"."""
    day_set = set(days)
    if day_set == set(range(7)):
        day_text = "Daily"
    elif day_set == {0, 1, 2, 3, 4}:
        day_text = "Mon-Fri"
    elif day_set == {5, 6}:
        day_text = "Sat-Sun"
    else:
        day_text = ", ".join(WEEKDAY_NAMES[d][:3] for d in sorted(day_set))
    fmt = lambda m: f"{m // 60:02d}:{m % 60:02d}"  # noqa: E731
    return f"{day_text} {fmt(start)}-{fmt(end)}"
