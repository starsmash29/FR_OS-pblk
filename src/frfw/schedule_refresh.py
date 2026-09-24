"""Keep scheduled rules correct across DST and time zone changes (phase 17).

Scheduled rules are rendered with the UTC offset in effect at `apply`
time (frfw.nft.schedule explains why). After a daylight-saving change, or
if the kernel's own time zone changes, the loaded rules are an hour off
until they are rendered again. `firewall-cli schedule-check`, run hourly
by fr-schedule-check.timer, compares the offset recorded at the last
apply with the current one and re-applies when they differ.

It only re-applies the *same* config that was last applied: the record
carries a fingerprint of it, and if config.yaml has been edited since
(saved in the webUI but not applied yet), the check refuses rather than
silently putting those edits live -- the admin's Apply does that.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from frfw import paths
from frfw.config.schema import Config
from frfw.nft.schedule import ScheduleClock, current_clock


def has_schedules(config: Config) -> bool:
    return any(rule.schedule is not None for rule in config.rules)


def config_fingerprint(config: Config) -> str:
    # The parsed Config is a tree of frozen dataclasses with a stable
    # repr, so formatting-only edits of config.yaml don't count.
    return hashlib.sha256(repr(config).encode()).hexdigest()


def record_applied(
    config: Config, clock: ScheduleClock, path: Path = paths.SCHEDULE_STATE_PATH
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({
        "clock": clock.as_dict(),
        "timezone": config.timezone,
        "config_fingerprint": config_fingerprint(config),
    }))
    tmp.replace(path)


def clear_record(path: Path = paths.SCHEDULE_STATE_PATH) -> None:
    path.unlink(missing_ok=True)


def load_record(path: Path = paths.SCHEDULE_STATE_PATH) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


@dataclass(frozen=True)
class CheckResult:
    #: "no_schedules" | "not_recorded" | "up_to_date" | "refresh" | "config_changed"
    status: str
    message: str
    clock: ScheduleClock | None = None


def check(
    config: Config,
    *,
    path: Path = paths.SCHEDULE_STATE_PATH,
    clock: ScheduleClock | None = None,
) -> CheckResult:
    if not has_schedules(config):
        return CheckResult("no_schedules", "No scheduled rules; nothing to check")
    clock = clock or current_clock(config.timezone)
    record = load_record(path)
    if record is None:
        # Nothing says what is loaded right now, so nothing may be assumed.
        return CheckResult(
            "not_recorded",
            "No record of an applied schedule; apply the config once to start tracking it",
            clock,
        )
    if record.get("clock") == clock.as_dict():
        return CheckResult("up_to_date", f"Scheduled rules are current ({clock.describe()})", clock)
    try:
        before = ScheduleClock(**record["clock"]).describe()
    except (KeyError, TypeError):
        before = "unknown"
    if record.get("config_fingerprint") != config_fingerprint(config):
        return CheckResult(
            "config_changed",
            f"Time offset changed ({before} -> {clock.describe()}), but config.yaml differs "
            "from the last applied config; not applying unapplied edits automatically -- "
            "apply the config to bring the scheduled rules up to date",
            clock,
        )
    return CheckResult(
        "refresh",
        f"Time offset changed ({before} -> {clock.describe()}); re-applying scheduled rules",
        clock,
    )
