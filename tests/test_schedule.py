"""Phase 17: time-based rules -- schedule parsing, the local-time ->
kernel-clock conversion, ruleset rendering, the DST refresh check, and
the CLI. tests/test_schedule_live.py runs the rendered matches through
the real kernel."""

from __future__ import annotations

import json
import random
import shutil
import subprocess
from datetime import datetime, timezone

import pytest

from frfw import provision, schedule_refresh
from frfw.config import ConfigError, parse_config
from frfw.nft import build_ruleset
from frfw.nft.schedule import (
    MINUTES_PER_WEEK,
    ScheduleClock,
    Segment,
    describe,
    is_active,
    local_minute_of_week,
    segment_matches,
    segments,
    utc_offset_minutes,
)

requires_nft = pytest.mark.skipif(shutil.which("nft") is None, reason="nft not installed")

BUDAPEST_SUMMER = ScheduleClock(120, 0)


def _raw(minimal_config_dict, *rules, tz="Europe/Budapest"):
    raw = dict(minimal_config_dict)
    raw["rules"] = list(rules)
    if tz:
        raw["timezone"] = tz
    return raw


def _bedtime(**schedule):
    return {
        "name": "kids-bedtime", "action": "reject", "from_zone": "lan", "to_zone": "wan",
        "src_mac": "AA:BB:CC:DD:EE:01",
        "schedule": {"days": ["weekdays"], "start": "21:30", "end": "06:30", **schedule},
    }


# --- conversion ------------------------------------------------------------------------------


def test_segments_agree_with_the_reference_for_every_minute_of_the_week():
    rng = random.Random(17)
    for _ in range(60):
        days = tuple(sorted(rng.sample(range(7), rng.randint(1, 7))))
        start = rng.randrange(0, 1440, 5)
        end = rng.choice([rng.randrange(0, 1441, 5), 1440])
        if start == end:
            continue
        offset = rng.choice([0, 60, 120, -300, -420, 330, 345, 765, 825, -600])
        clock = ScheduleClock(offset, rng.choice([0, -offset, 300]))
        segs = segments(days, start, end, clock)
        for minute in range(0, MINUTES_PER_WEEK, 5):
            expected = is_active(days, start, end, minute)
            assert any(segment_matches(s, minute - offset, clock) for s in segs) == expected, (
                days, start, end, clock, minute
            )


def test_office_hours_in_budapest_summer_become_utc():
    (seg,) = segments((0, 1, 2, 3, 4), 8 * 60, 17 * 60, BUDAPEST_SUMMER)
    assert seg.render() == (
        'meta day { "Monday", "Tuesday", "Wednesday", "Thursday", "Friday" } '
        'meta hour "06:00:00"-"14:59:59"'
    )


def test_a_window_past_midnight_belongs_to_the_next_day():
    rendered = [s.render() for s in segments((4,), 22 * 60, 6 * 60, ScheduleClock(0, 0))]
    assert rendered == ['meta day "Saturday" meta hour "00:00:00"-"05:59:59"',
                        'meta day "Friday" meta hour "22:00:00"-"23:59:59"']
    assert is_active((4,), 22 * 60, 6 * 60, 5 * 1440 + 3 * 60)       # Saturday 03:00
    assert not is_active((4,), 22 * 60, 6 * 60, 4 * 1440 + 3 * 60)   # Friday 03:00


def test_kernel_time_zone_shifts_day_names_not_hours():
    # With the kernel keeping UTC+2 (minuteswest -120), UTC 23:00 on Monday is
    # already "Tuesday" to meta day, while meta hour stays UTC.
    segs = segments((0,), 23 * 60 + 30, 24 * 60, ScheduleClock(0, -120))
    assert [s.render() for s in segs] == ['meta day "Tuesday" meta hour "23:30:00"-"23:59:59"']


def test_whole_week_renders_no_time_match_at_all():
    assert segments(tuple(range(7)), 0, 1440, BUDAPEST_SUMMER) == [Segment(None, None)]


def test_offset_and_describe_helpers():
    summer = datetime(2026, 7, 1, tzinfo=timezone.utc)
    winter = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert utc_offset_minutes("Europe/Budapest", summer) == 120
    assert utc_offset_minutes("Europe/Budapest", winter) == 60
    assert utc_offset_minutes("Asia/Kolkata", winter) == 330
    # 2026-09-24 is a Thursday.
    assert local_minute_of_week("UTC", datetime(2026, 9, 24, 1, 2, tzinfo=timezone.utc)) == 3 * 1440 + 62
    assert describe((0, 1, 2, 3, 4), 1290, 390) == "Mon-Fri 21:30-06:30"
    assert describe((2, 6), 0, 1440) == "Wed, Sun 00:00-24:00"


# --- config -----------------------------------------------------------------------------------


def test_schedule_parses_day_groups_and_times(minimal_config_dict):
    config = parse_config(_raw(minimal_config_dict, _bedtime(days=["weekend", "wed"])))
    rule = config.rules[0]
    assert rule.schedule.days == (2, 5, 6)
    assert (rule.schedule.start, rule.schedule.end) == (21 * 60 + 30, 6 * 60 + 30)
    assert rule.src_mac == "aa:bb:cc:dd:ee:01"
    assert config.timezone == "Europe/Budapest"


@pytest.mark.parametrize(
    "schedule, error",
    [
        ({"days": ["someday"]}, "unknown day 'someday'"),
        ({"days": []}, "non-empty list"),
        ({"start": "25:00"}, "must be a \"HH:MM\" time"),
        ({"start": "7:00"}, "must be a \"HH:MM\" time"),
        ({"start": "24:00", "end": "06:00"}, "start cannot be 24:00"),
        ({"start": "06:30", "end": "06:30"}, "start and end are both"),
        ({"cut_established": "yes"}, "cut_established must be a boolean"),
    ],
)
def test_invalid_schedules(minimal_config_dict, schedule, error):
    with pytest.raises(ConfigError, match=error):
        parse_config(_raw(minimal_config_dict, _bedtime(**schedule)))


def test_cut_established_is_only_for_drop_and_reject(minimal_config_dict):
    rule = _bedtime(cut_established=True)
    rule["action"] = "accept"
    with pytest.raises(ConfigError, match="only applies to drop/reject"):
        parse_config(_raw(minimal_config_dict, rule))


def test_invalid_timezone_and_mac(minimal_config_dict):
    with pytest.raises(ConfigError, match="IANA time zone"):
        parse_config(_raw(minimal_config_dict, _bedtime(), tz="Mars/Olympus"))
    rule = _bedtime()
    rule["src_mac"] = "aa:bb:cc"
    with pytest.raises(ConfigError, match="invalid src_mac"):
        parse_config(_raw(minimal_config_dict, rule))


# --- rendering ------------------------------------------------------------------------------


def _chain(ruleset: str, name: str) -> list[str]:
    lines = ruleset.splitlines()
    start = lines.index(f"\tchain {name} {{")
    end = lines.index("\t}", start)
    return [l.strip() for l in lines[start:end]]


def test_scheduled_rule_expands_per_segment_and_keeps_its_matches(minimal_config_dict):
    config = parse_config(_raw(minimal_config_dict, _bedtime()))
    forward = _chain(build_ruleset(config, clock=BUDAPEST_SUMMER), "forward")
    bedtime = [l for l in forward if "rule:kids-bedtime" in l]
    assert len(bedtime) == 2
    assert all("ether saddr aa:bb:cc:dd:ee:01" in l and l.endswith('reject comment "rule:kids-bedtime"')
               for l in bedtime)
    # Ordinary scheduled rules stay after the established accept.
    assert forward.index("ct state established,related accept") < forward.index(bedtime[0])


def test_cut_established_rules_go_before_the_established_accept(minimal_config_dict):
    ssh = {"name": "no-ssh-at-night", "action": "drop", "from_zone": "lan", "to_zone": "self",
           "proto": "tcp", "dst_port": 22,
           "schedule": {"start": "23:00", "end": "05:00", "cut_established": True}}
    config = parse_config(_raw(minimal_config_dict, _bedtime(cut_established=True), ssh))
    ruleset = build_ruleset(config, clock=BUDAPEST_SUMMER)
    for chain, name in (("forward", "kids-bedtime"), ("input", "no-ssh-at-night")):
        lines = _chain(ruleset, chain)
        cut = [i for i, l in enumerate(lines) if f"rule:{name}" in l]
        assert cut and max(cut) < lines.index("ct state established,related accept"), chain


def test_unscheduled_rulesets_do_not_need_a_clock(minimal_config_dict):
    assert "meta hour" not in build_ruleset(parse_config(minimal_config_dict))


@requires_nft
def test_scheduled_ruleset_passes_real_nft_check(minimal_config_dict):
    config = parse_config(_raw(minimal_config_dict, _bedtime(cut_established=True)))
    ruleset = build_ruleset(config, clock=ScheduleClock(345, -120))  # Kathmandu, odd kernel tz
    proc = subprocess.run(["nft", "-c", "-f", "-"], input=ruleset, capture_output=True, text=True,
                          env={"TZ": "UTC", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    assert proc.returncode == 0, proc.stderr


# --- DST refresh -------------------------------------------------------------------------------


def test_refresh_check_statuses(minimal_config_dict, tmp_path):
    path = tmp_path / "state.json"
    plain = parse_config(minimal_config_dict)
    config = parse_config(_raw(minimal_config_dict, _bedtime()))
    assert schedule_refresh.check(plain, path=path).status == "no_schedules"
    assert schedule_refresh.check(config, path=path, clock=BUDAPEST_SUMMER).status == "not_recorded"

    schedule_refresh.record_applied(config, BUDAPEST_SUMMER, path)
    assert schedule_refresh.check(config, path=path, clock=BUDAPEST_SUMMER).status == "up_to_date"
    winter = ScheduleClock(60, 0)
    result = schedule_refresh.check(config, path=path, clock=winter)
    assert result.status == "refresh" and "UTC+02:00 -> UTC+01:00" in result.message

    edited = parse_config(_raw(minimal_config_dict, _bedtime(start="20:00")))
    assert schedule_refresh.check(edited, path=path, clock=BUDAPEST_SUMMER).status == "up_to_date"
    assert schedule_refresh.check(edited, path=path, clock=winter).status == "config_changed"


def test_apply_records_the_clock_and_reports_it(minimal_config_dict, tmp_path, monkeypatch):
    from frfw import apply as apply_mod

    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: None)
    monkeypatch.setattr(apply_mod, "capture_running_ruleset", lambda: "")
    monkeypatch.setattr(provision, "current_clock", lambda tz: BUDAPEST_SUMMER)
    state = tmp_path / "schedule.json"
    paths = dict(
        backup_dir=tmp_path / "backups", kea_config_path=tmp_path / "kea.json",
        xdp_state_path=tmp_path / "xdp.json", pqc_conf_path=tmp_path / "pqc.cnf",
        ssh_kex_dropin_path=tmp_path / "kex.conf", adblock_hosts_path=tmp_path / "adblock.hosts",
        adblock_dnsmasq_conf_path=tmp_path / "dnsmasq.conf", schedule_state_path=state,
    )
    config = parse_config(_raw(minimal_config_dict, _bedtime()))

    result = provision.apply_all(config, dry_run=True, **paths)
    assert "Scheduled rules: 1, rendered for UTC+02:00 (Europe/Budapest)" in result.messages
    assert not state.exists()  # a dry run records nothing

    provision.apply_all(config, **paths)
    record = json.loads(state.read_text())
    assert record["clock"] == {"utc_offset_minutes": 120, "kernel_minuteswest": 0}
    assert record["config_fingerprint"] == schedule_refresh.config_fingerprint(config)

    provision.apply_all(parse_config(minimal_config_dict), **paths)
    assert not state.exists()  # no scheduled rules left: nothing to keep fresh


def test_schedule_check_cli(monkeypatch, capsys, tmp_path, minimal_config_dict):
    import yaml

    import frfw.cli as cli_mod
    from frfw.cli import main

    cfg = tmp_path / "config.yaml"
    cfg.write_text(yaml.safe_dump(_raw(minimal_config_dict, _bedtime())))
    applied = []
    monkeypatch.setattr(cli_mod, "apply_all", lambda config: applied.append(config) or type("R", (), {"messages": ["applied"]})())

    def fake_check(status):
        return lambda config: schedule_refresh.CheckResult(status, f"status {status}")

    monkeypatch.setattr(cli_mod.schedule_refresh, "check", fake_check("up_to_date"))
    assert main(["schedule-check", str(cfg)]) == 0 and applied == []
    monkeypatch.setattr(cli_mod.schedule_refresh, "check", fake_check("config_changed"))
    assert main(["schedule-check", str(cfg)]) == 1 and applied == []
    monkeypatch.setattr(cli_mod.schedule_refresh, "check", fake_check("refresh"))
    assert main(["schedule-check", str(cfg)]) == 0 and len(applied) == 1
    assert "applied" in capsys.readouterr().out
