"""Confirm an apply, or go back (ROADMAP SEC-26, review v0.2.1 FR-NEW-006).

The record, the confirmation by id, the revert -- config.yaml back, the
unconfirmed config kept, a security alert -- the wait for the deadline,
and `firewall-cli` and the boot. The apply-helper's side, over its real
socket, is in tests/test_helper.py.
The host's fr-apply-revert.service is never started (tests/conftest.py).
"""

from __future__ import annotations

import json
import stat

import pytest
import yaml

from frfw import apply_confirm, paths
from frfw.config import ConfigError, parse_config
from frfw.transaction import ApplyError

OLD = "version: 1\nhostname: old\n"


@pytest.fixture
def two_configs(minimal_config_dict, tmp_path):
    """config.yaml holds the new config; `old` is the one applied before."""
    old = dict(minimal_config_dict, hostname="old-router")
    new = dict(minimal_config_dict, hostname="new-router")
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(new))
    config_path.chmod(0o640)
    return yaml.safe_dump(old), yaml.safe_dump(new), config_path


class Applied:
    """apply_all stood in: what it was asked to apply."""

    def __init__(self, fail: str | None = None):
        self.configs, self.fail = [], fail

    def __call__(self, config, **kwargs):
        self.configs.append((config.hostname, kwargs.get("source_text")))
        if self.fail:
            raise ApplyError("DHCP (Kea)", RuntimeError(self.fail), changed=True, rolled_back=("the firewall",))
        return type("Result", (), {"messages": ["Ruleset applied"]})()


# --- the record ----------------------------------------------------------------


def test_a_pending_apply_is_root_s_alone_and_never_shows_the_previous_config(_never_touch_the_hosts_pending_apply):
    pending = apply_confirm.begin(OLD, 300, by="boss", addresses=["192.168.1.1"], now=1000.0)
    assert stat.S_IMODE(paths.APPLY_PENDING_PATH.stat().st_mode) == 0o600
    assert _never_touch_the_hosts_pending_apply == [1], "the waiting unit was not started"
    assert apply_confirm.read() == pending and pending.previous == OLD
    shown = pending.public(now=1001.0)
    assert shown == {"id": pending.id, "remaining": 299, "seconds": 300, "by": "boss", "addresses": ["192.168.1.1"]}
    assert OLD not in json.dumps(shown)


def test_an_apply_that_can_t_be_held_is_not_left_half_held(monkeypatch):
    def no_systemd():
        raise apply_confirm.PendingError("could not start fr-apply-revert.service: no systemd")

    monkeypatch.setattr(apply_confirm, "_start_waiting", no_systemd)
    with pytest.raises(apply_confirm.PendingError, match="no systemd"):
        apply_confirm.begin(OLD, 300)
    assert apply_confirm.read() is None, "nothing would ever revert it"


def test_an_unreadable_record_is_no_pending_apply():
    paths.APPLY_PENDING_PATH.write_text("{not json")
    assert apply_confirm.read() is None


def test_only_the_pending_apply_s_own_id_confirms_it():
    pending = apply_confirm.begin(OLD, 300)
    with pytest.raises(apply_confirm.PendingError, match="not the apply waiting"):
        apply_confirm.confirm("0" * 16)
    assert apply_confirm.read() is not None
    apply_confirm.confirm(pending.id)
    assert apply_confirm.read() is None
    with pytest.raises(apply_confirm.PendingError, match="No apply is waiting"):
        apply_confirm.confirm(pending.id)


@pytest.mark.parametrize("seconds, previous, text, held", [
    (300, OLD, "version: 1\nhostname: new\n", True),
    (300, None, "version: 1\nhostname: new\n", False),   # nothing to go back to
    (300, OLD, OLD, False),                              # the same config again
    (0, OLD, "version: 1\nhostname: new\n", False),      # turned off
])
def test_which_applies_are_held(minimal_config_dict, seconds, previous, text, held):
    minimal_config_dict["management"] = {"confirm_apply_seconds": seconds}
    assert apply_confirm.needs_confirmation(parse_config(minimal_config_dict), text, previous) is held


@pytest.mark.parametrize("value", [59, 3601, True, "300", -1])
def test_the_confirmation_window_is_checked(minimal_config_dict, value):
    minimal_config_dict["management"] = {"confirm_apply_seconds": value}
    with pytest.raises(ConfigError, match="confirm_apply_seconds"):
        parse_config(minimal_config_dict)


def test_the_confirmation_window_is_five_minutes_unless_set(minimal_config_dict):
    assert parse_config(minimal_config_dict).management.confirm_apply_seconds == 300
    minimal_config_dict["management"] = {"confirm_apply_seconds": 0}
    assert parse_config(minimal_config_dict).management.confirm_apply_seconds == 0


# --- the revert ------------------------------------------------------------------


def test_a_revert_goes_back_keeps_the_unconfirmed_config_and_alerts(two_configs):
    old, new, config_path = two_configs
    apply_confirm.begin(old, 300, by="boss")
    applied, alerts = Applied(), []
    messages = apply_confirm.revert("no confirmation within 300 s", config_path=config_path, apply=applied,
                                    alert=alerts.append)
    assert applied.configs == [("old-router", old)], "the config applied before, recorded as applied"
    assert config_path.read_text() == old, "the next Apply or boot would bring the unconfirmed one back"
    assert paths.REJECTED_CONFIG_PATH.read_text() == new
    assert stat.S_IMODE(paths.REJECTED_CONFIG_PATH.stat().st_mode) == 0o640, "config.yaml's mode, not wider"
    assert apply_confirm.read() is None
    assert len(alerts) == 1 and "by boss was not confirmed (no confirmation within 300 s)" in alerts[0]
    assert messages[0] == alerts[0] and "Ruleset applied" in messages
    assert "hostname: old-router" in paths.SENSOR_CONFIG_PATH.read_text(), "the sensors' copy follows"


def test_a_revert_that_can_t_apply_still_puts_config_yaml_back_and_says_so(two_configs):
    old, new, config_path = two_configs
    apply_confirm.begin(old, 300)
    alerts = []
    apply_confirm.revert("the admin went back", config_path=config_path, apply=Applied(fail="subnet overlaps"),
                         alert=alerts.append)
    assert config_path.read_text() == old and apply_confirm.read() is None
    assert "going back to the config applied before it failed" in alerts[0]
    assert "a reboot applies it" in alerts[0]


def test_a_previous_config_that_no_longer_parses_is_not_left_pending_forever(two_configs):
    """After an update changed the schema, say: the router keeps what it
    runs, says so, and a later apply isn't blocked by a revert that can
    never happen."""
    config_path = two_configs[2]
    apply_confirm.begin("version: 99\n", 300)
    alerts = []
    apply_confirm.revert("x", config_path=config_path, apply=lambda *a, **k: pytest.fail("applied"),
                         alert=alerts.append)
    assert apply_confirm.read() is None and "no longer valid" in alerts[0]
    assert config_path.read_text() == two_configs[1]


def test_nothing_pending_is_nothing_to_revert(two_configs):
    with pytest.raises(apply_confirm.PendingError):
        apply_confirm.revert("x", config_path=two_configs[2], apply=Applied())


def test_the_wait_ends_when_the_apply_is_confirmed(two_configs):
    old, _, config_path = two_configs
    pending = apply_confirm.begin(old, 300, now=1000.0)
    clock = iter([1000.0, 1001.0, 1002.0])
    applied = Applied()

    def sleep(seconds):
        assert seconds == 1.0
        apply_confirm.confirm(pending.id)  # the admin, a second in

    messages = apply_confirm.wait(sleep=sleep, clock=lambda: next(clock), config_path=config_path, apply=applied)
    assert messages == ["Nothing waiting for confirmation"] and applied.configs == []
    assert config_path.read_text() != old


def test_the_wait_reverts_at_the_deadline(two_configs):
    old, _, config_path = two_configs
    apply_confirm.begin(old, 60, now=1000.0)
    times = iter([1000.0, 1030.0, 1059.5, 1060.0])
    slept, applied, alerts = [], Applied(), []
    messages = apply_confirm.wait(sleep=slept.append, clock=lambda: next(times), config_path=config_path,
                                  apply=applied, alert=alerts.append)
    assert slept == [1.0, 1.0, 0.5], "never sleeps past the deadline"
    assert applied.configs == [("old-router", old)] and config_path.read_text() == old
    assert "no confirmation within 60 s" in messages[0]


def test_the_unconfirmed_config_can_be_loaded_back_to_fix(two_configs):
    old, new, config_path = two_configs
    apply_confirm.begin(old, 300)
    apply_confirm.revert("x", config_path=config_path, apply=Applied(), alert=lambda m: None)
    apply_confirm.begin(old, 300)
    with pytest.raises(apply_confirm.PendingError, match="first"):
        apply_confirm.restore_rejected(config_path=config_path)
    paths.APPLY_PENDING_PATH.unlink()
    assert "fix it" in apply_confirm.restore_rejected(config_path=config_path)
    assert config_path.read_text() == new and not apply_confirm.has_rejected()
    with pytest.raises(apply_confirm.PendingError, match="no unconfirmed config"):
        apply_confirm.restore_rejected(config_path=config_path)


def test_a_kept_config_that_no_longer_parses_is_not_loaded(two_configs):
    config_path = two_configs[2]
    paths.REJECTED_CONFIG_PATH.write_text("version: 99\n")
    with pytest.raises(ConfigError):
        apply_confirm.restore_rejected(config_path=config_path)
    assert config_path.read_text() == two_configs[1]


# --- firewall-cli and the boot -----------------------------------------------------------


def test_a_boot_with_an_apply_pending_goes_back(two_configs, monkeypatch, capsys):
    """A reboot is no confirmation: an admin cut off by the apply may have
    power-cycled the router to get it back."""
    from frfw import cli

    old, _, config_path = two_configs
    apply_confirm.begin(old, 300, by="boss")
    applied, alerts = Applied(), []
    monkeypatch.setattr(cli, "apply_all", applied)
    monkeypatch.setattr(apply_confirm, "_alert", alerts.append)
    assert cli.main(["apply", "--fail-closed", str(config_path)]) == 0
    assert applied.configs == [("old-router", old)] and config_path.read_text() == old
    assert "the router restarted before it was confirmed" in alerts[0]
    assert apply_confirm.read() is None


def test_a_boot_whose_earlier_config_fails_too_applies_it_as_far_as_it_goes(two_configs, monkeypatch):
    from frfw import cli

    old, _, config_path = two_configs
    apply_confirm.begin(old, 300)
    calls = []

    def apply_all(config, **kwargs):
        calls.append(kwargs.get("transactional", True))
        if kwargs.get("transactional", True):
            raise ApplyError("DHCP (Kea)", RuntimeError("no such device"), changed=True)
        return type("Result", (), {"messages": []})()

    monkeypatch.setattr(cli, "apply_all", apply_all)
    monkeypatch.setattr(apply_confirm, "_alert", lambda m: None)
    assert cli.main(["apply", "--fail-closed", str(config_path)]) == 0
    assert calls == [True, False], "the ruleset first, whatever fails after it"


def test_the_console_can_t_apply_over_a_pending_apply(two_configs, monkeypatch, capsys):
    from frfw import cli

    old, _, config_path = two_configs
    apply_confirm.begin(old, 300)
    monkeypatch.setattr(cli, "apply_all", lambda *a, **k: pytest.fail("applied"))
    assert cli.main(["apply", str(config_path)]) == 1
    assert "waiting for confirmation" in capsys.readouterr().err


def test_the_console_confirms_and_reports(two_configs, capsys):
    from frfw import cli

    apply_confirm.begin(two_configs[0], 300, by="boss")
    assert cli.main(["apply-status"]) == 0
    assert "waiting for confirmation (applied by boss)" in capsys.readouterr().out
    assert cli.main(["apply-confirm"]) == 0 and apply_confirm.read() is None
    assert cli.main(["apply-confirm"]) == 1
    assert "No apply is waiting" in capsys.readouterr().err


def test_an_apply_over_ssh_can_ask_to_be_held(two_configs, monkeypatch, capsys,
                                              _never_touch_the_hosts_pending_apply):
    from frfw import cli

    old, new, config_path = two_configs
    paths.APPLIED_CONFIG_PATH.write_text(old)
    monkeypatch.setattr(cli, "apply_all", Applied())
    assert cli.main(["apply", "--confirm-within", "30", str(config_path)]) == 1, "below the minimum"
    assert cli.main(["apply", "--confirm-within", "120", str(config_path)]) == 0
    pending = apply_confirm.read()
    assert pending is not None and pending.seconds == 120 and pending.previous == old and pending.by == "console"
    assert "firewall-cli apply-confirm" in capsys.readouterr().out
