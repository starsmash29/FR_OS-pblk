"""Confirm an apply, or go back (ROADMAP SEC-26, review v0.2.1 FR-NEW-006).

SEC-5 rolls an apply back when one of its steps fails. An apply whose
every step succeeds can still cut the admin off -- the management address
moved, a rule too broad, the webUI's zone forgotten -- and nothing then
brings the router back but someone at its console. So an Apply from the
webUI is *pending* until the admin confirms it, from a new request that
reaches the router through the new rules and addresses: an admin the
apply cut off can't confirm it, and the router goes back by itself.

- **Begun** by the apply-helper after an apply succeeded, when there is a
  config applied before it to go back to and the new one differs:
  `paths.APPLY_PENDING_PATH` (root's alone) records an id, the deadline,
  who applied it, where the webUI listens now and the text of the config
  applied before it; `fr-apply-revert.service` is (re)started to wait for
  the deadline. The countdown is that unit's, not the webUI's or the
  helper's: it survives either restarting -- an apply that moves the
  management addresses restarts the webUI.
- **Confirmed** (`confirm`): the record goes; the waiting unit sees that
  and exits. Only the pending apply's own id confirms it, so a stale page
  can't confirm a later apply.
- **Reverted** at the deadline, on request, or by a boot that finds an
  apply still pending (a reboot is no confirmation): the config applied
  before it is applied again -- SEC-5's transaction, so a failure there
  is rolled back too -- config.yaml goes back to that text, so the next
  Apply or boot doesn't bring the unconfirmed config back, and the
  unconfirmed config is kept in `paths.REJECTED_CONFIG_PATH` for the
  admin to load back into the editor and fix. Every revert is a security
  alert.

One lock (`paths.APPLY_LOCK_PATH`, flock) serializes all of it across the
helper, the waiting unit and the boot: a confirmation can't land halfway
through a revert, and a new apply never starts while one is pending.
"""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import subprocess
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterator

import yaml

from frfw import paths, svc
from frfw.config import parse_config
from frfw.config.schema import Config
from frfw.transaction import ApplyError, write_keeping_owner, write_private

#: The unit that waits for the deadline and reverts (systemd/).
REVERT_UNIT = "fr-apply-revert.service"


class PendingError(Exception):
    """Raised when an apply can't begin, be confirmed or be reverted."""


@dataclass(frozen=True)
class Pending:
    """An apply waiting to be confirmed. `previous` is the text of the
    config applied before it -- what the router goes back to -- and is
    never shown outside root (see `public`)."""

    id: str
    deadline: float
    seconds: int
    by: str
    addresses: tuple[str, ...]
    previous: str

    def remaining(self, now: float | None = None) -> int:
        return max(0, int(self.deadline - (time.time() if now is None else now) + 0.999))

    def public(self, now: float | None = None) -> dict:
        """What the webUI may see."""
        return {"id": self.id, "remaining": self.remaining(now), "seconds": self.seconds,
                "by": self.by, "addresses": list(self.addresses)}


@contextmanager
def locked(lock_path: Path | None = None) -> Iterator[None]:
    """The one lock an apply, its confirmation and its revert take."""
    path = lock_path or paths.APPLY_LOCK_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)  # releases the lock


def read(path: Path | None = None) -> Pending | None:
    """The pending apply, or None. A record that can't be read is treated
    as none: there is nothing it could be reverted to."""
    try:
        data = json.loads((path or paths.APPLY_PENDING_PATH).read_text())
        return Pending(
            id=str(data["id"]), deadline=float(data["deadline"]), seconds=int(data["seconds"]),
            by=str(data.get("by") or ""), addresses=tuple(str(a) for a in data.get("addresses") or ()),
            previous=str(data["previous"]),
        )
    except (FileNotFoundError, NotADirectoryError):
        return None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def begin(previous: str, seconds: int, *, by: str = "", addresses: list[str] | tuple[str, ...] = (),
          path: Path | None = None, start: Callable[[], None] | None = None,
          now: float | None = None) -> Pending:
    """Record a pending apply and start the unit that waits for it. The
    caller holds `locked()` and has just applied the new config."""
    pending = Pending(id=secrets.token_hex(8), deadline=(time.time() if now is None else now) + seconds,
                      seconds=seconds, by=by, addresses=tuple(addresses), previous=previous)
    record = path or paths.APPLY_PENDING_PATH
    write_private(record, json.dumps({**asdict(pending), "addresses": list(addresses)}))
    try:
        (start or _start_waiting)()
    except PendingError:
        # Nothing would ever revert it: an apply that can't be held isn't.
        record.unlink(missing_ok=True)
        raise
    return pending


def confirm(pending_id: str, *, path: Path | None = None) -> Pending:
    """Keep the pending apply. The caller holds `locked()`."""
    pending = read(path)
    if pending is None:
        raise PendingError("No apply is waiting for confirmation (it may have been reverted already)")
    if not secrets.compare_digest(str(pending_id), pending.id):
        raise PendingError("That is not the apply waiting for confirmation -- reload the page")
    (path or paths.APPLY_PENDING_PATH).unlink(missing_ok=True)
    return pending


def revert(why: str, *, config_path: Path | None = None, path: Path | None = None,
           rejected_path: Path | None = None, apply: Callable[..., object] | None = None,
           alert: Callable[[str], None] | None = None) -> list[str]:
    """Go back to the config applied before the pending apply. The caller
    holds `locked()`. Returns what was done; raises PendingError when
    nothing is pending."""
    pending_path = path or paths.APPLY_PENDING_PATH
    config_path = config_path or paths.CONFIG_PATH
    rejected_path = rejected_path or paths.REJECTED_CONFIG_PATH
    pending = read(pending_path)
    if pending is None:
        raise PendingError("No apply is waiting for confirmation")
    if apply is None:
        from frfw.provision import apply_all as apply
    try:
        previous = parse_config(yaml.safe_load(pending.previous))
    except Exception as exc:  # e.g. an update changed the schema since
        # Nothing to go back to: the router keeps the applied config, and
        # nothing is left pending that no one could ever resolve.
        pending_path.unlink(missing_ok=True)
        warning = (f"The apply was not confirmed ({why}), but the config applied before it is no longer valid "
                   f"({exc}): the router keeps the one applied")
        (alert or _alert)(warning)
        return [warning]

    messages: list[str] = []
    failure = None
    try:
        result = apply(previous, source_text=pending.previous)
        messages.extend(getattr(result, "messages", []))
    except ApplyError as exc:
        failure = str(exc)

    # config.yaml back to what the router runs again, so neither the next
    # Apply nor a boot brings the unconfirmed config back; that one is
    # kept for the admin, with config.yaml's owner and mode.
    try:
        unconfirmed = config_path.read_text()
    except OSError:
        unconfirmed = None
    if unconfirmed is not None and unconfirmed != pending.previous:
        _write_like(rejected_path, unconfirmed, config_path)
    write_keeping_owner(config_path, pending.previous)
    _refresh_sensor_copy(config_path)
    pending_path.unlink(missing_ok=True)

    who = f" by {pending.by}" if pending.by else ""
    if failure is None:
        warning = (f"The apply{who} was not confirmed ({why}): the router went back to the config applied "
                   "before it. The unconfirmed config is kept -- load it from the dashboard to fix it.")
    else:
        warning = (f"The apply{who} was not confirmed ({why}), and going back to the config applied before it "
                   f"failed: {failure}. config.yaml is that config again, so a reboot applies it.")
    (alert or _alert)(warning)
    return [warning, *messages]


def wait(*, path: Path | None = None, lock_path: Path | None = None,
         sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.time,
         **revert_kwargs) -> list[str]:
    """fr-apply-revert.service: wait for the pending apply's deadline and
    revert it, unless it is confirmed (or reverted) first. Re-reads the
    record every second, so a confirmation ends the wait within one."""
    while True:
        with locked(lock_path):
            pending = read(path)
            if pending is None:
                return ["Nothing waiting for confirmation"]
            left = pending.deadline - clock()
            if left <= 0:
                return revert(f"no confirmation within {pending.seconds} s", path=path, **revert_kwargs)
        sleep(min(1.0, left))


def restore_rejected(*, config_path: Path | None = None, rejected_path: Path | None = None,
                     path: Path | None = None) -> str:
    """Load the unconfirmed config back into config.yaml, for the admin to
    fix and apply again. The caller holds `locked()`."""
    if read(path) is not None:
        raise PendingError("Confirm or revert the pending apply first")
    rejected_path = rejected_path or paths.REJECTED_CONFIG_PATH
    config_path = config_path or paths.CONFIG_PATH
    try:
        text = rejected_path.read_text()
    except FileNotFoundError:
        raise PendingError("There is no unconfirmed config to load") from None
    parse_config(yaml.safe_load(text))  # still a valid config for this version
    write_keeping_owner(config_path, text)
    _refresh_sensor_copy(config_path)
    rejected_path.unlink(missing_ok=True)
    return f"The unconfirmed config is in {config_path} again: fix it, then Apply"


def has_rejected(rejected_path: Path | None = None) -> bool:
    return (rejected_path or paths.REJECTED_CONFIG_PATH).is_file()


def needs_confirmation(config: Config, text: str, previous: str | None) -> bool:
    """Whether an apply of `config` (from `text`) is held for confirmation:
    on unless turned off, there is a config applied before it to go back
    to, and this one is a different config."""
    return config.management.confirm_apply_seconds > 0 and previous is not None and previous != text


def _write_like(path: Path, text: str, like: Path) -> None:
    """Write `path` with `like`'s owner and mode (it holds what config.yaml
    holds)."""
    write_keeping_owner(path, text)
    try:
        st = like.stat()
    except OSError:
        return
    if os.geteuid() == 0:
        os.chown(path, st.st_uid, st.st_gid)
    os.chmod(path, st.st_mode & 0o777)


def _refresh_sensor_copy(config_path: Path) -> None:
    # ROADMAP SEC-11: the parser daemons read a secrets-free copy of
    # config.yaml, kept in step with it.
    from frfw.config.export import refresh_sensor_copy

    refresh_sensor_copy(config_path)


def _start_waiting() -> None:
    # A restart, not a start: a waiting unit from a confirmed apply that
    # hasn't noticed yet would otherwise make the start a no-op, then exit.
    try:
        proc = svc.systemctl("restart", REVERT_UNIT, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise PendingError(f"could not start {REVERT_UNIT}: {exc}") from exc
    if proc.returncode != 0:
        raise PendingError(f"could not start {REVERT_UNIT}: {proc.stderr.strip()}")


def _alert(message: str) -> None:
    """Security-lessons G9: a revert shows up in the webUI's security
    alerts and the audit log."""
    from frfw.webui import audit

    try:
        audit.prepare(paths.AUDIT_LOG_PATH)
        audit.alert(paths.AUDIT_LOG_PATH, message, user="system", client="apply-confirm")
    except OSError:
        pass
