"""One apply, one transaction, across every subsystem (ROADMAP SEC-5).

Review v0.2.0 R6: `frfw.provision.apply_all` stopped at the first failing
step and left the earlier ones applied -- a new ruleset with the old DHCP
server, addresses half changed, the resolver of one config and the XDP
filter of another. The firewall itself was always safe (it goes first and
`nft -f` is atomic), everything after it was not.

An apply is now a transaction:

1. **Checked first.** What can be checked without touching the system is
   (`frfw.provision.preflight`); a config that fails there changes
   nothing.
2. **Journalled.** Before a step changes anything, it records how to put
   back what is there now (`Transaction.begin`). The step that fails is
   journalled too: it may have done part of its work.
3. **Rolled back.** When a step fails, the journal is undone in reverse
   order, the firewall last -- the router is never without a ruleset,
   and the new one keeps filtering until the previous one is back. An
   undo that fails is reported by name, and the others still run.

The undo of a step is one of:
- the step itself, run with the last config that was applied in full
  (`APPLIED_CONFIG_PATH`, kept by `frfw.provision`) -- for the steps that
  reconcile the system with a config (the ruleset, rebuilt with the live
  bans, quarantines, ZTNA sessions and isolated devices; the XDP filter);
- what was really there before (`FileState`, `ServiceState`,
  `LinkState`) -- for the steps that only ever add (addresses), or whose
  state is a file and a service.

What this does not cover is said where it applies: the ad-block lists'
allowlist filtering (data, refreshed daily), and a webUI restart that was
already scheduled (the last step, so it only happens when everything
before it succeeded).
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from frfw import svc, validate


class ApplyError(Exception):
    """An apply that failed. `changed` is False when it failed before
    anything was changed (the preflight, or reading what the reload must
    carry over); otherwise the journal was rolled back, and
    `rolled_back` / `not_rolled_back` say what was and wasn't put back."""

    def __init__(self, step: str, cause: BaseException, *, changed: bool,
                 rolled_back: tuple[str, ...] = (), not_rolled_back: tuple[str, ...] = ()) -> None:
        self.step = step
        self.cause = cause
        self.changed = changed
        self.rolled_back = rolled_back
        self.not_rolled_back = not_rolled_back
        super().__init__(self._describe())

    def _describe(self) -> str:
        cause = str(self.cause) or type(self.cause).__name__
        if not self.changed:
            return f"Nothing was applied -- {self.step}: {cause}. The running system is unchanged."
        text = f"Apply failed at {self.step}: {cause}."
        if self.rolled_back:
            text += f" Rolled back to the previous state: {', '.join(self.rolled_back)}."
        if self.not_rolled_back:
            text += f" NOT rolled back: {'; '.join(self.not_rolled_back)}."
        else:
            text += " Nothing else was changed."
        return text


@dataclass
class _Entry:
    name: str
    undo: Callable[[], object] | None
    why_not: str


@dataclass
class Transaction:
    """The undo journal of one apply."""

    _entries: list[_Entry] = field(default_factory=list)

    def begin(self, name: str, undo: Callable[[], object] | None, *, why_not: str = "") -> None:
        """Record, before step `name` changes anything, how to undo it --
        or None and why it can't be (reported if it comes to a rollback)."""
        self._entries.append(_Entry(name, undo, why_not))

    def roll_back(self) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Undo every journalled step, last first. Returns (rolled back,
        not rolled back with the reason)."""
        done, failed = [], []
        for entry in reversed(self._entries):
            if entry.undo is None:
                failed.append(f"{entry.name} ({entry.why_not})")
                continue
            try:
                entry.undo()
            except Exception as exc:  # each undo is independent; report, go on
                failed.append(f"{entry.name} ({str(exc) or type(exc).__name__})")
            else:
                done.append(entry.name)
        self._entries.clear()
        return tuple(done), tuple(failed)


# --- files -----------------------------------------------------------------


@dataclass(frozen=True)
class FileState:
    """A file's bytes, mode and owner -- or that it didn't exist."""

    path: Path
    content: bytes | None
    mode: int = 0o644
    uid: int = 0
    gid: int = 0

    @classmethod
    def capture(cls, path: Path) -> "FileState":
        try:
            st = path.stat()
            return cls(path, path.read_bytes(), st.st_mode & 0o7777, st.st_uid, st.st_gid)
        except FileNotFoundError:
            return cls(path, None)

    def differs(self) -> bool:
        return FileState.capture(self.path) != self

    def restore(self) -> None:
        if self.content is None:
            self.path.unlink(missing_ok=True)
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}.")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(self.content)
            os.chmod(tmp, self.mode)
            if os.geteuid() == 0:
                os.chown(tmp, self.uid, self.gid)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


def write_private(path: Path, text: str) -> None:
    """Root's alone (0600), written atomically: the record of the applied
    config holds what config.yaml holds, ZTNA password hashes included."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


# --- services --------------------------------------------------------------


@dataclass(frozen=True)
class ServiceState:
    """Whether a unit was running; None when that can't be told (no
    systemd), and then nothing is done to it on undo."""

    unit: str
    active: bool | None

    @classmethod
    def capture(cls, unit: str) -> "ServiceState":
        try:
            proc = svc.systemctl("is-active", unit, timeout=30)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return cls(unit, None)
        return cls(unit, proc.stdout.strip() in ("active", "activating", "reloading"))

    def restore(self, *, config_changed: bool, how: str = "restart") -> None:
        """Back to running (re-reading its restored config with `how`) or
        stopped."""
        if self.active is None:
            return
        if self.active:
            action = how if config_changed else "start"
        else:
            if ServiceState.capture(self.unit).active is False:
                return
            action = "stop"
        proc = svc.systemctl(action, self.unit, timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or f"systemctl {action} {self.unit} failed")

    @staticmethod
    def enabled(unit: str) -> bool | None:
        """Whether `unit` starts at boot; None when that can't be told."""
        try:
            proc = svc.systemctl("is-enabled", unit, timeout=30)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        state = proc.stdout.strip()
        if state in ("enabled", "enabled-runtime"):
            return True
        if state in ("disabled", "masked"):
            return False
        return None

    @staticmethod
    def set_enabled(unit: str, enabled: bool | None) -> None:
        if enabled is None or ServiceState.enabled(unit) is enabled:
            return
        action = "enable" if enabled else "disable"
        proc = svc.systemctl(action, unit, timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or f"systemctl {action} {unit} failed")


# --- interfaces ------------------------------------------------------------


@dataclass(frozen=True)
class LinkState:
    """A network device as it was: whether it existed, was up, and its
    IPv4 addresses."""

    device: str
    exists: bool
    up: bool = False
    addresses: frozenset[str] = frozenset()

    @classmethod
    def capture(cls, device: str) -> "LinkState":
        device = validate.ifname(device)
        proc = subprocess.run(["ip", "-j", "addr", "show", "dev", device], capture_output=True, text=True)
        if proc.returncode != 0:
            return cls(device, False)
        try:
            (link,) = json.loads(proc.stdout)
        except ValueError as exc:
            raise RuntimeError(f"could not read the state of {device}: {exc}") from exc
        addresses = frozenset(
            str(ipaddress.IPv4Interface(f"{a['local']}/{a['prefixlen']}"))
            for a in link.get("addr_info", []) if a.get("family") == "inet"
        )
        return cls(device, True, "UP" in link.get("flags", []), addresses)

    def restore(self) -> None:
        """Remove what an apply added; a device it created goes away."""
        now = LinkState.capture(self.device)
        if not now.exists:
            return
        if not self.exists:
            _ip(["link", "del", "dev", self.device])
            return
        for address in sorted(now.addresses - self.addresses):
            _ip(["addr", "del", address, "dev", self.device])
        if now.up and not self.up:
            _ip(["link", "set", "dev", self.device, "down"])


def _ip(args: list[str]) -> None:
    proc = subprocess.run(["ip", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"ip {' '.join(args)} failed")
