"""The unprivileged accounts FR_OS runs as, and the directories they own.

- `fr_os-webui` runs the webUI. Its state directory (paths.WEBUI_STATE_DIR:
  session secret, TLS key, accounts, audit log) is private to it (0700).
- `fr_os-sensor` runs the daemons that parse untrusted network input:
  fr-ai-ids, fr-appid, fr-iot-scan and fr-tls-fp (after it drops root).
  It is a member of the `fr_os-webui` group only so that it can read
  config.yaml (0640 root:fr_os-webui) and connect to the apply-helper
  socket; the helper then lets it send only frfw.helper.peer's
  SENSOR_COMMANDS. Its output goes to paths.SENSOR_STATE_DIR
  (fr_os-sensor:fr_os-webui 0750), which the webUI reads.

`ensure()` is idempotent. It runs from install-system-integration.sh and
from fr-accounts.service, which every unit that runs as one of these
accounts pulls in -- so an update that brings new units also brings the
account they need, without depending on the version doing the update.
"""

from __future__ import annotations

import grp
import os
import pwd
import subprocess
from pathlib import Path

from frfw import paths

NOLOGIN = "/usr/sbin/nologin"


class AccountsError(Exception):
    pass


def _run(cmd: list[str]) -> None:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise AccountsError(f"{cmd[0]} not found") from exc
    if proc.returncode != 0:
        raise AccountsError(f"{' '.join(cmd)} failed: {(proc.stderr or proc.stdout).strip()}")


def _user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def _group_exists(name: str) -> bool:
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


def _group_members(name: str) -> list[str]:
    try:
        return list(grp.getgrnam(name).gr_mem)
    except KeyError:
        return []


def _ensure_dir(path: Path, mode: int, user: str, group: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
    os.chmod(path, mode)


def ensure() -> list[str]:
    """Create what's missing; returns what was done, for the log."""
    done = []
    if not _user_exists(paths.WEBUI_USER):
        _run(["useradd", "--system", "--user-group", "--no-create-home", "--shell", NOLOGIN, "--", paths.WEBUI_USER])
        done.append(f"created user {paths.WEBUI_USER}")
    if not _user_exists(paths.SENSOR_USER):
        _run(["useradd", "--system", "--user-group", "--no-create-home", "--shell", NOLOGIN, "--", paths.SENSOR_USER])
        done.append(f"created user {paths.SENSOR_USER}")
    if paths.SENSOR_USER not in _group_members(paths.WEBUI_USER):
        _run(["usermod", "--append", "--groups", paths.WEBUI_USER, "--", paths.SENSOR_USER])
        done.append(f"added {paths.SENSOR_USER} to group {paths.WEBUI_USER}")

    if not _group_exists(paths.SSH_GROUP):
        # sshd's AllowGroups (frfw.management): empty until the admin adds
        # someone, i.e. no SSH login at all by default.
        _run(["groupadd", "--system", "--", paths.SSH_GROUP])
        done.append(f"created group {paths.SSH_GROUP}")

    paths.CONFIG_PATH.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _ensure_dir(paths.WEBUI_STATE_DIR, 0o700, paths.WEBUI_USER, paths.WEBUI_USER)
    _ensure_dir(paths.SENSOR_STATE_DIR, 0o750, paths.SENSOR_USER, paths.WEBUI_USER)
    return done
