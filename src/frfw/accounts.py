"""The unprivileged accounts FR_OS runs as, and the directories they own.

- `fr_os-webui` runs the webUI. Its state directory (paths.WEBUI_STATE_DIR:
  session secret, TLS key, accounts, audit log) is private to it (0700).
- `fr_os-sensor` runs the daemons that parse untrusted network input:
  fr-ai-ids, fr-appid, fr-iot-scan and fr-tls-fp (after it drops root).
  It reads the configuration from paths.SENSOR_CONFIG_PATH, a copy
  without secrets, and is *not* in the `fr_os-webui` group (ROADMAP
  SEC-11, review v0.2.0 R17): that group reads config.yaml with its
  ZTNA password hashes and metrics token digest, the audit log and the
  update state, and a parser bug must reach none of them. Its output
  goes to paths.SENSOR_STATE_DIR (fr_os-sensor:fr_os-webui 0750), which
  the webUI reads.
- `fr_os-feeds` is the one group the two share (paths.FEEDS_GROUP): the
  apply-helper socket -- where the helper lets fr_os-sensor send only
  frfw.helper.peer's SENSOR_COMMANDS -- the XDP SNI event file and the
  resolver's query log.

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


def _regroup_feeds() -> list[str]:
    """The SNI event file and the resolver's query log, their directories,
    and the live apply-helper socket, in paths.FEEDS_GROUP where they
    exist. Mode untouched. The socket's unit names the new group, but a
    socket keeps the one it was created with until the unit restarts --
    on an update, fr-accounts.service is run again (frfw.update) and moves
    it here, so the sensors keep reaching the helper without a reboot."""
    try:
        gid = grp.getgrnam(paths.FEEDS_GROUP).gr_gid
    except KeyError:  # not created (groupadd failed, or a dry run): nothing to move to
        return []
    done = []
    for path in (paths.SNI_EVENTS_DIR, paths.SNI_EVENTS_PATH, paths.DNS_QUERY_LOG_DIR, paths.DNS_QUERY_LOG_PATH,
                 paths.APPLY_SOCKET_PATH):
        try:
            st = path.lstat()
        except FileNotFoundError:
            continue
        if path.is_symlink() or st.st_gid == gid:
            continue
        os.chown(path, -1, gid, follow_symlinks=False)
        done.append(f"moved {path} to group {paths.FEEDS_GROUP}")
    return done


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
    if not _group_exists(paths.FEEDS_GROUP):
        _run(["groupadd", "--system", "--", paths.FEEDS_GROUP])
        done.append(f"created group {paths.FEEDS_GROUP}")
    for user in (paths.WEBUI_USER, paths.SENSOR_USER):
        if user not in _group_members(paths.FEEDS_GROUP):
            _run(["usermod", "--append", "--groups", paths.FEEDS_GROUP, "--", user])
            done.append(f"added {user} to group {paths.FEEDS_GROUP}")
    # ROADMAP SEC-11: an earlier version put the sensor account in the
    # webUI's group; a router updated from it loses that here, at boot,
    # before any sensor daemon starts (they all pull in fr-accounts).
    if paths.SENSOR_USER in _group_members(paths.WEBUI_USER):
        _run(["gpasswd", "--delete", paths.SENSOR_USER, paths.WEBUI_USER])
        done.append(f"removed {paths.SENSOR_USER} from group {paths.WEBUI_USER}")
    # The feeds an earlier version made with the webUI's group: their
    # writers keep a file's group, so it is moved here once.
    done.extend(_regroup_feeds())

    if not _group_exists(paths.SSH_GROUP):
        # sshd's AllowGroups (frfw.management): empty until the admin adds
        # someone, i.e. no SSH login at all by default.
        _run(["groupadd", "--system", "--", paths.SSH_GROUP])
        done.append(f"created group {paths.SSH_GROUP}")

    paths.CONFIG_PATH.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    _ensure_dir(paths.WEBUI_STATE_DIR, 0o700, paths.WEBUI_USER, paths.WEBUI_USER)
    _ensure_dir(paths.SENSOR_STATE_DIR, 0o750, paths.SENSOR_USER, paths.WEBUI_USER)
    # The audit log is root's; the webUI reads it (security-lessons G9/E6).
    _ensure_dir(paths.AUDIT_LOG_DIR, 0o750, "root", paths.WEBUI_USER)
    return done
