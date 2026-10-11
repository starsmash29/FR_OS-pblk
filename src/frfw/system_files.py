"""Who can log in, and what the router's own system files say (ROADMAP SEC-29).

frfw.integrity.persistence_changes (SEC-22) lists every file the
persistence layer adds to or changes in the image -- except the Debian
files the router changes by itself: first boot and live-config write the
accounts files, `sshd_config` and `/etc/pam.d/login`, and FR_OS writes its
sshd drop-ins. Their content went unjudged, so a root attacker's second
uid-0 account, a password on a locked account, or `PermitRootLogin yes`
passed. This judges what is in them, against the image's own copy:

- accounts (`/etc/passwd`, `/etc/shadow`, `/etc/group`): an account the
  image doesn't have, other than FR_OS's own (frfw.accounts); an image
  account whose uid, gid, home or shell changed; a locked account that
  now has a password, or any account with an empty one; a member added
  to a privileged group (one that reads secrets or acts as root);
- who can log in: an account with a password, or with a key in
  `~/.ssh/authorized_keys` and a shell. FR_OS has none by default -- the
  webUI is the way in -- so each one is a finding, unless the admin named
  it (`login_ok`: verify-medium's `--login-ok NAME`, for an SSH user they
  added to the `fr_os-ssh` group themselves);
- `sshd_config`, `/etc/pam.d/login` and `/etc/fstab`: only the edits
  live-config and live-boot make on every boot (EXPECTED_EDITS), nothing
  else; a group password in `/etc/gshadow`;
- FR_OS's sshd drop-ins: only the lines frfw.management and frfw.pqc
  write, and all of management's hardening lines.

Everything is read from the untrusted medium without following a link
(frfw.integrity.OverlayView), and every finding names the file it is in.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from frfw import integrity, management, paths, pqc

#: Accounts and groups frfw.accounts creates, and the members it gives
#: its groups.
FR_OS_ACCOUNTS = frozenset({paths.WEBUI_USER, paths.SENSOR_USER})
FR_OS_GROUP_MEMBERS = {
    paths.WEBUI_USER: frozenset(),
    paths.SENSOR_USER: frozenset(),
    paths.FEEDS_GROUP: frozenset({paths.WEBUI_USER, paths.SENSOR_USER}),
    paths.SSH_GROUP: frozenset(),  # the admin's SSH users: login_ok
}

#: Groups whose members read secrets or act as root.
PRIVILEGED_GROUPS = frozenset({
    "root", "sudo", "wheel", "adm", "shadow", "disk", "kmem", "staff", "systemd-journal",
    paths.WEBUI_USER, paths.FEEDS_GROUP, paths.SSH_GROUP,
})

#: Shells nobody logs in with.
NO_LOGIN_SHELLS = frozenset({"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "/bin/sync"})

#: What live-config changes in these files on every boot, as
#: (lines added, lines removed) against the image's copy -- comment and
#: blank lines aside, whitespace collapsed. Taken from the boot test.
EXPECTED_EDITS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    # live-config's openssh-server component turns password logins off.
    "/etc/ssh/sshd_config": (frozenset({"PasswordAuthentication no"}), frozenset()),
    # Its login component comments pam_lastlog out.
    "/etc/pam.d/login": (frozenset(), frozenset({"session optional pam_lastlog.so"})),
    # live-boot's root and /tmp.
    "/etc/fstab": (frozenset({"overlay / overlay rw 0 0", "tmpfs /tmp tmpfs nosuid,nodev 0 0"}), frozenset()),
}

#: FR_OS's sshd drop-ins, where they are on the router (by name: tests
#: move paths.* elsewhere).
SSHD_DROPINS = {
    f"/etc/ssh/sshd_config.d/{paths.SSHD_MANAGEMENT_DROPIN_PATH.name}": "management",
    f"/etc/ssh/sshd_config.d/{paths.SSHD_PQC_DROPIN_PATH.name}": "pqc",
}

_LISTEN = re.compile(r"ListenAddress [0-9A-Fa-f.:\[\]]+\Z")


@dataclass(frozen=True)
class SystemFilesReport:
    #: What is wrong, one line each, naming the file.
    findings: list[str] = field(default_factory=list)
    #: Who can log in, and how: "name: password", "name: SSH key".
    logins: list[str] = field(default_factory=list)


def _table(text: bytes | None, width: int) -> dict[str, list[str]]:
    rows = {}
    for line in (text or b"").decode(errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        fields += [""] * (width - len(fields))
        rows.setdefault(fields[0], fields)
    return rows


def _usable_password(field_: str) -> bool:
    """A hash someone can log in with: not locked (`!`, `*`), not empty."""
    return bool(field_) and field_[0] not in "!*"


def _config_lines(text: bytes | None) -> list[str]:
    lines = []
    for line in (text or b"").decode(errors="replace").splitlines():
        line = " ".join(line.split())
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def _members(row: list[str]) -> set[str]:
    return {m for m in row[3].split(",") if m} if len(row) > 3 else set()


def check(lower: Path | str, upper: Path | str, *, login_ok: set[str] | frozenset[str] = frozenset()) -> SystemFilesReport:
    """The router's accounts, login access and SSH and PAM config (see
    the module docstring), from its image and persistence layer."""
    lower, upper = Path(lower), Path(upper)
    now = integrity.OverlayView(lower, upper)
    image = integrity.OverlayView(lower, _EMPTY)
    findings: list[str] = []

    passwd_was, passwd = _table(image.read("/etc/passwd"), 7), _table(now.read("/etc/passwd"), 7)
    shadow_was, shadow = _table(image.read("/etc/shadow"), 9), _table(now.read("/etc/shadow"), 9)
    group_was, group = _table(image.read("/etc/group"), 4), _table(now.read("/etc/group"), 4)
    if not passwd:
        findings.append("/etc/passwd: missing or unreadable")

    for name, row in sorted(passwd.items()):
        uid, gid, home, shell = row[2], row[3], row[5], row[6]
        if uid == "0" and name != "root":
            findings.append(f"/etc/passwd: {name} has uid 0")
        was = passwd_was.get(name)
        if was is None:
            if name in FR_OS_ACCOUNTS:
                if shell not in NO_LOGIN_SHELLS:
                    findings.append(f"/etc/passwd: FR_OS's account {name} has the login shell {shell}")
            elif name not in login_ok:
                findings.append(f"/etc/passwd: an account the image doesn't have: {name} (uid {uid}, shell {shell})")
            continue
        for what, before, after in (("uid", was[2], uid), ("gid", was[3], gid), ("home", was[5], home),
                                    ("shell", was[6], shell)):
            if before != after and name not in login_ok:
                findings.append(f"/etc/passwd: {name}'s {what} changed from {before} to {after}")

    for name, row in sorted(shadow.items()):
        password = row[1]
        before = shadow_was.get(name, [name, "!"])[1]
        if password == "" and before != "":
            findings.append(f"/etc/shadow: {name} has an empty password")
        elif _usable_password(password) and not _usable_password(before) and name not in login_ok:
            findings.append(f"/etc/shadow: {name} has a password; the image's account is locked")

    gshadow_was, gshadow = _table(image.read("/etc/gshadow"), 4), _table(now.read("/etc/gshadow"), 4)
    for name, row in sorted(gshadow.items()):
        if _usable_password(row[1]) and not _usable_password(gshadow_was.get(name, [name, "!"])[1]):
            findings.append(f"/etc/gshadow: the group {name} has a password (newgrp joins it)")

    for name, row in sorted(group.items()):
        if row[2] == "0" and name != "root":
            findings.append(f"/etc/group: {name} has gid 0")
        if name not in PRIVILEGED_GROUPS:
            continue
        allowed = _members(group_was.get(name, [name, "", "", ""])) | FR_OS_GROUP_MEMBERS.get(name, frozenset())
        if name == paths.SSH_GROUP:
            allowed |= set(login_ok)
        for member in sorted(_members(row) - allowed):
            findings.append(f"/etc/group: {member} was added to the privileged group {name}")

    logins = []
    for name, row in sorted(passwd.items()):
        how = []
        if _usable_password(shadow.get(name, [name, "!"])[1]):
            how.append("password")
        home = row[5].rstrip("/") or "/"
        if row[6] not in NO_LOGIN_SHELLS and now.read(f"{home}/.ssh/authorized_keys") is not None:
            how.append("SSH key")
        if not how:
            continue
        logins.append(f"{name}: {', '.join(how)}")
        could = _usable_password(shadow_was.get(name, [name, "!"])[1])
        if name not in login_ok and not (how == ["password"] and could):
            findings.append(f"{name} can log in ({', '.join(how)}); FR_OS has no login but the webUI "
                            "(name an SSH user you added with --login-ok)")

    for path, (added_ok, removed_ok) in EXPECTED_EDITS.items():
        before, after = _config_lines(image.read(path)), _config_lines(now.read(path))
        for line in sorted(set(after) - set(before) - added_ok):
            findings.append(f"{path}: a line the image doesn't have: {line}")
        for line in sorted(set(before) - set(after) - removed_ok):
            findings.append(f"{path}: a line of the image is gone: {line}")

    findings += _dropin_findings(now)
    return SystemFilesReport(findings, logins)


def _dropin_findings(now: integrity.OverlayView) -> list[str]:
    findings = []
    known_kex = set(management.SSHD_KEX) | set(pqc.CLASSICAL_KEX_FALLBACK) | {pqc.MLKEM_KEX_NAME}
    fixed = set(management.SSHD_HARDENING) | {
        "KexAlgorithms " + ",".join(management.SSHD_KEX),
        "Ciphers " + ",".join(management.SSHD_CIPHERS),
        "MACs " + ",".join(management.SSHD_MACS),
    }
    for path, which in SSHD_DROPINS.items():
        text = now.read(path)
        if text is None:
            continue
        lines = _config_lines(text)
        for line in lines:
            if which == "management":
                ok = line in fixed or _LISTEN.match(line)
            else:
                kex = line.split(" ", 1)
                ok = kex[0] == "KexAlgorithms" and len(kex) == 2 and set(kex[1].split(",")) <= known_kex
            if not ok:
                findings.append(f"{path}: a line FR_OS doesn't write: {line}")
        if which == "management":
            for line in management.SSHD_HARDENING:
                if line not in lines:
                    findings.append(f"{path}: FR_OS's line is gone: {line}")
    return findings


#: An upper layer with nothing in it: OverlayView over the image alone.
_EMPTY = Path("/nonexistent/fr_os-empty-upper")
