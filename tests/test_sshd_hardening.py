"""Security-lessons F3: the sshd drop-in hardens authentication -- keys
only, no root, only members of fr_os-ssh, three tries, 30 s to log in --
on top of F2's ListenAddress. Checked with the real sshd where one is
installed: `sshd -T` prints the configuration sshd would actually use.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from frfw import management, paths
from frfw.config import parse_config
from frfw.skeleton import build_skeleton_config

CONFIG = parse_config(yaml.safe_load(build_skeleton_config("eth0", "eth1")))


def test_the_dropin_hardens_authentication():
    text = management.sshd_dropin(CONFIG)
    for line in ("PermitRootLogin no", "PasswordAuthentication no", "KbdInteractiveAuthentication no",
                 "AuthenticationMethods publickey", f"AllowGroups {paths.SSH_GROUP}",
                 "MaxAuthTries 3", "LoginGraceTime 30"):
        assert line in text.splitlines()


def effective_sshd_config(tmp_path: Path, dropin: str) -> dict[str, list[str]]:
    """`sshd -T` for a config that is just our drop-in plus a host key."""
    Path("/run/sshd").mkdir(exist_ok=True)
    key = tmp_path / "host_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    (tmp_path / "40-fr_os-management.conf").write_text(dropin)
    config = tmp_path / "sshd_config"
    config.write_text(f"Include {tmp_path}/40-fr_os-management.conf\nHostKey {key}\n")
    proc = subprocess.run(["sshd", "-T", "-f", str(config)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    settings: dict[str, list[str]] = {}
    for line in proc.stdout.splitlines():
        name, _, value = line.partition(" ")
        settings.setdefault(name, []).append(value)
    return settings


needs_sshd = pytest.mark.skipif(
    not shutil.which("sshd") or not shutil.which("ssh-keygen") or os.geteuid() != 0,
    reason="needs openssh-server (sshd -T) and root",
)


@needs_sshd
def test_real_sshd_accepts_the_dropin_and_applies_it(tmp_path):
    settings = effective_sshd_config(tmp_path, management.sshd_dropin(CONFIG))
    assert settings["permitrootlogin"] == ["no"]
    assert settings["passwordauthentication"] == ["no"]
    assert settings["kbdinteractiveauthentication"] == ["no"]
    assert settings["authenticationmethods"] == ["publickey"]
    assert settings["allowgroups"] == [paths.SSH_GROUP]
    assert settings["maxauthtries"] == ["3"]
    assert settings["logingracetime"] == ["30"]
    assert sorted(settings["listenaddress"]) == ["10.73.1.1:22", "127.0.0.1:22"]


@needs_sshd
def test_the_dropin_wins_over_a_later_distribution_dropin(tmp_path):
    """sshd keeps the first value it reads: ours (40-) comes before e.g.
    cloud-init's 50- file that turns passwords back on."""
    later = "PasswordAuthentication yes\nPermitRootLogin yes\n"
    settings = effective_sshd_config(tmp_path, management.sshd_dropin(CONFIG) + later)
    assert settings["passwordauthentication"] == ["no"]
    assert settings["permitrootlogin"] == ["no"]


def _record_systemctl(monkeypatch):
    import subprocess

    calls = []
    monkeypatch.setattr(management.svc, "systemctl",
                        lambda action, unit, timeout=None: calls.append((action, unit))
                        or subprocess.CompletedProcess([], 0, "", ""))
    return calls


def _fake_sshd(tmp_path):
    script = tmp_path / "sshd"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o755)
    return str(script)


def test_sshd_is_off_while_nobody_can_log_in(tmp_path, monkeypatch):
    """Security-lessons I1: a listening service nobody can use is only
    attack surface -- stopped and disabled until someone has a key."""
    monkeypatch.setattr(management, "ssh_login_users", lambda: [])
    monkeypatch.setattr("os.geteuid", lambda: 0)
    calls = _record_systemctl(monkeypatch)
    result = management.sync_sshd(CONFIG, dropin_path=tmp_path / "40.conf", sshd_binary=_fake_sshd(tmp_path))
    assert result.message.startswith("SSH is off: nobody can log in")
    assert ("disable", "ssh.service") in calls and ("stop", "ssh.service") in calls
    assert ("stop", "ssh.socket") in calls
    assert not any(action in ("start", "enable", "reload-or-restart") for action, _ in calls)
    # The hardened drop-in is still written, for when it is turned on.
    assert "PasswordAuthentication no" in (tmp_path / "40.conf").read_text()


def test_sshd_runs_once_someone_can_log_in(tmp_path, monkeypatch):
    monkeypatch.setattr(management, "ssh_login_users", lambda: ["netadmin"])
    monkeypatch.setattr("os.geteuid", lambda: 0)
    calls = _record_systemctl(monkeypatch)
    sshd = _fake_sshd(tmp_path)
    result = management.sync_sshd(CONFIG, dropin_path=tmp_path / "40.conf", sshd_binary=sshd)
    assert result.message.endswith("key login for netadmin")
    assert calls == [("enable", "ssh.service"), ("reload-or-restart", "ssh.service")]
    calls.clear()
    management.sync_sshd(CONFIG, dropin_path=tmp_path / "40.conf", sshd_binary=sshd)  # nothing changed
    assert calls == [("enable", "ssh.service"), ("start", "ssh.service")]


def test_dry_run_says_ssh_would_be_off(tmp_path, monkeypatch):
    monkeypatch.setattr(management, "ssh_login_users", lambda: [])
    calls = _record_systemctl(monkeypatch)
    result = management.sync_sshd(CONFIG, dry_run=True, dropin_path=tmp_path / "40.conf",
                                  sshd_binary=_fake_sshd(tmp_path))
    assert "Would turn SSH off" in result.message and calls == []


def test_ensure_accounts_creates_the_ssh_group(monkeypatch, tmp_path):
    from frfw import accounts

    ran = []
    monkeypatch.setattr(accounts, "_run", ran.append)
    monkeypatch.setattr(accounts, "_user_exists", lambda name: True)
    monkeypatch.setattr(accounts, "_group_members", lambda name: [paths.SENSOR_USER])
    monkeypatch.setattr(accounts, "_group_exists", lambda name: False)
    monkeypatch.setattr(accounts, "_ensure_dir", lambda *a: None)
    monkeypatch.setattr(paths, "CONFIG_PATH", tmp_path / "config.yaml")
    accounts.ensure()
    assert ["groupadd", "--system", "--", paths.SSH_GROUP] in ran
