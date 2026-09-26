"""frfw.svc: service restarts from an apply must not deadlock the boot."""

from __future__ import annotations

import subprocess

from frfw import svc


def _fake_run(state: str, calls: list):
    def run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["systemctl", "is-system-running"]:
            return subprocess.CompletedProcess(cmd, 1, stdout=f"{state}\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    return run


def test_while_booting_the_job_is_only_queued(monkeypatch):
    # fr-firewall applies in sysinit; a blocking restart of Kea (ordered
    # after it) would wait forever.
    for state in ("starting", "initializing"):
        calls = []
        monkeypatch.setattr(svc.subprocess, "run", _fake_run(state, calls))
        svc.systemctl("restart", "kea-dhcp4-server")
        assert calls[-1] == ["systemctl", "--no-block", "restart", "kea-dhcp4-server"]


def test_once_up_the_call_waits_so_failures_are_reported(monkeypatch):
    for state in ("running", "degraded"):
        calls = []
        monkeypatch.setattr(svc.subprocess, "run", _fake_run(state, calls))
        svc.systemctl("reload", "ssh")
        assert calls[-1] == ["systemctl", "reload", "ssh"]


def test_no_systemctl_means_not_booting(monkeypatch):
    def run(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])
    monkeypatch.setattr(svc.subprocess, "run", run)
    assert svc.system_is_booting() is False
