"""Restarting/reloading other services from an apply, without deadlocking
the boot.

`fr-firewall.service` applies the config very early (it orders itself
before network-pre.target, in sysinit), and an apply restarts Kea, reloads
sshd, restarts the DNS-filtering dnsmasq... A plain `systemctl restart
kea-dhcp4-server` there waits for a job that systemd has ordered *after*
fr-firewall itself: each waits for the other and the boot hangs forever
(found booting the image in QEMU: "Job fr-firewall.service/start running
(8min / no limit)").

So while the system is still booting, the job is only queued
(`--no-block`) and runs in its proper place in the boot order; the
configuration it will load was already validated (kea-dhcp4 -t, sshd -t,
dnsmasq --test). Once the system is up -- an Apply from the webUI or the
CLI -- the call stays synchronous, so a service that fails to come back
is reported to the user.
"""

from __future__ import annotations

import subprocess

#: `systemctl is-system-running` states in which systemd is still working
#: through the boot transaction.
BOOTING_STATES = frozenset({"initializing", "starting"})


def system_is_booting() -> bool:
    try:
        proc = subprocess.run(["systemctl", "is-system-running"], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return proc.stdout.strip() in BOOTING_STATES


def systemctl(action: str, unit: str, *, timeout: float | None = None) -> subprocess.CompletedProcess:
    """`systemctl ACTION UNIT`, with --no-block while booting. Raises
    FileNotFoundError without systemctl, like subprocess.run."""
    cmd = ["systemctl", action, unit]
    if system_is_booting():
        cmd.insert(1, "--no-block")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
