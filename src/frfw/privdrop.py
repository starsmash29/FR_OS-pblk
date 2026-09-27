"""Dropping root for good once the one privileged step is done.

The daemons that read packet data out of BPF maps (fr-tls-fp,
fr-xdp-sni-logger) need CAP_BPF only to *open* a pinned map. They start as
root with nothing but that in their capability bounding set, open it, and
then become the fr_os-sensor account before reading a byte of it -- the
parsing of untrusted input never runs with privileges (security-lessons
I1). An already open ring buffer keeps working after the drop.
"""

from __future__ import annotations

import grp
import os
import pwd

from frfw import paths

RUN_AS_USER = paths.SENSOR_USER


def drop_privileges(user: str = RUN_AS_USER) -> None:
    """Permanently become `user` (falling back to nobody on a dev box that
    lacks it), keeping only the fr_os-webui group -- which lets it read
    config.yaml and reach the apply-helper, where frfw.helper.peer limits
    it to the sensor commands. Raises if root could not be left."""
    try:
        account = pwd.getpwnam(user)
    except KeyError:
        account = pwd.getpwnam("nobody")
    try:
        extra = [grp.getgrnam(paths.WEBUI_USER).gr_gid]
    except KeyError:
        extra = []
    os.setgroups(extra)
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    if os.getuid() == 0 or os.geteuid() == 0:
        raise RuntimeError(f"failed to drop root privileges to {account.pw_name!r}")
