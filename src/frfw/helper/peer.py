"""Who is on the other end of a helper socket, and what may they ask for.

Both root helpers used to rely on the socket file's permissions alone
(0660 root:fr_os-webui). That group was shared by the webUI *and* by the
daemons that parse attacker-controlled network input (AI IDS, App-ID,
IoT scan, TLS fingerprinting), so one bug in a parser was one JSON line
away from root: `save_config` + `apply` on the apply-helper, or an
arbitrary `apply` on the update-helper.

(Since ROADMAP SEC-11 the apply-helper socket is root:fr_os-feeds, a
group the two share and nothing else, and the sensor account is no
longer in fr_os-webui; the per-uid check below is unchanged.)

Now the kernel tells each helper the connecting process's uid
(`SO_PEERCRED`, which the peer cannot forge) and the helper decides per
command:

- **full**: root, the helper's own uid (a development run where client
  and helper are the same unprivileged user) and the webUI's account
  (`fr_os-webui`) -- everything;
- **sensor**: the parser daemons' account (`fr_os-sensor`) -- only the
  few commands those daemons exist to send (quarantine a host, read
  conntrack and DHCP leases, sync IoT isolation);
- anyone else: nothing, not even `ping`.

The update-helper accepts only the full role. The parser daemons run as
`fr_os-sensor` with their state in paths.SENSOR_STATE_DIR, so they can't
read the webUI's session secret or TLS key either (see frfw.accounts).
"""

from __future__ import annotations

import grp
import os
import pwd
import socket
import struct
from dataclasses import dataclass, field

from frfw import paths

FULL = "full"
SENSOR = "sensor"

#: What a parser daemon may ask the apply-helper for -- exactly what
#: frfw.ai_ids.daemon, frfw.tlsfp.daemon and frfw.iot.scanner send.
SENSOR_COMMANDS = frozenset({
    "ping",
    "quarantine_ip",
    "conntrack_sample",
    "dhcp_leases",
    "iot_sync_isolation",
})

_UCRED = struct.Struct("3i")  # struct ucred: pid, uid, gid


def peer_credentials(sock: socket.socket) -> tuple[int, int, int]:
    """(pid, uid, gid) of the process at the other end of a Unix socket."""
    return _UCRED.unpack(sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size))


def _uid_of(user: str) -> int | None:
    try:
        return pwd.getpwnam(user).pw_uid
    except KeyError:
        return None


def gid_of(group: str) -> int | None:
    try:
        return grp.getgrnam(group).gr_gid
    except KeyError:
        return None


@dataclass(frozen=True)
class PeerPolicy:
    full_uids: frozenset[int] = field(default_factory=frozenset)
    sensor_uids: frozenset[int] = field(default_factory=frozenset)

    @classmethod
    def from_system(cls) -> "PeerPolicy":
        full = {0, os.geteuid()}
        webui = _uid_of(paths.WEBUI_USER)
        if webui is not None:
            full.add(webui)
        sensor = _uid_of(paths.SENSOR_USER)
        # An account can't be both; if someone points them at one uid,
        # the narrower role wins.
        sensors = frozenset() if sensor is None else frozenset({sensor})
        return cls(frozenset(full - sensors), sensors)

    def role(self, uid: int) -> str | None:
        if uid in self.full_uids:
            return FULL
        if uid in self.sensor_uids:
            return SENSOR
        return None

    def allows(self, uid: int, cmd: object, *, sensor_commands: frozenset[str] = SENSOR_COMMANDS) -> bool:
        role = self.role(uid)
        if role == FULL:
            return True
        return role == SENSOR and cmd in sensor_commands
