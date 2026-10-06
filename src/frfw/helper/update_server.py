"""Root-run update-helper daemon: the privileged side of the webUI's
update mechanism (phase 6, see frfw.update and ARCHITECTURE.md).

Deliberately a separate daemon/socket from frfw.helper.server (the
firewall apply-helper) -- see frfw.helper.update_protocol's module
docstring for why. Structurally this mirrors that module closely
(systemd socket activation, one-JSON-object-per-line, StreamRequestHandler
per connection); the duplication is small and keeping the two daemons
fully independent (no shared base class) means a change to one's
request handling can never accidentally affect the other's.

Only root and the webUI's account may use it: the socket file belongs to
fr_os-webui with mode 0600 (systemd/fr-update-helper.socket), and every
connection's kernel-reported peer uid is checked again here
(frfw.helper.peer) -- installing a release runs code as root.

It also runs the kernel side of the Update screen (ROADMAP SEC-14,
frfw.kernel_update): what kernel runs, which is ready to try, "check now"
(starts fr-kernel-prepare.service), "try it" -- stage the prepared kernel
and reboot into its trial, the one reboot FR_OS asks for, and only an
admin's -- and cancelling a staged one.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import socketserver
import subprocess
import sys
import threading
from pathlib import Path
from typing import Callable

from frfw import kernel_boot, kernel_update, paths
from frfw import update as update_mod
from frfw.helper.peer import FULL, PeerPolicy, peer_credentials
from frfw.helper.update_protocol import MAX_LINE_BYTES

_SD_LISTEN_FDS_START = 3


def _systemd_provided_socket() -> socket.socket | None:
    """Return the socket systemd handed us via socket activation, if any."""
    listen_pid = os.environ.get("LISTEN_PID")
    listen_fds = os.environ.get("LISTEN_FDS")
    if not listen_pid or not listen_fds:
        return None
    if int(listen_pid) != os.getpid() or int(listen_fds) < 1:
        return None
    return socket.fromfd(_SD_LISTEN_FDS_START, socket.AF_UNIX, socket.SOCK_STREAM)


def _handle_request(request: dict, server: "UpdateHelperServer") -> dict:
    cmd = request.get("cmd")
    try:
        if cmd == "ping":
            return {"ok": True, "message": "pong"}

        if cmd == "apply":
            version = request.get("version")
            if not isinstance(version, str) or not version:
                return {"ok": False, "message": "'version' must be a non-empty string"}
            new_version = update_mod.apply_update(
                version,
                repo=server.repo,
                state_path=server.state_path,
                releases_dir=server.releases_dir,
            )
            return {"ok": True, "message": f"Updated to {new_version}"}

        if cmd == "rollback":
            restored = update_mod.rollback_update(
                repo=server.repo,
                state_path=server.state_path,
                releases_dir=server.releases_dir,
            )
            return {"ok": True, "message": f"Rolled back to {restored}"}

        if cmd == "kernel_status":
            return {"ok": True, "kernel": kernel_update.overview(state_path=server.kernel_state_path,
                                                                 boot_dir=server.kernel_boot_dir())}

        if cmd == "kernel_check":
            server.start_unit("fr-kernel-prepare.service")
            return {"ok": True, "message": "Checking Debian for a newer kernel -- this page shows the result"}

        if cmd == "kernel_try":
            boot_dir = server.kernel_boot_dir()
            if boot_dir is None:
                return {"ok": False, "message": "no persistence partition in use: a kernel can't be tried"}
            version = kernel_update.try_prepared(boot_dir=boot_dir, state_path=server.kernel_state_path)
            server.alert(f"kernel {version} staged from the webUI: the router reboots into its trial; it keeps "
                         "it only if it comes up on it")
            server.reboot_soon()
            return {"ok": True, "message": f"Kernel {version} staged -- the router reboots into its trial now"}

        if cmd == "kernel_cancel":
            boot_dir = server.kernel_boot_dir()
            if boot_dir is None or not kernel_boot.unstage(boot_dir=boot_dir):
                return {"ok": True, "message": "Nothing was staged"}
            server.alert("staged kernel removed from the webUI: the image's own kernel boots from the next reboot")
            return {"ok": True, "message": "Staged kernel removed: the image's own kernel boots from the next reboot"}

        return {"ok": False, "message": f"unknown command {cmd!r}"}
    except (update_mod.UpdateError, kernel_update.KernelUpdateError, kernel_boot.KernelBootError) as exc:
        return {"ok": False, "message": str(exc)}


def _start_unit(unit: str) -> None:
    subprocess.run(["systemctl", "start", "--no-block", unit], check=True, capture_output=True)


def _reboot_soon(delay: float = 3.0) -> None:
    """After the answer has gone back to the webUI."""
    timer = threading.Timer(delay, subprocess.run, args=(["systemctl", "reboot"],), kwargs={"check": False})
    timer.daemon = False
    timer.start()


def _alert(message: str) -> None:
    """Security-lessons G9: in the dashboard's security alerts."""
    from frfw.webui import audit

    try:
        audit.prepare(paths.AUDIT_LOG_PATH)
        audit.alert(paths.AUDIT_LOG_PATH, message, user="webUI", client="update-helper")
    except OSError:
        pass


class _Handler(socketserver.StreamRequestHandler):
    server: "UpdateHelperServer"

    def handle(self) -> None:
        line = self.rfile.readline(MAX_LINE_BYTES)
        if not line:
            return
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("request must be a JSON object")
            pid, uid, _gid = peer_credentials(self.connection)
            if self.server.peer_policy.role(uid) == FULL:
                response = _handle_request(request, self.server)
            else:
                print(f"firewall-update-helper: refused {request.get('cmd')!r} from pid {pid} uid {uid}",
                      file=sys.stderr, flush=True)
                response = {"ok": False, "message": f"uid {uid} may not use the update-helper"}
        except (ValueError, TypeError) as exc:
            response = {"ok": False, "message": f"invalid request: {exc}"}
        self.wfile.write(json.dumps(response).encode() + b"\n")


class UpdateHelperServer(socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(
        self,
        socket_path: Path = paths.UPDATE_SOCKET_PATH,
        *,
        repo: str = update_mod.DEFAULT_REPO,
        state_path: Path = paths.UPDATE_STATE_PATH,
        releases_dir: Path = paths.RELEASES_DIR,
        systemd_socket: socket.socket | None = None,
        peer_policy: PeerPolicy | None = None,
        kernel_state_path: Path = paths.KERNEL_UPDATE_STATE_PATH,
        kernel_boot_dir: Callable[[], Path | None] = kernel_boot.boot_dir,
        start_unit: Callable[[str], None] | None = None,
        reboot_soon: Callable[[], None] | None = None,
        alert: Callable[[str], None] | None = None,
    ) -> None:
        self._peer_policy = peer_policy
        self.kernel_state_path = kernel_state_path
        self.kernel_boot_dir = kernel_boot_dir
        self.start_unit = start_unit or _start_unit
        self.reboot_soon = reboot_soon or _reboot_soon
        self.alert = alert or _alert
        self.repo = repo
        self.state_path = state_path
        self.releases_dir = releases_dir
        self._owns_socket_file = systemd_socket is None

        if systemd_socket is not None:
            super().__init__(str(socket_path), _Handler, bind_and_activate=False)
            self.socket.close()
            self.socket = systemd_socket
        else:
            socket_path = Path(socket_path)
            socket_path.parent.mkdir(parents=True, exist_ok=True)
            socket_path.unlink(missing_ok=True)
            super().__init__(str(socket_path), _Handler)

    @property
    def peer_policy(self) -> PeerPolicy:
        # Looked up per connection, not once at start: fr-accounts.service
        # may create fr_os-sensor after this daemon is already running
        # (the first boot after an update).
        return self._peer_policy or PeerPolicy.from_system()

    def server_close(self) -> None:
        super().server_close()
        if self._owns_socket_file:
            Path(self.server_address).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="firewall-update-helper")
    parser.add_argument("--socket", default=str(paths.UPDATE_SOCKET_PATH))
    parser.add_argument("--repo", default=update_mod.DEFAULT_REPO)
    parser.add_argument("--state-path", default=str(paths.UPDATE_STATE_PATH))
    parser.add_argument("--releases-dir", default=str(paths.RELEASES_DIR))
    args = parser.parse_args(argv)

    server = UpdateHelperServer(
        Path(args.socket),
        repo=args.repo,
        state_path=Path(args.state_path),
        releases_dir=Path(args.releases_dir),
        systemd_socket=_systemd_provided_socket(),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
