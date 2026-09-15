"""Client for the update-helper Unix socket, for use by the webUI.

Reuses frfw.helper.client's transport (`send_command`, `HelperError`)
wholesale -- the wire format is identical (one JSON object per line,
same size bound), it just talks to a different socket for a different,
deliberately separate daemon (see frfw.helper.update_server for why).
"""

from __future__ import annotations

from pathlib import Path

from frfw import paths
from frfw.helper.client import HelperError, send_command

__all__ = ["HelperError", "ping", "apply", "rollback"]

#: A real update (download + pip install + service restarts) can easily
#: take much longer than the apply-helper's fast nft operations, hence a
#: far more generous default timeout here.
DEFAULT_TIMEOUT = 300.0


def ping(socket_path: Path = paths.UPDATE_SOCKET_PATH) -> dict:
    return send_command({"cmd": "ping"}, socket_path)


def apply(
    version: str,
    socket_path: Path = paths.UPDATE_SOCKET_PATH,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    return send_command({"cmd": "apply", "version": version}, socket_path, timeout=timeout)


def rollback(
    socket_path: Path = paths.UPDATE_SOCKET_PATH, timeout: float = DEFAULT_TIMEOUT
) -> dict:
    return send_command({"cmd": "rollback"}, socket_path, timeout=timeout)
