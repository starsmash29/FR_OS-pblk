"""The webUI's view of the two privileged helpers (firewall apply, and
system update -- see frfw.helper.update_server for why they're
separate): a small Protocol plus the real Unix-socket-backed
implementation for each.

Routes depend on the Protocols, not the Socket* classes directly, so
tests can inject an in-memory fake instead of needing a real helper
daemon and Unix socket running.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from frfw import paths
from frfw.helper import client as helper_client
from frfw.helper import update_client


class HelperClient(Protocol):
    def ping(self) -> dict: ...
    def save_config(self, yaml_text: str) -> dict: ...
    def apply(self, dry_run: bool = False) -> dict: ...
    def rollback(self) -> dict: ...


class SocketHelperClient:
    def __init__(self, socket_path: Path = paths.APPLY_SOCKET_PATH) -> None:
        self.socket_path = socket_path

    def ping(self) -> dict:
        return helper_client.ping(self.socket_path)

    def save_config(self, yaml_text: str) -> dict:
        return helper_client.save_config(yaml_text, self.socket_path)

    def apply(self, dry_run: bool = False) -> dict:
        return helper_client.apply_config(dry_run=dry_run, socket_path=self.socket_path)

    def rollback(self) -> dict:
        return helper_client.rollback(self.socket_path)


class UpdateHelperClient(Protocol):
    def ping(self) -> dict: ...
    def apply(self, version: str) -> dict: ...
    def rollback(self) -> dict: ...


class SocketUpdateHelperClient:
    def __init__(self, socket_path: Path = paths.UPDATE_SOCKET_PATH) -> None:
        self.socket_path = socket_path

    def ping(self) -> dict:
        return update_client.ping(self.socket_path)

    def apply(self, version: str) -> dict:
        return update_client.apply(version, socket_path=self.socket_path)

    def rollback(self) -> dict:
        return update_client.rollback(socket_path=self.socket_path)
