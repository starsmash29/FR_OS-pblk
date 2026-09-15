"""Loads/saves the frfw config as a plain dict for the webUI to edit.

The webUI edits YAML at the dict level (load -> mutate a section -> dump)
rather than through the `Config` dataclasses: a screen only ever touches
one section (interfaces, rules, nat, dhcp), and re-validating the whole
document via `frfw.config.parse_config` before every save is what
actually guarantees the result is something `firewall-cli` would accept
too -- there is no separate "webUI's idea of a valid config".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from frfw.config import parse_config

_EMPTY_CONFIG: dict[str, Any] = {
    "version": 1,
    "hostname": "fr-router",
    "interfaces": {},
    "zones": {},
    "rules": [],
    "nat": {},
    "dhcp": {},
}


def load_raw(config_path: Path) -> dict[str, Any]:
    if not config_path.is_file():
        return dict(_EMPTY_CONFIG)
    raw = yaml.safe_load(config_path.read_text())
    return raw if isinstance(raw, dict) else dict(_EMPTY_CONFIG)


def dump_raw(raw: dict[str, Any]) -> str:
    return yaml.safe_dump(raw, sort_keys=False, default_flow_style=False)


def validate(raw: dict[str, Any]):
    """Return the parsed `Config` if valid; raises `ConfigError` otherwise."""
    return parse_config(raw)
