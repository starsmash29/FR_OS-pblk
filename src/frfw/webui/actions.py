"""Shared "validate then save through the helper" logic for every screen.

Validating client-side (in the webUI process) first means a bad edit gets
a fast, specific error without a socket round trip; the apply-helper's
own `save_config` re-validates from scratch before writing anything, so
there is never a path where an invalid config reaches disk even if this
first check were skipped or wrong.
"""

from __future__ import annotations

from frfw.config import ConfigError
from frfw.webui.config_store import dump_raw, validate
from frfw.webui.helper_client import HelperClient


def try_save(raw: dict, helper: HelperClient) -> tuple[bool, str]:
    try:
        validate(raw)
    except ConfigError as exc:
        return False, str(exc)

    result = helper.save_config(dump_raw(raw))
    return bool(result.get("ok")), str(result.get("message", ""))
