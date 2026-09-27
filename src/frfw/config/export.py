"""A configuration export that is safe to hand out (security-lessons G3).

FortiBleed attackers exported config backups and cracked the admin
hashes in them offline. Anything that ever exports FR_OS's configuration
-- today `firewall-cli config-export`, later the backup feature (ROADMAP
phase 29) -- goes through `redacted()`, which leaves out every secret:
ZTNA users' password hashes and the /metrics token digest. The webUI's
own accounts (auth.json), session key and TLS key are never part of the
config at all. An imported ZTNA user needs a new password; one with the
placeholder can't sign in (it never verifies).
"""

from __future__ import annotations

import copy

import yaml

REMOVED = "<removed on export: set a new password>"


def redacted(raw: dict) -> dict:
    out = copy.deepcopy(raw) if isinstance(raw, dict) else {}
    ztna = out.get("ztna")
    if isinstance(ztna, dict):
        for user in ztna.get("users") or []:
            if isinstance(user, dict) and "password_hash" in user:
                user["password_hash"] = REMOVED
    metrics = out.get("metrics")
    if isinstance(metrics, dict):
        metrics.pop("token_sha256", None)
    return out


def export_text(raw: dict) -> str:
    return ("# FR_OS configuration export -- secrets removed (ZTNA password hashes,\n"
            "# metrics token). Set new ones after importing.\n"
            + yaml.safe_dump(redacted(raw), sort_keys=False))
