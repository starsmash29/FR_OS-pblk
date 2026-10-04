"""A configuration export that is safe to hand out (security-lessons G3).

FortiBleed attackers exported config backups and cracked the admin
hashes in them offline. Anything that ever exports FR_OS's configuration
-- today `firewall-cli config-export`, later the backup feature (ROADMAP
phase 29) -- goes through `redacted()`, which leaves out every secret:
ZTNA users' password hashes and the /metrics token digest. The webUI's
own accounts (auth.json), session key and TLS key are never part of the
config at all. An imported ZTNA user needs a new password; one with the
placeholder can't sign in (it never verifies).

The same redaction makes the copy the parser daemons read
(paths.SENSOR_CONFIG_PATH, ROADMAP SEC-11): they parse untrusted network
input, so they get the configuration without its secrets, and can't read
config.yaml itself. `write_sensor_copy()` rewrites it whenever root
writes or applies config.yaml (the apply-helper's save_config and apply,
`firewall-cli apply` -- also at boot -- and `firewall-cli metrics-token`).
"""

from __future__ import annotations

import copy
import grp
import os
from pathlib import Path

import yaml

from frfw import paths

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


SENSOR_COPY_HEADER = (
    "# Generated from config.yaml without its secrets, for the parser daemons\n"
    "# (ROADMAP SEC-11). Rewritten on every save and apply: edit config.yaml.\n"
)


def write_sensor_copy(raw: dict, path: Path | None = None) -> Path:
    """Write `raw`, redacted, as the parser daemons' configuration:
    root:fr_os-sensor 0640, replaced atomically, never briefly readable by
    anyone else. Returns the path written."""
    path = path or paths.SENSOR_CONFIG_PATH
    text = SENSOR_COPY_HEADER + yaml.safe_dump(redacted(raw), sort_keys=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        if os.geteuid() == 0:
            try:
                gid = grp.getgrnam(paths.SENSOR_USER).gr_gid
            except KeyError:  # no sensor account (a dev box): root's alone
                gid = 0
            os.chown(tmp, 0, gid)
        os.chmod(tmp, 0o640)
        tmp.replace(path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return path


def refresh_sensor_copy(config_path: Path, path: Path | None = None) -> str | None:
    """write_sensor_copy() from the config file at `config_path`. Returns
    None, or what went wrong -- a failure here never fails the save or
    apply it follows, it is reported with it (the daemons then keep the
    copy they have)."""
    try:
        raw = yaml.safe_load(Path(config_path).read_text()) or {}
        write_sensor_copy(raw if isinstance(raw, dict) else {}, path)
    except (OSError, yaml.YAMLError) as exc:
        return f"could not refresh the sensors' config copy: {exc}"
    return None
