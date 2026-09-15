"""PQC (post-quantum hybrid key exchange) status + settings screen.

Follows the same "edit the raw YAML dict, validate, save through the
privileged helper" pattern as every other settings screen (see
frfw.webui.actions.try_save): saving `pqc.enabled` never touches TLS or
sshd directly from this process -- the actual OpenSSL config fragment
and sshd_config.d drop-in are only (re)written the next time `apply`
runs (`frfw.pqc.sync_tls_pqc_conf`/`sync_ssh_kex`, called from
`frfw.provision.apply_all`), exactly like an nftables ruleset or Kea
config change.

Capability detection itself (`frfw.pqc.get_status`) needs no privilege
at all -- `ssl.OPENSSL_VERSION_INFO` is a pure interpreter attribute and
`sshd -Q kex` is an unprivileged, config-file-independent query of
sshd's own compiled-in algorithm list -- so, unlike the ZTNA gate's
kernel-state reads, this status is computed directly in the
unprivileged webUI process rather than round-tripping through the
apply-helper.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request

from frfw import pqc as pqc_mod
from frfw.config import ConfigError, parse_config
from frfw.webui.actions import try_save
from frfw.webui.deps import get_helper, get_raw_config, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


@router.get("/system")
def show_system(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
):
    try:
        config = parse_config(raw)
    except ConfigError:
        # Mirrors update.py's _resolve_repo: an otherwise-invalid config
        # shouldn't make *this* screen unusable, since the invalid
        # config was written by the same webUI its other screens still
        # need to work to fix. Only `pqc.enabled` feeds the status
        # computed below, so a minimal stand-in Config carrying just
        # that one field is enough.
        enabled = bool((raw.get("pqc") or {}).get("enabled", False))
        config = _minimal_config(pqc_enabled=enabled)

    status = pqc_mod.get_status(config)

    return templates.TemplateResponse(
        request,
        "system.html",
        {
            "username": username,
            "status": status,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


def _minimal_config(*, pqc_enabled: bool):
    from frfw.config.schema import Config, NatConfig, PqcConfig

    return Config(
        version=1,
        hostname="fr-router",
        interfaces={},
        zones={},
        rules=[],
        nat=NatConfig(),
        pqc=PqcConfig(enabled=pqc_enabled),
    )


@router.post("/system/pqc/settings")
def save_pqc_settings(
    enabled: bool = Form(False),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    raw["pqc"] = {"enabled": enabled}

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with(
            "/system",
            success="PQC settings saved -- click Apply on the dashboard, then "
            "restart fr-webui, to load them",
        )
    return redirect_with("/system", error=message)
