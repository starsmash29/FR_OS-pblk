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

import base64
import hashlib
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import Response

from frfw import pqc as pqc_mod
from frfw import persistence as persistence_mod
from frfw.config import ConfigError, parse_config
from frfw.metrics import generate_metrics_token
from frfw.webui.actions import try_save
from frfw.webui.deps import get_helper, get_raw_config, get_webui_cert_path, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


@router.get("/system")
def show_system(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    cert_path: Path = Depends(get_webui_cert_path),
):
    return _render_system(request, username, raw, cert_path, new_token=None)


def _render_system(request: Request, username: str, raw: dict, cert_path: Path, *, new_token: str | None):
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
    metrics_raw = raw.get("metrics") or {}
    # Unprivileged: no blkid probing, only /proc (which is all the webUI needs).
    persistence = persistence_mod.status(labelled=[])

    return templates.TemplateResponse(
        request,
        "system.html",
        {
            "username": username,
            "status": status,
            "persistence": persistence,
            "metrics_site": metrics_raw.get("site") or "",
            "metrics_hostname": raw.get("hostname") or "",
            "metrics_token_set": bool(metrics_raw.get("token_sha256")),
            "cert_sha256": _cert_fingerprint(cert_path),
            "new_token": new_token,
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


# --- phase 20: multi-site monitoring --------------------------------------


def _cert_der(cert_path: Path) -> bytes | None:
    try:
        text = cert_path.read_text()
    except OSError:
        return None
    begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    if begin not in text or end not in text:
        return None
    body = text.split(begin, 1)[1].split(end, 1)[0]
    try:
        return base64.b64decode("".join(body.split()))
    except ValueError:
        return None


def _cert_fingerprint(cert_path: Path) -> str | None:
    """SHA-256 of the webUI certificate, colon-separated like browsers and
    `openssl x509 -fingerprint -sha256` show it -- to check that the
    certificate a remote Prometheus is given really is this router's."""
    der = _cert_der(cert_path)
    if der is None:
        return None
    return ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())


@router.get("/system/cert.pem")
def download_cert(username: str = Depends(require_login), cert_path: Path = Depends(get_webui_cert_path)):
    """The webUI's (public) certificate, for a remote Prometheus's ca_file."""
    if _cert_der(cert_path) is None:
        return Response("no certificate\n", status_code=404, media_type="text/plain")
    return Response(cert_path.read_text(), media_type="application/x-pem-file",
                    headers={"Content-Disposition": 'attachment; filename="fr_os-webui.pem"'})


@router.post("/system/metrics/site")
def save_metrics_site(
    site: str = Form(""),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    section = dict(raw.get("metrics") or {})
    if site.strip():
        section["site"] = site.strip()
    else:
        section.pop("site", None)
    raw["metrics"] = section
    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/system", success="Site name saved")
    return redirect_with("/system", error=message)


@router.post("/system/metrics/token")
def change_metrics_token(
    request: Request,
    action: str = Form(...),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
    cert_path: Path = Depends(get_webui_cert_path),
):
    section = dict(raw.get("metrics") or {})
    token = None
    if action == "generate":
        token, section["token_sha256"] = generate_metrics_token()
    elif action == "disable":
        section.pop("token_sha256", None)
    else:
        return redirect_with("/system", error=f"unknown action {action!r}")
    raw["metrics"] = section
    ok, message = try_save(raw, helper)
    if not ok:
        return redirect_with("/system", error=message)
    if token is None:
        return redirect_with("/system", success="Metrics token removed: /metrics is public again")
    # Rendered directly, never redirected: a token in a URL would end up in
    # browser history and access logs. This page is the only place it appears.
    return _render_system(request, username, raw, cert_path, new_token=token)
