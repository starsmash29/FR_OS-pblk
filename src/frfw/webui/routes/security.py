"""The security checklist screen (security-lessons K8; see
frfw.security_score). The dashboard shows the score and what's open."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request

from frfw import __version__, integrity, rule_lint, security_score, surface
from frfw import update as update_mod
from frfw.admin_account import AdminStore
from frfw.config import ConfigError, parse_config
from frfw.webui.deps import get_admin_store, get_helper, get_raw_config, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.templating import templates

router = APIRouter()


def score_for(request: Request, raw: dict, admin_store: AdminStore, helper: HelperClient) -> security_score.Score:
    try:
        config = parse_config(raw)
    except ConfigError:
        config = None
    rows = None
    findings = None
    if config is not None:
        findings = rule_lint.lint(config)
        try:
            reply = helper.listening_sockets()
        except OSError:
            reply = {}
        if reply.get("ok"):
            listeners = [surface.Listener(**l) for l in reply.get("listeners", [])]
            rows = surface.surface(config, listeners, reply.get("addresses") or {})
    return security_score.evaluate(
        config=config,
        accounts=admin_store.users(),
        policy=admin_store.policy(),
        update_check=update_mod.read_check_cache(Path(request.app.state.update_check_path),
                                                 current_version=__version__),
        integrity=integrity.cached_check(),
        lint_findings=findings,
        surface_rows=rows,
    )


@router.get("/security")
def show_security(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    admin_store: AdminStore = Depends(get_admin_store),
    helper: HelperClient = Depends(get_helper),
):
    return templates.TemplateResponse(request, "security.html", {
        "username": username,
        "score": score_for(request, raw, admin_store, helper),
    })
