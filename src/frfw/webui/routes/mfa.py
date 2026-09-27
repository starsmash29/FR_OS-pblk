"""Second-factor sign-in and enrolment (security-lessons G5; see
frfw.webui.mfa for the design).

Sign-in: POST /login with the right password and a factor on the account
sets only a ticket cookie; /login/mfa takes a TOTP code or a security-key
assertion and only then issues the session. Enrolment and removal live
under /account/mfa and always need the current password again, so a
hijacked session can't quietly add its own factor or remove the owner's.
"""

from __future__ import annotations

import io
import json
import threading
from pathlib import Path

import segno
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse

from frfw.admin_account import AccountError
from frfw.webui import audit, mfa
from frfw.webui.auth import AdminStore, SessionManager
from frfw.webui.auth_rate_limiter import BruteforceGuard, reject_failed_login
from frfw.webui.client_ip import client_ip
from frfw.webui.deps import (
    get_admin_store,
    get_audit_log_path,
    get_bruteforce_guard,
    get_helper,
    get_mfa_enrolments,
    get_mfa_tickets,
    get_session_manager,
    require_admin,
    require_login,
)
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.routes.auth import issue_session
from frfw.webui.templating import templates

router = APIRouter()

#: Checking a TOTP code and recording its time step is one step, so two
#: requests racing with the same code can't both get through.
_TOTP_LOCK = threading.Lock()


def _rp(request: Request) -> tuple[str | None, str]:
    host = request.url.hostname
    return mfa.rp_id_for(host), mfa.origin_for(request.url.scheme, host or "", request.url.port)


def _ticket(request: Request, tickets: mfa.TicketStore, store: AdminStore):
    tid = request.cookies.get(mfa.TICKET_COOKIE)
    found = tickets.get(tid, store.get)
    return (tid, *found) if found else (None, None, None)


def _finish_login(request, tid, account, tickets, store, session_manager, guard, audit_log_path, how):
    if not tickets.consume(tid):  # used up in a parallel request
        return redirect_with("/login", error="This sign-in was already completed or has expired")
    ip = client_ip(request)
    guard.record_success(ip)
    audit.append(audit_log_path, {"user": account.username, "role": account.role, "client": ip,
                                  "event": f"login ({how})"})
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(mfa.TICKET_COOKIE, path="/login")
    return issue_session(request, response, store.get(account.username), session_manager)


# -- the second sign-in step ----------------------------------------------------------------

@router.get("/login/mfa")
def mfa_form(
    request: Request,
    store: AdminStore = Depends(get_admin_store),
    tickets: mfa.TicketStore = Depends(get_mfa_tickets),
):
    tid, _entry, account = _ticket(request, tickets, store)
    if account is None:
        return redirect_with("/login", error="Sign in again")
    rp_id, _origin = _rp(request)
    keys = [c for c in account.mfa.get("webauthn", []) if rp_id and c.get("rp_id") == rp_id]
    return templates.TemplateResponse(request, "mfa_login.html", {
        "totp": bool(account.mfa.get("totp")),
        "keys": bool(keys),
        "keys_elsewhere": bool(account.mfa.get("webauthn")) and not keys,
        "error": request.query_params.get("error"),
    })


@router.post("/login/mfa/totp")
def mfa_totp(
    request: Request,
    code: str = Form(...),
    store: AdminStore = Depends(get_admin_store),
    tickets: mfa.TicketStore = Depends(get_mfa_tickets),
    session_manager: SessionManager = Depends(get_session_manager),
    helper: HelperClient = Depends(get_helper),
    guard: BruteforceGuard = Depends(get_bruteforce_guard),
    audit_log_path: Path = Depends(get_audit_log_path),
):
    tid, _entry, account = _ticket(request, tickets, store)
    if account is None or tickets.account_locked(account.username):
        return redirect_with("/login", error="Sign in again")
    with _TOTP_LOCK:
        account = store.get(account.username)
        totp = account.mfa.get("totp") or {}
        step = (mfa.totp_step(totp.get("secret", ""), code, last_step=int(totp.get("last_step", -1)))
                if totp else None)
        if step is not None:
            # A code works once: remember its time step before anything else.
            store.set_mfa(account.username, {**account.mfa, "totp": {**totp, "last_step": step}})
    if step is None:
        ip = client_ip(request)
        audit.append(audit_log_path, {"user": account.username, "client": ip, "event": "second factor failed"})
        still_usable = tickets.fail(tid)
        return reject_failed_login(ip, guard, helper, redirect_path="/login/mfa" if still_usable else "/login")
    return _finish_login(request, tid, account, tickets, store, session_manager, guard, audit_log_path, "TOTP")


@router.post("/login/mfa/webauthn/options")
def mfa_webauthn_options(
    request: Request,
    store: AdminStore = Depends(get_admin_store),
    tickets: mfa.TicketStore = Depends(get_mfa_tickets),
):
    tid, entry, account = _ticket(request, tickets, store)
    rp_id, _origin = _rp(request)
    if account is None or rp_id is None:
        return JSONResponse({"error": "sign in again, by name (not IP address)"}, status_code=400)
    options, challenge = mfa.authentication_options(account, rp_id)
    entry.data["challenge"] = challenge
    return JSONResponse(json.loads(options))


@router.post("/login/mfa/webauthn/verify")
async def mfa_webauthn_verify(
    request: Request,
    store: AdminStore = Depends(get_admin_store),
    tickets: mfa.TicketStore = Depends(get_mfa_tickets),
    session_manager: SessionManager = Depends(get_session_manager),
    helper: HelperClient = Depends(get_helper),
    guard: BruteforceGuard = Depends(get_bruteforce_guard),
    audit_log_path: Path = Depends(get_audit_log_path),
):
    tid, entry, account = _ticket(request, tickets, store)
    rp_id, origin = _rp(request)
    challenge = entry.data.pop("challenge", None) if entry else None
    if account is None or rp_id is None or challenge is None or tickets.account_locked(account.username):
        return JSONResponse({"error": "sign in again"}, status_code=400)
    try:
        body = (await request.body()).decode()
        updated = mfa.verify_authentication(account, body, challenge, rp_id, origin)
    except Exception:  # noqa: BLE001 -- any verification failure is a failed login
        ip = client_ip(request)
        audit.append(audit_log_path, {"user": account.username, "client": ip, "event": "second factor failed"})
        tickets.fail(tid)
        reject_failed_login(ip, guard, helper, redirect_path="/login")
        return JSONResponse({"error": "the security key was not accepted"}, status_code=403)
    store.set_mfa(account.username, updated)
    response = _finish_login(request, tid, account, tickets, store, session_manager, guard, audit_log_path,
                             "security key")
    if isinstance(response, RedirectResponse) and response.headers["location"] == "/":
        out = JSONResponse({"redirect": "/"})
        for key, value in response.raw_headers:
            if key == b"set-cookie":
                out.raw_headers.append((key, value))
        return out
    return JSONResponse({"error": "this sign-in was already completed"}, status_code=409)


# -- enrolment ----------------------------------------------------------------------------------

def _view(request: Request, username: str, store: AdminStore, **extra):
    account = store.get(username)
    rp_id, _origin = _rp(request)
    return templates.TemplateResponse(request, "mfa_account.html", {
        "username": username,
        "totp": bool(account.mfa.get("totp")),
        "keys": account.mfa.get("webauthn", []),
        "rp_id": rp_id,
        "required": store.policy().get("require_mfa_for_admins") and account.is_admin and not account.has_mfa,
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
        **extra,
    })


@router.get("/account/mfa")
def mfa_account(request: Request, username: str = Depends(require_login),
                store: AdminStore = Depends(get_admin_store)):
    return _view(request, username, store)


@router.get("/account/mfa/totp")
def mfa_totp_start(
    request: Request,
    username: str = Depends(require_login),
    store: AdminStore = Depends(get_admin_store),
    enrolments: mfa.TicketStore = Depends(get_mfa_enrolments),
):
    account = store.get(username)
    secret = mfa.new_totp_secret()
    tid = enrolments.create(account)
    enrolments.get(tid, store.get)[0].data["totp_secret"] = secret
    uri = mfa.totp_uri(secret, username, request.url.hostname or "fr-router")
    svg = io.BytesIO()
    segno.make(uri, error="m").save(svg, kind="svg", scale=5, dark="#0C141F", light="#FFFFFF", xmldecl=False)
    return _view(request, username, store, new_totp={"tid": tid, "secret": secret, "qr": svg.getvalue().decode()})


@router.post("/account/mfa/totp")
def mfa_totp_confirm(
    request: Request,
    tid: str = Form(...),
    code: str = Form(...),
    password: str = Form(...),
    username: str = Depends(require_login),
    store: AdminStore = Depends(get_admin_store),
    enrolments: mfa.TicketStore = Depends(get_mfa_enrolments),
    audit_log_path: Path = Depends(get_audit_log_path),
):
    if store.verify(username, password) is None:
        return redirect_with("/account/mfa", error="Current password is wrong")
    found = enrolments.get(tid, store.get)
    if found is None or found[1].username != username or "totp_secret" not in found[0].data:
        return redirect_with("/account/mfa", error="That setup expired -- start again")
    secret = found[0].data["totp_secret"]
    step = mfa.totp_step(secret, code)
    if step is None:
        return redirect_with("/account/mfa", error="The code didn't match -- check the phone's clock and try again")
    enrolments.consume(tid)
    account = store.get(username)
    store.set_mfa(username, {**account.mfa, "totp": {"secret": secret, "last_step": step}})
    audit.append(audit_log_path, {"user": username, "client": client_ip(request), "event": "added authenticator app"})
    return redirect_with("/account/mfa", success="Authenticator app added")


@router.post("/account/mfa/webauthn/options")
async def mfa_key_options(
    request: Request,
    username: str = Depends(require_login),
    store: AdminStore = Depends(get_admin_store),
    enrolments: mfa.TicketStore = Depends(get_mfa_enrolments),
):
    body = await request.json()
    rp_id, _origin = _rp(request)
    if rp_id is None:
        return JSONResponse({"error": "open the router by name, not IP address, to add a security key"},
                            status_code=400)
    if store.verify(username, str(body.get("password", ""))) is None:
        return JSONResponse({"error": "current password is wrong"}, status_code=403)
    account = store.get(username)
    options, challenge = mfa.registration_options(account, rp_id)
    tid = enrolments.create(account)
    enrolments.get(tid, store.get)[0].data.update(challenge=challenge, name=str(body.get("name", "")))
    return JSONResponse({"tid": tid, "options": json.loads(options)})


@router.post("/account/mfa/webauthn/register")
async def mfa_key_register(
    request: Request,
    username: str = Depends(require_login),
    store: AdminStore = Depends(get_admin_store),
    enrolments: mfa.TicketStore = Depends(get_mfa_enrolments),
    audit_log_path: Path = Depends(get_audit_log_path),
):
    body = await request.json()
    tid = str(body.get("tid", ""))
    found = enrolments.get(tid, store.get)
    rp_id, origin = _rp(request)
    if found is None or found[1].username != username or rp_id is None or not enrolments.consume(tid):
        return JSONResponse({"error": "that setup expired -- start again"}, status_code=400)
    try:
        key = mfa.verify_registration(json.dumps(body.get("credential")), found[0].data["challenge"], rp_id,
                                      origin, found[0].data.get("name", ""))
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "the security key's answer did not verify"}, status_code=400)
    account = store.get(username)
    store.set_mfa(username, {**account.mfa, "webauthn": [*account.mfa.get("webauthn", []), key]})
    audit.append(audit_log_path, {"user": username, "client": client_ip(request),
                                  "event": f"added security key {key['name']!r}"})
    return JSONResponse({"redirect": "/account/mfa?success=Security+key+added"})


@router.post("/account/mfa/remove")
def mfa_remove(
    request: Request,
    kind: str = Form(...),
    password: str = Form(...),
    key_id: str = Form(""),
    username: str = Depends(require_login),
    store: AdminStore = Depends(get_admin_store),
    audit_log_path: Path = Depends(get_audit_log_path),
):
    if store.verify(username, password) is None:
        return redirect_with("/account/mfa", error="Current password is wrong")
    account = store.get(username)
    current = dict(account.mfa)
    if kind == "totp":
        current.pop("totp", None)
    elif kind == "webauthn":
        current["webauthn"] = [c for c in current.get("webauthn", []) if c["id"] != key_id]
    else:
        return redirect_with("/account/mfa", error="Unknown factor")
    store.set_mfa(username, current)
    audit.append(audit_log_path, {"user": username, "client": client_ip(request), "event": f"removed {kind}"})
    return redirect_with("/account/mfa", success="Removed")


# -- admin controls ------------------------------------------------------------------------------

@router.post("/users/mfa-policy")
def mfa_policy(
    request: Request,
    require: bool = Form(False),
    username: str = Depends(require_admin),
    store: AdminStore = Depends(get_admin_store),
    audit_log_path: Path = Depends(get_audit_log_path),
):
    store.set_policy(require_mfa_for_admins=require)
    audit.append(audit_log_path, {"user": username, "client": client_ip(request),
                                  "event": f"require MFA for admins: {require}"})
    return redirect_with("/users", success="Admins must use a second factor" if require else
                         "A second factor is optional again")


@router.post("/users/{target}/mfa-reset")
def mfa_reset(
    request: Request,
    target: str,
    username: str = Depends(require_admin),
    store: AdminStore = Depends(get_admin_store),
    session_manager: SessionManager = Depends(get_session_manager),
    audit_log_path: Path = Depends(get_audit_log_path),
):
    try:
        store.reset_mfa(target)
    except AccountError as exc:
        return redirect_with("/users", error=str(exc))
    session_manager.revoke_user(target)
    audit.append(audit_log_path, {"user": username, "client": client_ip(request),
                                  "event": f"reset second factors of {target!r}"})
    return redirect_with("/users", success=f"Second factors of {target!r} removed; their sessions ended")
