"""Zero Trust Network Access (ZTNA) gate: local auth portal + admin
settings (see frfw.ztna and frfw.nft.builder.ZTNA_SET_NAME for the
kernel-space enforcement side).

Three route groups, two very different trust levels:

- `GET/POST /ztna/login` and `GET /ztna/status` are deliberately
  *public* (no `require_login`): they authenticate a ZTNA *end user*,
  not the router's admin, so gating them behind the admin session would
  defeat the point. `/ztna/login` verifies the submitted password
  in-process (config.yaml's `ztna.users[].password_hash` is readable by
  this unprivileged process already, same as every other config read),
  then -- only once already convinced -- asks the privileged helper to
  actually authorize the caller's *current* source IP; this webUI
  process never touches nftables itself.

- `GET /ztna` (admin, `require_login`) and its `/ztna/settings` and
  `/ztna/users/*` POST endpoints manage `config.ztna` the same
  "edit the raw dict, validate, save through the helper" way every
  other settings screen does (see frfw.webui.actions.try_save) --
  turning the gate on/off, the session TTL, and which local accounts
  can authenticate. A submitted plaintext password is hashed with
  `frfw.admin_account.hash_password` (the exact same PBKDF2
  implementation the single admin account uses) before it's ever
  written to config.yaml; the plaintext itself is never persisted or
  logged.

Note what's *not* here: there is no ZTNA-specific session cookie.
`/ztna/status` doesn't need one -- the actual security boundary is "is
my current source IP currently a member of the kernel's nftables set",
which is exactly what it asks the helper, every time, fresh. A cookie
recording "you logged in a while ago" would be a second, driftable
source of truth alongside the kernel's own authoritative one, for no
real benefit (if the IP changes -- a new device, a DHCP renewal -- the
old cookie couldn't grant network access anyway, since the kernel set
is keyed on IP, not on a browser).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request

from frfw.admin_account import hash_password, verify_password
from frfw.webui.actions import try_save
from frfw.webui.deps import get_helper, get_raw_config, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()

_DEFAULT_SESSION_TTL_SECONDS = 8 * 3600


def _client_ip(request: Request) -> str:
    # This appliance's webUI is reached directly by clients on the LAN
    # (see ARCHITECTURE.md's security model) -- there is no reverse
    # proxy in front of it in this project's deployment model, so
    # request.client.host *is* the real source IP nftables will see for
    # this same connection. A deployment that puts something in front of
    # this webUI (not how FR_OS ships) would need to trust
    # X-Forwarded-For instead, which opens its own can of worms (that
    # header is trivially spoofable unless the proxy strips client-
    # supplied copies of it first) -- deliberately not handled here.
    return request.client.host if request.client else "0.0.0.0"


def _find_user(raw: dict, username: str) -> dict | None:
    for user in (raw.get("ztna") or {}).get("users") or []:
        if isinstance(user, dict) and user.get("username") == username:
            return user
    return None


def _format_duration(seconds: int) -> str:
    seconds = max(seconds, 0)
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


# --- public: end-user login + status ----------------------------------------


@router.get("/ztna/login")
def login_form(request: Request):
    return templates.TemplateResponse(
        request,
        "ztna_login.html",
        {
            "username": None,  # not the admin session -- suppresses base.html's nav bar
            "client_ip": _client_ip(request),
            "error": request.query_params.get("error"),
        },
    )


@router.post("/ztna/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    ztna_raw = raw.get("ztna") or {}
    if not ztna_raw.get("enabled"):
        return redirect_with("/ztna/login", error="The ZTNA gate is currently disabled")

    user = _find_user(raw, username)
    if user is None:
        # Still hash *something*, so a nonexistent username doesn't
        # respond measurably faster than a wrong password for a real
        # one -- same rationale as frfw.admin_account.AdminStore.verify.
        hash_password(password)
        return redirect_with("/ztna/login", error="Invalid credentials")

    if not verify_password(password, user.get("password_hash", "")):
        return redirect_with("/ztna/login", error="Invalid credentials")

    ip = _client_ip(request)
    result = helper.authorize_ztna(ip, username)
    if not result.get("ok"):
        return redirect_with("/ztna/login", error=result.get("message") or "Authorization failed")

    return redirect_with("/ztna/status", success=f"Welcome, {username} -- access granted")


@router.get("/ztna/status")
def status_page(
    request: Request,
    helper: HelperClient = Depends(get_helper),
):
    ip = _client_ip(request)
    result = helper.ztna_status(ip)

    authorized = bool(result.get("ok") and result.get("authorized"))
    expires_in = result.get("expires_in") if authorized else None

    return templates.TemplateResponse(
        request,
        "ztna_status.html",
        {
            "username": None,
            "client_ip": ip,
            "authorized": authorized,
            "ztna_username": result.get("username") if authorized else None,
            "expires_in_seconds": expires_in,
            "expires_in_display": _format_duration(expires_in) if expires_in is not None else None,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


# --- admin: gate settings + user management ---------------------------------


@router.get("/ztna")
def show_settings(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
):
    ztna_raw = raw.get("ztna") or {}
    return templates.TemplateResponse(
        request,
        "ztna.html",
        {
            "username": username,
            "enabled": bool(ztna_raw.get("enabled", False)),
            "session_ttl_seconds": ztna_raw.get("session_ttl_seconds", _DEFAULT_SESSION_TTL_SECONDS),
            "session_ttl_display": _format_duration(
                ztna_raw.get("session_ttl_seconds", _DEFAULT_SESSION_TTL_SECONDS)
            ),
            "users": [u.get("username") for u in ztna_raw.get("users") or [] if isinstance(u, dict)],
            "gated_rules": [
                r.get("name") for r in raw.get("rules") or []
                if isinstance(r, dict) and r.get("require_ztna")
            ],
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/ztna/settings")
def save_settings(
    enabled: bool = Form(False),
    session_ttl_seconds: int = Form(_DEFAULT_SESSION_TTL_SECONDS),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    ztna_raw = raw.setdefault("ztna", {})
    ztna_raw["enabled"] = enabled
    ztna_raw["session_ttl_seconds"] = session_ttl_seconds
    ztna_raw.setdefault("users", [])

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with(
            "/ztna",
            success="ZTNA gate settings saved -- click Apply on the dashboard "
            "to load them into the kernel",
        )
    return redirect_with("/ztna", error=message)


@router.post("/ztna/users/add")
def add_user(
    new_username: str = Form(...),
    new_password: str = Form(...),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    if len(new_password) < 8:
        return redirect_with("/ztna", error="Password must be at least 8 characters")

    ztna_raw = raw.setdefault("ztna", {})
    users = ztna_raw.setdefault("users", [])
    users[:] = [u for u in users if u.get("username") != new_username]
    users.append({"username": new_username, "password_hash": hash_password(new_password)})

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/ztna", success=f"ZTNA user {new_username!r} saved")
    return redirect_with("/ztna", error=message)


@router.post("/ztna/users/remove/{target_username}")
def remove_user(
    target_username: str,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    ztna_raw = raw.setdefault("ztna", {})
    users = ztna_raw.get("users") or []
    remaining = [u for u in users if u.get("username") != target_username]
    if len(remaining) == len(users):
        return redirect_with("/ztna", error=f"No such ZTNA user {target_username!r}")
    ztna_raw["users"] = remaining

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/ztna", success=f"ZTNA user {target_username!r} removed")
    return redirect_with("/ztna", error=message)
