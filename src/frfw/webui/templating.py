from pathlib import Path

from fastapi.templating import Jinja2Templates
from markupsafe import Markup

from frfw import __codename__, __version__, codename_for, passwords
from frfw.webui.config_store import load_raw

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# "0.1.0" -> "0.1.0 “Ice Breaker”" (the release codenames, see ROADMAP.md).
templates.env.filters["with_codename"] = (
    lambda version: f"{version} “{codename_for(version)}”" if codename_for(str(version)) else version
)

#: The sidebar: (section, [(label, path, icon, admin_only)]). Icons are
#: symbol ids in static/icons.svg (scripts/build-webui-icons.py).
NAV = [
    ("Core", [
        ("Dashboard", "/", "dashboard", False),
    ]),
    ("Network", [
        ("Interfaces", "/interfaces", "settings_ethernet", False),
        ("Segments", "/segments", "lan", False),
        ("Rules", "/rules", "security", False),
        ("NAT", "/nat", "alt_route", False),
        ("DHCP", "/dhcp", "dynamic_form", False),
        ("VPN", "/vpn", "key", False),
    ]),
    ("Protection", [
        ("AI IDS/IPS", "/ai-ids", "psychology", False),
        ("TLS SNI Filter", "/xdp", "filter_alt", False),
        ("Ad-Block", "/adblock", "block", False),
        ("IoT Devices", "/iot", "devices", False),
        ("Applications", "/apps", "apps", False),
        ("TLS Fingerprints", "/tls", "fingerprint", False),
        ("ZTNA Gate", "/ztna", "vpn_lock", False),
    ]),
    ("System", [
        ("Update", "/update", "system_update_alt", False),
        ("System", "/system", "tune", False),
        ("Attack surface", "/surface", "shield_lock", False),
        ("Security score", "/security", "verified_user", False),
        ("Users", "/users", "group", True),
    ]),
]

#: Pages outside the sidebar, for the breadcrumb.
_EXTRA_PAGES = {"/account": ("System", "Account")}


def _matches(path: str, href: str) -> bool:
    return path == href if href == "/" else path == href or path.startswith(href + "/")


def nav_location(path: str) -> tuple[str, str] | None:
    """(section, page label) of the page at `path`, for the breadcrumb."""
    for section, items in NAV:
        for label, href, _icon, _admin in items:
            if _matches(path, href):
                return section, label
    return _EXTRA_PAGES.get(path)


def shell_hostname(request) -> str:
    """This router's hostname for the top bar -- read from the config the
    webUI edits (a small YAML file), so it is right straight after a save."""
    config_path = getattr(request.app.state, "config_path", None)
    if config_path is None:
        return "fr-router"
    try:
        return str(load_raw(Path(config_path)).get("hostname") or "fr-router")
    except Exception:  # an unreadable config must not break every page
        return "fr-router"


def update_notice(request) -> dict | None:
    """Security-lessons G10: what the periodic update check found (the
    cache fr-update-check.timer writes), for the banner on every page."""
    cache_path = getattr(request.app.state, "update_check_path", None)
    if cache_path is None:
        return None
    from frfw import update

    data = update.read_check_cache(Path(cache_path), current_version=__version__)
    if not data or not data.get("update_available") or not data.get("latest_version"):
        return None
    return data


def apply_notice(request) -> dict | None:
    """ROADMAP SEC-26: an apply waiting for confirmation, or a reverted
    one whose config is kept, for the banner on every page -- on every
    page, because an apply that moved the webUI lands the admin wherever
    they sign in again. Nothing when the helper can't say."""
    helper = getattr(request.app.state, "helper", None)
    if helper is None:
        return None
    try:
        reply = helper.apply_status()
    except Exception:  # a helper that can't answer must not break every page
        return None
    if not reply.get("ok") or not (reply.get("pending") or reply.get("rejected")):
        return None
    return reply


def csrf_token(request) -> str:
    """Return the CSRF token for the current session."""
    if not request:
        return ""
    state = getattr(request, "state", None)
    return getattr(state, "csrf_token", "") or ""


def csrf_input(request) -> Markup:
    """Return a hidden form input containing the CSRF token."""
    token = csrf_token(request)
    if not token:
        return Markup("")
    return Markup(f'<input type="hidden" name="csrf_token" value="{token}">')


templates.env.globals.update(
    NAV=NAV,
    nav_matches=_matches,
    nav_location=nav_location,
    shell_hostname=shell_hostname,
    update_notice=update_notice,
    apply_notice=apply_notice,
    csrf_token=csrf_token,
    csrf_input=csrf_input,
    FROS_VERSION=__version__,
    FROS_CODENAME=__codename__,
    MIN_PASSWORD_LENGTH=passwords.MIN_LENGTH,
)
