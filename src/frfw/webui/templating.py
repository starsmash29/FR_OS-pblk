from pathlib import Path

from fastapi.templating import Jinja2Templates

from frfw import __codename__, __version__, codename_for
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
        ("Rules", "/rules", "security", False),
        ("NAT", "/nat", "alt_route", False),
        ("DHCP", "/dhcp", "dynamic_form", False),
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


templates.env.globals.update(
    NAV=NAV,
    nav_matches=_matches,
    nav_location=nav_location,
    shell_hostname=shell_hostname,
    FROS_VERSION=__version__,
    FROS_CODENAME=__codename__,
)
