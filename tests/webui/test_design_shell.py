"""The dark webUI shell (Stitch design): static assets, sidebar,
breadcrumb, and the "nothing loaded from the internet" guarantee."""

from __future__ import annotations

import fnmatch
import re
import tomllib
from pathlib import Path

import pytest

from frfw.webui.templating import NAV, TEMPLATES_DIR, nav_location

WEBUI_DIR = TEMPLATES_DIR.parent
STATIC_DIR = WEBUI_DIR / "static"
REPO = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("path", "content_type"),
    [
        ("/static/fros.css", "text/css"),
        ("/static/icons.svg", "image/svg+xml"),
        ("/static/fonts/geist-latin.woff2", "font/woff2"),
        ("/static/fonts/jetbrains-mono-latin.woff2", "font/woff2"),
    ],
)
def test_static_assets_are_served_without_login(client, path, content_type):
    # The sign-in page needs them before anyone is logged in.
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(content_type)


def test_nothing_is_loaded_from_the_internet():
    # A router's UI must work with the WAN down: no CDN, no web fonts, no
    # remote scripts -- only links the user clicks may point elsewhere.
    remote = re.compile(r"""(?:src|href)\s*=\s*["']https?://|url\(\s*["']?https?://|@import""", re.I)
    for path in [*TEMPLATES_DIR.glob("*.html"), STATIC_DIR / "fros.css"]:
        for match in remote.finditer(path.read_text()):
            line = path.read_text()[: match.start()].count("\n") + 1
            context = path.read_text().splitlines()[line - 1]
            # <a href="https://..."> is a link, not a resource the page loads.
            assert re.search(r"<a\s[^>]*href", context), f"{path.name}:{line} loads a remote resource: {context.strip()}"


def test_every_icon_used_exists_in_the_sprite():
    sprite = set(re.findall(r'<symbol id="([^"]+)"', (STATIC_DIR / "icons.svg").read_text()))
    used = {icon for _section, items in NAV for _label, _href, icon, _admin in items}
    for path in TEMPLATES_DIR.glob("*.html"):
        text = path.read_text()
        used |= set(re.findall(r'icons\.svg#([a-z_]+)"', text))
        used |= set(re.findall(r'icon\("([a-z_]+)"', text))
    dashboard_src = (WEBUI_DIR / "routes" / "dashboard.py").read_text()
    used |= set(re.findall(r'"icon": "([a-z_]+)"', dashboard_src))
    assert used and used <= sprite, f"missing icons: {sorted(used - sprite)}"


def test_every_static_file_is_packaged():
    # pip installs the webUI from pyproject's package-data; a file it
    # doesn't match silently goes missing on the router.
    pyproject = tomllib.loads((REPO / "pyproject.toml").read_text())
    patterns = pyproject["tool"]["setuptools"]["package-data"]["frfw.webui"]
    for path in STATIC_DIR.rglob("*"):
        if path.is_file():
            relative = path.relative_to(WEBUI_DIR).as_posix()
            assert any(fnmatch.fnmatch(relative, p) and relative.count("/") == p.count("/") for p in patterns), relative


def test_font_licences_ship_with_the_fonts():
    for name in ("LICENSE-Geist.txt", "LICENSE-JetBrainsMono.txt"):
        assert "SIL Open Font License" in (STATIC_DIR / "fonts" / name).read_text()
    assert "Apache License" in (STATIC_DIR / "LICENSE-MaterialSymbols.txt").read_text()


def test_sidebar_marks_the_current_page_and_breadcrumb(logged_in_client):
    page = logged_in_client.get("/iot").text
    assert 'class="nav-link active" href="/iot"' in page
    assert page.count("nav-link active") == 1
    assert '<span class="here">IoT Devices</span>' in page
    assert "/static/fros.css" in page


def test_dashboard_is_only_active_on_the_root_path(logged_in_client):
    page = logged_in_client.get("/rules").text
    assert 'class="nav-link active" href="/rules"' in page
    assert 'class="nav-link active" href="/"' not in page


def test_nav_location():
    assert nav_location("/") == ("Core", "Dashboard")
    assert nav_location("/rules") == ("Network", "Rules")
    assert nav_location("/iot/scan") == ("Protection", "IoT Devices")
    assert nav_location("/account") == ("System", "Account")
    assert nav_location("/nowhere") is None
    assert nav_location("/rulesx") is None


def test_top_bar_shows_hostname_and_release(logged_in_client, webui_env):
    page = logged_in_client.get("/").text
    assert 'class="host-name">' in page
    assert "Ice Breaker" in page


def test_login_page_uses_the_standalone_layout(client):
    page = client.get("/login").text
    assert 'class="auth-card"' in page
    assert 'class="sidebar"' not in page


def test_dashboard_shows_real_system_figures(logged_in_client):
    page = logged_in_client.get("/").text
    assert "System resources" in page
    assert "Protection services" in page
    assert "Root filesystem" in page
