"""SEC-9 / R15: an explicit CSRF token on every state-changing request, and
app-wide HTTP security headers.

The CSRF part is checked by walking *every* route the app registers, the
same way tests/webui/test_rbac.py does for roles, so a POST route added later
without a token fails here instead of shipping unprotected. The template part
is checked by reading the template sources, so a new form without the hidden
field fails before it reaches a browser.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from fastapi import Depends
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from frfw.webui.app import SECURITY_HEADERS, create_app
from frfw.webui.auth import COOKIE_NAME
from frfw.webui.deps import CSRF_FIELD, VIEWER_ALLOWED_PATHS, require_login
from frfw.webui.templating import TEMPLATES_DIR

_CONFIG = {
    "version": 1,
    "hostname": "router",
    "zones": {"wan": {}, "lan": {}},
    "interfaces": {"wan": {"device": "eth0", "zone": "wan"}, "lan": {"device": "eth1", "zone": "lan"}},
    "rules": [{"name": "lan-out", "action": "accept", "from_zone": "lan", "to_zone": "wan"}],
    "nat": {"masquerade": [{"out_zone": "wan"}]},
}

_ADMIN_PASSWORD = "adminpass1"

#: <form ...> ... </form>, non-greedy and across lines.
_POST_FORM = re.compile(r"<form\b[^>]*\bmethod\s*=\s*[\"']post[\"'][^>]*>(.*?)</form>", re.DOTALL | re.IGNORECASE)


@pytest.fixture
def env(webui_env):
    webui_env["config_path"].write_text(yaml.safe_dump(_CONFIG))
    webui_env["admin_store"].set_password("boss", _ADMIN_PASSWORD, "admin")
    return webui_env


def _signed_in(env, password: str = _ADMIN_PASSWORD, username: str = "boss") -> TestClient:
    client = TestClient(create_app(**env), follow_redirects=False)
    response = client.post("/login", data={"username": username, "password": password})
    # A refused sign-in also answers 303, so the redirect target is the
    # assertion that says we really hold a session cookie.
    assert response.headers.get("location") == "/", response.headers
    return client


def _token(client: TestClient) -> str:
    return client.app.state.session_manager.csrf_token_for(client.cookies.get(COOKIE_NAME))


def _without_token(client: TestClient, method: str, path: str):
    """A request that goes out carrying no token at all.

    conftest.py normally adds the session's token to every unsafe-method
    request, the way a browser would; the marker header tells it to keep
    its hands off, so these calls are the ones that actually reach the app
    bare.
    """
    return client.request(method, path, data={}, headers={"x-test-skip-csrf": "1"})


def _detail(response) -> str:
    """The `detail` of a refusal, or "" for anything that isn't one.

    A 403 is not always FastAPI's HTTPException -- a route can answer with
    an empty body of its own -- so the walk reads the field defensively
    instead of assuming the body parses.
    """
    try:
        body = response.json()
    except ValueError:
        return ""
    return body.get("detail", "") if isinstance(body, dict) else ""


#: The public POST forms: no session yet, so there is no token to carry.
#: Signing in *is* the proof of intent, and the login ticket paths are
#: already bound to the ticket (security-lessons G5).
_PUBLIC_FORM_TEMPLATES = frozenset({"login.html", "mfa_login.html", "ztna_login.html"})


def _api_routes(routes):
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        elif hasattr(route, "original_router"):
            yield from _api_routes(route.original_router.routes)


def _change_routes(app) -> list[tuple[str, str]]:
    return sorted({
        (method, route.path)
        for route in _api_routes(app.routes)
        for method in route.methods - {"GET", "HEAD", "OPTIONS"}
    })


def _concrete(path: str) -> str:
    return path.replace("{", "").replace("}", "")


def _calls(dependant, target) -> bool:
    """Whether `dependant` resolves `target` anywhere in its tree.

    A route that says `Depends(require_admin)` reaches the CSRF check too,
    because `require_admin` depends on `require_login` in turn.
    """
    if dependant.call is target:
        return True
    return any(_calls(sub, target) for sub in dependant.dependencies)


def _session_protected_routes(app) -> set[tuple[str, str]]:
    """Which change routes sit behind `require_login`.

    Read off the app's own dependency graph rather than off a hand-written
    list, so the CSRF expectation can never drift from the set of routes that
    actually carry a session cookie. Status codes can't answer this:
    `/logout` sends an anonymous caller to /login too, and it is not a
    session-protected route.
    """
    return {
        (method, route.path)
        for route in _api_routes(app.routes)
        if isinstance(route, APIRoute) and _calls(route.dependant, require_login)
        for method in route.methods - {"GET", "HEAD", "OPTIONS"}
    }


# ---------------------------------------------------------------- the token


def test_every_change_route_behind_the_session_needs_a_csrf_token(env):
    probe = _signed_in(env)
    routes = _change_routes(probe.app)
    # Cross-check against the OpenAPI schema, a second independent listing.
    documented = {
        (method.upper(), path)
        for path, ops in probe.app.openapi()["paths"].items()
        for method in ops
        if method.upper() not in {"GET", "HEAD", "OPTIONS"}
    }
    assert set(routes) == documented

    protected = _session_protected_routes(probe.app)
    checked = 0
    for method, path in protected:
        # A fresh session per route: the walk itself revokes sessions and
        # resets passwords on some of them, and a stale cookie would read
        # as a missing-token failure. `raise_server_exceptions=False` so a
        # route that happens to dislike this walk's empty body answers with
        # a status instead of blowing the walk up -- what is under test here
        # is the gate in front of the route, not the route's own parsing.
        admin = TestClient(probe.app, follow_redirects=False, raise_server_exceptions=False)
        login = admin.post("/login", data={"username": "boss", "password": _ADMIN_PASSWORD})
        assert login.headers.get("location") == "/", login.headers

        bare = _without_token(admin, method, _concrete(path))
        assert bare.status_code == 403, (method, path, bare.status_code)
        assert "CSRF" in _detail(bare), (method, path, bare.status_code, bare.text)

        good = admin.request(
            method, _concrete(path), data={}, headers={"X-CSRF-Token": _token(admin)}
        )
        assert "CSRF" not in _detail(good), (method, path, good.status_code, good.text)
        checked += 1
    assert checked >= 30, f"only walked {checked} change routes -- is the walk broken?"


def test_a_change_route_the_new_check_covers_also_covers_a_later_one(env):
    """A route registered *after* create_app is held to the same rule.

    The first test proves the routes that exist are covered; this proves the
    coverage comes from `require_login` rather than from a list that happens
    to match today's routes. The probe is declared the way every real route
    is -- `Depends(require_login)`, nothing about CSRF -- which is exactly
    the case that used to need a manual remember-to-add-the-check.
    """
    admin = _signed_in(env)
    app_before = len(_change_routes(admin.app))

    @admin.app.post("/csrf-probe/forgotten")
    def _forgotten(username: str = Depends(require_login)):
        return {"ok": True}

    assert len(_change_routes(admin.app)) == app_before + 1
    assert ("POST", "/csrf-probe/forgotten") in _session_protected_routes(admin.app)

    response = _without_token(admin, "POST", "/csrf-probe/forgotten")
    assert response.status_code == 403 and "CSRF" in _detail(response)

    allowed = admin.request(
        "POST", "/csrf-probe/forgotten", data={}, headers={"X-CSRF-Token": _token(admin)}
    )
    assert allowed.status_code == 200 and allowed.json() == {"ok": True}


def test_a_token_from_another_session_is_refused(env):
    """The token belongs to one session, not to the account."""
    first = _signed_in(env)
    second = _signed_in(env)
    assert first.cookies.get(COOKIE_NAME) != second.cookies.get(COOKIE_NAME)

    response = second.request(
        "POST", "/adblock/refresh", data={}, headers={"X-CSRF-Token": _token(first)}
    )
    assert response.status_code == 403 and "CSRF" in _detail(response)


def test_a_guessed_or_tampered_token_is_refused(env):
    admin = _signed_in(env)
    good = _token(admin)
    for bad in ("", good[:-1], good + "0", "0" * len(good)):
        response = admin.request(
            "POST", "/adblock/refresh", data={}, headers={"X-CSRF-Token": bad}
        )
        assert response.status_code == 403, bad
        assert "CSRF" in _detail(response), (bad, response.status_code)


def test_safe_methods_do_not_need_a_token(env):
    admin = _signed_in(env)
    for page in ("/", "/rules", "/interfaces", "/nat", "/adblock", "/account"):
        assert admin.get(page).status_code == 200, page


def test_the_token_travels_in_a_form_field_and_a_json_body_too(env):
    """Not just the header: a real form post and a fetch() both work."""
    admin = _signed_in(env)
    token = _token(admin)

    form = admin.post("/adblock/refresh", data={CSRF_FIELD: token})
    assert form.status_code == 303, form.text

    as_json = admin.post(
        "/account/mfa/webauthn/options", json={CSRF_FIELD: token}
    )
    assert "CSRF" not in _detail(as_json), as_json.text


def test_a_token_in_the_query_string_is_not_accepted(env):
    """A query string is not a carrier: it lands in the access log, in the
    browser history and in the `Referer` of every link on the page."""
    admin = _signed_in(env)
    token = _token(admin)

    refused = admin.post(f"/adblock/refresh?{CSRF_FIELD}={token}",
                         headers={"x-test-skip-csrf": "1"})
    assert refused.status_code == 403, refused.text
    assert "CSRF" in _detail(refused)


def test_the_role_check_still_answers_before_anything_is_written(env):
    """R15 must not have displaced phase 18: a viewer's own allowed paths
    still work, and a viewer still cannot reach an admin route."""
    env["admin_store"].add_user("guest", "viewerpass1", "viewer")
    viewer = _signed_in(env, "viewerpass1", username="guest")
    token = _token(viewer)

    refused = viewer.request("POST", "/users/add",
                             data={"new_username": "mallory", "new_password": "mallorypass1", "role": "admin"},
                             headers={"X-CSRF-Token": token})
    assert refused.status_code == 403, refused.text
    assert "viewer role" in _detail(refused)
    assert "mallory" not in env["admin_store"].path.read_text()

    # VIEWER_ALLOWED_PATHS stays reachable for the viewer's own account.
    allowed = viewer.request("POST", "/account/password",
                             data={"current_password": "viewerpass1",
                                   "new_password": "viewerpass2",
                                   "new_password_confirm": "viewerpass2"},
                             headers={"X-CSRF-Token": token})
    assert allowed.status_code == 303, allowed.text
    assert "/account/password" in VIEWER_ALLOWED_PATHS


# ----------------------------------------------------------- the templates


def test_every_post_form_in_every_template_carries_the_token():
    """A new form that forgets `csrf_input` fails here, not in a browser.

    Checked on the template sources rather than on rendered pages, because a
    form behind a page some test never visits would otherwise slip through.
    The three public sign-in forms are the documented exception: there is no
    session yet, so they have no token to carry.
    """
    without_token = []
    for template in sorted(TEMPLATES_DIR.glob("*.html")):
        if template.name in _PUBLIC_FORM_TEMPLATES:
            continue
        for body in _POST_FORM.findall(template.read_text()):
            if "csrf_input(request)" not in body:
                without_token.append(template.name)
    assert not without_token, sorted(set(without_token))


def test_the_public_sign_in_forms_are_exactly_the_expected_ones():
    """If a route moves behind the session, its form has to gain a token."""
    public = {
        template.name
        for template in TEMPLATES_DIR.glob("*.html")
        if _POST_FORM.search(template.read_text())
    }
    assert _PUBLIC_FORM_TEMPLATES <= public


def test_a_page_offers_the_token_in_a_meta_tag_and_in_its_forms(env):
    client = _signed_in(env)
    token = _token(client)
    assert token

    page = client.get("/adblock")
    assert page.status_code == 200
    assert f'<meta name="csrf-token" content="{token}">' in page.text
    assert f'name="{CSRF_FIELD}" value="{token}"' in page.text


def test_an_anonymous_page_renders_no_token(env):
    """The login page has no session, so there is no token to hand out --
    and none is invented."""
    anonymous = TestClient(create_app(**env), follow_redirects=False)
    page = anonymous.get("/login")
    assert page.status_code == 200
    assert '<meta name="csrf-token" content="">' in page.text


# -------------------------------------------------------- security headers


def test_every_response_carries_the_security_headers(env):
    client = _signed_in(env)
    pages = ["/", "/rules", "/static/fros.css", "/login", "/static/icons.svg"]
    for page in pages:
        response = client.get(page)
        for header, value in SECURITY_HEADERS.items():
            assert response.headers.get(header) == value, (page, header)


def test_the_security_headers_are_on_error_responses_too(env):
    """A 403 or a redirect is still a response a browser renders."""
    client = _signed_in(env)
    refused = client.post("/adblock/refresh", data={}, headers={"X-CSRF-Token": "wrong"})
    assert refused.status_code == 403
    for header, value in SECURITY_HEADERS.items():
        assert refused.headers.get(header) == value, header


def test_the_csp_names_no_remote_source_and_forbids_framing(env):
    """security-lessons G11: 100% local. A CDN in the policy would be a bug."""
    csp = SECURITY_HEADERS["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp
    assert "'none'" in csp or "'self'" in csp
    for scheme in ("http://", "https://", "//cdn", "data:font", "blob:"):
        assert scheme not in csp, scheme
    assert "default-src 'self'" in csp

    client = _signed_in(env)
    assert client.get("/").headers["X-Frame-Options"] == "DENY"
    assert client.get("/").headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert client.get("/").headers["X-Content-Type-Options"] == "nosniff"


def test_the_csp_allows_only_same_origin_scripts(env):
    """script-src is exactly 'self': no 'unsafe-inline', no 'unsafe-eval'.
    Every script is a static file (forms.js, xdp.js, webauthn.js), so an
    injected inline <script> or on*= handler would not run. Styles keep
    'unsafe-inline' for inline `style` attributes, which can't run code."""
    csp = SECURITY_HEADERS["Content-Security-Policy"]
    directives = {d.split()[0]: d.split()[1:] for d in csp.split(";") if d.strip()}
    assert directives["script-src"] == ["'self'"]
    assert "'unsafe-eval'" not in csp
    assert directives["style-src"] == ["'self'", "'unsafe-inline'"]
    assert "img-src 'self' data:" in csp  # the inline SVG favicon
    assert "font-src 'self'" in csp  # the bundled woff2 files
    assert "connect-src 'self'" in csp  # EventSource on /xdp/logs/stream


def test_no_template_has_inline_script_or_event_handlers():
    """What lets script-src stay 'self': no template carries code. A
    `<script>` must have a src, and no element an on*= attribute; a
    confirmation prompt is `data-confirm` text, handled by static/forms.js."""
    templates = Path(TEMPLATES_DIR)
    inline_script = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.IGNORECASE)
    handler = re.compile(r"\son[a-z]+\s*=", re.IGNORECASE)
    for template in sorted(templates.glob("*.html")):
        text = template.read_text()
        assert not inline_script.search(text), template.name
        assert not handler.search(text), template.name


def test_destructive_forms_still_ask_for_confirmation():
    """Moving the prompts out of onsubmit must not drop any: every one of
    them is now a data-confirm attribute (the allow-WAN one only while its
    checkbox is ticked)."""
    templates = Path(TEMPLATES_DIR)
    text = "".join(t.read_text() for t in templates.glob("*.html"))
    assert text.count("data-confirm=") == 12
    assert 'data-confirm-when-checked="allow_wan"' in text


def test_the_page_scripts_are_served_and_linked(env):
    client = _signed_in(env)
    for script in ("/static/forms.js", "/static/xdp.js"):
        response = client.get(script)
        assert response.status_code == 200, script
        assert "javascript" in response.headers["content-type"], script
    assert "/static/forms.js" in client.get("/").text
    assert "/static/xdp.js" in client.get("/xdp").text


def test_a_page_never_loads_a_resource_from_a_remote_source(env):
    """The other half of G11: the policy can't allow a CDN that the markup
    also has to stay clear of. Only attributes that make the browser fetch
    something count -- a URL shown as text or in a placeholder is not one."""
    loading = re.compile(r"(?:src|href)\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)
    client = _signed_in(env)
    for page in ("/", "/rules", "/adblock", "/xdp", "/vpn", "/users", "/system"):
        body = client.get(page).text
        remote = [url for url in loading.findall(body) if url.startswith(("http://", "https://", "//"))]
        assert not remote, (page, remote)
        # The icon sprite and the fonts are fetched by `use href=` and CSS,
        # both same-origin; a data: URL is the inline SVG favicon.
        for url in loading.findall(body):
            assert url.startswith(("/", "data:", "#")), (page, url)
