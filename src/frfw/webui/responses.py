from __future__ import annotations

from urllib.parse import urlencode

from fastapi.responses import RedirectResponse


def redirect_with(path: str, **params: str | None) -> RedirectResponse:
    """A 303 redirect to `path`, carrying non-None `params` as a query
    string (used for one-shot flash messages -- see base.html)."""
    query = urlencode({k: v for k, v in params.items() if v is not None})
    url = f"{path}?{query}" if query else path
    return RedirectResponse(url, status_code=303)
