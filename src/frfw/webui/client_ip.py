"""Shared "what is this request's source IP" helper.

Originally lived as a private `_client_ip` inside
`frfw.webui.routes.ztna` (the only route that needed it before phase
10); hoisted out here so `frfw.webui.routes.auth` (the admin `/login`
route) can use the exact same logic for brute-force tracking instead of
each route file growing its own slightly-different copy.
"""

from __future__ import annotations

from fastapi import Request


def client_ip(request: Request) -> str:
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
