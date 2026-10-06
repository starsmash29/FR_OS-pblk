"""Security-lessons I3: the attack-surface screen."""

from __future__ import annotations

import pytest
import yaml
from fastapi.testclient import TestClient

from frfw import surface
from tests.test_surface import ADDRESSES, SS_OUTPUT


def _signed_in(app, username, password):
    client = TestClient(app, follow_redirects=False)
    assert client.post("/login", data={"username": username, "password": password}).headers["location"] == "/"
    return client


@pytest.fixture
def exposed_router(webui_env):
    webui_env["config_path"].write_text(yaml.safe_dump({
        "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"},
                       "lan": {"device": "eth1", "zone": "lan", "address": "192.168.1.1/24"}},
        "rules": [{"name": "http-from-anywhere", "action": "accept", "to_zone": "self", "proto": "tcp",
                   "dst_port": 8080}],
        "nat": {"masquerade": [{"out_zone": "wan"}]},
    }))
    helper = webui_env["helper"]
    helper.listeners = [{"proto": l.proto, "address": l.address, "port": l.port, "device": l.device,
                         "process": l.process} for l in surface.parse_ss(SS_OUTPUT)]
    helper.interface_addresses = ADDRESSES
    webui_env["admin_store"].set_password("boss", "adminpass-001", "admin")
    webui_env["admin_store"].add_user("guest", "viewerpass-01", "viewer")
    return webui_env


def test_the_screen_flags_what_the_internet_can_reach(exposed_router):
    from frfw.webui.app import create_app

    app = create_app(**exposed_router)
    for who in (("boss", "adminpass-001"), ("guest", "viewerpass-01")):  # viewers see it too, read-only
        page = _signed_in(app, *who).get("/surface")
        assert page.status_code == 200
        text = page.text
        assert "1 service reachable from the internet side" in text and "tcp/8080" in text
        assert "nmap -Pn -sS -sU --top-ports 1000 203.0.113.7" in text
        assert "management is off this zone" in text or "closed" in text


def test_the_screen_says_when_the_helper_cannot_answer(exposed_router):
    from frfw.webui.app import create_app

    exposed_router["helper"].listening_sockets = lambda: {"ok": False, "message": "helper down"}
    page = _signed_in(create_app(**exposed_router), "boss", "adminpass-001").get("/surface").text
    assert "Can&#39;t list the listening sockets: helper down" in page
