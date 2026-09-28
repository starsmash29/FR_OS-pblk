"""Security-lessons K4: the Segments screen, and first-run setup leading
to it."""

from __future__ import annotations

from urllib.parse import unquote_plus

import yaml

from frfw import skeleton
from frfw.config import load_config


def test_offered_after_setup_and_adds_segments(logged_in_client, webui_env):
    webui_env["config_path"].write_text(skeleton.build_skeleton_config("eth0", "eth1"))
    page = logged_in_client.get("/segments?first_run=1").text
    assert "Your account is set up" in page and "Skip for now" in page and "eth1.30" in page
    response = logged_in_client.post("/segments", data={"segment": ["iot", "guest"]})
    assert "Added: iot, guest" in unquote_plus(response.headers["location"])
    config = load_config(webui_env["config_path"])
    assert {"iot", "guest"} <= set(config.zones)
    page = logged_in_client.get("/segments").text
    assert page.count("set up</span>") == 2


def test_skipping_changes_nothing(logged_in_client, webui_env):
    webui_env["config_path"].write_text(skeleton.build_skeleton_config("eth0", "eth1"))
    before = webui_env["config_path"].read_text()
    assert logged_in_client.post("/segments", data={}).headers["location"].startswith("/?success=")
    assert webui_env["config_path"].read_text() == before


def test_without_a_lan_it_says_so(logged_in_client, webui_env):
    webui_env["config_path"].write_text(yaml.safe_dump({
        "version": 1, "hostname": "r", "zones": {"wan": {}}, "interfaces": {"wan": {"device": "eth0", "zone": "wan"}},
        "rules": [], "nat": {}}))
    assert "error=No+%27lan%27+interface" in logged_in_client.post("/segments", data={"segment": "iot"}).headers[
        "location"]
