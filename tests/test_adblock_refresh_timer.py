"""The daily ad-block list refresh (ROADMAP SEC-21).

fr-adblock-refresh.timer was installed in the image but never enabled, so
the block lists -- the malware and phishing categories included -- were
only ever as fresh as the admin's last click on "Refresh now". First boot
now enables it on every router; so the timer's run (`adblock-refresh
--scheduled`) must not reach the internet while ad-blocking is off
(security-lessons G11). A local HTTP server stands in for the list
hosts: it counts every request, so "nothing fetched" means no request
left the router at all.
"""

from __future__ import annotations

import http.server
import threading
from pathlib import Path

import pytest
import yaml

from frfw import cli

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def list_host():
    """A hosts-format block list served over HTTP on loopback; `requests`
    records every path asked for."""
    requests: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            body = b"0.0.0.0 ads.example\n0.0.0.0 tracker.example\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/hosts", requests
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def run_refresh(tmp_path, monkeypatch, minimal_config_dict):
    """`firewall-cli adblock-refresh` against a config with one list, the
    real fetch, and the writes kept out of /etc (dry run)."""
    real = cli.adblock_refresh
    monkeypatch.setattr(cli, "adblock_refresh", lambda urls, **kw: real(
        urls, hosts_path=tmp_path / "adblock.hosts", category_dir=tmp_path / "adblock.d", dry_run=True, **kw))

    def run(url: str, *, enabled: bool, scheduled: bool) -> int:
        config = dict(minimal_config_dict, adblocker={"enabled": enabled, "source_urls": [url]})
        path = tmp_path / "config.yaml"
        path.write_text(yaml.safe_dump(config))
        return cli.main(["adblock-refresh", *(["--scheduled"] if scheduled else []), str(path)])

    return run


def test_the_timers_run_fetches_nothing_while_ad_blocking_is_off(list_host, run_refresh, capsys):
    url, requests = list_host
    assert run_refresh(url, enabled=False, scheduled=True) == 0
    assert requests == []
    assert "ad-blocking is off: nothing fetched" in capsys.readouterr().out


def test_the_timers_run_fetches_the_lists_while_ad_blocking_is_on(list_host, run_refresh, capsys):
    url, requests = list_host
    assert run_refresh(url, enabled=True, scheduled=True) == 0
    assert requests == ["/hosts"]
    assert "Would write 2 deduped domains" in capsys.readouterr().out


def test_an_admins_own_run_still_fetches_with_ad_blocking_off(list_host, run_refresh):
    """Before turning ad-blocking on, the admin may fetch the lists to
    see what they block: their own run is the opt-in."""
    url, requests = list_host
    assert run_refresh(url, enabled=False, scheduled=False) == 0
    assert requests == ["/hosts"]


def test_the_unit_runs_the_scheduled_refresh():
    unit = (REPO_ROOT / "systemd" / "fr-adblock-refresh.service").read_text()
    exec_start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
    assert exec_start.split()[1:3] == ["adblock-refresh", "--scheduled"]
