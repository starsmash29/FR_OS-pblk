"""`fr-appid`: the unprivileged app identification daemon (phase 16,
systemd/fr-appid.service).

Reads two journals, never the network or the kernel directly:

1. fr-adblock-dns.service (only when `adblocker.query_logging` is on):
   every "query[...]" line names a client and the name it looked up;
2. fr-xdp-sni-logger.service (only when `app_control.observe_sni` is on,
   which makes the XDP program report *passed* SNIs as well as drops).

Each name is matched against the bundled catalog (frfw.appid) and counted
per app and client (frfw.appid.usage). The summary is written to
paths.APPID_USAGE_PATH every FLUSH_SECONDS for the webUI and /metrics.
This process only observes: blocking an app is done by the resolver and
the XDP blocklist, configured by `firewall-cli apply` / the webUI.

The unit is enabled unconditionally and follows config.yaml by itself:
while app identification is off (or has no source) it only re-reads the
config every CONFIG_POLL_SECONDS, and once running it re-executes itself
when the set of enabled sources changes -- so turning the feature on or
off in the webUI never needs a manual service restart.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable

from frfw import paths
from frfw.appid import AppMatcher, Catalog, load_catalog
from frfw.appid.usage import UsageTracker
from frfw.config.schema import Config
from frfw.journal import tail_journal_forever

FLUSH_SECONDS = 30.0
CONFIG_POLL_SECONDS = 30.0

XDP_LOGGER_UNIT = "fr-xdp-sni-logger.service"

#: Repeated observations of the same name by the same client through the
#: same source within this many seconds count once: a browser typically
#: asks for A, AAAA and HTTPS records of every name at the same moment.
DEDUP_SECONDS = 10.0
_DEDUP_MAX_ENTRIES = 20000

#: dnsmasq `log-queries=extra` query line as journald's `-o cat` hands it
#: over, checked against real dnsmasq 2.91 output:
#:   "2 10.0.0.5/46381 query[A] www.netflix.com from 10.0.0.5"
_DNS_QUERY_RE = re.compile(
    r"^\d+ (?P<client>[0-9A-Fa-f:.]+)/\d+ query\[(?P<qtype>[A-Za-z0-9]+)\] (?P<name>\S+) from \S+$"
)

#: Record types that say nothing about which app a client is about to use.
_IGNORED_QTYPES = {"PTR", "SOA", "NS", "SRV", "TXT"}


class AppIdDaemon:
    def __init__(
        self,
        config: Config,
        *,
        catalog: Catalog | None = None,
        usage_path: Path = paths.APPID_USAGE_PATH,
        clock: Callable[[], float] = time.time,
    ):
        self.config = config
        self.matcher = AppMatcher(catalog or load_catalog())
        self.usage_path = usage_path
        self._clock = clock
        self._lock = threading.Lock()
        self._recent: dict[tuple[str, str, str], float] = {}
        self.tracker = UsageTracker.restore(_read_json(usage_path))

    # -- ingestion ---------------------------------------------------------

    def observe(self, client: str, name: str, source: str) -> str | None:
        """Attribute one observed name; returns the app id, if any."""
        app_id = self.matcher.match(name)
        if app_id is None:
            return None
        now = self._clock()
        key = (client, name.lower(), source)
        with self._lock:
            last = self._recent.get(key)
            if last is not None and now - last < DEDUP_SECONDS:
                return app_id
            self._recent[key] = now
            if len(self._recent) > _DEDUP_MAX_ENTRIES:
                self._recent = {k: t for k, t in self._recent.items() if now - t < DEDUP_SECONDS}
            self.tracker.record(app_id, client, source, now=now)
        return app_id

    def handle_dns_log_line(self, line: str) -> None:
        match = _DNS_QUERY_RE.match(line)
        if not match or match.group("qtype").upper() in _IGNORED_QTYPES:
            return
        self.observe(match.group("client"), match.group("name"), "dns")

    def handle_sni_event_line(self, line: str) -> None:
        """One fr-xdp-sni-logger line (frfw.xdp.format_event_json). Both
        passes and drops count: a dropped connection is still an attempt
        to use the app."""
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return
        if not isinstance(event, dict) or event.get("action") not in ("pass", "drop"):
            return
        client, sni = event.get("saddr"), event.get("sni")
        if isinstance(client, str) and client and isinstance(sni, str) and sni:
            self.observe(client, sni, "sni")

    # -- output ------------------------------------------------------------

    def write_snapshot(self) -> dict:
        with self._lock:
            snapshot = self.tracker.snapshot(now=self._clock())
        self.usage_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.usage_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(snapshot))
        tmp.replace(self.usage_path)
        return snapshot

    def sources(self) -> list[tuple[str, Callable[[str], None]]]:
        """(journal unit, handler) pairs this config enables."""
        handlers = {
            f"{paths.ADBLOCK_DNS_SERVICE_NAME}.service": self.handle_dns_log_line,
            XDP_LOGGER_UNIT: self.handle_sni_event_line,
        }
        return [(unit, handlers[unit]) for unit in source_units(self.config)]

    def run_forever(
        self, reload_config: Callable[[], Config | None]
    ) -> None:  # pragma: no cover -- thin composition of tested parts
        units = source_units(self.config)
        for unit, handler in self.sources():
            threading.Thread(
                target=tail_journal_forever, args=(unit, handler), kwargs={"program": "fr-appid"},
                daemon=True,
            ).start()
        while True:
            time.sleep(FLUSH_SECONDS)
            self.write_snapshot()
            fresh = reload_config()
            if fresh is not None and source_units(fresh) != units:
                print("fr-appid: observation sources changed; restarting", flush=True)
                os.execv(sys.executable, [sys.executable, "-m", "frfw.appid.daemon"])


def source_units(config: Config) -> list[str]:
    """The journals to follow for `config`; empty while app
    identification is off."""
    if not config.app_control.enabled:
        return []
    units = []
    if config.adblocker.enabled and config.adblocker.query_logging:
        units.append(f"{paths.ADBLOCK_DNS_SERVICE_NAME}.service")
    if config.xdp_sni_filter.enabled and config.app_control.observe_sni:
        units.append(XDP_LOGGER_UNIT)
    return units


APPID_SERVICE_NAME = "fr-appid.service"


def is_daemon_active() -> bool:
    """`systemctl is-active` on fr-appid.service -- a read-only query any
    user may run, same as frfw.ai_ids.daemon.is_daemon_active."""
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", APPID_SERVICE_NAME], capture_output=True, text=True
        )
    except FileNotFoundError:
        return False
    return proc.stdout.strip() == "active"


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def load_usage(path: Path = paths.APPID_USAGE_PATH) -> dict:
    """The last written summary, for the webUI and the metrics exporter;
    `{"generated": None, "apps": {}}` if there is none yet."""
    data = _read_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("apps"), dict):
        return {"generated": None, "apps": {}}
    return data


def _load_config_or_none() -> Config | None:
    from frfw.config import ConfigError, load_config

    try:
        return load_config(paths.CONFIG_PATH)
    except (OSError, ConfigError) as exc:
        print(f"fr-appid: cannot load {paths.CONFIG_PATH}: {exc}", file=sys.stderr, flush=True)
        return None


def main() -> int:  # pragma: no cover -- process entry point
    announced = False
    while True:
        config = _load_config_or_none()
        if config is not None and source_units(config):
            break
        if not announced:
            print(
                "fr-appid: idle -- needs app_control.enabled plus adblocker.query_logging "
                "and/or app_control.observe_sni; re-checking config.yaml periodically",
                flush=True,
            )
            announced = True
        time.sleep(CONFIG_POLL_SECONDS)
    daemon = AppIdDaemon(config)
    print(f"fr-appid: following {', '.join(source_units(config))}", flush=True)
    daemon.run_forever(_load_config_or_none)
    return 0


if __name__ == "__main__":
    sys.exit(main())
