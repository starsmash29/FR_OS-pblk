"""`fr-ai-ids`: the unprivileged, out-of-band AI IDS/IPS background
daemon (systemd/fr-ai-ids.service).

Fully decoupled from the 40Gbps XDP data plane and from `firewall-cli
apply`/`frfw.provision.apply_all`: it is a long-running process of its
own, started once at boot and left running, not something the config-
apply pipeline attaches/detaches like the XDP filter or starts/stops
like the ad-block resolver. It only ever *reads* two things and, on a
decision, makes exactly one kind of privileged request:

1. `fr-xdp-sni-logger.service`'s journald output (one JSON line per TLS
   ClientHello the phase 4 XDP filter dropped for matching the SNI
   blocklist; with phase 16's `app_control.observe_sni` also one per
   passed SNI, which this daemon ignores) -- tailed via
   `journalctl -f -o cat`, the identical
   mechanism and identical `SupplementaryGroups=systemd-journal`
   permission model the webUI's own `/xdp/logs/stream` route already
   uses to read the same daemon's output without needing root.
2. A periodic snapshot of the kernel's connection-tracking table
   (`frfw.conntrack`, via the privileged apply-helper's
   "conntrack_sample" command -- `/proc/net/nf_conntrack` is root-only,
   confirmed by hand, so this unprivileged process cannot read it
   itself).

Both feed `frfw.ai_ids.engine.AnomalyEngine`. When `evaluate()` flags an
IP, this daemon sends exactly one privileged request -- "quarantine_ip"
-- over the same Unix socket the webUI uses for "ban_ip"; it never
touches `nft` itself. See ARCHITECTURE.md's phase 11 section for the
full design writeup, including the honest correction that
fr-xdp-sni-logger alone cannot supply connection-rate/destination-
diversity signal (it only ever logs a *blocklist match*, never a plain
pass), which is why conntrack sampling exists as a second, independent
telemetry source rather than everything being read from one log.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Callable

from frfw import paths
from frfw.adblock.categories import THREAT_CATEGORIES
from frfw.adblock.dga import looks_generated
from frfw.ai_ids.engine import AnomalyEngine, AnomalyEvent
from frfw.config.schema import Config
from frfw.helper import client as helper_client
from frfw.helper.client import HelperError
from frfw.journal import tail_journal_forever

#: How often to poll conntrack and check whether a window has elapsed.
#: Independent of frfw.ai_ids.engine.WINDOW_SECONDS (the *scoring*
#: window) -- this only controls how promptly a new connection is
#: observed and how promptly a window tick is noticed, not detection
#: sensitivity.
TICK_SECONDS = 5.0

#: How many of the most recent flagged/quarantined events to keep in the
#: display-only events log (paths.AI_IDS_STATE_PATH) for the webUI's AI
#: IDS screen -- unbounded growth would turn this into an unbounded log
#: file over an appliance's lifetime for no benefit past "the last
#: several".
RECENT_EVENTS_LIMIT = 50

#: The systemd unit this process runs under -- see `is_daemon_active`.
AI_IDS_SERVICE_NAME = "fr-ai-ids.service"

#: One line of the ad-block resolver's query log (dnsmasq with
#: `log-queries=extra`, phase 15), as journald's `-o cat` hands it over.
#: Format checked against real dnsmasq 2.91 output:
#:   "3 10.0.0.5/46443 reply www.nxtest.example is NXDOMAIN"
#:   "1 10.0.0.5/33904 /etc/fr_os/adblock.d/malware.hosts bad.example is 0.0.0.0"
#: Every line starts with a per-query serial and the client address/port,
#: which is what makes per-host attribution possible at all.
_DNS_LINE_RE = re.compile(r"^\d+ (?P<client>[0-9A-Fa-f:.]+)/\d+ (?P<rest>.+)$")
_DNS_NXDOMAIN_RE = re.compile(r"^(?:reply|cached) (?P<name>\S+) is NXDOMAIN$")
_DNS_HOSTS_BLOCK_RE = re.compile(r"^(?P<file>/\S+) (?P<name>\S+) is (?:0\.0\.0\.0|::)$")


def resolve_excluded_ips(config: Config) -> set[str]:
    """`ai_ids.excluded_macs`, resolved against the current DHCP static
    reservations to the IP addresses the engine actually sees traffic
    from -- see `frfw.config.schema.AiIdsConfig`'s docstring for why a
    MAC-based exclusion list needs this translation step now that
    profiling is IP-based, not device-record-based. A MAC with no
    matching reservation resolves to nothing (not an error) -- there is
    no IP to exclude yet."""
    excluded_macs = set(config.ai_ids.excluded_macs)
    if not excluded_macs:
        return set()
    ips: set[str] = set()
    for pool in config.dhcp.zones.values():
        for reservation in pool.reservations:
            if reservation.mac_address in excluded_macs:
                ips.add(reservation.address)
    return ips


class IDSDaemon:
    """Holds the engine plus everything needed to turn its verdicts into
    quarantine actions. Split into small, independently callable methods
    (`handle_sni_event_line`, `poll_conntrack_once`, `evaluate_and_enforce`)
    specifically so tests can drive each one directly with synthetic
    input and a fake helper/clock, without a real journald, conntrack
    table, or Unix socket -- only `run_forever` is the actual blocking
    entry point, and it is intentionally a thin composition of those
    pieces rather than where any real logic lives.
    """

    def __init__(
        self,
        config: Config,
        *,
        engine: AnomalyEngine | None = None,
        quarantine_fn: Callable[[str, int], dict] = helper_client.quarantine_ip,
        conntrack_fn: Callable[[], dict] = helper_client.conntrack_sample,
        events_path: Path = paths.AI_IDS_STATE_PATH,
        clock: Callable[[], float] | None = None,
        adblock_category_dir: Path = paths.ADBLOCK_CATEGORY_DIR,
    ) -> None:
        self.config = config
        self.engine = engine or AnomalyEngine()
        self._quarantine_fn = quarantine_fn
        self._conntrack_fn = conntrack_fn
        self._events_path = events_path
        self._clock = clock or time.monotonic
        self._excluded_ips = resolve_excluded_ips(config)
        self._known_flow_keys: set[tuple[str, str, int, str, int]] = set()
        self._threat_files = {
            str(adblock_category_dir / f"{name}.hosts")
            for name in THREAT_CATEGORIES
            if name in config.adblocker.categories
        }

    # -- ingestion ---------------------------------------------------------

    def handle_sni_event_line(self, line: str) -> None:
        """One line of fr-xdp-sni-logger's journald output (see
        `frfw.xdp.format_event_json`). Malformed/unrelated lines are
        ignored rather than raising -- a log stream occasionally carrying
        an unexpected line (e.g. a systemd-injected notice) must never
        take the daemon down."""
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return
        if not isinstance(event, dict) or event.get("action") != "drop":
            return
        src_ip = event.get("saddr")
        if isinstance(src_ip, str) and src_ip:
            self.engine.observe_sni_block(src_ip, now=self._clock())

    def handle_dns_log_line(self, line: str) -> None:
        """One line of fr-adblock-dns.service's journald output (only
        produced with `adblocker.query_logging`). NXDOMAIN answers feed the
        NXDOMAIN/DGA counters; an answer served from a malware/phishing
        category file feeds the threat-lookup counter. Everything else --
        the query itself, forwarding, ordinary answers, dnsmasq's own
        start-up notices, the DoH canary's "config ... is NXDOMAIN" -- is
        ignored."""
        match = _DNS_LINE_RE.match(line)
        if not match:
            return
        client, rest = match.group("client"), match.group("rest")
        now = self._clock()
        nx = _DNS_NXDOMAIN_RE.match(rest)
        if nx:
            name = nx.group("name").lower()
            self.engine.observe_dns_nxdomain(client, name, generated=looks_generated(name), now=now)
            return
        blocked = _DNS_HOSTS_BLOCK_RE.match(rest)
        if blocked and blocked.group("file") in self._threat_files:
            self.engine.observe_dns_threat_block(client, now=now)

    def poll_conntrack_once(self) -> None:
        """One "conntrack_sample" round trip through the privileged
        helper: diff the returned flows against the previous sample so
        only genuinely *new* flows (not still-open long-lived ones) are
        counted as connection attempts -- see
        `AnomalyEngine.observe_connection`'s docstring for why that
        distinction matters. A transport failure (helper not running
        yet) is logged and skipped, never raised -- a single missed
        sample just means one tick's worth of connections isn't
        observed, not a reason to stop the whole daemon."""
        try:
            response = self._conntrack_fn()
        except HelperError as exc:
            print(f"fr-ai-ids: conntrack sample failed: {exc}", file=sys.stderr, flush=True)
            return
        if not response.get("ok"):
            return

        now = self._clock()
        current_keys: set[tuple[str, str, int, str, int]] = set()
        for flow in response.get("flows", []):
            try:
                key = (flow["proto"], flow["src"], int(flow["sport"]), flow["dst"], int(flow["dport"]))
            except (KeyError, TypeError, ValueError):
                continue
            current_keys.add(key)
            if key not in self._known_flow_keys:
                self.engine.observe_connection(flow["src"], flow["dst"], now=now)
        self._known_flow_keys = current_keys

    def evaluate_and_enforce(self) -> list[AnomalyEvent]:
        """Score every currently-tracked IP once, quarantine (via the
        privileged helper) any that are flagged and not excluded, and
        append each such event to the display-only recent-events log.
        Returns every flagged event (including excluded ones, so a
        caller/test can tell the difference between "not anomalous" and
        "anomalous but excluded")."""
        now = self._clock()
        flagged: list[AnomalyEvent] = []
        for ip in self.engine.tracked_ips():
            event = self.engine.evaluate(ip, now=now)
            if event is None:
                continue
            flagged.append(event)
            if ip in self._excluded_ips:
                continue
            self._enforce(event)
        return flagged

    def _enforce(self, event: AnomalyEvent) -> None:
        duration = self.config.ai_ids.quarantine_duration_seconds
        try:
            response = self._quarantine_fn(event.ip, duration)
        except HelperError as exc:
            print(f"fr-ai-ids: quarantine request failed: {exc}", file=sys.stderr, flush=True)
            return
        if not response.get("ok"):
            print(
                f"fr-ai-ids: apply-helper refused to quarantine {event.ip}: "
                f"{response.get('message')}",
                file=sys.stderr,
                flush=True,
            )
            return
        print(
            f"fr-ai-ids: quarantined {event.ip} for {duration}s "
            f"(score={event.score}, reasons={', '.join(event.reasons)})",
            flush=True,
        )
        self._append_event_log(event)

    # -- display-only recent-events log ------------------------------------

    def _append_event_log(self, event: AnomalyEvent) -> None:
        events = _load_events(self._events_path)
        events.append({"ts": time.time(), **asdict(event)})
        events = events[-RECENT_EVENTS_LIMIT:]
        self._events_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._events_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(events))
        tmp_path.replace(self._events_path)

    # -- the real, blocking entry point -------------------------------------

    def run_forever(self) -> None:  # pragma: no cover -- thin composition, see class docstring
        import threading

        threading.Thread(
            target=self._tail_journal_forever,
            args=("fr-xdp-sni-logger.service", self.handle_sni_event_line),
            daemon=True,
        ).start()
        adblocker = self.config.adblocker
        if adblocker.enabled and adblocker.query_logging:
            threading.Thread(
                target=self._tail_journal_forever,
                args=(f"{paths.ADBLOCK_DNS_SERVICE_NAME}.service", self.handle_dns_log_line),
                daemon=True,
            ).start()

        next_eval_at = self._clock() + self.engine.window_seconds
        while True:
            time.sleep(TICK_SECONDS)
            self.poll_conntrack_once()
            if self._clock() >= next_eval_at:
                self.evaluate_and_enforce()
                next_eval_at = self._clock() + self.engine.window_seconds

    def _tail_journal_forever(self, unit: str, handler: Callable[[str], None]) -> None:  # pragma: no cover
        tail_journal_forever(unit, handler, program="fr-ai-ids")


def is_daemon_active() -> bool:
    """`systemctl is-active` on fr-ai-ids.service -- a read-only status
    query any user can run (no root needed), the same reasoning as
    frfw.adblock.dns_service.is_resolver_active. The webUI's AI IDS
    screen calls this directly rather than through the privileged
    helper."""
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", AI_IDS_SERVICE_NAME], capture_output=True, text=True
        )
    except FileNotFoundError:
        return False
    return proc.stdout.strip() == "active"


def _load_events(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    return data if isinstance(data, list) else []


def load_recent_events(path: Path = paths.AI_IDS_STATE_PATH, limit: int = RECENT_EVENTS_LIMIT) -> list[dict]:
    """Public read accessor for the webUI's AI IDS screen -- the most
    recently flagged/quarantined events, newest last. Display-only, like
    frfw.ztna's own state file: the kernel quarantine set (queried live
    via the "ids_quarantine_status" helper command) is always the
    authority on who is *currently* quarantined; this is only a history
    of what the engine has decided, for context."""
    return _load_events(path)[-limit:]


def main() -> int:  # pragma: no cover -- process entry point
    from frfw.config import ConfigError, load_config

    try:
        config = load_config(paths.CONFIG_PATH)
    except (FileNotFoundError, ConfigError) as exc:
        print(f"fr-ai-ids: cannot load {paths.CONFIG_PATH}: {exc}", file=sys.stderr)
        return 1

    if not config.ai_ids.enabled:
        print("fr-ai-ids: ai_ids.enabled is false in config.yaml; exiting", flush=True)
        return 0

    IDSDaemon(config).run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
