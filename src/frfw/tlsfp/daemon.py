"""`fr-tls-fp`: TLS client fingerprinting daemon (phase 19,
systemd/fr-tls-fp.service).

Reads the ClientHello segments the XDP program copies to its `hello_pkts`
ring buffer (with `tls_fingerprint.enabled`), reassembles hellos that span
several segments, computes JA4 and JA3 per client, keeps an inventory
(frfw.tlsfp.inventory), and reports two kinds of events:

- a JA4 never seen on the network before (after a 24-hour learning
  period) -- typically a new device, an app update, or a script/malware
  bringing its own TLS library;
- a match on `tls_fingerprint.blocklist`, optionally followed by
  quarantining the client through the privileged helper (the same
  "quarantine_ip" command the AI IDS uses).

Privileges: opening a pinned BPF map needs CAP_BPF, which an unprivileged
account doesn't have. So the process starts as root, opens the ring
buffer, and then permanently drops to the fr_os-webui account
(`drop_privileges`) *before* reading a single byte of packet data -- the
parsing of untrusted input never runs with privileges. The open ring
buffer keeps working after the drop (checked by hand, and by
tests/test_tlsfp_live.py), but the pinned path can't be reopened, so when
the XDP program is reloaded the daemon exits and systemd restarts it
(frfw.provision also restarts it after an apply).
"""

from __future__ import annotations

import json
import os
import pwd
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

from frfw import svc
from frfw import paths, xdp
from frfw.config.schema import Config
from frfw.helper import client as helper_client
from frfw.helper.client import HelperError
from frfw.tlsfp.clienthello import ParseError, parse_client_hello
from frfw.tlsfp.fingerprint import ja3, ja4
from frfw.tlsfp.inventory import FingerprintInventory
from frfw.tlsfp.reassembly import Reassembler

SERVICE_NAME = "fr-tls-fp.service"
RUN_AS_USER = "fr_os-webui"
FLUSH_SECONDS = 30.0
CONFIG_POLL_SECONDS = 30.0

#: A blocklisted client is quarantined at most this often (the kernel set
#: entry lasts ai_ids.quarantine_duration_seconds anyway).
QUARANTINE_REPEAT_SECONDS = 600.0


class TlsFingerprintDaemon:
    def __init__(
        self,
        config: Config,
        *,
        state_path: Path = paths.TLSFP_STATE_PATH,
        quarantine_fn: Callable[[str, int], dict] = helper_client.quarantine_ip,
        clock: Callable[[], float] = time.time,
    ):
        self._clock = clock
        self.state_path = state_path
        self.quarantine_fn = quarantine_fn
        self.reassembler = Reassembler()
        self.inventory = FingerprintInventory.restore(_read_json(state_path), clock())
        self._quarantined_at: dict[str, float] = {}
        self.stats = {"hellos": 0, "parse_errors": 0}
        self.update_config(config)

    def update_config(self, config: Config) -> None:
        self.config = config
        self.blocklist = {e.fingerprint: e.label for e in config.tls_fingerprint.blocklist}

    # -- ingestion -----------------------------------------------------------

    def handle_segment(self, segment: xdp.HelloSegment) -> None:
        now = self._clock()
        key = (segment.saddr, segment.sport, segment.daddr, segment.dport)
        try:
            message = self.reassembler.add(key, segment.seq, segment.payload, now, first=segment.first)
            if message is None:
                return
            hello = parse_client_hello(message)
        except ParseError:
            self.stats["parse_errors"] += 1
            return
        self.stats["hellos"] += 1
        self.handle_hello(segment.saddr, ja4(hello), ja3(hello), hello.server_name, now)

    def handle_hello(self, client: str, ja4_fp: str, ja3_fp: str, sni: str | None, now: float) -> None:
        is_new = self.inventory.observe(client, ja4_fp, ja3_fp, sni, now)
        base = {"ts": now, "client": client, "ja4": ja4_fp, "ja3": ja3_fp, "sni": sni}
        if is_new:
            self.inventory.add_event({**base, "type": "new_fingerprint"})
        label = self.blocklist.get(ja4_fp, self.blocklist.get(ja3_fp))
        if label is None and ja4_fp not in self.blocklist and ja3_fp not in self.blocklist:
            return
        event = {**base, "type": "blocklist", "label": label or "", "action": "reported"}
        if self.config.tls_fingerprint.quarantine_on_match:
            event["action"] = self._quarantine(client, now)
        self.inventory.add_event(event)

    def _quarantine(self, client: str, now: float) -> str:
        last = self._quarantined_at.get(client)
        if last is not None and now - last < QUARANTINE_REPEAT_SECONDS:
            return "already quarantined"
        self._quarantined_at[client] = now
        try:
            response = self.quarantine_fn(client, self.config.ai_ids.quarantine_duration_seconds)
        except HelperError as exc:
            return f"quarantine failed: {exc}"
        return "quarantined" if response.get("ok") else f"quarantine failed: {response.get('message')}"

    # -- output --------------------------------------------------------------

    def write_state(self) -> dict:
        snapshot = self.inventory.snapshot(self._clock())
        snapshot["stats"] = dict(self.stats)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(snapshot))
        tmp.replace(self.state_path)
        return snapshot


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def load_state(path: Path = paths.TLSFP_STATE_PATH) -> dict:
    """The last written inventory, for the webUI and metrics."""
    data = _read_json(path)
    if not isinstance(data, dict):
        return {"generated": None, "clients": {}, "events": [], "learning": True}
    return data


def drop_privileges(user: str = RUN_AS_USER) -> None:
    """Permanently become `user` (falling back to nobody on a dev box that
    lacks it). Must succeed before any packet data is read."""
    try:
        account = pwd.getpwnam(user)
    except KeyError:
        account = pwd.getpwnam("nobody")
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    if os.getuid() == 0 or os.geteuid() == 0:
        raise RuntimeError("fr-tls-fp: failed to drop root privileges")


def restart_service() -> None:
    """Called by frfw.provision after an apply with fingerprinting on: the
    daemon can't reopen a replaced ring buffer once it has dropped its
    privileges, so it is restarted to pick up the current one. Best
    effort -- no systemd (tests, dev boxes) is not an error."""
    try:
        svc.systemctl("try-restart", SERVICE_NAME, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def is_daemon_active() -> bool:
    try:
        proc = subprocess.run(["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True)
    except FileNotFoundError:
        return False
    return proc.stdout.strip() == "active"


def _load_config() -> Config | None:
    from frfw.config import ConfigError, load_config

    try:
        return load_config(paths.CONFIG_PATH)
    except (OSError, ConfigError) as exc:
        print(f"fr-tls-fp: cannot load {paths.CONFIG_PATH}: {exc}", file=sys.stderr, flush=True)
        return None


def main() -> int:  # pragma: no cover -- process entry point, see tests/test_tlsfp_live.py
    # Phase 1, as root: wait until fingerprinting is on and the XDP
    # program's buffer exists. Nothing untrusted is touched here.
    announced = False
    while True:
        config = _load_config()
        if config is not None and config.tls_fingerprint.enabled and xdp.PIN_HELLO_PKTS_PATH.exists():
            break
        if not announced:
            print("fr-tls-fp: idle until tls_fingerprint.enabled and the XDP filter is loaded", flush=True)
            announced = True
        time.sleep(CONFIG_POLL_SECONDS)

    daemon_holder: list[TlsFingerprintDaemon] = []
    reader = xdp.RingBufferReader(
        lambda seg: daemon_holder[0].handle_segment(seg),
        xdp.PIN_HELLO_PKTS_PATH,
        decode=xdp.HelloSegment.from_bytes,
    )
    # Phase 2: no privileges from here on.
    drop_privileges()
    daemon_holder.append(TlsFingerprintDaemon(config))
    print(f"fr-tls-fp: running as uid {os.getuid()}, fingerprinting ClientHellos", flush=True)

    next_flush = time.time() + FLUSH_SECONDS
    while True:
        reader.poll(500)
        if time.time() >= next_flush:
            daemon_holder[0].write_state()
            next_flush = time.time() + FLUSH_SECONDS
            fresh = _load_config()
            if fresh is not None:
                if not fresh.tls_fingerprint.enabled:
                    print("fr-tls-fp: disabled in config; exiting", flush=True)
                    return 0
                daemon_holder[0].update_config(fresh)


if __name__ == "__main__":
    sys.exit(main())
