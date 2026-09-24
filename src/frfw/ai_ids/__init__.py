"""Real-time, kernel-assisted AI IDS/IPS (phase 11).

Replaces the earlier explicit-mock engine (which fabricated per-device
"learning progress"/"risk label" data pending this phase, see git
history and ROADMAP.md's phase 11 entry) with an actual anomaly
detector: a lightweight, pure-stdlib sliding-window scorer
(`frfw.ai_ids.engine.AnomalyEngine`) fed by real telemetry (connection-
tracking data and the phase 4 XDP filter's SNI-blocklist hits), running
as its own out-of-band systemd daemon (`frfw.ai_ids.daemon`,
`fr-ai-ids.service`) that asks the privileged apply-helper to quarantine
an IP in the kernel (`frfw.ids_quarantine`) when it flags one.

See:
- `frfw.ai_ids.engine` for the scoring itself (no ML libraries -- see
  that module's docstring for why that is a deliberate design choice,
  not a missing feature).
- `frfw.ai_ids.daemon` for how real data reaches the engine, and the
  honest correction (documented in ARCHITECTURE.md's phase 11 section)
  that fr-xdp-sni-logger alone cannot supply every feature a "read the
  XDP logger" request might assume it can.
- `frfw.ids_quarantine` for the kernel-side enforcement action.
"""

from __future__ import annotations

from frfw.ai_ids.daemon import IDSDaemon, is_daemon_active, load_recent_events, resolve_excluded_ips
from frfw.ai_ids.engine import AnomalyEngine, AnomalyEvent

__all__ = [
    "AnomalyEngine",
    "AnomalyEvent",
    "IDSDaemon",
    "is_daemon_active",
    "load_recent_events",
    "resolve_excluded_ips",
]
