"""Mock anomaly-detection engine for the AI IDS/IPS feature.

Everything this module reports is FABRICATED. There is no real traffic
capture yet -- that needs the phase 4 XDP/eBPF fast path to see packets
in the first place. This exists so the config schema, the webUI, and the
retrain-scheduling plumbing (CLI command + systemd timer) can all be
built and tested now, and swapped for a real scikit-learn
IsolationForest-based pipeline later (see `train_isolation_forest` below)
without changing any of their interfaces.

Every screen and API response that surfaces this data MUST make the mock
nature obvious to the admin -- see the "MOCK" banner in
frfw/webui/templates/ai_ids.html. Nothing here should ever be presented,
logged, or alerted on as a real security signal.

Device enumeration comes from the DHCP static reservations already
declared in the config -- the closest thing to a "known devices" list
available without real traffic capture (a dynamically-leased device with
no reservation isn't profiled yet; that also needs phase 4).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from frfw import paths
from frfw.config.schema import Config

#: Cosmetic-only labels for the mock risk classification -- not derived
#: from anything resembling real behavioral analysis.
_RISK_LABELS = [
    "Low Complexity / IoT",
    "Medium Complexity / Media Device",
    "High Complexity / Workstation",
]

#: Cosmetic-only protocol pool the mock "top protocols" are drawn from.
_PROTOCOL_POOL = [
    "tcp:443", "tcp:80", "udp:53", "udp:123", "tcp:22", "tcp:8443", "udp:5353", "tcp:445",
]


@dataclass(frozen=True)
class DeviceProfile:
    mac: str
    ip: str | None
    hostname: str
    learning_percent: int
    risk_label: str
    top_protocols: list[str]
    known_domains_count: int
    locked: bool


@dataclass
class _DeviceState:
    locked: bool = False
    retrain_started_at: str | None = None  # ISO 8601 UTC timestamp


def _stable_seed(mac: str) -> int:
    """A deterministic per-MAC seed -- the mock stats below need to stay
    stable across calls/page loads, not re-roll on every render."""
    return int(hashlib.sha256(mac.encode()).hexdigest(), 16)


def _mock_risk_label(mac: str) -> str:
    return _RISK_LABELS[_stable_seed(mac) % len(_RISK_LABELS)]


def _mock_top_protocols(mac: str) -> list[str]:
    seed = _stable_seed(mac)
    count = 2 + (seed % 3)  # 2-4 entries
    picks = [_PROTOCOL_POOL[(seed >> (i * 4)) % len(_PROTOCOL_POOL)] for i in range(count)]
    seen: set[str] = set()
    unique = [p for p in picks if not (p in seen or seen.add(p))]
    return unique or [_PROTOCOL_POOL[0]]


def _mock_known_domains_count(mac: str) -> int:
    return 3 + (_stable_seed(mac) % 40)


class AIIDSEngine:
    """Mock IDS engine: derives a per-device "profile" from the DHCP
    reservations declared in the config, plus a small persisted state
    file tracking each device's simulated learning progress and whether
    its profile has been locked.

    Deliberately does not touch nftables, Kea, or any other privileged
    resource -- runs entirely unprivileged, no `frfw.helper` round trip
    needed for `force_retrain`/`lock_profile`.
    """

    def __init__(self, config: Config, state_path: Path = paths.AI_IDS_STATE_PATH) -> None:
        self.config = config
        self.state_path = state_path

    # -- state persistence ------------------------------------------------

    def _load_state(self) -> dict[str, _DeviceState]:
        if not self.state_path.is_file():
            return {}
        raw = json.loads(self.state_path.read_text())
        return {
            mac: _DeviceState(
                locked=body.get("locked", False),
                retrain_started_at=body.get("retrain_started_at"),
            )
            for mac, body in raw.items()
        }

    def _save_state(self, state: dict[str, _DeviceState]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        raw = {
            mac: {"locked": s.locked, "retrain_started_at": s.retrain_started_at}
            for mac, s in state.items()
        }
        tmp_path = self.state_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(raw))
        tmp_path.replace(self.state_path)

    # -- device enumeration -------------------------------------------------

    def _known_devices(self) -> dict[str, dict]:
        """mac -> {"ip", "hostname"}, from all DHCP reservations, minus
        anything listed in ai_ids.excluded_macs."""
        excluded = set(self.config.ai_ids.excluded_macs)
        devices: dict[str, dict] = {}
        for pool in self.config.dhcp.zones.values():
            for reservation in pool.reservations:
                if reservation.mac_address in excluded:
                    continue
                devices[reservation.mac_address] = {
                    "ip": reservation.address,
                    "hostname": reservation.hostname or reservation.mac_address,
                }
        return devices

    def list_devices(self) -> list[DeviceProfile]:
        known = self._known_devices()
        state = self._load_state()
        now = datetime.now(timezone.utc)
        changed = False

        profiles = []
        for mac, info in sorted(known.items()):
            device_state = state.get(mac)
            if device_state is None:
                device_state = _DeviceState(retrain_started_at=now.isoformat())
                state[mac] = device_state
                changed = True

            if device_state.locked:
                learning_percent = 100
            else:
                started = datetime.fromisoformat(device_state.retrain_started_at)
                elapsed_days = (now - started).total_seconds() / 86400
                learning_days = max(self.config.ai_ids.learning_days, 1)
                learning_percent = min(100, int(elapsed_days / learning_days * 100))

            profiles.append(
                DeviceProfile(
                    mac=mac,
                    ip=info["ip"],
                    hostname=info["hostname"],
                    learning_percent=learning_percent,
                    risk_label=_mock_risk_label(mac),
                    top_protocols=_mock_top_protocols(mac),
                    known_domains_count=_mock_known_domains_count(mac),
                    locked=device_state.locked,
                )
            )

        if changed:
            self._save_state(state)
        return profiles

    def global_learning_progress(self) -> float:
        profiles = self.list_devices()
        if not profiles:
            return 0.0
        return sum(p.learning_percent for p in profiles) / len(profiles)

    # -- actions --------------------------------------------------------------

    def force_retrain(self, mac: str | None = None) -> None:
        """Reset the simulated learning clock for one device, or every
        known device if `mac` is None. Also unlocks the affected
        device(s) -- forcing a retrain is an explicit override of a
        locked profile.

        Raises `KeyError` if `mac` is given but not a known device.
        """
        known = self._known_devices()
        if mac is not None and mac not in known:
            raise KeyError(f"Unknown device {mac!r}")

        state = self._load_state()
        now_iso = datetime.now(timezone.utc).isoformat()
        for target in [mac] if mac is not None else known:
            state[target] = _DeviceState(locked=False, retrain_started_at=now_iso)
        self._save_state(state)

    def lock_profile(self, mac: str) -> None:
        """Freeze a device's profile at 100% learned, no further
        adaptation until explicitly retrained. Raises `KeyError` if `mac`
        is not a known device."""
        known = self._known_devices()
        if mac not in known:
            raise KeyError(f"Unknown device {mac!r}")

        state = self._load_state()
        existing = state.get(mac, _DeviceState())
        state[mac] = _DeviceState(locked=True, retrain_started_at=existing.retrain_started_at)
        self._save_state(state)


def train_isolation_forest(*args, **kwargs) -> None:
    """Placeholder for the real model (phase 4+): scikit-learn's
    `IsolationForest` trained on real per-device flow features (packet
    size/interval distributions, protocol mix, destination diversity)
    collected via the XDP/eBPF fast path.

    Deliberately raises rather than silently no-op-ing, so nothing can
    mistake this for a working integration. `scikit-learn` is
    intentionally not a dependency of this module (nor of any pyproject
    extra) until this is implemented for real -- see ROADMAP.md.
    """
    raise NotImplementedError(
        "Real anomaly detection needs phase 4's traffic capture first; "
        "see the frfw.ai_ids module docstring and ROADMAP.md."
    )
