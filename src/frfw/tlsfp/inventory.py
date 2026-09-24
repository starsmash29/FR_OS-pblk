"""Which TLS client fingerprints each device presented (phase 19).

Per client address: every JA4 seen, the JA3 values that went with it
(several per JA4 for browsers that shuffle extensions), a few server
names, counts and first/last-seen times. Network-wide: when each JA4 was
first seen, which drives the "new fingerprint" event after a learning
period. Everything is bounded so a noisy or hostile network can't grow it
without limit, and it round-trips through the JSON state file.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: No "new fingerprint" events until the inventory is this old: at first
#: every fingerprint is new.
LEARNING_SECONDS = 24 * 3600

MAX_CLIENTS = 1024
MAX_FINGERPRINTS_PER_CLIENT = 32
MAX_NETWORK_FINGERPRINTS = 10000
MAX_JA3_PER_FINGERPRINT = 8
MAX_SNI_PER_FINGERPRINT = 5
MAX_EVENTS = 200


@dataclass
class Seen:
    first_seen: float
    last_seen: float
    count: int = 0
    ja3: list[str] = field(default_factory=list)
    sni: list[str] = field(default_factory=list)


def _remember(values: list[str], value: str | None, limit: int) -> None:
    if not value:
        return
    if value in values:
        values.remove(value)
    values.append(value)
    del values[:-limit]


class FingerprintInventory:
    def __init__(self, started: float):
        self.started = started
        self.clients: dict[str, dict[str, Seen]] = {}
        self.network_first_seen: dict[str, float] = {}
        self.events: list[dict] = []

    def observe(self, client: str, ja4: str, ja3: str, sni: str | None, now: float) -> bool:
        """Record one fingerprinted ClientHello. True if this JA4 has never
        been seen on the network before and the learning period is over."""
        is_new = ja4 not in self.network_first_seen
        if is_new:
            if len(self.network_first_seen) >= MAX_NETWORK_FINGERPRINTS:
                oldest = min(self.network_first_seen, key=self.network_first_seen.get)
                del self.network_first_seen[oldest]
            self.network_first_seen[ja4] = now

        fingerprints = self.clients.get(client)
        if fingerprints is None:
            if len(self.clients) >= MAX_CLIENTS:
                stalest = min(self.clients, key=lambda c: max(s.last_seen for s in self.clients[c].values()))
                del self.clients[stalest]
            fingerprints = self.clients[client] = {}
        seen = fingerprints.get(ja4)
        if seen is None:
            if len(fingerprints) >= MAX_FINGERPRINTS_PER_CLIENT:
                del fingerprints[min(fingerprints, key=lambda f: fingerprints[f].last_seen)]
            seen = fingerprints[ja4] = Seen(first_seen=now, last_seen=now)
        seen.last_seen = now
        seen.count += 1
        _remember(seen.ja3, ja3, MAX_JA3_PER_FINGERPRINT)
        _remember(seen.sni, sni, MAX_SNI_PER_FINGERPRINT)
        return is_new and now - self.started >= LEARNING_SECONDS

    def add_event(self, event: dict) -> None:
        self.events.append(event)
        del self.events[:-MAX_EVENTS]

    def learning(self, now: float) -> bool:
        return now - self.started < LEARNING_SECONDS

    def snapshot(self, now: float) -> dict:
        return {
            "generated": now,
            "started": self.started,
            "learning": self.learning(now),
            "clients": {
                client: {
                    ja4: {
                        "first_seen": s.first_seen, "last_seen": s.last_seen, "count": s.count,
                        "ja3": list(s.ja3), "sni": list(s.sni),
                    }
                    for ja4, s in sorted(fps.items())
                }
                for client, fps in sorted(self.clients.items())
            },
            "network_first_seen": dict(self.network_first_seen),
            "events": list(self.events),
        }

    @classmethod
    def restore(cls, data: object, now: float) -> "FingerprintInventory":
        """Rebuild from a snapshot; anything malformed is dropped."""
        if not isinstance(data, dict):
            return cls(started=now)
        try:
            inventory = cls(started=float(data.get("started", now)))
        except (TypeError, ValueError):
            return cls(started=now)
        for client, fps in (data.get("clients") or {}).items():
            if not isinstance(fps, dict):
                continue
            for ja4, row in fps.items():
                try:
                    seen = Seen(
                        first_seen=float(row["first_seen"]), last_seen=float(row["last_seen"]),
                        count=int(row.get("count", 0)),
                        ja3=[str(v) for v in row.get("ja3", [])][-MAX_JA3_PER_FINGERPRINT:],
                        sni=[str(v) for v in row.get("sni", [])][-MAX_SNI_PER_FINGERPRINT:],
                    )
                except (KeyError, TypeError, ValueError, AttributeError):
                    continue
                inventory.clients.setdefault(str(client), {})[str(ja4)] = seen
        for ja4, ts in (data.get("network_first_seen") or {}).items():
            if isinstance(ts, (int, float)):
                inventory.network_first_seen[str(ja4)] = float(ts)
        inventory.events = [e for e in (data.get("events") or []) if isinstance(e, dict)][-MAX_EVENTS:]
        return inventory
