"""Per-app, per-client usage accounting for phase 16's app identification.

A "hit" is one observation that a client used an app: one DNS lookup of
one of the app's names, or one TLS connection whose SNI was one of them.
It is a coarse activity signal, not traffic volume or time spent -- one
page load can easily be a dozen lookups, and a cached answer on the
client produces none.

Counts are kept in hourly buckets for RETENTION_SECONDS, so the summary
("hits in the last 24 hours", "clients active in the last 15 minutes")
survives a daemon restart through the snapshot file and never grows
without bound.
"""

from __future__ import annotations

from dataclasses import dataclass, field

BUCKET_SECONDS = 3600
RETENTION_SECONDS = 24 * 3600
ACTIVE_WINDOW_SECONDS = 15 * 60

#: Upper bound on distinct clients tracked per app; beyond it the least
#: recently seen client is forgotten. A home/small-office network never
#: gets near it -- it only keeps a flood of spoofed sources from growing
#: the daemon's memory without limit.
MAX_CLIENTS_PER_APP = 512

SOURCES = ("dns", "sni")


@dataclass
class ClientUsage:
    first_seen: float
    last_seen: float
    buckets: dict[int, int] = field(default_factory=dict)
    sources: set[str] = field(default_factory=set)

    def hits(self) -> int:
        return sum(self.buckets.values())


class UsageTracker:
    def __init__(self) -> None:
        self._apps: dict[str, dict[str, ClientUsage]] = {}

    def record(self, app_id: str, client: str, source: str, *, now: float) -> None:
        clients = self._apps.setdefault(app_id, {})
        usage = clients.get(client)
        if usage is None:
            if len(clients) >= MAX_CLIENTS_PER_APP:
                oldest = min(clients, key=lambda c: clients[c].last_seen)
                del clients[oldest]
            usage = clients[client] = ClientUsage(first_seen=now, last_seen=now)
        usage.last_seen = max(usage.last_seen, now)
        bucket = int(now // BUCKET_SECONDS) * BUCKET_SECONDS
        usage.buckets[bucket] = usage.buckets.get(bucket, 0) + 1
        usage.sources.add(source)

    def prune(self, *, now: float) -> None:
        # A bucket is kept while any part of it is inside the retention window.
        cutoff = now - RETENTION_SECONDS - BUCKET_SECONDS
        for app_id in list(self._apps):
            clients = self._apps[app_id]
            for client in list(clients):
                usage = clients[client]
                usage.buckets = {b: n for b, n in usage.buckets.items() if b > cutoff}
                if not usage.buckets:
                    del clients[client]
            if not clients:
                del self._apps[app_id]

    def snapshot(self, *, now: float) -> dict:
        """JSON-ready summary, also the persistence format (`restore`)."""
        self.prune(now=now)
        apps = {}
        for app_id, clients in sorted(self._apps.items()):
            client_rows = {
                client: {
                    "hits_24h": usage.hits(),
                    "first_seen": usage.first_seen,
                    "last_seen": usage.last_seen,
                    "active": now - usage.last_seen <= ACTIVE_WINDOW_SECONDS,
                    "sources": sorted(usage.sources),
                    "buckets": {str(b): n for b, n in sorted(usage.buckets.items())},
                }
                for client, usage in sorted(clients.items())
            }
            apps[app_id] = {
                "hits_24h": sum(row["hits_24h"] for row in client_rows.values()),
                "active_clients": sum(1 for row in client_rows.values() if row["active"]),
                "last_seen": max(row["last_seen"] for row in client_rows.values()),
                "clients": client_rows,
            }
        return {"generated": now, "apps": apps}

    @classmethod
    def restore(cls, data: object) -> "UsageTracker":
        """Rebuild from a previous `snapshot`. Anything malformed is
        skipped -- a damaged state file must never stop the daemon."""
        tracker = cls()
        if not isinstance(data, dict) or not isinstance(data.get("apps"), dict):
            return tracker
        for app_id, app in data["apps"].items():
            if not isinstance(app, dict) or not isinstance(app.get("clients"), dict):
                continue
            for client, row in app["clients"].items():
                try:
                    usage = ClientUsage(
                        first_seen=float(row["first_seen"]),
                        last_seen=float(row["last_seen"]),
                        buckets={int(b): int(n) for b, n in row.get("buckets", {}).items()},
                        sources={s for s in row.get("sources", []) if s in SOURCES},
                    )
                except (KeyError, TypeError, ValueError, AttributeError):
                    continue
                if usage.buckets:
                    tracker._apps.setdefault(str(app_id), {})[str(client)] = usage
        return tracker
