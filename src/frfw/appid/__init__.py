"""Coarse application identification from DNS names and TLS SNIs (phase 16).

This is not deep packet inspection: nothing here looks inside encrypted
traffic. It answers "which app is this connection probably for?" from the
one piece of cleartext almost every connection still exposes -- the name
the client asked for -- by looking it up in a catalog of per-app domains.

Two observation points feed it (see frfw.appid.daemon):

- the resolver's query log (dnsmasq `log-queries=extra`, phase 15): sees
  every name a client resolves through the router, whatever its length;
- the XDP SNI parser (phase 4) with pass reporting switched on: sees the
  SNI of TLS connections a client opens, even when it resolved the name
  elsewhere -- but only names shorter than 32 bytes, only TCP (not QUIC),
  and never a name hidden by Encrypted Client Hello.

The catalog (`signatures.json`, next to this file) is generated from
v2fly/domain-list-community by scripts/update_app_signatures.py and
records the commit it was built from. A name is attributed to the app
whose catalog entry is the *longest* matching suffix, so a more specific
entry always wins over a broader one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

SIGNATURES_PATH = Path(__file__).with_name("signatures.json")


@dataclass(frozen=True)
class AppSignature:
    id: str
    name: str
    category: str
    #: Suffix entries: the name itself and every subdomain of it.
    domains: tuple[str, ...]
    #: Exact entries: only this precise name.
    exact: tuple[str, ...]

    def all_names(self) -> tuple[str, ...]:
        return self.domains + self.exact


@dataclass(frozen=True)
class Catalog:
    apps: tuple[AppSignature, ...]
    source: str
    license: str
    ref: str
    generated: str

    def by_id(self) -> dict[str, AppSignature]:
        return {app.id: app for app in self.apps}

    def categories(self) -> list[str]:
        return sorted({app.category for app in self.apps})


class CatalogError(Exception):
    pass


def parse_catalog(data: object) -> Catalog:
    if not isinstance(data, dict) or not isinstance(data.get("apps"), list):
        raise CatalogError("signature catalog must be an object with an 'apps' list")
    apps = []
    seen: set[str] = set()
    for i, raw in enumerate(data["apps"]):
        try:
            app = AppSignature(
                id=str(raw["id"]),
                name=str(raw["name"]),
                category=str(raw["category"]),
                domains=tuple(str(d).lower() for d in raw.get("domains", [])),
                exact=tuple(str(d).lower() for d in raw.get("exact", [])),
            )
        except (KeyError, TypeError) as exc:
            raise CatalogError(f"apps[{i}]: malformed entry ({exc})") from exc
        if app.id in seen:
            raise CatalogError(f"apps[{i}]: duplicate app id {app.id!r}")
        seen.add(app.id)
        apps.append(app)
    return Catalog(
        apps=tuple(apps),
        source=str(data.get("source", "")),
        license=str(data.get("license", "")),
        ref=str(data.get("ref", "")),
        generated=str(data.get("generated", "")),
    )


@lru_cache(maxsize=1)
def load_catalog(path: Path = SIGNATURES_PATH) -> Catalog:
    """The bundled catalog (cached -- it never changes at runtime)."""
    return parse_catalog(json.loads(path.read_text()))


def known_app_ids() -> set[str]:
    return set(load_catalog().by_id())


class AppMatcher:
    """name -> app id lookup. O(number of labels) per name: the exact
    table first, then every suffix from longest to shortest."""

    def __init__(self, catalog: Catalog):
        self._exact: dict[str, str] = {}
        self._suffix: dict[str, str] = {}
        for app in catalog.apps:
            for name in app.exact:
                self._exact.setdefault(name, app.id)
            for name in app.domains:
                self._suffix.setdefault(name, app.id)

    def match(self, hostname: str) -> str | None:
        name = hostname.strip().rstrip(".").lower()
        if not name:
            return None
        app = self._exact.get(name)
        if app is not None:
            return app
        labels = name.split(".")
        for i in range(len(labels)):
            app = self._suffix.get(".".join(labels[i:]))
            if app is not None:
                return app
        return None


def blocking_names(app_ids: list[str], catalog: Catalog | None = None) -> list[str]:
    """Every catalog name of the given apps, for the resolver's and the XDP
    filter's blocklists (both block a name *and* its subdomains, so an
    exact entry is blocked a little more broadly than it matches -- its
    subdomains belong to the same app in practice). Unknown ids are
    ignored; the config loader already rejects them."""
    by_id = (catalog or load_catalog()).by_id()
    names: set[str] = set()
    for app_id in app_ids:
        app = by_id.get(app_id)
        if app is not None:
            names.update(app.all_names())
    return sorted(names)
