"""Ready-made blocklist categories the webUI offers as checkboxes
(phase 15). The engine itself has no built-in notion of these -- the
config only ever stores `adblocker.categories: {name: [urls]}` -- so an
admin can use any other list, or edit these URLs, without code changes.

Every URL below was fetched and checked while writing this (HTTP 200,
format as noted): StevenBlack's `alternates/<x>-only/hosts` files are
hosts format and, per their own header, "The unified hosts file was not
used while generating this file" (so they don't duplicate the base ad
list); URLhaus is hosts format with 127.0.0.1 and tabs; Phishing Army
and the DoH resolver list are plain one-domain-per-line lists. Some
guessed paths (StevenBlack `extensions/gambling/hosts` and friends) were
404 and are deliberately not here.

Licensing is the list publishers', not this project's -- the `note`
field says what each list's own header states, and it matters for a
small office: Phishing Army is CC BY-NC 4.0 (non-commercial).
"""

from __future__ import annotations

from dataclasses import dataclass

_STEVENBLACK = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates"


@dataclass(frozen=True)
class CategoryPreset:
    name: str
    title: str
    urls: tuple[str, ...]
    note: str


PRESETS: tuple[CategoryPreset, ...] = (
    CategoryPreset(
        "malware",
        "Malware distribution sites",
        ("https://urlhaus.abuse.ch/downloads/hostfile/",),
        "abuse.ch URLhaus host file; terms of use at urlhaus.abuse.ch/api/",
    ),
    CategoryPreset(
        "phishing",
        "Phishing",
        ("https://phishing.army/download/phishing_army_blocklist.txt",),
        "Phishing Army; CC BY-NC 4.0 -- non-commercial use only",
    ),
    CategoryPreset(
        "doh-bypass",
        "Public DNS-over-HTTPS resolvers",
        ("https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains.txt",),
        "stops browsers and apps from bypassing this resolver via DoH; dibdot/DoH-IP-blocklists",
    ),
    CategoryPreset("gambling", "Gambling", (f"{_STEVENBLACK}/gambling-only/hosts",), "StevenBlack/hosts extension"),
    CategoryPreset("adult", "Adult content", (f"{_STEVENBLACK}/porn-only/hosts",), "StevenBlack/hosts extension"),
    CategoryPreset("social", "Social networks", (f"{_STEVENBLACK}/social-only/hosts",), "StevenBlack/hosts extension"),
    CategoryPreset("fakenews", "Fake news", (f"{_STEVENBLACK}/fakenews-only/hosts",), "StevenBlack/hosts extension"),
)

PRESETS_BY_NAME = {p.name: p for p in PRESETS}

#: Categories whose blocked lookups are a *security* signal (a host
#: trying to reach known malware/phishing infrastructure), fed to the AI
#: IDS alongside XDP SNI-blocklist hits -- unlike, say, "social", where a
#: blocked lookup is policy, not compromise.
THREAT_CATEGORIES = frozenset({"malware", "phishing"})
