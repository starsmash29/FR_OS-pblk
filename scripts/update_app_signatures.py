#!/usr/bin/env python3
"""Regenerate src/frfw/appid/signatures.json from v2fly/domain-list-community.

Phase 16's app identification maps a DNS name or TLS SNI to an app by
domain suffix. Rather than hand-maintaining those domain lists, they come
from https://github.com/v2fly/domain-list-community (MIT licensed), which
keeps one list per service. This script is run by a developer, never on
the router: the router only ever reads the bundled JSON.

    python3 scripts/update_app_signatures.py [--ref <commit>]

Without --ref it resolves the current master commit with `git ls-remote`
and downloads every list at that exact commit, so the recorded `ref` in
the output always identifies the data it was built from.

What is taken from a list (see the v2fly README for the format):

- plain / `domain:` entries -> suffix match (the name and its subdomains)
- `full:` entries -> exact name only
- `include:<list>` -> followed only when named in the app's `includes`
  below; many lists include loosely related brands (Disney's includes
  ESPN, Hulu, ABC...) that would misattribute traffic
- `keyword:` / `regexp:` entries are skipped (not expressible as a suffix
  lookup), as are entries tagged `@ads` (ad/analytics hosts belong to the
  ad blocker, and would inflate an app's usage)

A name listed by more than one app is kept only for the first app in
APPS order, so specific apps (Messenger, Instagram) are listed before
the umbrella list that also claims their domains (Facebook).
"""

from __future__ import annotations

import argparse
import datetime
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO_URL = "https://github.com/v2fly/domain-list-community"
RAW_URL = "https://raw.githubusercontent.com/v2fly/domain-list-community/{ref}/data/{name}"
OUTPUT = Path(__file__).resolve().parents[1] / "src" / "frfw" / "appid" / "signatures.json"

# (id, display name, category, v2fly list, includes to follow)
APPS: list[tuple[str, str, str, str, tuple[str, ...]]] = [
    # Messaging first: their domains also appear in the Facebook list.
    ("messenger", "Messenger", "messaging", "messenger", ()),
    ("whatsapp", "WhatsApp", "messaging", "whatsapp", ()),
    ("telegram", "Telegram", "messaging", "telegram", ()),
    ("signal", "Signal", "messaging", "signal", ()),
    ("discord", "Discord", "messaging", "discord", ()),
    ("instagram", "Instagram", "social", "instagram", ()),
    ("threads", "Threads", "social", "threads", ()),
    ("facebook", "Facebook", "social", "facebook", ()),
    ("tiktok", "TikTok", "social", "tiktok", ()),
    ("twitter", "X (Twitter)", "social", "twitter", ()),
    ("reddit", "Reddit", "social", "reddit", ()),
    ("snapchat", "Snapchat", "social", "snap", ()),
    ("pinterest", "Pinterest", "social", "pinterest", ()),
    ("linkedin", "LinkedIn", "social", "linkedin", ()),
    ("netflix", "Netflix", "streaming", "netflix", ()),
    ("youtube", "YouTube", "streaming", "youtube", ()),
    ("disney-plus", "Disney+", "streaming", "disney", ("bamtech",)),
    ("prime-video", "Prime Video", "streaming", "primevideo", ()),
    ("hbo-max", "HBO Max", "streaming", "hbo", ()),
    ("apple-tv-plus", "Apple TV+", "streaming", "apple-tvplus", ()),
    ("dazn", "DAZN", "streaming", "dazn", ()),
    ("vimeo", "Vimeo", "streaming", "vimeo", ()),
    ("twitch", "Twitch", "streaming", "twitch", ()),
    ("spotify", "Spotify", "music", "spotify", ()),
    ("deezer", "Deezer", "music", "deezer", ()),
    ("steam", "Steam", "gaming", "steam", ()),
    ("epic-games", "Epic Games", "gaming", "epicgames", ()),
    ("roblox", "Roblox", "gaming", "roblox", ()),
    ("xbox", "Xbox", "gaming", "xbox", ()),
    ("playstation", "PlayStation", "gaming", "playstation", ()),
    ("nintendo", "Nintendo", "gaming", "nintendo", ()),
    ("riot-games", "Riot Games", "gaming", "riot", ()),
    ("ea", "EA", "gaming", "ea", ("origin",)),
    ("blizzard", "Blizzard", "gaming", "blizzard", ()),
    ("zoom", "Zoom", "conferencing", "zoom", ()),
    ("webex", "Webex", "conferencing", "webex", ()),
    ("teamviewer", "TeamViewer", "remote-access", "teamviewer", ()),
    ("dropbox", "Dropbox", "storage", "dropbox", ()),
    ("onedrive", "OneDrive", "storage", "onedrive", ()),
    ("icloud", "iCloud", "storage", "icloud", ()),
    ("openai", "ChatGPT / OpenAI", "ai", "openai", ()),
]


def resolve_ref() -> str:
    out = subprocess.run(
        ["git", "ls-remote", REPO_URL, "refs/heads/master"],
        capture_output=True, text=True, check=True, timeout=60,
    ).stdout.split()
    if not out:
        raise SystemExit("git ls-remote returned nothing")
    return out[0]


def fetch(ref: str, name: str) -> str:
    with urllib.request.urlopen(RAW_URL.format(ref=ref, name=name), timeout=30) as resp:
        return resp.read().decode("utf-8")


def parse_list(text: str) -> tuple[set[str], set[str], list[str], int]:
    """(suffix domains, exact names, include targets, skipped entry count)."""
    suffixes: set[str] = set()
    exact: set[str] = set()
    includes: list[str] = []
    skipped = 0
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        entry, *attrs = line.split()
        if "@ads" in attrs:
            skipped += 1
            continue
        kind, _, value = entry.partition(":") if ":" in entry else ("domain", "", entry)
        value = value.lower().rstrip(".")
        if kind == "domain":
            suffixes.add(value)
        elif kind == "full":
            exact.add(value)
        elif kind == "include":
            includes.append(value)
        else:  # keyword, regexp
            skipped += 1
    return suffixes, exact, includes, skipped


def build(ref: str) -> dict:
    claimed: dict[str, str] = {}
    apps = []
    for app_id, name, category, list_name, follow in APPS:
        suffixes, exact, includes, skipped = parse_list(fetch(ref, list_name))
        for inc in includes:
            if inc in follow:
                s, e, _nested, sk = parse_list(fetch(ref, inc))
                suffixes |= s
                exact |= e
                skipped += sk
            else:
                print(f"  {app_id}: not following include:{inc}", file=sys.stderr)
        # An exact name already covered by one of the app's own suffixes is redundant.
        exact = {n for n in exact if not any(n == s or n.endswith("." + s) for s in suffixes)}
        kept_suffixes, kept_exact = [], []
        for bucket, kept in ((suffixes, kept_suffixes), (exact, kept_exact)):
            for domain in sorted(bucket):
                owner = claimed.get(domain)
                if owner is not None:
                    print(f"  {app_id}: {domain} already claimed by {owner}", file=sys.stderr)
                    continue
                claimed[domain] = app_id
                kept.append(domain)
        print(f"{app_id}: {len(kept_suffixes)} domains, {len(kept_exact)} exact, {skipped} skipped",
              file=sys.stderr)
        apps.append({
            "id": app_id, "name": name, "category": category,
            "domains": kept_suffixes, "exact": kept_exact,
        })
    return {
        "source": REPO_URL,
        "license": "MIT",
        "ref": ref,
        "generated": datetime.date.today().isoformat(),
        "apps": apps,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--ref", help="v2fly commit to build from (default: current master)")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    ref = args.ref or resolve_ref()
    data = build(ref)
    args.output.write_text(json.dumps(data, indent=1) + "\n")
    total = sum(len(a["domains"]) + len(a["exact"]) for a in data["apps"])
    print(f"wrote {args.output} ({len(data['apps'])} apps, {total} names, ref {ref})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
