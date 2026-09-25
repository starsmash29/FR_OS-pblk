#!/usr/bin/env python3
"""Rebuild src/frfw/webui/static/icons.svg, the webUI's icon sprite.

The icons are Google's Material Symbols (Outlined, weight 400; Apache-2.0,
see static/LICENSE-MaterialSymbols.txt), the set the Stitch designs use.
Only the icons listed below are included, so the router serves one small
file instead of a multi-megabyte icon font from the internet.

Usage:
    npm pack @material-symbols/svg-400 && tar xzf material-symbols-svg-400-*.tgz
    scripts/build-webui-icons.py package/outlined

Templates use an icon as
    <svg class="icon"><use href="/static/icons.svg#dashboard"/></svg>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ICONS = [
    # navigation (as in the Stitch sidebar)
    "dashboard", "settings_ethernet", "security", "alt_route", "dynamic_form",
    "psychology", "filter_alt", "block", "devices", "apps", "fingerprint",
    "vpn_lock", "system_update_alt", "tune", "group",
    # header and account
    "shield", "person", "logout", "menu", "lock", "key", "visibility",
    # states and actions
    "check_circle", "warning", "error", "info", "bolt", "play_arrow",
    "science", "undo", "restart_alt", "schedule", "lan", "router", "dns",
    "memory", "hub", "timer", "monitoring", "shield_lock", "verified_user",
    "download", "search", "add", "delete", "edit", "close",
]

OUT = Path(__file__).resolve().parent.parent / "src/frfw/webui/static/icons.svg"


def main(source_dir: str) -> int:
    source = Path(source_dir)
    symbols = []
    for name in ICONS:
        svg = (source / f"{name}.svg").read_text()
        viewbox = re.search(r'viewBox="([^"]+)"', svg).group(1)
        body = re.search(r"<svg[^>]*>(.*)</svg>", svg, re.S).group(1).strip()
        symbols.append(f'<symbol id="{name}" viewBox="{viewbox}">{body}</symbol>')
    OUT.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg">\n'
        "<!-- Material Symbols Outlined (Apache-2.0), built by scripts/build-webui-icons.py -->\n"
        + "\n".join(symbols) + "\n</svg>\n"
    )
    print(f"{OUT}: {len(symbols)} icons, {OUT.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
