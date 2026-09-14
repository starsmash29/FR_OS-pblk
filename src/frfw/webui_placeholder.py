"""Placeholder entry point for fr-webui.service until phase 3 lands.

The systemd unit is installed now (see ROADMAP.md phase 2) so the boot
sequence and service dependencies can be wired up and tested ahead of the
actual FastAPI app; this just says so and exits cleanly.
"""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    print(
        "fr-webui: not implemented yet -- see ROADMAP.md phase 3. "
        "This is a placeholder so fr-webui.service can be installed and "
        "its dependencies (fr-apply-helper.socket) exercised ahead of time."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
