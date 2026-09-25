"""frfw: FR_OS firewall config engine.

Single source of truth for turning a declarative YAML configuration into an
nftables ruleset. Used by the CLI (phase 1), the systemd integration
(phase 2) and the webUI (phase 3).
"""

import re

__version__ = "0.1.0"

#: Release codenames (see ROADMAP.md, "Release cycle & codenames"). The
#: v0.1.0 - v1.0.0 range is Ice Breaker, 1.0.0 included; every later 1.x
#: release is Idun; each following major version has its own name.
_CODENAMES_BY_MAJOR = {0: "Ice Breaker", 1: "Idun", 2: "Ivar", 3: "Inari", 4: "Ingemar"}
_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def codename_for(version: str) -> str | None:
    """The codename of a release version ("0.1.0", "v1.2.3"), or None for
    an unparsable version or a major version without a name yet."""
    match = _VERSION_RE.match(version.strip())
    if match is None:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    if (major, minor, patch) == (1, 0, 0):
        return _CODENAMES_BY_MAJOR[0]
    return _CODENAMES_BY_MAJOR.get(major)


__codename__ = codename_for(__version__)
