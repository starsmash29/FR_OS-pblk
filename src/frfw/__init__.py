"""frfw: FR_OS firewall config engine.

Single source of truth for turning a declarative YAML configuration into an
nftables ruleset. Used by the CLI (phase 1), the systemd integration
(phase 2) and the webUI (phase 3).
"""

__version__ = "0.1.0"
