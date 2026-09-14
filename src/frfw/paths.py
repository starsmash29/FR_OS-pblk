"""Canonical filesystem locations used by frfw once installed on a router.

Centralized here so the CLI, the systemd units and the privileged helper
all agree on where things live without repeating string literals.
"""

from __future__ import annotations

from pathlib import Path

#: Source-of-truth config file, written by the webUI (phase 3) or by hand.
CONFIG_PATH = Path("/etc/fr_os/config.yaml")

#: Timestamped snapshots of previously-applied nftables rulesets, taken
#: before each real (non-dry-run) apply, so a bad config can be rolled back.
BACKUP_DIR = Path("/etc/fr_os/backups")

#: How many ruleset backups to retain; older ones are pruned on apply.
BACKUP_RETENTION = 10

#: Runtime directory (tmpfs, matches a systemd RuntimeDirectory= entry) for
#: the privileged apply-helper's Unix socket.
RUNTIME_DIR = Path("/run/fr_os")

#: Unix socket the unprivileged webUI (phase 3) connects to in order to
#: ask the root-run apply-helper to apply/rollback the firewall config.
APPLY_SOCKET_PATH = RUNTIME_DIR / "apply.sock"

#: The webUI's own state: self-signed TLS keypair (generated on first run
#: if missing, see frfw.webui.tls), the local admin account
#: (frfw.admin_account) and the session-signing secret key
#: (frfw.webui.auth). Kept in one directory, owned and read/write for the
#: unprivileged fr_os-webui user/group, distinct from /etc/fr_os/config.yaml
#: itself (root-owned, written only through the apply-helper) -- so the
#: systemd unit can grant exactly one ReadWritePaths= for all of it.
WEBUI_STATE_DIR = Path("/etc/fr_os/webui")
WEBUI_CERT_PATH = WEBUI_STATE_DIR / "cert.pem"
WEBUI_KEY_PATH = WEBUI_STATE_DIR / "key.pem"
WEBUI_AUTH_PATH = WEBUI_STATE_DIR / "auth.json"
WEBUI_SECRET_KEY_PATH = WEBUI_STATE_DIR / "secret.key"
