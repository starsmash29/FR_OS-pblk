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

#: Mock AI IDS engine's persisted per-device state (locked/retrain
#: timestamps -- see frfw.ai_ids). Needs no root, so it lives alongside
#: the webUI's other unprivileged state rather than under root-owned
#: /etc/fr_os directly.
AI_IDS_STATE_PATH = WEBUI_STATE_DIR / "ai_ids_state.json"

#: Update mechanism's (phase 6, see frfw.update) persisted apply/rollback
#: history -- installed/previous version, last update's outcome. Written
#: only by the privileged fr-update-helper (then chowned to the webUI
#: user so it can read it), analogous to config.yaml's own
#: root:fr_os-webui, 0640 pattern. Version *checking* itself needs no
#: persisted state or privilege at all -- see frfw.update.check_latest,
#: called fresh on every webUI page load, same as the AI IDS screen's
#: live-computed progress.
UPDATE_STATE_PATH = Path("/etc/fr_os/update_state.json")

#: Extracted release source trees, one directory per installed version,
#: kept around after each successful update so a rollback can reinstall
#: the previous version without needing network access again.
RELEASES_DIR = Path("/opt/fr_os/releases")

#: Unix socket for the privileged update-helper (frfw.helper.update_server)
#: -- deliberately separate from APPLY_SOCKET_PATH/the firewall
#: apply-helper: installing packages and restarting services is a much
#: broader privilege surface than that daemon's narrow "touch only
#: CONFIG_PATH/BACKUP_DIR" scope (see frfw.helper.protocol), so it gets
#: its own small, single-purpose daemon instead of widening that one.
UPDATE_SOCKET_PATH = RUNTIME_DIR / "update.sock"

#: Compiled XDP TLS SNI filter object (phase 4, see frfw.xdp and
#: bpf/xdp_sni_filter.c). Shipped precompiled by the live-build image
#: (installer/live-build) rather than compiled on first boot -- a router
#: appliance image has no business assuming clang/llvm are installed --
#: but frfw.xdp.ensure_compiled() will compile it here itself (requires
#: clang) if it's missing, which is what this sandbox's own manual
#: testing used, and is a reasonable fallback for a from-source install.
XDP_BPF_OBJ_PATH = Path("/usr/local/share/fr_os/bpf/xdp_sni_filter.o")

#: Persisted "which interfaces currently have the XDP program attached,
#: in which mode" state, so frfw.xdp can detach cleanly from exactly the
#: interfaces/modes it (or the last process that ran it) actually
#: attached to, and so the webUI can show live attach-mode status without
#: re-probing every interface via `ip link` on every page load.
XDP_STATE_PATH = Path("/etc/fr_os/xdp_state.json")
