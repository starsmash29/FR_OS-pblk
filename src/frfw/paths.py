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

#: AI IDS engine's display-only recent-events log (phase 11, see
#: frfw.ai_ids.daemon.load_recent_events) -- the last several
#: flagged/quarantined IPs with their anomaly score/reasons, for the
#: webUI's AI IDS screen. Written directly by the unprivileged
#: `fr-ai-ids` daemon itself (its own decisions, not privileged data),
#: needs no root, so it lives alongside the webUI's other unprivileged
#: state rather than under root-owned /etc/fr_os directly. Never the
#: source of truth for "is this IP currently quarantined" -- that is
#: always a live kernel-state query via the privileged helper's
#: "ids_quarantine_status" command (frfw.ids_quarantine.list_quarantined),
#: the same "display file vs. live kernel query" split frfw.ztna's own
#: ZTNA_STATE_PATH documents.
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

#: Small display-only record of which username most recently authorized
#: each currently-authenticated ZTNA client IP (see frfw.ztna). Never the
#: source of truth for "is this IP still authorized" or "how much time is
#: left" -- that's always a live query against the kernel's own nftables
#: set (frfw.ztna.get_authorization), which is the only thing actually
#: enforcing anything. This file can only ever go stale in the cosmetic
#: direction (a name shown for an IP the kernel has already evicted, in
#: which case frfw.ztna simply doesn't return it), never in the
#: security-relevant one. Root-only, like XDP_STATE_PATH -- written by
#: fr-apply-helper, read back only by it (over the same socket that
#: wrote it), never by the unprivileged webUI process directly.
ZTNA_STATE_PATH = Path("/etc/fr_os/ztna_state.json")

#: OpenSSL config fragment the webUI's own process points `OPENSSL_CONF`
#: at (see systemd/fr-webui.service and frfw.pqc), regenerated by every
#: `apply` to match `config.pqc.enabled` and the host OpenSSL build's
#: actual ML-KEM support. Not secret (it only ever names TLS group
#: algorithms), so -- like XDP_STATE_PATH/ZTNA_STATE_PATH -- it is
#: written with plain default permissions rather than the root:fr_os-webui
#: 0640 pattern reserved for files that hold credentials.
PQC_OPENSSL_CONF_PATH = Path("/etc/fr_os/webui_pqc_openssl.cnf")

#: sshd_config.d drop-in frfw.pqc writes/removes to control the PQC
#: hybrid SSH KexAlgorithms line, exploiting Debian's own default
#: `Include /etc/ssh/sshd_config.d/*.conf` in /etc/ssh/sshd_config
#: (present since the openssh 8.4p1 packaging) rather than editing that
#: file directly. Lives under OpenSSH's own config tree, not
#: /etc/fr_os -- it is sshd's file, not frfw's own state.
SSHD_PQC_DROPIN_PATH = Path("/etc/ssh/sshd_config.d/50-fr_os-pqc-kex.conf")

#: Deduped, hosts-format ad/tracker blocklist (phase 9, see
#: frfw.adblock) -- `0.0.0.0 <domain>` per line, one entry per unique
#: domain across every configured `adblocker.source_urls` list. This is
#: frfw's own generated artifact (like XDP_STATE_PATH/ZTNA_STATE_PATH),
#: not the resolver's config -- it lives under /etc/fr_os for that
#: reason, even though only the dnsmasq instance below actually reads
#: it. Not secret (it's public blocklist data), so -- like the other
#: state files under this directory -- written with plain default
#: permissions, not the root:fr_os-webui 0640 pattern reserved for
#: config.yaml.
ADBLOCK_HOSTS_PATH = Path("/etc/fr_os/adblock.hosts")

#: Per-category blocklists (phase 15, `adblocker.categories`): one
#: `<category>.hosts` file each, same format and same "frfw's own
#: generated artifact" status as ADBLOCK_HOSTS_PATH. Kept as separate
#: files, not merged, so the dedicated dnsmasq instance's query log names
#: the file (and therefore the category) that blocked each lookup.
ADBLOCK_CATEGORY_DIR = Path("/etc/fr_os/adblock.d")

#: Complete, self-contained dnsmasq config frfw generates and owns --
#: intentionally NOT a drop-in under Debian's /etc/dnsmasq.d/, since
#: that directory is only auto-included if a `conf-dir=` line is
#: uncommented in /etc/dnsmasq.conf, which is not guaranteed on a stock
#: install. frfw instead runs its own dedicated dnsmasq instance
#: (fr-adblock-dns.service) entirely from this file, the same
#: "one complete generated config, one dedicated service" pattern Kea
#: already uses (frfw.kea.KEA_CONFIG_PATH / KEA_SERVICE_NAME) -- it
#: never touches the system's own dnsmasq.service/dnsmasq.conf, if
#: either happens to also be installed for something unrelated.
ADBLOCK_DNSMASQ_CONF_PATH = Path("/etc/fr_os/dnsmasq_adblock.conf")

#: systemd unit name for frfw's dedicated dnsmasq instance (see above).
ADBLOCK_DNS_SERVICE_NAME = "fr-adblock-dns"

#: IoT device inventory (phase 14, see frfw.iot.scanner): the last
#: scan's discovered devices, their classification and the reasons for
#: it. Display-only state written by the unprivileged scanner (running
#: as fr_os-webui, like AI_IDS_STATE_PATH) and read back by the webUI and
#: the metrics exporter -- the enforcement state itself lives in the
#: kernel's nftables set, never here.
IOT_INVENTORY_PATH = WEBUI_STATE_DIR / "iot_inventory.json"
