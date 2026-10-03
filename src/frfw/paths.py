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

#: The unprivileged accounts (created by frfw.accounts). The webUI runs as
#: WEBUI_USER; the daemons that parse untrusted network input (AI IDS,
#: App-ID, IoT scan, TLS fingerprinting) run as SENSOR_USER, so a bug in a
#: parser reaches neither the webUI's secrets nor anything but the few
#: helper commands frfw.helper.peer.SENSOR_COMMANDS allows.
WEBUI_USER = "fr_os-webui"
SENSOR_USER = "fr_os-sensor"
#: Who may log in over SSH (sshd AllowGroups, security-lessons F3).
SSH_GROUP = "fr_os-ssh"

#: The parser daemons' display-only output (AI IDS events, IoT inventory,
#: App-ID usage, TLS fingerprints): fr_os-sensor:fr_os-webui 0750, written
#: by the daemons, read by the webUI and the metrics exporter. Separate
#: from WEBUI_STATE_DIR, which holds the webUI's session secret, TLS key
#: and accounts and is private to fr_os-webui (0700).
SENSOR_STATE_DIR = Path("/etc/fr_os/sensors")

#: The webUI's own state: self-signed TLS keypair (generated on first run
#: if missing, see frfw.webui.tls), the local admin account
#: (frfw.admin_account) and the session-signing secret key
#: (frfw.webui.auth). Kept in one directory, private to the unprivileged
#: fr_os-webui user (0700), distinct from /etc/fr_os/config.yaml
#: itself (root-owned, written only through the apply-helper) -- so the
#: systemd unit can grant exactly one ReadWritePaths= for all of it.
WEBUI_STATE_DIR = Path("/etc/fr_os/webui")
WEBUI_CERT_PATH = WEBUI_STATE_DIR / "cert.pem"
WEBUI_KEY_PATH = WEBUI_STATE_DIR / "key.pem"
WEBUI_AUTH_PATH = WEBUI_STATE_DIR / "auth.json"
WEBUI_SECRET_KEY_PATH = WEBUI_STATE_DIR / "secret.key"
#: Failed-login counters and each account's known sign-in sources,
#: persisted so a webUI restart doesn't reset them (security-lessons G6).
LOGIN_GUARD_STATE_PATH = WEBUI_STATE_DIR / "login_guard.json"

#: AI IDS engine's display-only recent-events log (phase 11, see
#: frfw.ai_ids.daemon.load_recent_events) -- the last several
#: flagged/quarantined IPs with their anomaly score/reasons, for the
#: webUI's AI IDS screen. Written directly by the unprivileged
#: `fr-ai-ids` daemon itself (its own decisions, not privileged data),
#: needs no root, so it lives in SENSOR_STATE_DIR rather than under
#: root-owned /etc/fr_os directly. Never the
#: source of truth for "is this IP currently quarantined" -- that is
#: always a live kernel-state query via the privileged helper's
#: "ids_quarantine_status" command (frfw.ids_quarantine.list_quarantined),
#: the same "display file vs. live kernel query" split frfw.ztna's own
#: ZTNA_STATE_PATH documents.
AI_IDS_STATE_PATH = SENSOR_STATE_DIR / "ai_ids_state.json"

#: Update mechanism's (phase 6, see frfw.update) persisted apply/rollback
#: history -- installed/previous version, last update's outcome. Written
#: only by the privileged fr-update-helper (then chowned to the webUI
#: user so it can read it), analogous to config.yaml's own
#: root:fr_os-webui, 0640 pattern. Version *checking* itself needs no
#: persisted state or privilege at all -- see frfw.update.check_latest,
#: called fresh on every webUI page load, same as the AI IDS screen's
#: live-computed progress.
UPDATE_STATE_PATH = Path("/etc/fr_os/update_state.json")

#: The last periodic update check (fr-update-check.timer, security-lessons
#: G10/J3), read by the webUI for the "update available" banner.
UPDATE_CHECK_PATH = Path("/etc/fr_os/update_check.json")

#: The WireGuard VPN's private key (security-lessons G8): root only,
#: never in config.yaml. frfw.wireguard generates it on first use.
WIREGUARD_DIR = Path("/etc/fr_os/wireguard")
WIREGUARD_KEY_PATH = WIREGUARD_DIR / "private.key"

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

#: Which interfaces frfw.xdp attached the SNI filter to -- only a list of
#: devices to look at. Whether the filter is attached *now* always comes
#: from the kernel (frfw.xdp.live_attachment, `ip -j link`): attachments
#: don't survive a reboot, this file does, and trusting it left the
#: filter off after every reboot while the UI said "attached" (review
#: triage B1).
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

#: sshd drop-in with the management listen addresses (frfw.management;
#: security-lessons F2). sshd uses the first value it reads for most
#: options, and reads sshd_config.d/*.conf in order.
SSHD_MANAGEMENT_DROPIN_PATH = Path("/etc/ssh/sshd_config.d/40-fr_os-management.conf")

#: sshd's privilege-separation directory: `sshd -t` refuses to run
#: without it, and only a running ssh.service creates it
#: (RuntimeDirectory=sshd). SSH is off while nobody can log in
#: (frfw.management.sync_sshd), so checks must cope with it missing.
SSHD_PRIVSEP_DIR = Path("/run/sshd")

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
#: as fr_os-sensor, like AI_IDS_STATE_PATH) and read back by the webUI and
#: the metrics exporter -- the enforcement state itself lives in the
#: kernel's nftables set, never here.
IOT_INVENTORY_PATH = SENSOR_STATE_DIR / "iot_inventory.json"

#: The XDP SNI filter's events, one JSON line each (frfw.xdp.format_event_json),
#: for the readers that used to follow fr-xdp-sni-logger's journal: the
#: webUI's live log, fr-ai-ids and fr-appid (ROADMAP SEC-4, review v0.2.0
#: R10). Created by the logger while it is still root, root:fr_os-webui
#: 0640 in a root:fr_os-webui 0750 directory (systemd's LogsDirectory=):
#: the readers -- the fr_os-webui user, and fr_os-sensor through that
#: group -- can read it, only the logger's open file can write it, so no
#: reader can forge an event another one acts on. Capped in size by the
#: logger (frfw.xdp.EventFile), which empties it when it gets too big.
SNI_EVENTS_DIR = Path("/var/log/fr_os-sni")
SNI_EVENTS_PATH = SNI_EVENTS_DIR / "events.jsonl"

#: The resolver's query log (with adblocker.query_logging), for fr-ai-ids
#: and fr-appid instead of fr-adblock-dns's journal (ROADMAP SEC-4).
#: dnsmasq opens it as root under the unit's Group=fr_os-webui and hands
#: it to its own unprivileged user: nobody:fr_os-webui 0640 in a
#: root:fr_os-webui 0750 directory. dnsmasq writes it, the readers can
#: only read it. fr-dns-log-trim.timer keeps it under
#: frfw.adblock.dns_service.QUERY_LOG_MAX_BYTES.
DNS_QUERY_LOG_DIR = Path("/var/log/fr_os-dns")
DNS_QUERY_LOG_PATH = DNS_QUERY_LOG_DIR / "queries.log"

#: App identification usage summary (phase 16, see frfw.appid.daemon):
#: which apps each client used recently, written by the unprivileged
#: fr-appid daemon and read by the webUI and the metrics exporter.
#: Display-only, like IOT_INVENTORY_PATH -- blocking an app is enforced
#: by the resolver and (optionally) the XDP blocklist, never from here.
APPID_USAGE_PATH = SENSOR_STATE_DIR / "appid_usage.json"

#: Time-based rules (phase 17, see frfw.schedule_refresh): the UTC offset
#: and kernel time zone the currently loaded ruleset's scheduled rules
#: were rendered for, plus a fingerprint of the config applied, so the
#: hourly check can tell a DST change from an unapplied config edit.
#: Root-only, written by apply.
SCHEDULE_STATE_PATH = Path("/etc/fr_os/schedule_state.json")

#: When each firewall rule last matched (security-lessons K2,
#: frfw.rule_hits), kept by fr-schedule-check.timer, read by the webUI.
RULE_HITS_PATH = Path("/etc/fr_os/rule_hits.json")

#: WebUI audit log (phase 18, see frfw.webui.audit): one JSON line per
#: change request and login -- who, when, from where, which endpoint, and
#: the HTTP status. Never form contents. Written by the unprivileged
#: webUI, size-capped with one rotated generation.
WEBUI_AUDIT_LOG_PATH = WEBUI_STATE_DIR / "audit.log"

#: The audit log since security-lessons G9/E6: root's, not the webUI's.
#: The webUI can read it (group fr_os-webui) but only *add* to it, through
#: the apply-helper -- a compromised webUI can't erase its tracks.
AUDIT_LOG_DIR = Path("/var/log/fr_os")
AUDIT_LOG_PATH = AUDIT_LOG_DIR / "audit.log"

#: Per admin: the time up to which they have seen the security alerts.
ALERTS_SEEN_PATH = WEBUI_STATE_DIR / "alerts_seen.json"

#: TLS client fingerprint inventory (phase 19, see frfw.tlsfp.daemon):
#: which JA4/JA3 fingerprints each client presented, and recent events
#: (new fingerprints, blocklist matches). Written by fr-tls-fp after it
#: has dropped to the fr_os-sensor account; display-only.
TLSFP_STATE_PATH = SENSOR_STATE_DIR / "tls_fingerprints.json"
