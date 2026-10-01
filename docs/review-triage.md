# Review triage – MiMo + Big Pickle (2026-09-27)

Consolidates the two independent reviews of `main` @ `076502e`:

- [review-mimo.md](review-mimo.md) – full repository, 48 findings (C1, H1–H7, M1–M18, L1–L22)
- [review-bigpickle-1-webui.md](review-bigpickle-1-webui.md) – webUI and helpers, 15 findings (BP1–BP15)

**Verified** = the finding was re-checked against the source by reading the
cited code (not just the review text). **Reported** = plausible, cited
precisely, not independently re-checked yet. **Needs verification** = cannot
be settled from the repository (needs a built image or a running box).

Where the two reviewers rated the same issue differently, the final severity
below is ours, with the reason given.

## Batch A – before any public release (P0)

| ID | Final sev | Finding | Status | Sources |
|---|---|---|---|---|
| A1 | high | Both root helper sockets are `0660 root:fr_os-webui`; `fr-ai-ids`, `fr-appid`, `fr-iot-scan` (network-input parsers) run as the same user; no `SO_PEERCRED` check → one bug in a parser = root | Verified (`systemd/fr-*-helper.socket:7-9`, `User=fr_os-webui` in those units, no peercred in `helper/`) | MiMo H7, BP1 |
| A2 | high | Firewall fails open: `ConditionPathExists=/etc/fr_os/config.yaml` skips the unit without a config; `apply_all` syncs addresses before nft, so a bad interface name aborts before any ruleset; `ExecStop=nft flush ruleset` empties the firewall on stop/restart | Verified (`fr-firewall.service:8,21,23`, `provision.py:87`) | MiMo H2, M2 |
| A3 | high | Unauthenticated first-run admin creation on `0.0.0.0:443`, not rate-limited, whenever `auth.json` is missing. Not reachable on a normal ISO first boot (password is generated before `fr-webui` starts), hence high rather than critical; reachable on manual installs or if `auth.json` is lost after first boot | Verified (`webui/routes/auth.py:52-65`, `webui/server.py:51`, `fr-first-boot.sh` order) | MiMo C1 (critical), BP11 (low) |
| A4 | high | Updates are installed as root with no signature/checksum verification | Verified (`update.py` module docstring states it) | MiMo H5, BP10 |
| A5 | medium | Admin password stays in world-readable `/etc/issue` forever | Verified (`fr-first-boot.sh:64-77`) | MiMo H1 (high), BP6 |
| A6 | medium | `save_config` → `_write_atomic` writes with the default umask: `config.yaml` becomes 0644 root:root (ZTNA password hashes, metrics token digest become world-readable) | Verified (`helper/server.py:299-303`; `cli.py:484-489` does it right) | MiMo H3 (high), BP3 |

Severity note for A5/A6: both need local read access on the router; on a
single-admin appliance that is rare, so medium. Still cheap to fix – do it
in this batch.

## Batch B – correctness of security controls (P1, before v0.2)

| ID | Final sev | Finding | Status | Sources |
|---|---|---|---|---|
| B1 | high | XDP SNI filter never re-attaches after reboot: `xdp_state.json` persists, kernel attachments don't, and `apply` skips any device listed in the state file; the UI shows "attached" from the same file | Verified (`xdp.py:565-567`) | MiMo H4 |
| B2 | medium | SNI filter only parses untagged IPv4 (`ETH_P_IP`), so 802.1Q-tagged frames pass unfiltered; only TCP/443 | Verified (`bpf/xdp_sni_filter.c:826,843`) | BP2 (high) |
| B3 | medium | SNI blocklist bypasses: case / trailing dot, names ≥32 bytes, split ClientHello | Reported | MiMo M1, BP9 |
| B4 | medium | First-boot WAN/LAN assignment is alphabetical (first two NICs), LAN can land on the WAN port | Verified (`netdetect.py:50`, `fr-first-boot.sh`) – also ROADMAP SEC-8 | MiMo M4 |
| B5 | medium | No ordering/masking against Debian's `nftables.service` | Needs verification | MiMo M3 |
| B6 | medium | XDP: partial apply leaves attachments unrecorded, logger loses events after disable/enable, stale pinned program reused after upgrade, root compiles BPF from a PATH-resolved clang | Reported | MiMo M11–M14 |
| B7 | medium | nft backups: non-atomic, name collisions, rollback without `nft -c`; rollback restores only the ruleset, not config.yaml | Reported | MiMo M10, BP14 |

## Batch C – update pipeline (P1)

| ID | Final sev | Finding | Status | Sources |
|---|---|---|---|---|
| C1 | high | A failed `_install_and_activate` leaves a half-applied system and records no `previous_version`, so rollback refuses | Verified (`update.py:449-461`) | MiMo H6 |
| C2 | medium | `rollback_update` doesn't validate `previous_version` (path traversal into `rmtree` / `pip install` as root if the state file is tampered with; the state file is root-owned, so needs root-level write first) | Reported | MiMo M6 |
| C3 | medium | The repo shown in the UI (`config.update.repo`) is not the repo the root installer uses | Reported | MiMo M7, BP5 |
| C4 | medium | No locking between update and apply; no post-update health check / auto-rollback; tar extraction without `filter="data"` fallback; no downgrade protection; unbounded downloads | Reported | MiMo M5, M8, M9, L7, L8 |

## Batch D – installer and image

| ID | Final sev | Finding | Status | Sources |
|---|---|---|---|---|
| D1 | medium | SSH host keys may be baked into the image (same keys on every install) | Needs verification: `unsquashfs -l` the built ISO and look for `etc/ssh/ssh_host_*` | MiMo M15 |
| D2 | low | No bootloader password (kernel cmdline edit = root shell). Physical access is usually game over on an appliance anyway; document it, offer an option | Verified (no `superusers`/password in `grub.cfg` / isolinux) | MiMo M16 (medium) |
| D3 | medium | systemd hardening gaps on root units, `/run/fr_os` 0755, no `UMask=` | Reported | MiMo M17 |
| D4 | low | Re-running first boot clobbers config and password; persistence partition auto-created without confirmation | Reported | MiMo L20 |

## Batch E – webUI hardening and quality (P2)

| ID | Final sev | Finding | Status | Sources |
|---|---|---|---|---|
| E1 | medium | No CI job runs the test suite | Reported | MiMo M18 |
| E2 | low | No CSRF token (SameSite=Lax only), no security headers | Reported | MiMo L1, L3, BP4 |
| E3 | low | `/metrics` unauthenticated by default | Reported | MiMo L2, BP7 |
| E4 | low | Unbounded `journalctl -f` per SSE client, reachable by viewers | Reported | MiMo L14, BP8 (medium) |
| E5 | low | Session/password: logout is client-side only, 8-char length-only policy, PBKDF2 200k, in-memory brute-force counters, session secret temp file | Reported | MiMo L4–L6, BP12, BP13 |
| E6 | low | Audit log writable by the audited identity; ZTNA grants not audited | Reported | MiMo L21, BP15 |
| E7 | low | Remaining code-quality items | Reported | MiMo L9–L13, L15–L19, L22 |

## Agreement between the reviewers

Most Big Pickle findings also appear in MiMo's report. Found only by Big
Pickle: B2 (VLAN blindness), BP12 (in-memory brute-force counters), BP13
(session secret temp file), BP14 (rollback restores only the ruleset) and
the "ZTNA grants not audited" half of BP15. The two disagreed
mainly on severity: first-run account creation (critical vs low) and the
update signature (high vs low). The table above settles both.

## Suggested order of work

1. Batch A as one PR, one commit per item, each with a regression test.
2. B1 + C1 (the two verified high-severity correctness bugs).
3. D1 check on a built ISO.
4. The rest of B and C, then D and E.
