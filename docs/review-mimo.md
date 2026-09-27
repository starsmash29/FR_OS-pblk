# FR_OS — independent security & correctness review

Scope: full repository (Python/FastAPI webUI, nftables generator, privileged Unix-socket
helpers, XDP/eBPF, live-build installer, systemd units, update mechanism).
Method: every finding below is grounded in the **actual source files**, not the docs
(`ARCHITECTURE.md`/`README.md` were read only for claims worth checking against code).
Nothing in the repository was modified.

Conventions used in this document:

* **Severity**: `critical` (unauthenticated remote compromise of the device/its security
  function), `high` (significant security impact with a realistic precondition),
  `medium` (defence-in-depth gap, local-only, availability, or misleading security
  state), `low` (hardening / code quality / missing tests).
* **"needs verification"** is used exactly where the repo alone cannot settle the
  question (image build outputs, runtime distro versions, kernel/dist defaults).

---

## Summary table

| # | Sev | Area | Finding | Location |
|---|-----|------|---------|----------|
| C1 | critical | webUI | Unauthenticated first-run admin account creation on `0.0.0.0:443`, not rate-limited, window can stay open indefinitely | `webui/routes/auth.py:52-65`, `webui/server.py:51` |
| H1 | high | installer | Generated admin password written to `/etc/issue` (0644) and printed on every console incl. serial, forever | `scripts/fr-first-boot.sh:64,70-77` |
| H2 | high | firewall | No fail-closed baseline: no nftables ruleset at all when `config.yaml` is missing or when `apply` fails at the address step | `systemd/fr-firewall.service:8,21`, `provision.py:87-96` |
| H3 | high | helpers | `save_config` rewrites `config.yaml` with default umask → 0644 root:root (credential hashes world-readable) | `helper/server.py:299-303` |
| H4 | high | XDP | Filter is never re-attached after reboot (stale state file suppresses attach) while the UI reports it attached | `xdp.py:565-567,484-496` |
| H5 | high | update | Updates have **no** authenticity verification (no signature/checksum) yet run `pip install` as root and rewrite systemd units | `update.py:282-290,348-375` |
| H6 | high | update | Failed update records no `previous_version` → rollback refuses; half-applied state | `update.py:449-461`, `update.py:492-494` |
| H7 | high | helpers | Both root sockets are `0660 root:fr_os-webui`, a group shared with every network-input-parsing daemon; no `SO_PEERCRED` | `systemd/fr-*.socket:7-10`, `helper/server.py:6-11` |
| M1 | medium | XDP | SNI blocklist trivially bypassable: parser clamps + case mismatch + ≥32-byte names + split ClientHello | `bpf/xdp_sni_filter.c:444,465,476,565`, `config/loader.py:647` |
| M2 | medium | firewall | `ExecStop=nft flush ruleset` opens the box on stop/restart | `systemd/fr-firewall.service:23` |
| M3 | medium | firewall | No ordering/masking vs Debian's `nftables.service`; docs claim ordering that does not exist | `systemd/fr-firewall.service:4-8` *(needs verification)* |
| M4 | medium | installer | Interface→zone assignment is **alphabetical**, so the LAN trust zone can land on the physical WAN port | `netdetect.py:50`, `scripts/fr-first-boot.sh:39-45` |
| M5 | medium | update | Tar extraction: symlink/hardlink write-through when `filter="data"` is unavailable | `update.py:304-318` *(needs verification)* |
| M6 | medium | update | `rollback_update` never validates `previous_version` → path traversal to `rmtree`/`pip install` as root | `update.py:492-497`, `update.py:329-343` |
| M7 | medium | update | Check source ≠ install source: `config.update.repo` only affects the *display* of updates | `webui/routes/update.py:35-56`, `helper/update_server.py:96,125` |
| M8 | medium | update | No locking anywhere: concurrent update/apply races; fixed transient unit name `fr-webui-restart` | `update.py:176,402`, `helper/update_server.py:89-90` |
| M9 | medium | update | No boot-time health check / post-update verification / auto-rollback | grep: nothing in `src/`, `systemd/`, `scripts/` |
| M10 | medium | firewall | nft backups: non-atomic write, second-granularity name collision, rollback without `nft -c` pre-check | `apply.py:126-146`, `apply.py:104-115` |
| M11 | medium | XDP | Partial-apply leaves interfaces attached but unrecorded; non-atomic state write; `XdpError` not caught by the helper | `xdp.py:558-577,494-496`, `helper/server.py:131-136` |
| M12 | medium | XDP | SNI event logger stops receiving events after any disable/enable cycle (holds the old ring-buffer fd) | `xdp.py:703-721,314-325` |
| M13 | medium | XDP | Root compiles whatever `bpf/xdp_sni_filter.c` it finds first, with a `PATH`-resolved `clang` | `xdp.py:242-286` *(needs verification)* |
| M14 | medium | XDP | Stale pinned BPF program reused forever after upgrades (pin existence == "loaded") | `xdp.py:296-311` |
| M15 | medium | installer | SSH host keys appear to be baked into the image (no regeneration step anywhere) | `package-lists/frfw.list.chroot:10` *(needs verification)* |
| M16 | medium | installer | No bootloader password: kernel cmdline edit yields an unauthenticated root shell | `isolinux/isolinux.cfg:1-4`, `grub/grub.cfg:36-44` |
| M17 | medium | installer | systemd hardening gaps across root daemons; `/run/fr_os` created 0755; no `UMask=` | `systemd/*.service`, `fr-*.socket:5` |
| M18 | medium | quality | No CI job ever runs the 817-test suite (only a manual ISO-build workflow exists) | `.github/workflows/` |
| L1 | low | webUI | No CSRF token anywhere; POSTs rely solely on `SameSite=Lax` | grep `csrf` → 0 hits; `routes/auth.py:74-80` |
| L2 | low | webUI | `/metrics` is unauthenticated unless an admin opts into a token | `routes/metrics.py:50-65`, `metrics.py:382-396` |
| L3 | low | webUI | No security headers (HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Cache-Control`) | `webui/app.py:73-136` |
| L4 | low | webUI | Logout deletes the cookie client-side only; a stolen cookie stays valid up to 12 h | `routes/auth.py:84-88`, `webui/auth.py:33` |
| L5 | low | webUI | Password policy is length-only (8 chars) and `AdminStore.set_password` itself does not validate | `admin_account.py:51,105-107,169-180` |
| L6 | low | webUI | PBKDF2-HMAC-SHA256 at 200 000 iterations (below current OWASP guidance) | `admin_account.py:44-45` |
| L7 | low | update | No downgrade protection: any differing semver tag is installable, including older/vulnerable ones | `update.py:441-446` |
| L8 | low | update | Unbounded download and extraction (no size/member caps); unbounded adblock list fetch as root | `update.py:286-288,304-318`, `adblock/__init__.py:94-98` |
| L9 | low | XDP | Merged blocklist entries (adblock critical domains) are not lowercased/revalidated → keys that can never match; non-ASCII aborts apply opaquely | `adblock/dns_service.py:315-344`, `xdp.py:211-236` |
| L10 | low | XDP | WebUI reads XDP stats unprivileged → all-zero counters, indistinguishable from "filter off" | `routes/xdp.py:95-98`, `xdp.py:453-467` *(needs verification)* |
| L11 | low | firewall | Interface `device:` string is only checked "non-empty" → flows unescaped into the nft script | `config/loader.py:189-197`, `nft/builder.py:247` |
| L12 | low | XDP | Uninitialized 3-byte padding tail of the LPM key passed to `bpf_map_lookup_elem` (verifier-fragile) | `bpf/xdp_sni_filter.c:945,686-751` |
| L13 | low | XDP | No IP-fragment / `ip->version` checks before treating bytes as a TCP header (memory-safe, wrong parse) | `bpf/xdp_sni_filter.c:823-849` |
| L14 | low | webUI | SSE log stream forks one `journalctl -f` per client with no cap; `wait(timeout=5)` can raise during teardown | `routes/xdp.py:192-238,199,206` |
| L15 | low | helpers | `json.loads` of `bpftool` output unguarded → `JSONDecodeError` escapes the helper's catch tuple | `xdp.py:380,429,463`, `helper/server.py:131-136` |
| L16 | low | helpers | `helper/protocol.COMMANDS` / `update_protocol.COMMANDS` are documented as authoritative but never enforced | `helper/protocol.py:62-80` |
| L17 | low | update | `update_state.json` is created 0644 root:root although the docs promise 0640 + chown to the webUI | `update.py:174-178`, `paths.py:56-64` |
| L18 | low | quality | `tests/test_xdp_sni_key.py` is referenced by three source files but does not exist | `bpf/xdp_sni_filter.c:82`, `xdp.py:84-86`, `config/loader.py:69-70` |
| L19 | low | installer | `isolinux/install.cfg` is literally `# FIXME` yet included; `make-hybrid-uefi-iso.sh` is excluded from the shellcheck test | `install.cfg:1`, `tests/test_installer.py:63-71` |
| L20 | low | installer | Re-running first boot (marker lost) silently clobbers config + regenerates the admin password; persistence partition is auto-created without confirmation | `scripts/fr-first-boot.sh:45,64`, `persistence.py:226-254` |
| L21 | low | webUI | Audit log lives in the webUI-writable state dir → a compromised webUI can forge/truncate it | `paths.py:185`, `webui/audit.py:25-36` |
| L22 | low | webUI | `AdminStore.users()` raises an uncaught `JSONDecodeError`/`KeyError` on a corrupt `auth.json` → 500 on every page | `admin_account.py:122-131` |

---

## Critical

### C1 — Unauthenticated first-run admin account creation, on a WAN-bound listener, with no rate limit

* **Severity**: critical
* **Where**: `src/frfw/webui/routes/auth.py:52-65` (account creation before any authentication),
  `src/frfw/webui/routes/auth.py:53-56` (branch deliberately not rate-limited),
  `src/frfw/webui/server.py:51` (`--host` default `0.0.0.0`), `systemd/fr-firewall.service:8`
  (no ruleset without `config.yaml`), `scripts/install-system-integration.sh:92-98`
  (prints `set-admin-password` as an optional "next step").
* **Description**: while `AdminStore.exists()` is false, `POST /login` *creates* the first
  account, as an **admin**, before any credential check. The branch is intentionally exempt
  from brute-force protection. The listener is `0.0.0.0:443`, i.e. every interface including
  WAN. Nothing in code forces a password to be set before the webUI starts, and
  `fr-firewall.service` is skipped entirely when `/etc/fr_os/config.yaml` does not exist
  (kernel default policy = accept all).
* **Exploit scenario**: on the documented manual-install path the operator is only *told* to
  run `firewall-cli set-admin-password` (it is not run for them). If `fr-webui` is started
  first — or if `auth.json` later disappears while `.first-boot-done` remains (restored
  backup, `rm -rf /etc/fr_os/webui`, failed disk write; first boot will not regenerate it,
  `scripts/fr-first-boot.sh:25-28`) — any host that can reach `:443` POSTs
  `username=admin&password=…` and owns the box. From there the `fr-apply-helper` socket
  (`0660 root:fr_os-webui`, which the webUI process is in) yields `save_config`/`apply`/`ban_ip`
  as root, and `fr-update-helper` yields root package installation. If `config.yaml` is also
  absent the firewall never loads, so the window is WAN-reachable, not just LAN.
* **Fix**: never allow account creation from a non-local context without proof of presence —
  require a one-shot token printed on the console (the generated password is already printed
  there), restrict first-run to loopback/LAN-zone source addresses, or refuse to start
  `fr-webui` when no account exists unless an explicit `--allow-first-run` flag is passed.
  Additionally make the firewall fail closed independently of `config.yaml` (see H2).

---

## High

### H1 — The generated admin password is written to `/etc/issue` in plaintext and stays there

* **Severity**: high
* **Where**: `scripts/fr-first-boot.sh:64` (`PASSWORD="$(firewall-cli set-admin-password --generate)"`),
  `:70-77` (prepends `FR_OS: initial webUI admin login is 'admin' / '$PASSWORD'` to `/etc/issue`),
  `:73` ("stays until you edit /etc/issue"). Intended per `README.md:89` and asserted by
  `installer/qemu-boot-test.py:209-210,229-230`.
* **Description**: `/etc/issue` is mode 0644 and is printed by getty on **every** tty,
  including the serial console enabled by `installer/live-build/auto/config:153`
  (`console=ttyS0,115200n8`) and `grub.cfg:37`. The credential never expires; the only
  removal is manual editing.
* **Exploit scenario**: (a) anyone with serial/BMC/serial-over-LAN/BSD access gets the live
  admin credential with no login at all; (b) any local process (e.g. a compromise of a
  `fr_os-webui`-running daemon, or any future local account) reads `/etc/issue` and obtains
  the admin password even though `auth.json` itself is 0640; (c) a device recovered years
  later still has its last admin password printed on its console.
* **Fix**: print the password once (a `wall`/`systemctl status` one-shot or journald entry),
  keep only the hash on disk, and auto-remove the line at first successful login. At minimum
  move it out of the world-readable `/etc/issue` into a root-only file consulted only by a
  local console helper.

### H2 — No fail-closed firewall baseline: the ruleset is simply absent when config is missing or apply fails

* **Severity**: high
* **Where**: `systemd/fr-firewall.service:8` (`ConditionPathExists=/etc/fr_os/config.yaml`),
  `:21` (`ExecStart=firewall-cli apply …`), `src/frfw/provision.py:87-96` (address sync runs
  **first**), `src/frfw/ifaddr.py:51-53` (`ip addr replace … dev <missing>` raises),
  `scripts/install-system-integration.sh:51-59,92-98`, `examples/config.yaml:9,14,19`.
* **Description**: there is no default drop-all file loaded independently of the config.
  If `config.yaml` does not exist the unit is skipped (kernel default = accept everything).
  If it does exist but `apply_all` aborts at step 1 (an interface name in the config that does
  not exist on this machine), `nft` is never reached — yet `fr-webui` keeps running and
  `fr-firewall` reports *failed* while nothing enforces anything. The manual install path
  installs `examples/config.yaml` (which names `eth0`/`eth1`/`eth2`) verbatim as the starting
  config, so any machine with different NIC names fails exactly this way. On the live image
  there is additionally a boot window between NIC-DHCP configuration and
  `fr-first-boot.sh:96` (which starts `fr-firewall`) where the WAN is up with no filtering,
  while `openssh-server` is installed.
* **Exploit scenario**: manual install on a box whose NICs are not `eth0/eth1/eth2` →
  `fr-firewall` fails → router runs with default-accept policy and a webUI listening on all
  interfaces → C1 (or any WAN-side service) is directly reachable; combined with H1 the
  credential is also on the console.
* **Fix**: load a fail-closed baseline from a separate early unit that does not depend on the
  config (e.g. `ExecStart=nft -f /usr/local/share/fr_os/baseline-drop.nft` with
  `Before=network-pre.target`, or an `ExecStartPost` fallback on failure); validate the
  applied result on every boot (`nft list ruleset` still contains our table) and treat a
  missing/failed ruleset as a hard failure that also stops the management plane.

### H3 — `save_config` silently downgrades `config.yaml` from 0640 root:`fr_os-webui` to 0644 root:root

* **Severity**: high
* **Where**: `src/frfw/helper/server.py:299-303` (`_write_atomic`: `tmp_path.write_text(text)`
  with the process umask, then `replace()`) — no `chmod`/`chown` afterwards;
  `systemd/fr-apply-helper.service:7-19` (no `UMask=`); contrast the correct behaviour in
  `src/frfw/cli.py:484-489` and the install-time enforcement in
  `scripts/install-system-integration.sh:62-63` / `scripts/fr-first-boot.sh:47-48`.
* **Description**: the **first** settings save from the webUI replaces `config.yaml` with a
  fresh temp file owned by root:root with mode 0644 (umask 022). `config.yaml` contains ZTNA
  account PBKDF2 hashes (`config/schema.py:232-239`) and the metrics bearer-token digest
  (`schema.py:453-461`).
* **Exploit scenario**: on any multi-user box, or after any local file-read primitive, every
  local account can read the ZTNA password hashes and run an offline dictionary attack
  against them, and read the metrics-token digest. It also silently breaks the documented
  invariant stated in `ARCHITECTURE.md` and `paths.py:33-35`.
* **Fix**: `os.chmod(tmp, 0o640)` + `os.chown(tmp, st.st_uid, st.st_gid)` of the target before
  `replace()` (mirror `cli.py:484-489`), and add `UMask=0077` to both helper units. Add a
  test that runs the real `save_config` path and asserts the mode/owner are preserved.

### H4 — The XDP filter is never re-attached after a reboot, while the UI says it is attached

* **Severity**: high
* **Where**: `src/frfw/xdp.py:565-567` (skip attach when the device is in the persisted
  state), `src/frfw/xdp.py:484-496` (`_load_state` returns "nothing attached" on *any* parse
  error; `_save_state` is a plain truncating `write_text`), `systemd/fr-firewall.service:21`
  (boot apply), `src/frfw/webui/routes/xdp.py:92-108` (status badges read the same file).
* **Description**: XDP attachments live only in the kernel and do not survive reboot, but
  `/etc/fr_os/xdp_state.json` does. At boot `fr-firewall` runs a full apply:
  `load_and_pin()` runs and `sync_blocklist()` runs, but `attach()` is skipped for every
  interface because the stale file says they are already attached. No code ever probes live
  kernel state (`ip link`/`bpftool net`) and nothing clears the state file at boot.
* **Exploit/failure scenario**: the admin enables the SNI filter, it works, the router
  reboots. From then on **no packet is inspected** (blocklist, drop stats, pass events and
  fingerprinting are all dead) while `GET /xdp` renders the green "Native/Driver" badges from
  the stale file and `firewall-cli xdp-status` reports the same. This is fail-open with a
  false "on" status — the worst possible combination for a security control.
  `tests/test_xdp.py:334-353` currently enshrines the skip without modelling a reboot.
* **Fix**: never trust the state file for liveness — at sync time probe each device
  (`bpftool link show dev X`, or compare the attached prog ID to the pinned prog ID) and
  attach when absent/mismatched; reset `attached` when the pins do not exist yet (they are
  recreated at boot, which proves kernel state is gone). Write state atomically (see M11).

### H5 — Updates have no authenticity verification, yet install code and rewrite systemd units as root

* **Severity**: high
* **Where**: `src/frfw/update.py:282-290` (`_download_tarball`: plain `urlopen`, no hash or
  signature check), `:329-331` (cached release reused without re-verification),
  `:348-375` (`shutil.copy2` of `systemd/fr-*` into `/etc/systemd/system`, scripts into
  `/usr/local/sbin`, then `pip3 install --break-system-packages <dir>[webui]` as root),
  `:28-33` (the limitation is admitted in the module docstring), no signing workflow
  (`.github/workflows/` contains only `build-installer.yml`).
* **Description**: the trust boundary is "TLS to GitHub plus whoever controls the GitHub
  repo". There is no GPG/minisign/cosign/detached-checksum verification anywhere in the
  update path, and `pip` additionally resolves unpinned transitive dependencies from PyPI
  (`pyproject.toml` uses `>=` floors only).
* **Exploit scenario**: a compromised maintainer account, a malicious insider, or a
  GitHub-side incident publishes tag `v0.2.1` → every router that clicks "Update" executes
  attacker code as root, rewrites **its own** update-helper unit (including
  `fr-update-helper.service`) and persists across reboots — fleet-wide root RCE from one
  release. Forced downgrades to an old, vulnerable tag are equally available (L7).
* **Fix**: sign releases (cosign / GPG-signed `SHA256SUMS`) at publish time and verify the
  digest in the helper against a public key baked into the *currently installed* package
  before extraction or `pip`; pin dependencies with `--require-hashes`; make the helper
  refuse to install a version whose signature does not verify.

### H6 — A failed update records no `previous_version`, so rollback refuses to work

* **Severity**: high
* **Where**: `src/frfw/update.py:434-439` (docstring: *"Records the currently-installed
  version as `previous_version` **before** switching"*), `src/frfw/update.py:449-461`
  (actual code sets `state.previous_version` only **after** `_install_and_activate`
  succeeds), `src/frfw/update.py:492-494` (`rollback_update` refuses when it is unset).
  `tests/test_update.py:241-259` asserts the current (wrong) behaviour.
* **Description**: `_install_and_activate` (`update.py:414-420`) is a non-transactional
  sequence: `pip install` new code → copy unit files → `daemon-reload` → restart services →
  `systemd-run` a webUI restart. If any step after the `pip` succeeds then fails, the new
  code is already installed (and possibly new units are on disk) but the state file records
  only `status="failed"` with `previous_version=None`.
* **Failure scenario**: first update to 0.2.0: `pip` succeeds, `systemctl try-restart
  fr-apply-helper.service` fails → UI says "update failed"; on reboot the new (broken) code
  starts; the admin clicks "Roll back" → *"no previous version recorded to roll back to"*.
  The box now runs code nobody believes was installed, with no programmatic way back — on a
  firewall appliance that may also mean no management UI (M9 compounds this: nothing
  health-checks at boot either).
* **Fix**: write `previous_version` (plus an `in_progress` marker) **before** `pip`, as the
  docstring already claims; stage unit/script copies atomically; on failure either
  auto-rollback or record enough state that rollback is possible; verify services are
  `active` before recording success. Fix the test that locks in the wrong ordering.

### H7 — Both root daemons are reachable by every `fr_os-webui` daemon, including the ones that parse attacker-controlled network input

* **Severity**: high
* **Where**: `systemd/fr-apply-helper.socket:7-10` and `systemd/fr-update-helper.socket:7-10`
  (`SocketMode=0660`, `SocketUser=root`, `SocketGroup=fr_os-webui`),
  `src/frfw/helper/server.py:6-11` and `helper/update_server.py:41-67` (access control is
  *purely* filesystem permissions; no `SO_PEERCRED`, no per-command authorisation),
  group members: `fr-webui.service:9-10`, `fr-ai-ids.service:9-10`, `fr-appid.service:8-9`,
  `fr-iot-scan.service:14-15` (explicitly "the process that parses untrusted network input"),
  `fr-tls-fp.service:9-16` + `tlsfp/daemon.py:147-156` (drops uid but keeps the primary group).
* **Description**: the sockets are correctly *not* world-connectable (0660, not 0666) and no
  script adds any interactive user to the group — but the group is shared with four daemons
  whose whole job is to parse mDNS/DHCP/TLS/SNI data from the LAN. The docstrings justify
  the group as "the webUI", which understates actual membership. The update socket in
  particular grants root `pip install` + systemd-unit rewriting; the apply socket grants
  `save_config`/`apply`/`ban_ip` (firewall takeover and LAN-wide DoS).
* **Exploit scenario**: one memory-corruption or logic bug in `fr-iot-scan` (attacker
  controls a mDNS hostname on the LAN) → connect to `/run/fr_os/update.sock` →
  `{"cmd":"apply","version":"vX"}` → root code execution (compounded by H5: no signature).
* **Fix**: give the update helper its own dedicated group that only `fr-webui` belongs to;
  run each parser daemon as its own user; verify `SO_PEERCRED` uid/gid in both daemons and
  log the peer; document the real trust boundary in the helper docstrings.

---

## Medium

### M1 — The XDP SNI blocklist is trivially bypassable by a non-cooperative client

* **Severity**: medium
* **Where**: `bpf/xdp_sni_filter.c:444-445` (`session_id_len > 32 → return -1`),
  `:465-466` (`cipher_suites_len > 512 → return -1`), `:476-477` (`compression_len > 16`),
  `:565` (max 32 extensions), `:600-611`/`:643-649` (extension-length cap), `:109`
  (`MAX_SNI_LEN 32`); case: `config/loader.py:647` lowercases the blocklist while the
  extracted SNI is compared as raw bytes (`bpf/xdp_sni_filter.c:687-751`).
* **Description**: any of these *server-acceptable* ClientHello shapes makes `extract_sni()`
  return a negative value → `XDP_PASS`, before the SNI is even reached: a 600-byte
  cipher-suites field (servers simply ignore unknown suites), a session-id >32, a compression
  list >16, SNI after extension #32, an SNI ≥32 bytes, or a ClientHello split across two TCP
  segments. Separately, a client sending `WWW.EXAMPLE.COM` never matches the lowercased
  entry — silently inconsistent with the DNS tier. The multi-segment / ECH / QUIC / 32-byte
  limits *are* documented in the C header and `ARCHITECTURE.md`; the **clamp** and
  **case** gaps are not.
* **Exploit scenario**: a LAN client that wants a blocked domain sends its ClientHello with a
  600-byte cipher_suites field (or upper-cases the SNI, or uses a raw socket to split the
  record). The connection succeeds and `drop_match` never moves — so the "kernel-enforced
  critical adblock subset" and `app_control.block_via_xdp` are advisory against anyone who
  reads the source.
* **Fix**: on the clamps, skip the field with a bounds-checked advance instead of aborting
  the parse (or at least bump a distinct `STAT_PASS_CLAMPED` counter so it is visible);
  lowercase (A–Z only) the extracted SNI before `build_lpm_key`; document the remaining
  unavoidable gaps in user-facing docs, not only in the C header.

### M2 — `ExecStop=/usr/sbin/nft flush ruleset` removes the entire firewall on stop/restart

* **Severity**: medium
* **Where**: `systemd/fr-firewall.service:23` (with `RemainAfterExit=yes` at `:12`).
* **Description**: stopping or restarting the unit flushes *all* nftables state — default
  accept on WAN — while networking and `fr-webui`/`sshd` are still up. The unit still reports
  "active" afterwards. This also fires on shutdown ordering (`Conflicts=shutdown.target`).
* **Failure scenario**: `systemctl restart fr-firewall` (or a package/removal hook) leaves
  the appliance fully open for the seconds/minutes until someone re-runs `apply`, with no
  indication in the unit status.
* **Fix**: replace with `ExecStop=/usr/sbin/nft -f /usr/local/share/fr_os/baseline-drop.nft`
  (a minimal drop-all), or delete `ExecStop` entirely — the next apply replaces the ruleset
  atomically anyway.

### M3 — No ordering or masking against Debian's `nftables.service` (docs claim otherwise)

* **Severity**: medium — **needs verification**
* **Where**: `systemd/fr-firewall.service:4-8` (no `After=nftables.service`, no `Conflicts=`);
  `installer/live-build/config/package-lists/frfw.list.chroot:1` installs the `nftables`
  package; `ARCHITECTURE.md:592-594` claims the unit *is* ordered after it.
* **Description**: Debian's default `/etc/nftables.conf` begins with `flush ruleset`. If
  `nftables.service` is enabled in the image and runs *after* `fr-firewall`, FR_OS's ruleset
  is wiped at boot while the unit stays "active" and the box runs open.
* **Verification needed**: whether `nftables.service` ends up enabled in the built image
  (`systemctl is-enabled` on a booted ISO) — nothing in the repo enables or masks it.
* **Fix**: add `After=nftables.service` and mask/`Conflicts=` the Debian unit in the image
  hook; correct the doc; add a test asserting the ordering exists.

### M4 — Interface→zone assignment is alphabetical, so the LAN trust zone can land on the WAN port

* **Severity**: medium
* **Where**: `src/frfw/netdetect.py:50` (`sorted(..., key=name)`), consumed by
  `scripts/fr-first-boot.sh:39-45` ("first detected NIC is WAN, second is LAN", no
  confirmation, `--force`).
* **Description**: on hardware where the alphabetically-first name is the physical LAN port
  (e.g. `eno1` vs `enp2s0`, or USB NICs enumerating as `eth0`), the LAN zone — static
  `192.168.1.1/24`, the DHCP server, and the `allow-mgmt-from-lan`/`webui-from-lan` rules for
  22/tcp and 443/tcp (`src/frfw/skeleton.py:17-43`) — is configured on the uplink port.
* **Exploit scenario**: management plane (SSH + HTTPS + DHCP server) exposed to the ISP-side
  L2 segment, while real internal traffic is treated as untrusted "WAN"; the reverse
  mis-assignment silently disables outbound NAT for the real LAN.
* **Fix**: choose WAN by link/carrier/DHCP-lease heuristics and require confirmation (console
  prompt or first-run webUI screen); never default trust zones on name sort order. At
  minimum print a loud, must-be-dismissed console warning.

### M5 — Tar extraction can write through symlinks/hardlinks when `filter="data"` is unavailable

* **Severity**: medium — **needs verification** (Python patch level on the image)
* **Where**: `src/frfw/update.py:304-318` — the pre-check at `:306-311` resolves only
  `member.name` *before* extraction; link targets (`member.linkname`) are never inspected;
  `filter="data"` at `:316` falls back to **unfiltered** `extractall` on `TypeError` (`:318`).
  Tests cover only `../` in *names* (`tests/test_update.py:158-163`).
* **Description**: a member `release/link -> /etc` passes the name check (nothing exists yet),
  then a following member `release/link/cron.d/evil` writes *through* the symlink outside the
  destination — the classic CVE-2007-4559 pattern. `filter="data"` (PEP 706) does catch this,
  but it exists only from 3.12 and was backported to 3.11.4+/3.10.12+, while the project
  minimum is `>=3.11`.
* **Verification needed**: the exact `python3` patch level in the shipped image.
* **Fix**: reject symlink/hardlink/device members outright (release tarballs never need them)
  and fail closed when `filter=` is unsupported instead of downgrading to unprotected
  extraction. Add a symlink/hardlink test.

### M6 — `rollback_update` never validates `previous_version` (path traversal to `rmtree` / root `pip install`)

* **Severity**: medium (defence in depth — the state file is root-written)
* **Where**: `src/frfw/update.py:492-497` (no `parse_version`, unlike `apply_update:441`),
  flowing into `update.py:329` (`existing = releases_dir / version` — an absolute `version`
  replaces the base), `:330-331` (cached dir returned as-is), `:341-342`
  (`shutil.rmtree(existing)`), `:371` (`pip install` of that directory as root).
* **Description**: `previous_version` is read from `/etc/fr_os/update_state.json` and used as
  a filesystem component without shape validation or a containment check
  (`existing.resolve().is_relative_to(releases_dir)`). On a stock install the file is
  root-written in a root-owned directory, so an unprivileged user cannot tamper with it —
  but a corrupted/hand-edited file (or any future writer) turns rollback into arbitrary
  root directory deletion or root code execution.
* **Fix**: `parse_version(target)` in `rollback_update`; assert containment under
  `RELEASES_DIR` before `rmtree`/`pip`; reject absolute versions. Add a test for a malformed
  `previous_version`.

### M7 — The repo you *check* is not the repo you *install* from

* **Severity**: medium
* **Where**: `src/frfw/webui/routes/update.py:35-40,50-56` (`_resolve_repo` → config, used
  only for `check_latest` display), `:76-89` (apply sends only `version`),
  `src/frfw/helper/update_server.py:96,125` (`repo` = argparse default `DEFAULT_REPO`; the
  unit runs with no args), `src/frfw/cli.py:567-569` vs `:270,276,586-595`; yet
  `update.py:21-23,60-62` claims the source is overridable via `update.repo`.
* **Description**: the Update page says "Checked against `<configured fork>`" and lists that
  fork's releases, but the privileged helper always downloads from the hard-coded default
  repo. The good news: a config field alone cannot redirect the *install* (config.yaml is
  0640, group read-only), so the "config redirects updates" escalation does not exist.
* **Failure scenario**: an admin reviews release notes from fork A while the router installs
  the same-named tag from repo B — a supply-chain confusion primitive and a plain bug.
* **Fix**: plumb a validated (`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`) configured repo through
  the helper protocol, or make check/CLI display use the same source apply uses — and fix the
  docstrings either way. Add a test that the configured repo is what apply uses.

### M8 — No locking anywhere: concurrent updates, and update racing apply

* **Severity**: medium
* **Where**: no `flock`/`lockf`/`lockfile` anywhere in `src/`; fixed state temp name
  `update.py:176` (`path.suffix + ".tmp"`); fixed transient unit name `update.py:402`
  (`--unit=fr-webui-restart`); helper is single-threaded (`update_server.py:89-90`) but
  `firewall-cli update apply` runs concurrently with it (`cli.py:586-589`); update
  `try-restart`s `fr-apply-helper`/`fr-firewall` underneath an in-flight apply
  (`update.py:72-75,378-385`).
* **Failure scenario**: two `pip install`s racing, read-modify-write races on the state file,
  and a previously failed `fr-webui-restart` transient unit left in `failed` state making the
  *next* update error out **after** the install already happened → exactly H6's
  no-rollback state. The 300 s client timeout (`helper/update_client.py:21`) can also expire
  while the single-threaded helper is still installing, so the admin retries and queues a
  second install.
* **Fix**: `flock` a lock file taken by both the helper and the CLI; unique transient unit
  names (or `reset-failed` first); an explicit in-progress state marker shown in the UI.

### M9 — No boot-time health check, no post-update verification, no auto-rollback

* **Severity**: medium
* **Where**: no `OnFailure=`/watchdog/health logic in `src/`, `systemd/`, `scripts/`;
  `apply_update`/`rollback_update` consider the job done when `systemctl try-restart` exits 0
  (`update.py:378-385`) — `try-restart` is a **no-op** for a disabled unit, so a silently
  skipped restart still counts as success.
* **Failure scenario**: an update ships code that makes `fr-webui` (or `fr-firewall`) crash
  on start → the appliance boots with no management UI and possibly no firewall ruleset;
  recovery needs SSH/console that may itself be broken (M2/H2 make this worse). If networking
  is broken too, the box is bricked until physical access.
* **Verification needed**: whether anything outside the repo (image build, ops tooling)
  provides this — none found here.
* **Fix**: verify services are `active` after restart before recording success; add
  `OnFailure=`/watchdog-based boot health checking that auto-rolls back to
  `state.previous_version` (which H6 must start recording reliably first).

### M10 — nftables backup/rollback is non-atomic and skips the syntax pre-check

* **Severity**: medium
* **Where**: `src/frfw/apply.py:126-140` (`backup_path.write_text(...)` directly — no
  temp+rename; filename `ruleset-<UTC second>.nft` at `:132-133` → two applies in the same
  second overwrite), `:143-146` (pruning may keep a truncated file after a mid-write crash),
  `:104-115` (`rollback_last` runs `nft -f` **without** the `nft -c` pre-check that normal
  applies get at `:81`, and does not snapshot the current ruleset first).
* **Failure scenario**: a power cut during the backup write leaves a truncated file; the
  next `firewall-cli rollback` loads it, `nft` fails on a half-written ruleset at the worst
  moment (or, worse, partially-structured input is rejected after `flush ruleset` semantics
  are applied) — and a rollback cannot itself be rolled back.
* **Fix**: temp file + `os.replace`, include microseconds or a counter in the name, run
  `check_syntax` before restoring, and snapshot the current ruleset before a rollback.

### M11 — XDP partial-apply failure leaves the filter attached but unrecorded; state writes are non-atomic

* **Severity**: medium
* **Where**: `src/frfw/xdp.py:558-577` (attach → sync → `_save_state` ordering),
  `:494-496` (plain truncating `write_text`), `:484-491` (any JSON/OS error ⇒ silently
  "no attachments recorded"), `:380` (unguarded `json.loads` of bpftool output),
  `src/frfw/helper/server.py:131-136` (catch tuple omits `xdp_mod.XdpError`).
* **Description**: devices are attached *before* the state is saved. If anything in between
  raises (`bpftool` transient error, map full, `JSONDecodeError`), the new attachment is
  never recorded. The disable path then sees `not state.attached` and reports "nothing to
  do", so the program stays attached forever with the admin believing filtering is off;
  `unload()` can then unlink pins under a live attachment, and the next enable loads a second,
  divergent program. Because `XdpError` is not in the helper's catch tuple, the helper thread
  dies with a traceback and the webUI's socket peer gets an EOF instead of `{"ok": false}`.
* **Fix**: record state at/after each successful attach (or roll back attachments on
  failure); make `_save_state` atomic (`os.replace`, like `helper/server.py:_write_atomic`)
  and make `_load_state` refuse to report "nothing attached" on corrupt JSON; add `XdpError`
  (and `json.JSONDecodeError`) to the helper's caught-exception tuple.

### M12 — The SNI event logger silently stops receiving events after any disable/enable

* **Severity**: medium
* **Where**: `src/frfw/xdp.py:703-721` (`run_event_logger` opens the ring buffer once, then
  polls forever), `:314-325` (`unload()` unlinks the pins),
  `systemd/fr-xdp-sni-logger.service:10` (`Restart=on-failure` only — a healthy daemon on a
  dead map never restarts). Contrast `provision.py:208-209`, which *does* restart `fr-tls-fp`.
* **Failure scenario**: toggling the filter (or upgrading and re-enabling) leaves the daemon
  polling the *old* map fd, which still returns cleanly. All subsequent events go to the new
  map that nobody reads: the live log page freezes and journald loses all drop/pass audit
  data — while the filter itself keeps dropping correctly. Silent loss of the security audit
  trail for exactly the traffic being blocked.
* **Fix**: re-check the pin path/inode each poll iteration and rebuild the reader on change,
  or `systemctl try-restart fr-xdp-sni-logger` from the sync/unload path (as is already done
  for `fr-tls-fp`), or exit non-zero on map replacement so `Restart=` catches it.

### M13 — Root compiles whatever BPF source it finds first, from a `PATH`-resolved compiler

* **Severity**: medium — **needs verification** (depends on install layout)
* **Where**: `src/frfw/xdp.py:242-251` (candidate order prefers the checkout's
  `bpf/xdp_sni_filter.c` over `RELEASES_DIR`), `:254-286` (`ensure_compiled`, mtime-based,
  runs as root inside apply), `:278-283` (`clang` from `PATH`), `:736-749` (`ip`/`bpftool`
  from `PATH`).
* **Description**: the apply-helper runs as root under systemd (sanitised `PATH` — safe
  there), but `firewall-cli apply` can also be run interactively as root from a git checkout,
  where the first existing candidate is the **checkout's** BPF source. If that checkout (or
  the `parents[2]` site-packages parent in some layouts) is writable by a non-root user,
  that user controls the BPF source root will compile and load into the kernel; simply
  touching the file triggers recompilation.
* **Verification needed**: whether a real install ships a precompiled `.o`
  (`installer/` contains no `bpf`/`clang` references, so real installs may always take this
  path) and the writability of the resolved paths in each layout.
* **Fix**: require the chosen source path to be root-owned and not group/world-writable
  before compiling; prefer `RELEASES_DIR`/precompiled objects when running under the helper;
  use absolute paths for `clang`/`ip`/`bpftool`.

### M14 — Stale pinned BPF program is reused forever after an upgrade

* **Severity**: medium
* **Where**: `src/frfw/xdp.py:296-311` (`load_and_pin` returns early if a pin exists),
  `:292-293`.
* **Description**: idempotence is keyed on pin existence only. After a release that changes
  `bpf/xdp_sni_filter.c` (or map sizes/semantics), apply keeps the old program indefinitely;
  the only accommodation is a special case for one class of drift (`:415-419`, `:580-588`)
  which tells the admin to disable and re-enable.
* **Failure scenario**: a release fixes a parser bug or adds a stat; support believes
  routers are on the fixed version while the kernel runs the old bytecode.
* **Fix**: compare the pinned program's `bpftool prog show … tag` against a freshly built
  object's digest and reload on mismatch (detach → unload → load → attach), or at minimum
  warn loudly in the apply message.

### M15 — SSH host keys appear to be baked into the image

* **Severity**: medium — **needs verification**
* **Where**: `installer/live-build/config/package-lists/frfw.list.chroot:10` installs
  `openssh-server` (postinst generates host keys inside the build chroot); no
  `ssh-keygen -A`/key-removal step exists in `installer/live-build/config/hooks/0100-install-frfw.hook.chroot`,
  `scripts/fr-first-boot.sh` or `scripts/install-system-integration.sh` (grep: zero hits).
* **Exploit scenario**: every router flashed from the same ISO shares identical SSH host
  keys → passive fleet fingerprinting and undetectable MITM of any SSH session.
* **Verification needed**: confirm on two independently built images whether
  `/etc/ssh/ssh_host_*` are identical; also whether `ssh.service` is enabled at all
  (nothing in the repo enables it).
* **Fix**: delete `/etc/ssh/ssh_host_*` in the chroot hook and regenerate on first boot
  (`ExecStartPre=/usr/sbin/sshd -t` + `ssh-keygen -A`, or a `ConditionPathExists` step).

### M16 — No bootloader password: kernel cmdline editing yields an unauthenticated root shell

* **Severity**: medium (physical/console attacker class)
* **Where**: `installer/live-build/config/bootloaders/isolinux/isolinux.cfg:1-4` (no
  `menu passwrd`/lock), `isolinux/menu.cfg:6-7`, `isolinux/live.cfg.in:1-10`,
  `installer/live-build/config/includes.binary/boot/grub/grub.cfg:36-44` (no
  `password`/`set superusers`), `auto/config:153` (serial console).
* **Exploit scenario**: a physical or IPMI/serial attacker edits the cmdline
  (`init=/bin/sh` / `single`) and gets a root shell, then reads the persistence partition for
  `/etc/fr_os/webui/auth.json`, `key.pem` and `/etc/issue` (H1).
* **Note**: because no login-capable account is ever created (see L-side notes and C1), this
  cmdline hack is also the *de facto* recovery path for legitimate admins — it cannot simply
  be locked without providing a real console credential path.
* **Fix**: set a GRUB password (`grub-mkpasswd_pbkdf2` + `set superusers`) and
  `menu passwrd` for isolinux, and provide a documented console login/recovery mechanism.

### M17 — Systemd hardening gaps across root-run units; `/run/fr_os` is world-traversable

* **Severity**: medium
* **Where**: grep over `systemd/` finds no `UMask=`, `PrivateTmp=`, `ProtectKernelModules=`,
  `ProtectKernelLogs=`, `RestrictAddressFamilies=`, `SystemCallFilter=`, `LockPersonality=`,
  `MemoryDenyWriteExecute=`; `CapabilityBoundingSet=` appears exactly once
  (`fr-tls-fp.service:13`). Specifics: `fr-update-helper.service:21` gives a root daemon
  `ReadWritePaths=/etc/fr_os /etc/systemd/system /opt/fr_os /usr/local` with no bounding
  set; `fr-adblock-dns.service:7-16` starts `dnsmasq` as root pre-drop with no
  `ProtectSystem`; `fr-apply-helper.service:11-18` and `fr-xdp-sni-logger.service:9-22`
  likewise unbounded. Both socket units create `/run/fr_os` with plain `mkdir -p` (0755)
  at `fr-*.socket:5`.
* **What is right**: `User=/Group=fr_os-webui` + `NoNewPrivileges=yes` +
  `ProtectSystem=full`/`ProtectHome=true` on `fr-webui`, `fr-ai-ids`, `fr-appid`,
  `fr-iot-scan`; narrowly correct `AmbientCapabilities=CAP_NET_BIND_SERVICE`
  (`fr-webui.service:19`); sockets are 0660, not 0666.
* **Fix**: add `UMask=0077`, `PrivateTmp=yes`, `ProtectKernelTunableModules/Logs`,
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, and per-unit
  `CapabilityBoundingSet=`; `ExecStartPre=/bin/mkdir -p -m 0750 /run/fr_os`.

### M18 — The test suite exists (817 tests) but no CI job ever runs it

* **Severity**: medium (code quality)
* **Where**: `.github/workflows/` contains only `build-installer.yml` (a manual ISO build
  with an optional QEMU boot test); no `pytest` invocation in any workflow; no `shellcheck`
  job either (it is wired into `tests/test_installer.py` only).
* **Description**: every mocked unit test, the RBAC route walk, the shellcheck lint and the
  XDP schema tests are developer-local. Regressions in auth/RBAC/apply/update can land
  without any automated signal — and the one automated signal that does exist (the QEMU boot
  test) is opt-in.
* **Fix**: add a `pytest` job (the root-only live tests skip cleanly without root) plus a
  shellcheck job; make the boot test required for releases.

---

## Low

* **L1 — No CSRF token anywhere (POSTs rely solely on `SameSite=Lax`).**
  `src/frfw/webui/routes/auth.py:74-80` sets `httponly`, `samesite="lax"`, `secure` on
  https; no `csrf`/`xsrf` code exists in `src/`, and no form carries a token.
  *Scenario*: modern browsers withhold the Lax cookie on cross-site POST, and there are no
  state-changing GETs (verified: every mutating route is POST), so practical risk is low —
  but older/non-conforming clients and same-site subdomain attackers are unprotected.
  *Fix*: per-session CSRF token on all POSTs, keep Lax.

* **L2 — `/metrics` is unauthenticated unless an admin opts into a token.**
  `src/frfw/webui/routes/metrics.py:50-65`, `src/frfw/metrics.py:382-396`
  (`expected is None → return True`). Discloses banned/quarantined counts, interface
  counters and hardware inventory to anyone who can reach `:443` (LAN-only *if* H2 is fixed).
  Deliberate and documented. *Fix*: default to requiring a token; keep the opt-out.

* **L3 — No security headers.** `src/frfw/webui/app.py:73-136` installs only an audit
  middleware: no HSTS, `X-Content-Type-Options`, `X-Frame-Options`/CSP, or
  `Cache-Control: no-store` on authenticated pages. *Fix*: add them in one middleware
  (HSTS optional given the self-signed cert).

* **L4 — Logout only deletes the cookie client-side.** `routes/auth.py:84-88`; the signed
  cookie stays valid for its 12 h lifetime (`webui/auth.py:33`) unless the password changes.
  *Scenario*: a stolen cookie survives the victim logging out. *Fix*: accept this (stateless
  design) or add a server-side session revocation list / short idle timeout.

* **L5 — Password policy is length-only, and `set_password` does not enforce even that.**
  `admin_account.py:51` (`MIN_PASSWORD_LENGTH = 8`), `:105-107` (validation lives only in
  `add_user`/the routes/CLI), `:169-180` (`AdminStore.set_password` imposes nothing).
  *Fix*: validate inside `set_password`; consider a denylist of common passwords.

* **L6 — PBKDF2-HMAC-SHA256 at 200 000 iterations.** `admin_account.py:44-45` — below
  current OWASP guidance (~600k for PBKDF2-HMAC-SHA256). Salt (16 B), `hmac.compare_digest`
  (`:77`) and the timing-equalised unknown-user path (`:140-143`) are all correct.
  *Fix*: raise the count (the stored format already carries it, so migration is safe) and
  re-hash on next successful login.

* **L7 — No downgrade protection.** `update.py:441-446` accepts any semver ≠ current,
  including older releases; the helper accepts any non-empty version string over the socket
  (`helper/update_server.py:47-57`) with no ordering check. *Fix*: refuse downgrades unless
  explicitly forced and audited.

* **L8 — Unbounded download and extraction.** `update.py:286-288` (`copyfileobj` with no size
  cap), `:304-318` (no member-count/size limits), `adblock/__init__.py:94-98`
  (`response.read()` of an admin-configured URL as root, also no cap). On a ≥256 MiB
  persistence image this wedges subsequent updates/rollbacks. *Fix*: enforce max download and
  max total extracted bytes in both paths.

* **L9 — Merged XDP blocklist entries are not revalidated.** `adblock/dns_service.py:315-344`
  only checks length (no charset/lowercase), `provision.py:186-206` merges in memory bypassing
  `_parse_xdp_sni_filter`, and `xdp.py:211-236` does `.encode("ascii")` (a `UnicodeEncodeError`
  escapes as an opaque `invalid request:` message). A mixed-case line in a hand-edited
  `adblock.hosts` becomes an LPM key that can never match — silent fail-open for the
  "critical" tier. *Fix*: run merged names through the same `_HOSTNAME_RE` + lowercase + length
  filter inside `sync_blocklist`, raising `XdpError` with the offending name.

* **L10 — XDP stats read by the unprivileged webUI come back all-zero** — **needs verification**.
  `routes/xdp.py:95-98` substitutes zeros on `XdpError`; `xdp.py:453-467` shells out to
  `bpftool map dump pinned …` as the calling user, which fails with `EPERM` whenever
  `kernel.unprivileged_bpf_disabled` is 1/2 (distro default). The dashboard then shows
  "0 drops / 0 everything" forever, indistinguishable from "filter never loaded".
  *Fix*: read stats through the privileged helper (a narrow `xdp_stats` command) or
  distinguish "EPERM" from "not loaded" in the UI. *Verify*: pin file modes and the target
  image's `unprivileged_bpf_disabled`.

* **L11 — Interface `device:` is only checked for being a non-empty string.**
  `config/loader.py:189-197`; the value is interpolated unescaped into the nft script at
  `nft/builder.py:247` (`elements = { "…" }`) and passed as an argv element to `ip`
  (`ifaddr.py:51-53`). An admin (or anyone who can write `config.yaml`) can inject nft syntax
  into a root-executed ruleset. *Scenario*: needs config-write access, so no privilege gain
  over an admin, but it is an unvalidated input crossing a trust boundary and could turn a
  benign config edit into a ruleset-loading failure. *Fix*: validate `device` against a
  strict interface-name regex (e.g. `^[A-Za-z0-9_.:-]{1,15}$`) in the loader, and reject
  values starting with `-`.

* **L12 — Uninitialized 3-byte padding tail of the LPM key.** `bpf/xdp_sni_filter.c:945`
  (`struct lpm_sni_key key;`), `:686-751` (`build_lpm_key` writes 37 of 40 bytes). The
  helper reads the full `key_size` from the stack; semantics are unaffected (only
  `prefixlen` bits are compared) but verifier acceptance depends on those slots having been
  initialised earlier in the frame — a toolchain/kernel change can make the program fail to
  load (fail-open outage). *Fix*: `struct lpm_sni_key key = {};`.
  *Needs verification*: clean-room compile on a stock toolchain.

* **L13 — No IP-fragment / `ip->version` checks.** `bpf/xdp_sni_filter.c:823-849`: non-first
  fragments (`protocol == TCP`) have their payload parsed as a TCP header. All reads remain
  bounds-checked against `data_end`, so this is memory-safe and yields `XDP_PASS` in
  practice. *Fix*: early `PASS` on
  `(bpf_ntohs(ip->frag_off) & (IP_MF|IP_OFFMASK))` and `ip->version != 4`.

* **L14 — SSE log stream spawns an unbounded number of `journalctl -f` processes.**
  `routes/xdp.py:192-238` — one `Popen` per connected client (viewers included, since GET is
  a safe method), no cap or idle timeout; `proc.wait(timeout=5)` at `:206` can raise
  `TimeoutExpired` inside `finally` during generator teardown. *Fix*: cap concurrent streams,
  catch `TimeoutExpired` and `kill()` the child.

* **L15 — `json.loads` of `bpftool` output is unguarded.** `xdp.py:380,429,463` raise a bare
  `JSONDecodeError`, which is not an `XdpError` and not in the helper's catch tuple
  (`helper/server.py:131-136`) → same connection-drop failure mode as M11; a raw traceback in
  the CLI. *Fix*: wrap and re-raise as `XdpError`; extend the helper's catch tuple.

* **L16 — `COMMANDS` is documented as authoritative but never enforced.**
  `helper/protocol.py:62-80` and `helper/update_protocol.py:22` are referenced by their own
  docstrings ("See `COMMANDS` for exactly what that set is today") but no code consults them;
  the handlers are an independent if/elif chain. Drift between the two is undetectable.
  *Fix*: validate `cmd in COMMANDS` before dispatch (a one-line fail-closed check) or delete
  the constant and point the docstring at the handlers.

* **L17 — `update_state.json` permissions do not match the docs.** `update.py:174-178` does
  `mkdir` + `write_text` + `replace` with no `chmod`/`chown`, while `paths.py:56-64` and
  `ARCHITECTURE.md:542` promise `root:fr_os-webui`, 0640, "chowned to the webUI user". In
  practice it lands 0644 root:root — works by accident; under a stricter umask the webUI
  could not read it and the Rollback button would never appear. *Fix*: `chmod 0640` +
  `chown` after create.

* **L18 — A referenced test file does not exist.** `tests/test_xdp_sni_key.py` is cited as
  the guard keeping C/Python `MAX_SNI_LEN` in sync by `bpf/xdp_sni_filter.c:82`,
  `src/frfw/xdp.py:84-86` and `src/frfw/config/loader.py:69-70` — it is absent from the repo.
  *Fix*: add it (assert the constants are equal on both sides plus a known-good key), or fold
  the assertion into `tests/test_xdp.py`.

* **L19 — Dead/unfinished installer artifacts.**
  `installer/live-build/config/bootloaders/isolinux/install.cfg:1` is literally `# FIXME` yet
  included by `menu.cfg:7`; `installer/make-hybrid-uefi-iso.sh` is the one installer script
  excluded from the shellcheck parametrisation in `tests/test_installer.py:63-71`, and it
  sources a *generated* file under `set -u`.
  *Fix*: delete or implement the cfg; add the script to the shellcheck list.

* **L20 — First-boot re-run clobbers config; persistence auto-partitions without consent.**
  `scripts/fr-first-boot.sh:45` (`assign-interfaces --force`) and `:64` (regenerates the
  admin password) if `.first-boot-done` is lost — silent config loss and an invalidated
  credential; `systemd/fr-persistence-setup.service:17` → `persistence.py:226-254` appends a
  partition to whatever disk the ISO booted from (it never touches existing partitions and
  refuses CD/loop/RO — good — but a laptop with the ISO dd'd to its internal disk gets
  repartitioned). *Fix*: refuse `--force` when `config.yaml` exists; require an explicit
  cmdline opt-in for auto-partitioning.

* **L21 — The audit log is writable by the process it audits.** `paths.py:185` puts
  `audit.log` in `WEBUI_STATE_DIR` (0750, owned by `fr_os-webui`), so a compromised webUI can
  truncate or forge audit entries. *Fix*: write audit records through the privileged helper
  (append-only, root-owned), or at least make the file root-owned 0640 with a group the webUI
  can only append to (immutable flag / separate append-only daemon).

* **L22 — Corrupt `auth.json` turns into a 500 on every page.** `admin_account.py:122-131`
  (`json.loads` and `data["username"]`/`entry["password_hash"]` are uncaught) — a partial
  write or manual edit breaks the whole webUI with a stack trace instead of a clear
  "account file is corrupt, run `firewall-cli set-admin-password`" message.
  *Fix*: catch `json.JSONDecodeError`/`KeyError`/`OSError` and raise a typed, user-facing
  error (and make `_write` atomic — it already is, via `tmp` + `replace`).

---

## What is done right

Acknowledging these matters for calibrating the findings above:

* **RBAC is genuinely centralised and tested.** Every protected route depends on
  `require_login` (`webui/deps.py:97-125`), which re-reads the account on each request (role
  changes and password changes take effect immediately via `session_version()`), and
  `tests/webui/test_rbac.py` walks **every** registered unsafe route (cross-checked against
  the OpenAPI schema) asserting viewers get 403 and anonymous callers get redirected. I
  independently enumerated all 65 routes: only `/login`, `/logout`, `/ztna/login`,
  `/ztna/status` and `/metrics` lack an auth dependency, all deliberate.
* **No command injection anywhere.** Zero uses of `shell=True`, `os.system`, `eval`, `exec`,
  `pickle.load` or non-safe `yaml.load` in the tree; every subprocess is an argv list
  (`nft`, `ip`, `bpftool`, `journalctl`, `systemctl`, `pip3`, `kea-dhcp4`, `openssl`,
  `dmidecode`, `clang`). Untrusted strings that reach `nft` element syntax (IPs, MACs) are
  validated with `ipaddress`/strict regexes first (`bruteforce.py:62-74`,
  `ids_quarantine.py:66-78`, `ztna.py:93-97`, `iot_isolation.py:48-62`).
* **No path traversal / file-upload surface.** No route accepts a caller-supplied file path
  or upload; the helper protocol deliberately has no path parameters
  (`helper/protocol.py:14-16`).
* **Templating escapes by default** — no `|safe`/`Markup` anywhere in the templates, and
  flash messages are rendered from a single place (`base.html:58-59`).
* **Fail-closed firewall design once applied**: `policy drop` on input and forward, jail and
  quarantine drops at the very top before loopback and established state
  (`nft/builder.py:160,166-179,193`), `nft -c` validation before every load
  (`apply.py:81`), backups before every apply, and snapshot/restore of the four
  runtime-state sets across every reload (`provision.py:107-165`).
* **BPF bounds-check discipline is excellent** — every packet dereference is guarded by a
  `cursor + N <= data_end` check in the same statement group, the `opaque()` asm barrier
  defeats clang strength-reduction, there are no packet-dependent loop bounds, no indirect
  map indexing with packet-derived indices, and the *only* `XDP_DROP` in 962 lines is
  reached after a genuine LPM match.
* **Hashing and sessions**: PBKDF2-HMAC-SHA256 with per-password salt, constant-time
  comparison, timing equalisation for unknown users, session cookies bound to the password
  hash version, `httponly` + `SameSite=Lax` + `Secure`, and a 32-byte random signing key
  written 0600.
* **No default credentials of any kind**: no `--root-password`, no baked password, no live
  user (the installer deliberately excludes `user-setup`/`sudo`), and the generated password
  is ~144 bits of `secrets.token_urlsafe(18)` — the problem is only *where it is written*
  (H1).
* **Disclosed limitations**: the missing update-signature verification is stated honestly in
  code, docs and the UI rather than hidden.

---

## Test coverage: what exists vs. what is missing

**Exists** (817 tests): full config-schema validation, nft builder rendering, schedule/DST
logic, RBAC walk over every route, auth/first-run/brute-force behaviour, helper wire
protocol round-trips, update schema, installer shellcheck + `systemd-analyze verify`,
persistence partition maths, packaging completeness, XDP key/event/attach-state unit tests,
and a real root-only XDP live test in network namespaces. The QEMU boot test actually boots
the ISO three times.

**Missing (would have caught, or should now guard, the findings above):**

1. No test that a reboot re-attaches XDP — the closest test enshrines H4's skip.
2. No test that `save_config` preserves `config.yaml` mode/owner (H3) — `_write_atomic` is
   entirely untested.
3. No test asserting socket units are `0660`/`SocketGroup=` (H7) — nothing checks the actual
   access control of either root daemon.
4. No test that a password never appears in a world-readable file (H1), or that the first-run
   window is closed before `fr-webui` starts (C1).
5. No test that *some* drop-all baseline exists when the config is missing, or that
   `fr-firewall` has an ordering relationship with `nftables.service` (H2/M3).
6. No extraction symlink/hardlink test (M5); no `previous_version`-validation test (M6);
   no test that `update.repo` is what apply uses (M7); no concurrency/lock tests (M8); no
   "restart fails after pip succeeds → rollback still possible" test (H6).
7. No adversarial/malformed ClientHello corpus (M1), no failure-path tests for
   `sync_blocklist` mid-apply (M11), no logger-restart test (M12).
8. No permission tests asserting an unprivileged user cannot `bpftool map update` the pinned
   blocklist (L10).
9. `tests/test_xdp_sni_key.py` referenced by three files does not exist (L18).
10. **No CI runs any of the above** (M18).

---

## Items that need verification (cannot be settled from this repository alone)

1. Whether `ssh.service`, `nftables.service` and `kea-dhcp4-server.service` end up *enabled*
   in the built image (determines practical severity of H2, M3 and M15).
2. Whether root is left locked and whether *any* console login exists on the image (no
   `--root-password`/`chpasswd`/user-setup anywhere).
3. The exact `python3` patch level in the image (M5: is `filter="data"` available?) and
   whether SSH host keys are identical across two independent builds (M15).
4. Whether releases are signed anywhere out-of-repo (H5) — no signing workflow exists here,
   and no consumer would check the signature anyway.
5. The deployment layout for `ensure_compiled` (M13): does the image ship a precompiled `.o`,
   and are the candidate source paths writable by non-root?
6. Target image's `kernel.unprivileged_bpf_disabled` and the effective bpffs/pin modes (L10).
7. Whether any external/boot component provides update health-checking (M9) — none in repo.
8. Whether the verifier accepts `bpf/xdp_sni_filter.c` on a stock toolchain given the
   uninitialised LPM-key padding (L12).
9. Starlette/Jinja2 autoescape is assumed on (default for `Jinja2Templates`); the code never
   sets it explicitly — worth pinning down in a dependency upgrade.

---

## Findings per severity

| Severity | Count |
|----------|-------|
| critical | 1 |
| high     | 7 |
| medium   | 18 |
| low      | 22 |
| **total**| **48** |
