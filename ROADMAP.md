# Roadmap

Phase-by-phase development plan. At the end of every phase the system must
be in a working, testable state on a plain Debian VM before the next phase
starts. For the architecture decisions, see: [ARCHITECTURE.md](ARCHITECTURE.md).

## Phase 1 – Firewall engine core — **done**

- [x] `ARCHITECTURE.md` / `ROADMAP.md`
- [x] YAML config schema design (interfaces, zones, rules, NAT)
- [x] `frfw` Python package: schema + validation (`frfw.config`)
- [x] nftables ruleset generator (`frfw.nft`)
- [x] `firewall-cli` (`validate` / `render` / `apply`)
- [x] Unit tests, with real `nft -c` syntax checking
- [x] Example homelab config (`examples/config.yaml`)

**Acceptance criterion**: `firewall-cli apply examples/config.yaml` on a
plain Debian VM (with nftables installed) generates and loads the ruleset
without errors, and `nft list ruleset` shows the expected rules.

## Phase 2 – System integration — **done**

- [x] A systemd unit for the firewall engine (automatic config apply at
      boot): `systemd/fr-firewall.service`, following the pattern of
      Debian's own `nftables.service` (early boot,
      `Before=network-pre.target`)
- [x] A systemd unit for the webUI: `systemd/fr-webui.service`, pointing
      at a placeholder binary for now (`fr-webui-placeholder`), with the
      actual FastAPI app arriving in phase 3 *(replaced with the real
      `fr-webui` binary in phase 3, see below)*
- [x] Automatic network interface detection -- unlike originally planned,
      this doesn't parse `ip link` output, it reads the
      `/sys/class/net/` sysfs tree directly (`frfw.netdetect`): gives
      the same information, has no dependencies, and is much easier to
      test (a fake sysfs tree in a tmp directory).
      `firewall-cli detect-interfaces` lists the discovered NICs, and
      `firewall-cli assign-interfaces --wan ... --lan ... [--opt zone:dev]`
      generates a minimal, valid config from that (a pfSense-like "which
      NIC is what" install step, in a non-interactive/scriptable form)
- [x] Config persistence: `/etc/fr_os/config.yaml` is the canonical
      location (`frfw.paths`), every CLI command defaults to it; before
      every real (non-dry-run) `apply`, the running ruleset is saved to a
      timestamped backup (`/etc/fr_os/backups/`, 10 versions kept by
      default), and `firewall-cli rollback [--list]` restores the most
      recent one
- [x] Root privilege separation: `frfw.helper` -- a root-running
      "apply-helper" daemon (`firewall-helper` / `fr-apply-helper.service`)
      listens on a Unix socket (`fr-apply-helper.socket`, socket
      activation, with group-based access control) for a minimal JSON
      protocol (`ping`/`apply`/`rollback`); the endpoint never accepts a
      file path from the caller, it always uses the canonical
      config/backup directory -- so the future unprivileged webUI can't
      gain general file-read/write or command-execution capability
      through the root daemon either

**Acceptance criterion**: on a fresh Debian VM, after running
`scripts/install-system-integration.sh`, `systemctl enable --now
fr-firewall` makes the system automatically apply the last-saved config
(`/etc/fr_os/config.yaml`) at boot; interface detection and assignment
can be run from the command line (`firewall-cli detect-interfaces`,
`firewall-cli assign-interfaces`); after applying a bad config,
`firewall-cli rollback` restores the previous one.

## Phase 3 – WebUI — **done**

- [x] A FastAPI backend on top of the `frfw` engine (`frfw.webui`) -- the
      webUI edits the config at the dict level
      (`frfw.webui.config_store`), then re-runs the whole document
      through `frfw.config.parse_config` before every save: there's no
      separate concept of "valid according to the webUI", only "valid
      according to the `frfw` schema"
- [x] Base screens (server-rendered Jinja2 + simple CSS, no SPA framework,
      as planned in ARCHITECTURE.md): dashboard/status, interfaces
      (along with the detected NICs), rules, NAT (masquerade +
      port-forward), DHCP
- [x] **DHCP added to both the config schema and the engine** (not just
      the webUI) -- this turned out to be necessary along the way:
      choosing the `dhcp` backend (Kea, agreed with the user) required a
      new schema section (`interfaces[].address`, `dhcp.<zone>`), a Kea
      JSON generator (`frfw.kea`, with a real `kea-dhcp4 -t` syntax
      check), and an interface-address-apply module (`frfw.ifaddr`,
      `ip addr`-based); these are all tied together by a shared
      `frfw.provision.apply_all` in address→firewall→DHCP order, used by
      both the CLI and the webUI
- [x] Admin login: a single local admin account
      (`frfw.admin_account`, PBKDF2-HMAC-SHA256 -- deliberately not
      bcrypt/argon2, to avoid a compiled C-extension dependency), a
      signed session cookie (`itsdangerous`); `firewall-cli
      set-admin-password` sets/resets it from the CLI
- [x] HTTPS by default: a self-signed certificate generated on first
      startup (`frfw.webui.tls`, via calling `openssl`); the webUI runs
      as the unprivileged `fr_os-webui` user, binding to port 443 via
      `AmbientCapabilities=CAP_NET_BIND_SERVICE` (the same pattern Kea's
      own systemd unit uses)
- [x] Config save/restore: saving goes through the privileged
      apply-helper (the `save_config` command, see below) -- **git-based
      versioning was not built** (`ROADMAP.md` originally marked it as a
      "maybe"); instead, the nftables ruleset-level backup/rollback
      (phase 2) remains the only "revert to the previous one" mechanism.
      Config-level (not just ruleset-level) versioning is an open
      question for a future iteration.
- [x] Root privilege separation extended: a new `save_config` command in
      `frfw.helper` (JSON protocol, see phase 2) validates and writes a
      YAML config -- so the webUI never writes directly to
      `/etc/fr_os/config.yaml`, only through the helper

**Acceptance criterion**: a complete WAN/LAN rule set + NAT can be built
through the browser-accessible interface, and after saving, the `frfw`
layer generates the exact same YAML we'd hand-write from the CLI. ✅
Verified: the
`tests/webui/test_routes.py::test_full_wan_lan_nat_round_trip_matches_cli_expectations`
test builds a complete WAN/LAN/NAT config with browser-simulated (FastAPI
`TestClient`) requests, which is then processed by
`frfw.config.load_config` + `frfw.nft.build_ruleset` -- on the exact same
code path the CLI would go through.

## Addendum – AI IDS/IPS (mock) — **done**

An addendum inserted after phase 3, before phase 4 (XDP/eBPF), since the
UI and the config core were already ready to receive it. **Not part of
the original 6 phases** — it landed here because the real
implementation's prerequisite (phase 4's traffic capture) doesn't exist
yet.

- [x] An `ai_ids` schema section (`enabled`/`learning_days`/`retrain_time`/
      `excluded_macs`), with full `frfw.config.loader` validation
- [x] `frfw.ai_ids.AIIDSEngine` — an **explicit mock engine**: builds its
      "known devices" list from the static DHCP reservations, with
      MAC-based deterministic (not re-randomized) fabricated profiles
      (a risk label, top protocols, count of known domains), plus
      persisted state (a locked flag/retrain timestamp) for the
      simulated learning %. `train_isolation_forest` is a stub that
      raises an explicit `NotImplementedError`, for a future
      scikit-learn integration.
- [x] `firewall-cli ai-ids-retrain` (unprivileged) +
      `fr-ai-ids-retrain.timer`/`.service` (daily, 03:30 by default) —
      infrastructure for the daily retrain, actually performing the
      (mock) retrain
- [x] WebUI: an "AI IDS/IPS" screen (device table, Force
      Retrain/Lock Profile buttons, settings), a global learning progress
      bar on the dashboard — each with a clearly visible "MOCK DATA"
      warning
- [x] **Security-model consistency**: Force Retrain/Lock Profile do
      *not* go through `frfw.helper` (no need to, it's a root-free
      userspace state change) — only saving the config (the `ai_ids`
      section) goes through the usual `save_config`. See
      [ARCHITECTURE.md](ARCHITECTURE.md#ai-idsips-mock).

**Acceptance criterion**: AI IDS can be turned on and off through the
webUI, the device table is populated from DHCP reservations, Force
Retrain/Lock Profile have an immediately visible effect, and the screen
clearly flags that the data is mock. ✅ Verified:
`tests/test_ai_ids_schema.py`, `tests/test_ai_ids_engine.py`,
`tests/webui/test_ai_ids_routes.py` — the existing 108 tests also keep
passing without issue (141 total).

**Open question for the future**: `fr-ai-ids-retrain.timer` uses a static
`OnCalendar=03:30`, and doesn't automatically follow the
`ai_ids.retrain_time` config value (this would need a privileged
timer-drop-in rewrite — a small-scope but non-trivial addition).

## Phase 4 – XDP/eBPF fast path: kernel-level TLS SNI filter — **kernel program + Python orchestrator + webUI done, performance measurement open**

> **Correction (phase 16):** the filter must be attached to the LAN-side
> interfaces to filter what LAN clients connect to -- XDP only sees
> received packets, so the WAN attachment this phase recommended never
> saw an outbound ClientHello. Verified with network namespaces, now an
> automated test; see phase 16.

The scope, agreed with the user, changed from the generic IP fast-drop
blocklist originally planned here to a more specific, more practical
function: **traffic dropped/passed in kernel space based on the SNI
(domain name) read out of the TLS ClientHello**. Full rationale,
architecture, and a summary of the (surprisingly long) struggle with the
BPF verifier:
[ARCHITECTURE.md](ARCHITECTURE.md#xdpebpf-fast-path-kernel-level-tls-sni-filter-phase-4).

- [x] **Kernel-side program written and actually verified**
      (`bpf/xdp_sni_filter.c`): TLS record/handshake/ClientHello/
      extensions parsing, SNI extraction, `BPF_MAP_TYPE_LPM_TRIE`
      blocklist lookup (a `reverse("." + hostname)` key scheme, which
      correctly blocks subdomains but not names that are only
      character-level similar and not actual subdomains), `XDP_DROP` on
      a match, an async `BPF_MAP_TYPE_RINGBUF` event for userspace
      logging. Not just compiled -- actually loaded and accepted by the
      real kernel BPF verifier
      (`ip link set dev lo xdpgeneric obj xdp_sni_filter.o sec xdp`),
      and tested end-to-end with a hand-assembled, real TLS 1.3
      ClientHello: a connection with a blocklisted SNI gets completely
      stuck (every retransmission is also dropped), a non-blocked SNI
      goes through intact, and the ring buffer event decodes correctly
      on the userspace side.
- [x] **`frfw.xdp` Python orchestrator written**: compilation
      (`ensure_compiled`, only if there's no precompiled `.o`), loading +
      pinning once, shared across every interface (`load_and_pin`,
      `bpftool prog loadall ... pinmaps ...`), attaching with a
      native→generic XDP mode fallback (`attach`), syncing the blocklist
      with the config (`sync_blocklist`), and a direct `ctypes` `libbpf`
      binding for lock-free ring buffer reads (`RingBufferReader`) --
      each of these actually tested in this sandbox, with no mocks,
      against the real kernel/bpftool/libbpf.
- [x] **Config schema + loader validation**: an `xdp_sni_filter` section
      (`enabled`, `interfaces`, `blocklist`), checking hostname format
      and the kernel-side `MAX_SNI_LEN` limit.
- [x] **`frfw.provision.apply_all`** calls `frfw.xdp.sync_sni_filter` as
      the fourth step.
- [x] **`fr-xdp-sni-logger` systemd daemon**: continuously reads the
      ring buffer (blocking poll, not busy-wait) and logs matches to
      journald.
- [x] **`firewall-cli xdp-status`**: shows attached interfaces + packet
      counters.
- [x] **WebUI screen** (`/xdp`): a status card (interface + a
      green/yellow/red badge for native/generic/disabled-or-not-yet-applied
      state), settings (enabled/interfaces/blocklist, saved via
      `frfw.webui.actions.try_save`, the same "only modifies the config,
      the actual attach happens on the next apply" pattern as every
      other screen), per-domain removal, and a live log over
      Server-Sent Events (`GET /xdp/logs/stream`, tailing `journalctl -u
      fr-xdp-sni-logger.service -f` -- not a direct, root-only read of
      the kernel ring buffer), with plain vanilla JS `EventSource` on the
      frontend, no SPA framework.
- [ ] **Live-build integration**: precompiling the `.o` file and
      packaging it into the image as part of the build pipeline.
- [ ] Performance testing (iperf3-style, with real TLS traffic) on
      10G/40GbE hardware, in native (`xdpdrv`) mode — this sandbox isn't
      suited for this (no suitable NIC/traffic generator); the program's
      *correctness* is proven, but the native-mode, high-packet-rate
      *performance advantage* can only be measured on proper test
      hardware.
- [ ] Decision: is XDP enough, or is DPDK needed (depends on the
      performance measurement above)
- [ ] **Real AI IDS data collection**: replacing the mock `frfw.ai_ids`
      engine with detection built on real per-device flow features
      (packet size/timing distribution, protocol mix, destination
      diversity), using scikit-learn's `IsolationForest`
      (`frfw.ai_ids.train_isolation_forest` is already prepared for
      this, but currently a stub raising `NotImplementedError`) -- this
      would need a separate data source, independent of the TLS SNI
      filter, which the work above doesn't provide.

**Acceptance criterion** (original wording): a measured, documented
performance improvement between XDP on and off, on the same hardware --
this part remains open, for lack of real 10G/40GbE hardware (see above).
Functional correctness (the filter actually, provably safely, and per
spec works), on the other hand, has been proven in this phase.

## Phase 5 – Automated installer

- [x] A live-build-based hybrid live ISO (`installer/live-build/`,
      `installer/build-live-image.sh`) -- the full frfw stack (nftables,
      Kea DHCP, Python/pip packages, webUI, AI IDS mock) preinstalled
      into the squashfs image
- [x] A first-boot script (`scripts/fr-first-boot.sh` +
      `systemd/fr-first-boot.service`): admin password generation
      (`firewall-cli set-admin-password --generate`), interface
      detection, enabling and starting every fr-*.service -- idempotent,
      runs only once
- [x] The build pipeline can also be triggered from CI
      (`.github/workflows/build-installer.yml`, `workflow_dispatch`)
- [x] **A real, end-to-end build run verified**: the full
      `installer/build-live-image.sh` pipeline actually ran and produced
      a real, bootable (`file`: "ISO 9660 CD-ROM filesystem data
      (DOS/MBR boot sector), bootable") ~327 MB hybrid ISO -- unpacking
      and checking the squashfs: the `frfw` package installed via pip,
      `firewall-cli` in place, all 7 `fr-*.service`/`.timer` units
      present, `fr-first-boot.service` enabled (under
      `multi-user.target.wants/`), the temporary `/opt/frfw-src` source
      directory correctly removed. The first-boot hook's logic (pip
      install + service enable) was also run manually, separately,
      inside the chroot, with the same result.
- [ ] **Not yet verified**: actually booting the ISO on a virtual or real
      machine (BIOS boot, a real run of the first-boot script on a fresh
      system, reaching the webUI on first boot) -- the verification
      above statically validated the build's output (the squashfs's
      contents), not a live boot.

**Known limitations** (limitations of this one specific, very old,
Ubuntu-patched live-build snapshot (`3.0~a57`) -- see the header comments
in `installer/live-build/auto/config` for the full, source-level
rationale on every point):
- ~~BIOS/syslinux only, no UEFI support.~~ Closed by phase 13 below.
- `--debian-installer false`: live-build's own "install to disk" wizard
  (`--debian-installer live`) isn't enabled, because this snapshot would
  try to install a hardcoded, nonexistent package list (`lilo`,
  `linux-image-2.6-amd64`) for it in any non-Ubuntu mode. This is why the
  current ISO is a **complete, working live system** you can boot into
  and use right away -- but not a classic "copy to disk" install wizard.
  With a fresh (not this sandbox's) live-build package, this would
  likely just work.
- Several small bugs stemming from this same snapshot's
  Debian-incompatible defaults were fixed/documented by hand:
  Ubuntu-specific mirror/keyring/kernel-package names, a missing `rsvg`
  binary (splash graphic removed), a missing `bootlogo` cpio archive,
  `isohybrid` being looked for under the wrong package name, and chroot
  hooks needing to use an older `config/hooks/*.chroot` convention
  (the `config/hooks/live/` subdirectory is silently ignored here).

**Acceptance criterion**: installed from USB, the user gets a working
webUI with no manual package installation/terminal work. The build side
(the squashfs's contents) has been verified, ✅. Actually booting from
USB + the first-boot experience on a real/virtual machine hasn't been
tried yet -- this is the last step, requiring hardware/VM access, before
this phase can be closed.

## Phase 6 – Update mechanism — **done**

- [x] Version checking + changelog: `frfw.update.check_latest`/
      `list_releases`, against the configured (or default) GitHub repo's
      Releases API, with no privilege, queried fresh on every webUI page
      load (no separate "last checked" state -- see the module's own
      docstring for why it isn't needed)
- [x] An update process launchable from the webUI: an `/update` screen +
      a separate, privileged `fr-update-helper` daemon/socket
      (deliberately NOT an extension of the existing firewall
      apply-helper -- its whole design is "only touches
      CONFIG_PATH/BACKUP_DIR, no general command execution", and package
      installation/service-restart is a far broader privilege surface,
      see the `frfw.helper.update_protocol` docstring)
- [x] Rollback: `apply_update` records the pre-update version as
      `previous_version`; `rollback_update` reinstalls it. It goes back
      exactly one level (a rollback can't itself be rolled back). If the
      previous version's unpacked source is still present under
      `/opt/fr_os/releases` (a successful update never deletes it),
      rollback also works without network -- which matters exactly when
      the bad update also broke the network.
- [x] `firewall-cli update check/apply/rollback` -- the same pattern as
      `apply`/`rollback`: the CLI runs with whatever privilege the
      operator started it with, while the webUI never calls them
      directly, only through the privileged socket
- [x] Tests: `frfw.update` (version parsing/comparison, every HTTP
      branch of check_latest/list_releases with monkeypatching, the full
      apply/rollback flow on both the success and failure branch,
      path-traversal protection on tarball extraction), the
      update-helper socket protocol (like the firewall apply-helper's),
      webUI routes, config schema/loader -- see
      `tests/test_update*.py`, `tests/webui/test_update_routes.py`

**Known limitation, stated openly**: there's no cryptographic signature
check on the downloaded release -- the HTTPS connection to GitHub is the
one trust boundary right now, the same as with a plain `git clone` or a
`pip install` from an unpinned index. Release signing (e.g. with
`cosign` or a GPG-signed checksum file) is a reasonable next step, once
there are real, tagged releases to sign.

**Not yet verified in a real scenario**: this repo currently (0.1.0,
under development) has no real GitHub releases, so "update from an older
version to a real newer one" has never run end-to-end against live
GitHub releases -- only with a monkeypatched network layer (see above)
and an actual, live call to `check_latest`/`list_releases` against the
project's own (currently empty) repo (which correctly returns a "no
release yet" response, handled as a 404). Once there's a first real
tag/release, it's worth running a full update from the webUI's Update
screen on a VM end to end.

**Acceptance criterion**: a VM with an older install can be updated from
the webUI without using a terminal, with both success and failure
handled cleanly. The mechanism (check/apply/rollback, failure branches,
state persistence) is verified with unit tests; the "real update of an
older-install VM" end-to-end scenario hasn't been tried yet, for lack of
a real release (see above).

## Phase 7 – Identity-based Zero Trust network access (ZTNA) — **done**

Goal: a 100% local (no Okta/Azure AD/cloud dependency), homelab-friendly
identity-aware login gate in front of the LAN/"Production Server Zone",
where the data plane (the actual packet filtering) still runs 100% in
kernel space (nftables) -- no userspace reverse proxy (Envoy/Squid) in
the traffic path, so the 40 Gbps target speed isn't compromised. Full
rationale, architecture, and the struggle with `flush ruleset`:
[ARCHITECTURE.md](ARCHITECTURE.md#identity-based-zero-trust-network-access-ztna-phase-7).

- [x] **Schema**: a `ztna` config section (`enabled`, `session_ttl_seconds`,
      `users` -- username + PBKDF2-HMAC-SHA256 password hash, reusing
      the existing `frfw.admin_account` scheme), with full
      `frfw.config.loader` validation (valid username format, unique
      usernames, TTL range, "at least one user required if enabled is
      true"). The existing `Rule` dataclass got a `require_ztna: bool`
      field -- there's no separate "protected zone" concept, it reuses
      the existing rule engine's matching logic.
- [x] **Data plane**: `frfw.nft.builder` renders an nftables named set
      called `authenticated_ztna_users`, with `flags dynamic,timeout`
      (only if `ztna.enabled`); every `require_ztna: true` rule gets an
      `ip saddr @authenticated_ztna_users` match. Elements are added to
      the set with their own individual TTL -- expired IPs are evicted by
      the **kernel** itself, with zero cron jobs/userspace background
      processes. Verified for real: an element added with a 5-second TTL
      was gone from the set within 6 seconds.
- [x] **Control plane**: `GET/POST /ztna/login` (`frfw.webui.routes.ztna`,
      a public route) checks against the stored hashes in a timing-safe
      way, then on a successful login asks the root-running
      `fr-apply-helper`, via a new `authorize_ztna` unix-socket command
      (`frfw.helper.protocol/server/client`), to add the client's
      source IP to the kernel set with the TTL set in the config. `GET
      /ztna/status` (also public) queries the remaining session time
      live via a new `ztna_status` helper command -- **there's no
      separate browser-side session cookie**, the sole source of truth
      is the kernel set's current contents. Finding: even a read-only
      `nft list` requires root/`CAP_NET_ADMIN`, so the `ztna_status`
      query also goes through the privileged helper, not directly from
      the webUI process.
- [x] **The `flush ruleset` problem solved**: `frfw.provision.apply_all`
      brackets the nftables-apply step with
      `frfw.ztna.snapshot_before_reload`/`restore_after_reload`, so that
      an arbitrary config save (e.g. a DHCP setting) doesn't
      accidentally log out an active ZTNA session because of `flush
      ruleset`. Confirmed with a real, non-mocked integration test (a
      real nft set flush + restore, with the correct remaining TTL).
- [x] **Admin screen** (`/ztna`): on/off + TTL setting, user management
      (adding with a password-length limit, removal), and a list of
      `require_ztna: true` rules -- the same "only modifies the config,
      the actual gating takes effect on the next apply" pattern as every
      other screen.
- [x] Tests: `tests/test_ztna.py` (the `frfw.ztna` module, with a real
      kernel-eviction test), `tests/test_ztna_schema.py` (schema/loader),
      `tests/test_builder.py` (set rendering, `require_ztna` matching,
      real `nft -c` syntax checking), `tests/test_helper.py` (the
      socket protocol's new commands), `tests/test_provision.py`
      (snapshot/restore wiring), `tests/webui/test_ztna_routes.py`
      (admin + public routes) -- the full test suite (310 tests) runs
      with no regressions.

**Known limitation, stated openly**: there's no rate-limiting/lockout on
`/ztna/login` -- this is consistent with the existing admin `/login`, but
neither protects against brute-force in production. Instead of the
original "encrypted YAML" idea, PBKDF2 password hashing was built (not
reversible encryption) -- this is the correct, safer approach for stored
credentials.

**Acceptance criterion**: a zone protected by a `require_ztna: true` rule
is only reachable after a successful `/ztna/login`, the session
automatically ends when the configured TTL expires, entirely via the
kernel (with no userspace code running), and a concurrent config
save/apply doesn't interrupt another user's active session. ✅ Verified
with unit tests and real (non-mocked) nftables integration tests; a real
40 Gbps performance measurement is open for the same reason as phase 4's
XDP filter (no suitable test hardware in this sandbox).

## Phase 8 – Hybrid post-quantum key exchange on the management layer — **done, tested without a real PQC build**

Goal: have the webUI's HTTPS and the host's sshd (if present) offer a
hybrid (classical+PQC) key exchange, falling back to classical unnoticed
for an older client/host. Full rationale, the two version thresholds, and
the "`SSLContext` can't take a group list" finding:
[ARCHITECTURE.md](ARCHITECTURE.md#hybrid-post-quantum-key-exchange-on-the-management-layer-phase-8).

- [x] **Schema**: `pqc.enabled` (`frfw.config.schema.PqcConfig`), with
      full `frfw.config.loader` validation.
- [x] **TLS**: `frfw.pqc.write_openssl_pqc_conf` generates the OpenSSL
      config fragment (`Groups = X25519MLKEM768:X25519:P-256`, or
      classical only, `MinProtocol`/`MaxProtocol = TLSv1.3`), which
      `fr-webui.service` unconditionally points at via `OPENSSL_CONF=`
      -- this, not Python's `ssl.SSLContext`, is the only mechanism that
      actually works for setting a TLS 1.3 group list (see
      ARCHITECTURE.md for the `set_ecdh_curve` limitation, confirmed
      with a direct test). The part that actually can be set via
      `ssl.SSLContext` (TLS 1.3-only) was implemented as
      `frfw.pqc.tls_ssl_context_factory`, through uvicorn's
      `ssl_context_factory=` extension point -- also verified with a
      real `uvicorn.Config(...).load()` call and an actual generated
      certificate.
- [x] **SSH**: `frfw.pqc.sync_ssh_kex` writes/deletes an
      `/etc/ssh/sshd_config.d/50-fr_os-pqc-kex.conf` drop-in (never the
      main sshd_config), matched to the installed sshd's actual
      capability, freshly queried with `sshd -Q kex` -- it never writes
      an `mlkem768x25519-sha256` name without the build already having
      confirmed it back. The generated drop-in is validated with
      `sshd -t` before being applied; on a failed validation the
      previous content (or its absence) is restored, never leaving sshd
      an unparseable config on disk. The daemon is updated with a
      *reload*, never a *restart* (doesn't interrupt live SSH
      sessions).
- [x] **`frfw.provision.apply_all`** calls `sync_tls_pqc_conf` and
      `sync_ssh_kex` as step 6.
- [x] **WebUI**: a `GET /system` admin screen (host capability vs.
      applied state, in a table, on/off toggle), and a small badge on the
      dashboard (`quantum-safe` is only green if the config is enabled,
      the most recent apply wrote a hybrid group, **and** the host's
      OpenSSL actually supports it -- missing any one of these can't be
      papered over by the other two).
- [x] Tests: `tests/test_pqc.py` (38+ cases: version thresholds, direct
      confirmation of the `set_ecdh_curve` limitation, real
      `uvicorn.Config` integration, the restore guarantee on a failed
      `sshd -t` validation, root requirement, dry-run safety),
      `tests/test_pqc_schema.py`, `tests/webui/test_system_routes.py`,
      `tests/test_webui_server.py`, an updated `tests/test_provision.py`
      -- the full test suite (360 tests) runs with no regressions.

**Known limitation, stated openly**: this module **has never been tested
against a real OpenSSL 3.5+ or OpenSSH 9.9+ build** -- this dev sandbox
runs OpenSSL 3.0.13 and has no sshd installed at all. Every capability
check was confirmed directly, on the real binary/interpreter, *for
correctly detecting the absence*, while the positive branch ("the hybrid
group is actually negotiated with a real PQC-capable client/sshd")
should be considered implemented to spec, not the same level of
independently verified fact as the project's kernel-adjacent subsystems
(nftables, XDP, ZTNA). On top of that, the live-build installer's own
base image (phase 5) uses an old snapshot whose OpenSSL/OpenSSH version
is almost certainly below the threshold, so today this feature there
actually only runs the "TLS 1.3-only, classical groups" branch.

**Acceptance criterion**: PQC hybrid mode can be turned on from the
webUI, and after applying, the `/system` screen and the dashboard badge
accurately reflect the host's real capability (never claims a safer
state than reality), and on an old OpenSSL/OpenSSH build the system
silently, cleanly falls back to classical mode. ✅ Verified with unit
tests and the real integrations listed above (uvicorn Config, actual
`set_ecdh_curve` behavior); running a real hybrid handshake end-to-end is
open for lack of an actual PQC-capable build, the same way phase 4's XDP
filter's 10G/40GbE measurement was open for lack of real test hardware.

## Phase 9 – Local DNS/XDP ad-blocker — **done**

Goal: download and dedupe hosts-format blocklists (the StevenBlack
"unified" hosts by default), and serve them from a 100% local,
memory-efficient DNS resolver, with an optional small "critical" subset
in the existing phase 4 XDP LPM trie. **Clarification**: the project
never had its own DNS resolver before this (Kea only did DHCP) -- this
phase introduces the first one, it doesn't extend an existing one. Full
rationale:
[ARCHITECTURE.md](ARCHITECTURE.md#local-dnsxdp-ad-blocker-phase-9).

- [x] **Schema**: an `adblocker` config section (`enabled`,
      `source_urls`, `xdp_critical_limit`), with full
      `frfw.config.loader` validation (URL format, "at least one source
      required if enabled is true", a non-negative integer limit).
- [x] **Download/parse/dedup** (`src/frfw/adblock/__init__.py`): a
      stdlib `urllib.request`-based download (following the project's
      only existing network precedent, `frfw.update` -- no new runtime
      dependency), parallelized across multiple sources with
      `concurrent.futures.ThreadPoolExecutor`, stripping comments/IPs,
      extracting unique domains, and writing them back deduplicated in
      hosts format to `/etc/fr_os/adblock.hosts`.
- [x] **Dedicated DNS resolver** (`src/frfw/adblock/dns_service.py`): its
      own, complete dnsmasq config (`fr-adblock-dns.service`) -- never
      the system's default `dnsmasq.service`/`dnsmasq.conf`, the same
      "one complete generated config, one dedicated service" pattern as
      the Kea DHCP engine.
- [x] **Downloads never happen inside `apply`**: `firewall-cli
      adblock-refresh` (daily via `fr-adblock-refresh.timer`) or the
      webUI's "Refresh now" button (a new `refresh_adblock` apply-helper
      socket command) does the actual downloading;
      `frfw.provision.apply_all` only reconciles whether the resolver is
      running/stopped to match the config, and never touches the
      network.
- [x] **XDP reuse, not a second kernel map**: the "critical" domains go
      into the existing `xdp_sni_filter.blocklist`/
      `frfw.xdp.sync_blocklist` mechanism, merged in memory (never
      written back into `config.yaml`) -- with `xdp_critical_limit == 0`
      (the default), this step doesn't touch XDP at all.
- [x] **WebUI**: `GET /adblock` (a live domain counter and resolver
      status, computed with no privilege -- counting a hosts file's
      lines and `systemctl is-active` both need no root), an on/off
      toggle + source lists + XDP-limit setting, a "Refresh now" button;
      a dashboard summary.
- [x] Tests: `tests/test_adblock.py` (parse/dedup/fetch/refresh, 21
      cases), `tests/test_adblock_schema.py` (schema/loader, 13 cases),
      `tests/test_adblock_dns_service.py` (config rendering, resolver
      reconciliation, real `dnsmasq --test` syntax checking, 18 cases),
      `tests/webui/test_adblock_routes.py` (9 cases), an updated
      `tests/test_provision.py` (adblock+XDP merging) and
      `tests/test_helper.py` (the `refresh_adblock` socket command) --
      the full test suite (425 tests) runs with no regressions.

**Known limitation, stated openly**: the DHCP clients' DNS server isn't
automatically switched to this resolver (`DhcpPool.dns_servers` still
serves whatever the admin explicitly set) -- this would be a separate,
non-trivial integration step, which this phase deliberately did not do
as a silent side effect. The actual blocking mechanism was confirmed by
hand, for real (`dig` against a real dnsmasq instance, a listed domain
resolving to `0.0.0.0`, a non-listed domain forwarded upstream) -- this
specific live-query scenario, however, wasn't turned into an automated
test, because in this CI sandbox a dnsmasq child process started from
inside pytest doesn't respond to queries despite binding to the correct
port -- an environment quirk, not an frfw code bug (see ARCHITECTURE.md
for the detailed diagnosis).

**Acceptance criterion**: the ad-blocker can be turned on from the
webUI, "Refresh now" downloads and dedupes the configured lists, `apply`
starts the dedicated DNS resolver with the fresh list, and the
`/adblock` screen shows an accurate, live domain count. ✅ Verified with
unit tests, a real `dnsmasq --test` syntax check, and manual, live,
end-to-end `dig` testing (see above for why the latter isn't automated
in this sandbox).

## Phase 10 – In-memory and kernel-level brute-force protection — **done**

Goal: stop password guessing against the `/login` and `/ztna/login`
endpoints in two, strictly separated layers: the non-root webUI process
counts failed attempts per source IP in memory, and once a threshold of
5 failed attempts / 5 minutes is crossed, tells the kernel — via the
privileged `fr-apply-helper` — to put that IP into an nftables named set
called `bruteforce_jail`, with a native kernel timeout (1 hour by
default) -- zero userspace CPU load during a flood, no Redis/fail2ban/
other external dependency. Full rationale:
[ARCHITECTURE.md](ARCHITECTURE.md#in-memory-and-kernel-level-brute-force-protection-phase-10).

- [x] **`frfw.webui.auth_rate_limiter`**: a thread-safe (`threading.Lock`
      -- the project's routes are plain `def`s, not `async def`, so
      uvicorn runs them in a thread pool, making `asyncio.Lock` the
      wrong primitive), sliding-window `BruteforceGuard` (5 failed
      attempts / 300s), memory-bounded with no dedicated cleanup thread
      (every 100th call triggers a sweep that evicts long-expired,
      one-off IPs). The shared `reject_failed_login()` helper is called
      by both `/login` and `/ztna/login`.
- [x] **Unix-socket protocol extension**: a new `ban_ip` command
      (`frfw.helper.protocol/server/client`) -- the webUI decides *when*
      to ban, but the actual `nft` call always goes through the
      root-running helper, the same privilege separation as ZTNA's
      `authorize_ztna` command.
- [x] **`frfw.bruteforce`** (a deliberate structural mirror of
      `frfw.ztna`): `ban_ip()`, `snapshot_before_reload()`/
      `restore_after_reload()` to solve the `flush ruleset` problem (see
      below).
- [x] **Nftables schema** (`frfw.nft.builder`): an always (not
      conditionally, unlike the ZTNA set) rendered `bruteforce_jail`
      named set (`flags timeout`) and an `ip saddr @bruteforce_jail
      drop` rule as the very first line of `chain input` -- even before
      the `lo` accept.
- [x] **`frfw.provision.apply_all`**: the jail set bracketed with
      snapshot/restore around the nftables apply, the same as the ZTNA
      session set -- an admin-side, completely unrelated config save
      (`flush ruleset`) never silently lifts an active ban.
- [x] Tests: `tests/test_bruteforce.py` (12 cases, 4 of them real,
      root-running `nft` integration -- an element added with a 2s
      timeout is evicted by the kernel itself with no code running),
      `tests/test_auth_rate_limiter.py` (13 cases, including a 5-thread
      concurrency test confirming the threshold is crossed exactly
      once), an updated `tests/test_builder.py` (2 new cases),
      `tests/test_provision.py` (3 new cases), `tests/test_helper.py`
      (5 new cases for the `ban_ip` socket command), and the two webUI
      route test files (`tests/webui/test_auth.py` +4,
      `tests/webui/test_ztna_routes.py` +3, including one confirming the
      counter is per-IP, not per-endpoint -- an attacker can't dodge the
      threshold by alternating between the two login forms) -- the full
      test suite (467 tests) runs with no regressions.

**Corrections to the original request** (see ARCHITECTURE.md for
details): instead of the requested `{"action": "ban_ip", ...}`, the
existing `"cmd"` field was used (for consistency with the whole
protocol); `threading.Lock` instead of an "async lock" (the routes are
synchronous `def`s); the logic was placed in the actual
`frfw/nft/builder.py` (set/rule) and `frfw/provision.py`
(snapshot/restore bracketing) instead of a "provision/ package"; and the
literally requested `flags timeout` was used instead of `flags
dynamic,timeout`, after directly confirming with real `nft` commands
that this alone is sufficient for a per-element timeout override on this
nftables version.

**Acceptance criterion**: 5 consecutive failed passwords from the same
source IP, on either `/login` or `/ztna/login`, within 5 minutes, puts
that IP into the kernel's `bruteforce_jail` set (with a 1-hour default
ban), and every packet it sends from then on is dropped by the firewall
on the very first rule -- all without the webUI process ever running a
single root-privileged command. ✅ Verified with unit tests, real `nft`
integration (the kernel evicts the expired ban on its own), and webUI-
level integration tests running through the full login path.

## Phase 11 – Real-time, kernel-assisted AI IDS/IPS — **done**

Replaces the earlier explicit-mock engine (see the "AI IDS/IPS (mock)"
addendum above) with an actual anomaly detector: a lightweight,
pure-stdlib sliding-window scorer profiling each source IP's connection-
rate, destination-diversity, and XDP SNI-blocklist-hit behavior against
its own recent baseline, running as its own out-of-band systemd daemon
that quarantines a flagged IP in the kernel through the same
privilege-separated pattern as every other enforcement action in this
project. **Important correction, up front**: the request assumed
`fr-xdp-sni-logger` alone could supply signal for all three requested
features -- checked against what that daemon actually logs (only a
*blocklist-matched, dropped* packet, never a plain pass), it structurally
cannot supply connection-rate or destination-diversity signal at all.
Those two come from a second, independent, already-active source
instead: the kernel's own connection tracker. Full rationale:
[ARCHITECTURE.md](ARCHITECTURE.md#real-time-kernel-assisted-ai-idsips-phase-11).

- [x] **`frfw.ai_ids.engine.AnomalyEngine`**: pure stdlib (`collections.deque`,
      `statistics.mean`/`pstdev` -- no scikit-learn, pandas, or numpy),
      per-source-IP sliding-window counters for connection-attempt rate,
      unique-destination ratio, and SNI-blocklist-hit count, each scored
      against that same IP's own historical baseline via a z-score once
      it has one (`MIN_BASELINE_SAMPLES`), or a generous absolute floor
      until it does. Two guardrails (a zero-variance-baseline minimum-
      value requirement, and a minimum-connection-count floor before the
      destination-ratio feature is scored at all) were added after a
      synthetic test caught both producing false positives on
      unrealistic-but-technically-valid inputs.
- [x] **`frfw.conntrack`**: parses `/proc/net/nf_conntrack` directly
      (no new system package) for connection-rate/destination-diversity
      signal -- confirmed by hand that this file is root-only
      (`-r--r----- root root`; an unprivileged read attempt fails with
      "Permission denied"), so this is only ever read from the
      privileged apply-helper, never the daemon itself.
- [x] **`frfw.ai_ids.daemon.IDSDaemon`**: a background thread tails
      `fr-xdp-sni-logger.service`'s journald output for SNI-blocklist
      hits (the same permission model the webUI's own live XDP log
      already uses); the main loop polls a new `conntrack_sample`
      helper command every 5s and diffs against the previous sample so
      a still-open, long-lived connection is never re-counted as a new
      attempt on every poll. On a window tick, flagged, non-excluded IPs
      are quarantined via a new `quarantine_ip` helper command and
      logged to a small, capped, display-only events file.
      `ai_ids.excluded_macs` is resolved against the current DHCP static
      reservations at daemon startup into the actual IPs to exclude,
      since profiling is now IP-based rather than device-record-based.
- [x] **`frfw.ids_quarantine`** (a deliberate structural mirror of
      `frfw.bruteforce`/`frfw.ztna`): `quarantine_ip()`,
      `list_quarantined()`, `snapshot_before_reload()`/
      `restore_after_reload()` for the same `flush ruleset` survival
      problem the brute-force jail and ZTNA already solve.
- [x] **Nftables schema**: an always-rendered `ids_quarantine` named set
      (`flags timeout`) and its drop rule placed second in `chain
      input`, right after the brute-force jail's own drop rule and
      before even the loopback accept -- confirmed against a real,
      loaded ruleset's `nft -j list chain` output.
- [x] **Unix-socket protocol**: three new commands --
      `quarantine_ip` (`ban_ip`'s IDS/IPS counterpart),
      `ids_quarantine_status` (read-only, live kernel-state query, like
      `ztna_status`), and `conntrack_sample` (read-only conntrack dump).
- [x] **`frfw.provision.apply_all`**: the quarantine set snapshot/restore-
      bracketed around the nftables apply, unconditionally, the same as
      the brute-force jail.
- [x] **WebUI**: `/ai-ids` now shows real engine health
      (`systemctl is-active fr-ai-ids.service`), the live list of
      currently quarantined hosts (via `ids_quarantine_status`), and a
      capped recent-flagged-events log (the daemon's own unprivileged,
      display-only state file) -- no more "Force Retrain"/"Lock
      Profile", which had no meaning for a continuously-running
      detector. The dashboard card shows engine status + quarantined
      count instead of a fake learning-progress bar.
- [x] Tests: `tests/test_ai_ids_engine.py` (10 cases, scoring logic
      against synthetic traffic), `tests/test_ai_ids_daemon.py` (21
      cases, every building block except the real blocking I/O loop),
      `tests/test_conntrack.py` (8 cases, including a real root-only
      permission check), `tests/test_ids_quarantine.py` (12 cases, 4 of
      them real `nft` integration, mirroring `test_bruteforce.py`
      exactly), rewritten `tests/test_ai_ids_schema.py`, updated
      `tests/test_builder.py`/`tests/test_provision.py`/
      `tests/test_helper.py`, and a rewritten
      `tests/webui/test_ai_ids_routes.py` -- the full test suite (519
      tests) runs with no regressions.

**Corrections to the original request** (see ARCHITECTURE.md for full
detail): `fr-xdp-sni-logger` alone cannot supply connection-rate/
destination-diversity signal (only SNI-blocklist-hit frequency) -- a
second telemetry source (kernel conntrack sampling, via a new privileged
helper command) was added rather than fabricating the missing two
features; `ai_ids.learning_days`/`retrain_time` (mock-specific, a
simulated daily-retrain clock) were removed since a continuously-running
online detector has no equivalent concept, replaced with
`quarantine_duration_seconds` (2 hours by default, matching the
request's own example); `excluded_macs` is now resolved to IP addresses
via DHCP reservations at daemon startup, since detection is IP-based.

**Acceptance criterion**: a source IP making an unusually high rate of
new connections, scanning an unusual number of distinct destinations, or
repeatedly hitting the XDP SNI blocklist -- each relative to that IP's
own recent, established baseline -- gets added to the kernel's
`ids_quarantine` set (2-hour default quarantine), and every packet it
sends from then on is dropped by the firewall near the top of the input
chain -- all without the `fr-ai-ids` daemon ever running a single
root-privileged command itself. ✅ Verified with unit tests against
synthetic traffic shaped to match real conntrack/XDP-logger data, real
`nft`/procfs integration for the enforcement and telemetry-permission
halves, and confirmed end-to-end through the CLI (`firewall-cli
ids-status`) and the webUI's AI IDS screen. Real attack-traffic
end-to-end validation (e.g. an actual `nmap` scan through a live
conntrack table) is open, for lack of an attacker/target host pair in
this sandbox -- see ARCHITECTURE.md's scope-of-verification note.

## Phase 12 – Lightweight native Prometheus metrics exporter — **done**

A `GET /metrics` endpoint exposing both software (per-subsystem counts
already computed elsewhere in this project) and hardware (CPU/RAM/
storage) telemetry in Prometheus text exposition format, with zero
external dependencies -- no `prometheus_client`, no `psutil` -- parsing
`/proc`, `/sys`, and `os.statvfs` directly. **A numbering correction,
stated up front**: the request that started this phase called it "Phase
11", a number already used for the AI IDS/IPS work completed immediately
before it (Phase 11 above); this work is documented as **phase 12**
instead to keep the numbering sequential, a purely cosmetic correction.
Full rationale: [ARCHITECTURE.md](ARCHITECTURE.md#lightweight-native-prometheus-metrics-exporter-phase-12).

- [x] **`frfw.metrics`**: a small native Prometheus text-exposition
      renderer (`MetricFamily`/`render()` -- `# HELP`/`# TYPE` plus
      `name{labels} value` sample lines, with label-value escaping and
      float formatting handled by hand) and one reader function per
      metric family, each isolated so a broken family never breaks the
      whole scrape (see below).
- [x] **Software metrics**: `fros_interface_bytes_total{device,
      direction}` (`/sys/class/net/*/statistics/{rx,tx}_bytes`),
      `fros_xdp_status`/`fros_xdp_blocked_connections_total` (existing
      `frfw.xdp.get_attached()`/`get_stats()`), `fros_adblock_total_domains`
      (existing `frfw.adblock.count_blocked_domains()`),
      `fros_ztna_active_sessions`, `fros_bruteforce_banned_ips`,
      `fros_ai_ids_quarantined_hosts` -- the last three via new/existing
      read-only helper-socket status commands
      (`ztna_sessions_status`/`bruteforce_status`/`ids_quarantine_status`)
      wrapping each module's own `_list_set_elements()`, no new kernel
      logic.
- [x] **Hardware metrics**: `fros_hw_cpu_info`/`_mhz` (`/proc/cpuinfo`,
      preferring `/sys/.../cpufreq/scaling_cur_freq` for MHz),
      `fros_hw_cpu_usage_ratio` (two `/proc/stat` samples, 100ms apart,
      taken inside the request itself -- no shared cross-request state,
      no new lock), `fros_hw_ram_usage_bytes`/`_total_bytes`
      (`/proc/meminfo`), `fros_hw_storage_info`/`_usage_bytes`/
      `_total_bytes` (`/proc/mounts` filtered to real block devices +
      `os.statvfs()` per mount) -- confirmed against this sandbox's real
      `/proc`/`/sys`, not just a fake tree shaped like one.
- [x] **`frfw.hwinfo`**: the one genuinely privileged hardware fact --
      RAM module part number/speed lives in the SMBIOS/DMI tables,
      readable only via `dmidecode`, which needs root -- confirmed by
      hand the same way every other permission claim in this project is
      confirmed. Parses `dmidecode -t memory`'s "Memory Device" records
      into `fros_hw_ram_info{model, speed_mhz}` samples, called only from
      a new `hw_ram_info` command on the privileged apply-helper socket,
      never directly from the unprivileged webUI. A real bug the parser's
      own tests caught: `dmidecode` reports `"Configured Memory Speed:
      Unknown"` (a non-empty, truthy string) for a module whose speed
      wasn't auto-negotiated, so a naive `a or b` fallback chain never
      fell through to the `"Speed"` field -- fixed by checking the
      preferred field actually parses to a non-zero value first.
- [x] **`GET /metrics`**: no `require_login` dependency, per the
      request's own "unprivileged public/telemetry endpoint" wording --
      matching how Prometheus scrape targets universally work, and stated
      honestly as a security tradeoff (mitigated at the network layer,
      not in-process) rather than left implicit. Returns
      `text/plain; version=0.0.4`; survives an invalid on-disk config the
      same way the dashboard already does (config-dependent families
      skipped, everything else still renders).
- [x] Tests: `tests/test_hwinfo.py` (9 cases, a hand-written realistic
      `dmidecode` sample plus a `shutil.which`-gated real test),
      `tests/test_metrics.py` (36 cases -- rendering, every metric
      family, real-system CPU/RAM/storage reads, and top-level
      error-isolation), `tests/webui/test_metrics_routes.py` (7 cases via
      a real FastAPI `TestClient`, including a full structural regex
      check of the Prometheus grammar), plus additions to
      `tests/test_helper.py`/`tests/webui/conftest.py` for the three new
      helper commands -- the full suite (576 tests, 1 skipped for the
      missing `dmidecode` binary) runs with no regressions.

**Corrections to the original request** (see ARCHITECTURE.md for full
detail): the "Phase 11" label collision described above; confirmed that
zero external dependencies (no `numpy` either) was sufficient for the
whole exporter, native string formatting only; `dmidecode` is not
installed in this project's own dev sandbox, so its real-output code path
was verified against a hand-written, format-accurate sample rather than
a live binary -- the same class of disclosed gap this project has made
for hardware/software it doesn't have on every prior phase that needed
it (phase 4's 10G NICs, phase 8's OpenSSL 3.5+, phase 9's live dnsmasq
queries).

**Acceptance criterion**: `GET /metrics`, reachable with no
authentication, returns a well-formed Prometheus text-exposition
document containing every requested software and hardware metric name,
each with correct `# HELP`/`# TYPE` annotations, reflecting this
machine's real interface/XDP/adblock/ZTNA/brute-force/AI-IDS state and
real CPU/RAM/storage readings -- all without the webUI process running a
single root-privileged command itself. ✅ Verified with unit tests, a
dedicated structural regex check of the full rendered output against the
Prometheus exposition grammar, and real end-to-end reads against this
sandbox's actual `/proc`/`/sys`/`os.statvfs`. The one path not
exercised against a real binary is `dmidecode` itself, for lack of one
installed in this sandbox -- see ARCHITECTURE.md's scope-of-verification
note.

## Phase 13 – Hybrid BIOS + UEFI boot support — **done**

The phase 5 live ISO gains real UEFI boot support alongside its
existing, unchanged legacy BIOS path, so it boots on modern UEFI-only
small-form-factor hardware (Intel NUCs, HP ProDesk/EliteDesk minis,
Lenovo Tiny clients) from the same `dd`/Rufus-flashed USB drive, with
under 1 MB of size overhead on the ~327 MB image. Full rationale:
[ARCHITECTURE.md](ARCHITECTURE.md#hybrid-bios--uefi-boot-support-phase-13).

- [x] **`installer/make-hybrid-uefi-iso.sh`**: a new post-processing
      step, run after `lb build` (wired into
      `installer/build-live-image.sh`), since this project's very old
      live-build snapshot has no working path to hybrid BIOS+UEFI at
      all -- confirmed by reading its actual scripts, not assumed (no
      plural `--bootloaders` option exists in its `lb_config`; its
      "grub" bootloader case is GRUB *Legacy*, not GRUB 2 EFI; its ISO
      packaging uses `genisoimage`, with no EFI System Partition/GPT
      logic anywhere in it). Builds a standalone GRUB EFI binary
      (`grub-mkstandalone`), packs it into a small FAT ESP image, and
      re-invokes ISO packaging via `xorriso -as mkisofs` with both the
      original BIOS El Torito entry (identical flags to what
      `lb_binary_iso` already used) and a new UEFI El Torito entry +
      `-isohybrid-gpt-basdat` GPT partition.
- [x] **`config/includes.binary/boot/grub/grub.cfg`**: a real,
      committed GRUB menu, copied into the ISO by live-build's own
      `config/includes.binary` mechanism and chainloaded by a tiny
      embedded GRUB stub. Boots with `boot=live config` -- the
      project's actual current syslinux boot line -- not the
      requested-but-nonexistent `components`/`enforcement=strict`
      parameters, to genuinely satisfy the "identical to legacy" goal.
- [x] **`installer/live-build/auto/config`**: documented, in the same
      style as every other already-disclosed limitation of this
      snapshot, exactly why `--bootloaders syslinux,grub-efi` can't be
      set here and where UEFI support actually lives instead.
- [x] Tests: none applicable (a shell/live-build pipeline, no Python
      unit-testable surface) -- verified instead by two real, hands-on
      end-to-end runs (see ARCHITECTURE.md), including against the
      actual leftover `binary/` tree from phase 5's own real build.
      The full Python test suite (576 passed, 1 skipped) is unaffected
      and still passes, since nothing in `src/frfw` changed.

**Corrections to the original request** (see ARCHITECTURE.md for full
detail): `--bootloaders syslinux,grub-efi` doesn't exist on this
project's live-build snapshot (verified by reading its `lb_config`
source) -- UEFI support is added via a new post-processing script
instead; the requested kernel parameters
(`boot=live components quiet splash enforcement=strict`) don't match
this project's actual boot line and `components`/`enforcement=strict`
aren't real live-boot(7) parameters -- the new GRUB menu boots with the
project's real, current line instead, to actually satisfy "identical
to legacy"; the four packages named for `config/package-lists/` are
build-host tools (`grub-mkstandalone` from `grub-common`, plus
`grub-efi-amd64-bin`'s module tree, plus `xorriso`), not chroot/live
packages -- documented as host build prerequisites instead of added to
`frfw.list.chroot` (`isolinux`, the fourth named package, was already
there from phase 5).

**Acceptance criterion**: `installer/build-live-image.sh` produces a
single ISO that is bootable via both legacy BIOS (unchanged from phase
5) and UEFI, still `dd`/Rufus-flashable to a single USB drive, at
negligible size cost. ✅ Verified twice, hands-on: a real repackaging
run against phase 5's actual leftover 312 MB `binary/` staging tree
produced a real 328 MB ISO with both a BIOS and a UEFI entry in its El
Torito boot catalog, a GPT table with a correctly-typed EFI System
Partition, and a `file`-confirmed valid PE32+ EFI binary inside it.
Actually booting that ISO on real or virtual UEFI hardware, and Secure
Boot support, are both open -- see ARCHITECTURE.md's open issues for
this phase.

## Phase 14 – IoT device discovery and isolation — **done**

First of seven "next-gen homelab / small office" additions (phases
14–20). Finds IoT devices in chosen zones, classifies them with a
transparent point system, and can isolate them by MAC address in the
router's own firewall. Full rationale:
[ARCHITECTURE.md](ARCHITECTURE.md#iot-device-discovery-and-isolation-phase-14).

- [x] **Inventory** (`frfw.iot.leases`, `frfw.iot.arp`, `frfw.iot.mdns`):
      Kea DHCP leases (read by the privileged helper's new `dhcp_leases`
      command -- the lease file belongs to Kea's user), the world-readable
      ARP table, and a one-shot mDNS/DNS-SD service query per IoT-zone
      interface, sent as an RFC 6762 "legacy unicast" query so replies
      come back by unicast to one fixed port and the firewall needs one
      narrow accept rule instead of opening mDNS. Bounded,
      loop-safe DNS parser for the untrusted responses.
- [x] **Classification** (`frfw.iot.classify`): IEEE OUI vendor (from
      Debian's `ieee-data`, nothing bundled), advertised mDNS service
      types, DHCP hostname, randomized-MAC bit -- each adds/subtracts
      points with a stated reason; "iot" / "general" / "unknown".
- [x] **Enforcement** (`frfw.iot_isolation`, `iot_isolated` nftables
      set of `ether_addr`): `internet_only` or `block` mode, rules ahead of
      `established` and of every config rule, DHCP/DNS always allowed,
      atomic whole-set replacement per sync, snapshot/restore across
      `flush ruleset` in `apply_all`. Decision made by the unprivileged
      scanner (`fr-iot-scan`, `fr-iot-scan.timer` every 10 min, as
      fr_os-webui); the helper's `iot_sync_isolation` drops trusted MACs
      before touching the kernel.
- [x] **Config** (`iot:` section): `enabled`, `zones`, `auto_isolate`
      (off by default -- discover first, isolate on purpose),
      `isolation_mode`, `trusted_macs`, `isolated_macs`, all validated.
- [x] **WebUI** (`/iot`): settings, inventory with vendor/services/verdict
      and every reason, live kernel isolation state, "Scan now", and
      per-device Trust / Isolate / Clear that re-applies immediately.
- [x] **Metrics**: `fros_iot_devices{category}`, `fros_iot_isolated_devices`.
- [x] **CLI**: `firewall-cli iot-status`.
- [x] Tests: config validation, all three sources (including the real
      `ieee-data` file and real `/proc/net/arp`), hostile mDNS packets,
      a real UDP round trip, classification, the scanner end to end with
      injected I/O, helper commands, webUI routes, metrics -- and real
      packet-level namespace tests (see below). Full suite: 673 passed,
      1 skipped.

**Corrections to the original idea**: "automatically move an unknown IoT
device into a separate VLAN/zone" isn't something a router can do on its
own (VLAN membership is set by the switch port/SSID). Implemented instead:
MAC-keyed isolation in the router's firewall, which covers all traffic
routed through it, plus clear documentation that same-segment traffic
needs a dedicated VLAN zone. `auto_isolate` defaults to off so enabling
the feature never cuts anything off before the admin has seen the
inventory.

**Acceptance criterion**: an IoT device in a configured zone is
discovered and classified with visible reasons, and once isolated can no
longer reach other zones or the router's services (and, in `block` mode,
the internet), surviving any later config apply, while a trusted device
is never isolated. ✅ Verified on the wire with two network namespaces
routed through the actual generated ruleset: TCP connections fail once
the real MAC is isolated and succeed again when cleared; a full reload
releases the device and snapshot/restore re-isolates it; `internet_only`
lets the internet through but not a router service despite an admin
accept rule; a real mDNS exchange discovers the responder's services, and
fails without the generated reply rule. Not verified against physical IoT
hardware or a live Kea lease file.

## Phase 15 – Categorized DNS filtering and DNS threat signals — **done**

Second of the seven "next-gen homelab / small office" additions. Moves
phase 9's single ad-block list toward "advanced URL filtering" and "DNS
security", fully local. Full rationale:
[ARCHITECTURE.md](ARCHITECTURE.md#categorized-dns-filtering-and-dns-threat-signals-phase-15).

- [x] **Categories** (`adblocker.categories`): one hosts file per
      category under `/etc/fr_os/adblock.d/`, independent fetch/write
      per category, stale categories removed, per-category counts.
      Verified webUI presets (`malware`, `phishing`, `doh-bypass`,
      `gambling`, `adult`, `social`, `fakenews`) -- every URL fetched and
      its format and license header checked.
- [x] **Parser**: plain one-domain-per-line lists in addition to hosts
      format (Phishing Army and the DoH list are plain lists).
- [x] **Allowlist** (`adblocker.allowlist`), applied at refresh and on
      every apply; the Firefox DoH canary is always excluded (a real bug
      found end to end, see below).
- [x] **LAN DNS**: `serve_lan` (Kea announces the router as DNS server,
      pool DNS servers become upstreams without self-loops, input accepts
      DNS from DHCP zones) and `force_dns` (port-53 redirect, port-853
      reject, Firefox DoH canary NXDOMAIN).
- [x] **DGA heuristic** (`frfw.adblock.dga`): registered-label entropy +
      frequent-bigram ratio, thresholds measured against real lists.
- [x] **AI IDS DNS signals** (`query_logging`): distinct NXDOMAIN names,
      distinct DGA-like NXDOMAIN names, and malware/phishing lookups per
      host, parsed from dnsmasq's real `log-queries=extra` format, scored
      like every other feature.
- [x] **WebUI / metrics / Grafana**: category checkboxes, allowlist, LAN
      DNS switches, per-category counts; `fros_dns_blocked_domains{category}`.
- [x] Tests: 52 new, including a real dnsmasq end-to-end test. Full
      suite: 725 passed, 1 skipped.

**Corrections found while building it**: several obvious StevenBlack
category URLs are 404 (the real files are `alternates/<x>-only/hosts`);
two useful lists are plain domain lists the old parser would have read
as empty; the public DoH-resolver list contains Firefox's DoH canary
domain, and a hosts-file answer for it (0.0.0.0) overrides the NXDOMAIN
rule and silently re-enables DoH in Firefox -- the canary is now excluded
from every list. Phishing Army is CC BY-NC 4.0, flagged in the UI.

**Acceptance criterion**: an admin can block whole categories, see which
category blocks what, allowlist false positives, make every DHCP client
use (and not bypass via plain DNS/DoT or Firefox DoH) the filtering
resolver, and get a host flagged when it produces a burst of
random-looking NXDOMAIN lookups or looks up malware/phishing names. ✅
Verified with a real dnsmasq instance and real log lines driving the AI
IDS, and a real download of every preset list. Not verified against
real DGA malware samples.

## Phase 16 – Coarse application identification (App-ID lite) — **done**

Third of the seven "next-gen homelab / small office" additions: which
apps the network uses, and one-click app blocking, from names only --
nothing is decrypted. Full rationale:
[ARCHITECTURE.md](ARCHITECTURE.md#coarse-application-identification-phase-16).

- [x] **Phase 4 direction fix**: XDP must sit on the LAN-side interfaces
      (docs, config docstring, webUI hint), proven by a real
      three-namespace test with the compiled program.
- [x] **Kernel**: a `settings` map switches on pass events for
      non-matching SNIs; pass events may only use half the ring buffer so
      drops (the AI IDS signal) are never starved. Verifier-accepted,
      exercised on real packets.
- [x] **Catalog**: 41 apps / ~1,850 names generated from
      v2fly/domain-list-community (MIT) at a pinned commit by
      `scripts/update_app_signatures.py`; longest-suffix matching.
- [x] **`fr-appid` daemon**: follows the resolver's query log and
      (optionally) the XDP SNI events, 24-hour per-app/per-client usage
      with de-duplication, persisted; follows config changes by itself.
- [x] **Blocking** (`app_control.blocked_apps`): resolver NXDOMAIN for all
      of an app's names; optional merge into the XDP blocklist
      (`block_via_xdp`), with an up-front kernel-map size check.
- [x] **WebUI `/apps`, `firewall-cli apps-status`, metrics**
      (`fros_app_active_clients`, `fros_app_hits_24h`, `fros_app_blocked`),
      Grafana panels.
- [x] Tests: 88 new (30 of them per-unit installer checks), including
      real-packet XDP tests and a real dnsmasq run. Full suite: 815
      passed, 1 skipped.

**Found and fixed along the way**: a regular `pip install` shipped the
webUI without its templates (package data was never declared), and
`fr-xdp-sni-logger.service` (plus the ad-block units in the live image)
was never installed -- both now guarded by tests.

**Acceptance criterion**: an admin can see which apps each client used in
the last 24 hours and block an app from the webUI; blocked names answer
NXDOMAIN, and with `block_via_xdp` TLS connections to them are dropped in
the kernel even when the client bypassed the resolver. ✅ Verified with a
real dnsmasq and real packets through the compiled XDP program. Not
verified with real phones, consoles or smart TVs.

## Phase 17 – Time-based firewall rules — **done**

Fourth of the seven "next-gen homelab / small office" additions: rules
that apply only at certain times, optionally per device (MAC). Full
rationale:
[ARCHITECTURE.md](ARCHITECTURE.md#time-based-rules-phase-17).

- [x] **Schedule syntax** on any rule: days (mon..sun, weekdays, weekend,
      daily), local start/end, windows past midnight; top-level
      `timezone` (IANA, validated).
- [x] **Correct kernel rendering** (`frfw.nft.schedule`): local windows
      converted to UTC hours and the kernel's own day clock, cut at both
      midnights; nft always run with `TZ=UTC`.
- [x] **DST / time zone refresh**: offset recorded at apply, hourly
      `fr-schedule-check.timer` re-applies -- never an unapplied config.
- [x] **`cut_established`** for drop/reject rules, so open connections
      end when the window starts.
- [x] **`src_mac`** on rules.
- [x] **WebUI**: schedule fields, "active now" per rule, time zone with
      the router's current time; `firewall-cli schedule-check`.
- [x] Tests: 35 new, including a real-kernel test in five time zones and
      a per-minute check of the conversion. Full suite: 850 passed, 1
      skipped.

**Corrections found while building it**: `meta hour` is UTC in the
kernel and nft converts it with its own process time zone at load time
(so it drifts after DST); `meta day` follows the kernel's separate
`sys_tz`, not UTC; and time rules alone never end an open connection.
All three are handled and each was verified on the real kernel.

**Acceptance criterion**: an admin can block or allow traffic for chosen
devices and times from the webUI, including windows past midnight, see
which rules are active now, and the rules stay correct across
daylight-saving changes without re-applying unapplied edits. ✅ Verified
against the real kernel's verdicts in five time zones and a non-zero
kernel time zone. An actual DST switch on a running router was not
observed.

## Phase 18 – Multiple webUI accounts with roles (RBAC) — **done**

Fifth of the seven "next-gen homelab / small office" additions. Full
rationale:
[ARCHITECTURE.md](ARCHITECTURE.md#multiple-webui-accounts-with-roles-phase-18).

- [x] **Accounts**: any number, role `admin` or `viewer`; at least one
      admin always remains; legacy single-account file still read.
- [x] **Central enforcement** in `require_login`: viewers get 403 on
      every change route (proven by walking all registered routes).
- [x] **Sessions follow the account**: role changes, password resets and
      deletions apply to open sessions immediately.
- [x] **Audit log**: every change request and login, never form
      contents, size-capped; shown to admins on `/users`.
- [x] **WebUI** `/users` and `/account`, read-only banner for viewers;
      `firewall-cli users`; `set-admin-password` always grants admin.
- [x] Tests: 18 new. Full suite: 868 passed, 1 skipped.

**Acceptance criterion**: several people can have their own login, some
read-only; a read-only account cannot change anything through any
endpoint; admins can see who changed what and when. ✅ Verified by an
exhaustive route walk that fails if the central check is removed.
Roles do not protect against a compromised webUI process (unchanged
trust boundary to the privileged helper).

## Phase 19 – TLS client fingerprinting (JA3/JA4) without decryption — **done**

Sixth of the seven "next-gen homelab / small office" additions. Full
rationale:
[ARCHITECTURE.md](ARCHITECTURE.md#tls-client-fingerprinting-without-decryption-phase-19).

- [x] **Kernel**: ClientHello segments copied to a separate ring buffer,
      including the follow-up segments of hellos that span packets (modern
      post-quantum hellos do), with verifier-accepted bounds.
- [x] **`frfw.tlsfp`**: TCP reassembly, strict ClientHello parsing, JA3 and
      JA4 (both BSD 3-Clause; the FoxIO-licensed JA4+ methods are
      deliberately not implemented).
- [x] **Validated** against FoxIO's reference outputs: 151/152 real TCP
      streams identical; the one difference is a documented
      spec-vs-reference disagreement.
- [x] **`fr-tls-fp`** drops root before parsing any packet; per-device
      inventory, new-fingerprint events after a learning period, blocklist
      with optional quarantine.
- [x] **WebUI `/tls`**, `firewall-cli tls-fingerprints`, metrics.
- [x] Tests: 43 new, including a two-segment post-quantum hello through the
      real XDP program into a privilege-dropped fingerprinter. Full suite:
      911 passed, 1 skipped.

**Acceptance criterion**: for every IPv4 TLS connection from the LAN the
router records the client's JA4/JA3 without decrypting anything, including
hellos split across packets; admins see fingerprints per device, get told
about new ones, and can block (and optionally quarantine) a fingerprint.
✅ Verified on real packets and against the reference implementation's
outputs. QUIC and IPv6 are not covered.

