# Architecture

This document records the project's fundamental architectural decisions. The
goal is a custom, Linux-based firewall/router operating system for homelab
use, with long-term potential as a GitHub community edition.

## Why not pfSense/OPNsense (FreeBSD)?

- **NIC compatibility**: Linux's driver ecosystem is far broader than
  FreeBSD's — not just Intel, but Realtek, Aquantia, and cheaper/used
  Mellanox cards are also natively supported.
- **High-speed path**: for 10GbE/40GbE line-rate stateful firewalling,
  Linux's XDP/eBPF (and DPDK if needed) ecosystem is more mature and
  tunable than FreeBSD's equivalents.

## Layers and chosen technologies

| Layer | Choice | Rationale |
|---|---|---|
| Base OS | Debian minimal (netinst) | Stable, well documented, long support cycle, minimal base image |
| Packet filtering | nftables | The modern Linux native firewall subsystem, replacing iptables, with good Python integration (`nft -f`, JSON API) |
| Fast path (10G+) | XDP/eBPF, with a later DPDK option | Bypasses the kernel stack at high packet rates; DPDK only if XDP isn't enough (extra complexity, userspace driver) |
| Management UI | Python/FastAPI backend + a simple frontend | Fast development, good async I/O, easy to test; the frontend is server-rendered Jinja2 + minimal CSS, not tied to an SPA framework |
| Config storage | YAML (source of truth) + SQLite (runtime state/sessions) | YAML is git-friendly, diffable, and hand-editable in an emergency; SQLite for runtime data that shouldn't be versioned (e.g. DHCP leases — though today Kea itself manages these in its own memfile lease database, not frfw) |
| DHCP server | Kea DHCPv4 | ISC's official successor to isc-dhcp-server, actively developed, JSON config (easy to generate from Python), a built-in `-t` syntax tester (`kea-dhcp4 -t`, playing the same role as `nft -c`) |
| Installation | Debian preseed / live-build + first-boot script | Automatic installation with no user interaction, a pfSense-like experience |

## System architecture (big picture)

```
                    ┌─────────────────────────┐
                    │        WebUI (UI)         │
                    │  FastAPI + Jinja2 frontend │
                    │  unprivileged fr_os-webui   │
                    │  user, HTTPS (:443)          │
                    └────────────┬─────────────┘
                        │                 │
        direct file read       │  save_config / apply / rollback
       (/etc/fr_os/config.yaml,│  (unix socket, only these
        via group permission)  │   operations)
                        │        ┌────────▼─────────────┐
                        │        │  apply-helper (root)   │
                        │        │  frfw.helper.server      │
                        │        └────────┬─────────────┘
                        │                 │
                    ┌───▼─────────────────▼─────┐
                    │      frfw config engine     │
                    │  (Python package: frfw)       │
                    │  - config schema + validation   │
                    │  - nftables ruleset gen.        │
                    │  - interface address apply       │
                    │  - Kea DHCP config gen.             │
                    │  - apply / rollback logic            │
                    └────┬───────────────┬───────────┘
                         │ ip addr       │ nft -f / -c    │ kea-dhcp4 -t +
                         │               │                │ systemctl restart
                    ┌────▼───┐      ┌────▼─────┐    ┌─────▼──────────┐
                    │ kernel  │      │ nftables  │    │ kea-dhcp4-server │
                    │ netlink │      │ (packet   │    │ (DHCP server)    │
                    │ (addrs) │      │ filtering)│    └──────────────────┘
                    └─────────┘      └───────────┘
```

The `frfw` Python package is the heart of the system: it holds the config
schema, the validation logic, the nftables ruleset generator, and the
interface-address and Kea DHCP config generators. It's used, phase-independently,
by the CLI (phase 1), the systemd service (phase 2) and the webUI (phase 3)
alike — a single source for the "config → system state" translation
(`frfw.provision.apply_all`), so there's never an inconsistency between a
system configured by hand via the CLI and one configured through the webUI.

## Configuration model

The configuration's basic concepts (full schema:
[`docs/CONFIG_SCHEMA.md`](docs/CONFIG_SCHEMA.md)):

- **interfaces**: physical/logical network interfaces, each assigned to a
  zone (e.g. `wan` device → `wan` zone), with an optional static IPv4
  address (`address: 10.0.0.1/24`) — applied by `frfw.ifaddr` via `ip
  addr`, and this also supplies the DHCP pool's subnet/gateway.
- **zones**: logical groups (following the wan/lan/opt pattern) that rules
  reference — you don't have to list every interface in every rule.
- **rules**: traffic filtering rules based on a zone pair (from_zone →
  to_zone), protocol, port, and address, with an `accept`/`drop`/`reject`
  action.
- **nat**: masquerade (outbound NAT) and port-forward (inbound DNAT) rules.
- **dhcp**: a per-zone DHCPv4 pool (address range, DNS servers, lease
  time, static reservations) — can only be set on a zone that has exactly
  one interface with a static address (see below).

The schema is deliberately simple and flat — the webUI builds its editing
UI directly on top of it (dict-level YAML editing + re-validation before
saving, see `frfw.webui.config_store`), with no manual YAML editing
required.

## nftables ruleset structure

The generated ruleset contains a single `inet fr_os` table with
`input`/`forward`/`output` chains (default drop policy, explicit accept
for loopback and established/related traffic), plus an `ip fr_os_nat`
table with `prerouting`/`postrouting` chains for the DNAT/masquerade
rules. Every generated rule carries a comment (`comment`) with the source
YAML rule's name, so `nft list ruleset` output can be traced back to the
configuration.

## DHCP (Kea) config generation

From the `dhcp` section, the `frfw.kea` module builds a Kea `Dhcp4` JSON
config (`interfaces-config` restricted to the relevant devices, a
`subnet4` array with pools, `routers`/`domain-name-servers` option data,
and `reservations` for static assignments). The generated file is
validated with `kea-dhcp4 -t` (playing the same role as `nft -c`) before
it's actually applied — this is the real `kea-dhcp4` binary, not a custom
JSON schema checker, so it also enforces Kea's own semantic rules (e.g.
that the listed interfaces must actually exist on the machine).

When applied, `frfw.kea.apply_dhcp_config` overwrites
`/etc/kea/kea-dhcp4.conf` and restarts the `kea-dhcp4-server` systemd
service — the same "generated file, never hand-edited" principle as the
nftables ruleset.

## AI IDS/IPS (mock)

> ⚠ The `frfw.ai_ids` module **currently serves entirely fabricated
> data**. Phase 4's XDP/eBPF work (see below) implements one specific,
> targeted function -- TLS SNI filtering -- not a general traffic-analysis
> pipeline the AI IDS could draw on; so this mock engine still has no real
> data source. The module was still built now so that the config schema,
> the webUI, and the scheduled-retrain infrastructure (CLI command +
> systemd timer) can already come together and be tested by the time a
> real data-collection path arrives. Every screen/API response that shows
> this data is required to flag its mock nature (see the warning banner
> in `ai_ids.html`) -- it must never be treated as a real security
> signal.

The "known devices" list comes from the `dhcp.<zone>.reservations` static
reservations (the closest thing to a "known device" concept without real
traffic monitoring). A deterministic (not re-randomized) mock profile is
generated per device based on its MAC address — a risk label, "top
protocols", a count of known domains — plus a part that carries genuinely
persisted state in `/etc/fr_os/webui/ai_ids_state.json`: the simulated
training percentage (based on time elapsed since `retrain_started_at` /
`learning_days`) and the "locked" flag.

**Security model — a deliberate departure from the other screens**: the
"Force Retrain" and "Lock Profile" actions do *not* go through the
privileged `frfw.helper` daemon. The helper is reserved exclusively for
operations that require root (nft, `ip addr`, restarting Kea); the AI IDS
engine never touches the kernel or a system service, it purely modifies
userspace JSON state in the webUI's own (unprivileged, already writable)
directory — putting this in the root daemon would needlessly widen its
attack surface. Saving the `ai_ids` *config section* (enabled/
learning_days/retrain_time/excluded_macs), on the other hand, goes
through the helper's usual `save_config` command, like every other YAML
change.

Future integration point: `frfw.ai_ids.train_isolation_forest` is a stub
that raises an explicit `NotImplementedError` for scikit-learn's
`IsolationForest` — `scikit-learn` is deliberately not a dependency of
either the core package or the `webui` extra until this is actually
implemented.

Scheduling of the daily retrain hour (`ai_ids.retrain_time`, `03:30` by
default) is handled by the `systemd/fr-ai-ids-retrain.timer` + `.service`
pair, running as the `fr_os-webui` user (same as the webUI, because it
writes the same state file). The timer currently uses a static
`OnCalendar=*-*-* 03:30:00`, which **does not automatically follow** a
custom `retrain_time` config value — syncing this is a future refinement
(an open question, see ROADMAP.md).

## XDP/eBPF fast path: kernel-level TLS SNI filter (phase 4)

**Status: written, actually compiled, genuinely accepted by the BPF
verifier, and tested end-to-end in this sandbox with a hand-assembled,
real TLS 1.3 ClientHello** (attached to `lo` under `ip link ...
xdpgeneric`; see below for the exact what-and-how). This section
replaces the earlier, purely design-level "fast-drop IP blocklist"
description: the actual scope, agreed with the user, ended up not being a
generic source-IP blocklist, but a **kernel-space TLS ClientHello parser
that drops packets based on the SNI (Server Name Indication) field** —
see the exact rationale and the scope difference below.

### Scope: SNI-based TLS filtering, not a generic IP fast-drop

Instead of the "IP source-address blocklist" originally planned here, the
actual implementation does something far more specific, but more
practical: **it looks for the TLS ClientHello in TCP traffic headed to
port 443, extracts the domain name (SNI) from it, and drops or lets the
packet through based on that** — before the kernel's network stack or
nftables ever sees it. This is exactly the Cloudflare/Meta-style "narrow,
fast pre-filter ahead of the full-featured path" pattern, just with a
domain name as the blocking criterion instead of an IP address — which
fits the practical "block ad/tracker domains" use case far more directly
than a raw IP list would.

### The kernel-side program: `bpf/xdp_sni_filter.c`

The file's own header comment (three separately highlighted "IMPORTANT"
sections) documents the real, deliberate limits — these are not gaps,
they're documented design decisions:

1. **No TCP stream reassembly.** The program works *statically, packet by
   packet*: it only sees a ClientHello that fits into a *single* TCP
   segment (a TLS handshake record header, 0x16, starting at payload byte
   0). A ClientHello fragmented across multiple segments (a large
   `key_share`/`supported_groups` list, or Chrome's deliberate
   ClientHello padding) remains invisible and fails open. This is a
   deliberate, documented tradeoff ("never block something we don't see
   in full"), not a bug.
2. **No Encrypted Client Hello (ECH) support.** With ECH the real SNI is
   encrypted; this is an unavoidable limit of any cleartext-SNI filter,
   not something specific to this implementation.
3. **No forged TCP RST.** The response on a match is `XDP_DROP`, not a
   synthesized, in-window RST — the latter would require tracking the
   peer's sequence number, recomputing the checksum, and re-injecting via
   `XDP_TX`; real, but substantially more complex, and not necessary for
   the "block the connection" goal.
4. IPv4 only — consistent with the rest of the project (`frfw.nft`, Kea
   DHCP are IPv4-only today too).

The actual kernel-space parser (TLS record → handshake → ClientHello
fields → extension list → server_name extension → reading the SNI bytes)
looks the result up in a `BPF_MAP_TYPE_LPM_TRIE`, into which blocked
domains are inserted as `reverse("." + hostname)` — this is what lets an
entry for "example.com" correctly block "www.example.com" too, while
*not* blocking a name that's only superficially similar at the character
level but isn't actually a subdomain (e.g. "notexample.com") — the file's
own "LPM trie key construction" comment walks through this with
hand-computed examples. On a match: `XDP_DROP`, and an async
`BPF_MAP_TYPE_RINGBUF` event carrying the source/destination IP:port plus
the matched SNI — this is purely a log for userspace, completely decoupled
from the actual drop decision (whether userspace reads it or not never
affects whether a packet gets dropped).

### The BPF verifier: the real difficulty wasn't TLS parsing

The packet-format parsing logic (walking record/handshake/extension
fields, length checks) was relatively straightforward. What took far
longer: **convincing the kernel's BPF verifier that this logic is
actually, provably safe** — a series of restrictions that are instructive
in their own right and recur as patterns, each documented in detail at
every occurrence directly in `bpf/xdp_sni_filter.c` (not here, to avoid
two copies of the same thing that could drift apart):

- The verifier's pointer-range proof is tied to a specific register, not
  to the memory address it points at — *reloading* an already-proven-safe
  pointer from a stack slot, or passing it as an argument to a
  BPF-to-BPF call, can lose that proof, even if the address it actually
  points to hasn't changed.
- A ternary (`cond ? read : 0`) doesn't stop LLVM from evaluating both
  branches if the "is it safe" condition is a saved boolean value from an
  *earlier*, separate check — the check guarding the actual memory access
  has to be in the *same* `if` as the read itself.
- The 512-byte BPF stack limit (kernel-side, not tunable) directly
  influenced the value of `MAX_SNI_LEN` (shrunk from 128→64→32), and
  required an explicit "barrel shifter" technique to implement a
  variable-length string shift, because a small stack array indexed
  directly by a runtime index can't be proven safe either at compile
  time (clang) or at the verifier level.
- A packet-pointer upper bound *tracked* by the verifier can *accumulate*
  across the iterations of an unrolled loop, even when the actual runtime
  value stays well under the bound — this, not register pressure, was the
  final reason the extension-walking loop failed to verify, until it was
  rewritten to recompute the pointer from a fixed base point on every
  iteration instead of adding to it iteratively.

### Real verification (not just review, actual execution)

1. `clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c
   xdp_sni_filter.c -o xdp_sni_filter.o` — compiles cleanly.
2. `ip link set dev lo xdpgeneric obj xdp_sni_filter.o sec xdp` — the
   kernel verifier actually accepts and loads it (not just syntactically
   valid C code, but provably memory-safe BPF bytecode).
3. A real TLS 1.3 ClientHello byte sequence (with an SNI extension), hand
   assembled with Python's `struct` module and sent over a real TCP
   socket to `127.0.0.1:443` while the program is attached to `lo`: for a
   blocklisted SNI the connection literally never receives the data
   (every retransmission is also dropped — the `STAT_DROP_MATCH` counter
   increments on every attempt), for a non-blocked SNI the payload
   arrives at the server intact.
4. The ring buffer event (source/destination IP:port + SNI) decodes
   correctly on the userspace side via a direct `ctypes` `libbpf`
   binding (see below).

### Userspace orchestrator: `frfw.xdp`

The Python layer for the kernel-side program follows the same "shell out
to the system's own tool" pattern as `frfw.nft`/`frfw.kea`/`frfw.ifaddr`
— `ip` and `bpftool`, not a heavier library (bcc, a full libbpf-python
binding). The one exception is reading the ring buffer, for which there's
no sensible CLI primitive: for that, a small, direct `ctypes` binding
wires in exactly three `libbpf` functions
(`ring_buffer__new`/`__poll`/`__free`) — this is the program's only point
that relies on a real library call instead of bcc, and it's purely
read-side (it can never influence the drop decision).

- **Compilation** (`ensure_compiled`): if the target has no precompiled
  `.o` and a `bpf/xdp_sni_filter.c` source is available (a dev checkout,
  or an installed release's preserved source file under `RELEASES_DIR`),
  it compiles with clang. A production image shouldn't need a C compiler
  -- the live-build pipeline should ship a precompiled `.o` (this isn't
  wired up yet, see Open issues).
- **Loading + pinning** (`load_and_pin`): loads and pins the program and
  ALL its maps once, under `/sys/fs/bpf/fr_os_xdp` (`bpftool prog loadall
  ... pinmaps ...`) — this is what lets it attach to multiple interfaces
  (e.g. WAN + a guest-WiFi uplink) and have all of them see *the same*
  blocklist/stats/events maps, instead of a separate copy per map per
  interface.
- **Attachment** (`attach`): tries native (`xdpdrv`) mode first (real
  driver-level speed on supported NICs), falls back to generic
  (`xdpgeneric`) mode on failure — this is the fallback chain the
  project's original plan called for, and one this sandbox's own `lo`
  interface actually forces in practice (loopback never supports native
  mode).
- **Blocklist sync** (`sync_blocklist`): reconciles the pinned LPM trie's
  contents with the config's desired state (add/remove), without
  clearing and rebuilding it on every `apply`.
- **`frfw.provision.apply_all`**: calls `frfw.xdp.sync_sni_filter` as the
  fourth (last) step, in address → nftables → DHCP → XDP order -- neither
  the CLI nor the webUI needs to know about XDP separately.
- **`fr-xdp-sni-logger` daemon** (`frfw.xdp.run_event_logger`,
  `systemd/fr-xdp-sni-logger.service`): continuously reads the ring
  buffer with a blocking `ring_buffer__poll` (not busy-waiting — uses
  effectively zero CPU while idle), and logs every match as a JSON line
  via journald (`frfw.xdp.format_event_json`) — this is what lets the
  webUI process the same line as structured data instead of text
  parsing.

### WebUI screen (`/xdp`)

The same "edit the raw YAML dict, validate, save through the privileged
helper" pattern as every other screen (`frfw.webui.actions.try_save`) —
saving `enabled`/`interfaces`/`blocklist` never attaches/detaches the
actual XDP program directly, that only happens on the next `apply` (CLI
or the dashboard's "Apply" button), exactly like an nftables ruleset or
Kea config change. The status card therefore deliberately distinguishes
*two* different states: "Disabled" (the feature is turned off) and "Not
attached yet -- run Apply" (turned on in the config, but the kernel-side
program isn't loaded/attached yet) — both with a red badge, but different
text, so an admin can see the difference between "disabled" and "enabled
but not yet applied".

The live log (`GET /xdp/logs/stream`, Server-Sent Events) does NOT read
the kernel ring buffer directly -- the map pinned for it is root-only
(see the `RingBufferReader` docstring), and the webUI process deliberately
does not run as root (`systemd/fr-webui.service`). Instead it tails the
already-decoded JSON lines that `fr-xdp-sni-logger` has already written
to journald (`journalctl -u fr-xdp-sni-logger.service -f -o cat`) --
`fr-webui.service` was given a `SupplementaryGroups=systemd-journal`
line for this, which is the usual, minimal-privilege way for a non-root
process to read the journal without root. On the frontend side, a native
`EventSource` (no WebSocket, no library) connects to this endpoint, and
appends every incoming JSON line to the bottom of the "terminal"
container, with auto-scroll and a cap of 300 lines (so the DOM doesn't
grow without bound on a tab left open) -- plain vanilla JS, no SPA
framework, consistent with the rest of the project's screens.

### Open issues

- **Live-build integration**: precompiling the `.o` file and packaging it
  into the image as part of the build pipeline, so a production image
  doesn't need to rely on `clang` at boot.
- **Real 10G/40GbE performance measurement**: this sandbox isn't suited
  to such measurement (no suitable NIC/traffic generator) -- the
  program's correctness (in the sense above) is proven, but the
  native-mode, high-packet-rate performance advantage can only be
  measured on proper test hardware, as an earlier version of this
  section also noted.

## Automated installer (phase 5)

Goal: an FR_OS system that works booted from USB, with no terminal work.
The approach chosen is a live-build-based hybrid live ISO (of the three
options considered -- a Debian preseed installer, a live-build hybrid
image, or a pre-built dd-able appliance image -- the live-build hybrid
image was chosen, the harder but more flexible route).

### Build pipeline

`installer/live-build/` is the live-build config tree (`auto/config`,
`config/package-lists/`, `config/hooks/`, `config/bootloaders/`).
`installer/build-live-image.sh` orchestrates it: syncs the repo's source
into the chroot's `includes.chroot/opt/frfw-src` (so the chroot hook can
pip-install frfw from there), then runs `lb clean && lb config && lb
build`. `.github/workflows/build-installer.yml` can also kick it off from
CI via `workflow_dispatch`.

The chroot hook (`config/hooks/0100-install-frfw.hook.chroot`) runs during
the build's **chroot** stage -- so everything it does becomes part of the
squashfs image: it installs the frfw package (`pip install frfw[webui]`),
copies the systemd units and scripts, then enables
`fr-first-boot.service` (the one unit the build itself enables -- the
first-boot script turns on the rest, see below).

### First boot

`scripts/fr-first-boot.sh` + `systemd/fr-first-boot.service` (oneshot,
`ConditionPathExists=!/etc/fr_os/.first-boot-done`) -- this runs exactly
once, after a real (not live-demo) install/boot:

1. Generate the admin password (`firewall-cli set-admin-password
   --generate` -- non-interactive, cryptographically random password,
   via the `secrets` module)
2. Auto-detect network interfaces
3. Enable and start every `fr-*.service`/`.timer` unit
4. Create a marker file so it never runs again

This step is what fulfills the "no terminal work" requirement: everything
that *can be baked into the image* (packages, code, unit files) already
happened at build time; what's *machine-specific* (which NIC is which,
password, TLS keys) is generated here, at first boot.

### Verification -- a real, end-to-end build run

The `installer/build-live-image.sh` pipeline actually ran in this
sandbox and produced a real, bootable hybrid ISO (per `file`, "ISO 9660
CD-ROM filesystem data (DOS/MBR boot sector), bootable", ~327 MB).
Unpacking and checking the squashfs:

- `frfw` installed via pip (`dist-packages/frfw`,
  `frfw-0.1.0.dist-info`), `firewall-cli` in place
- all 7 `fr-*.service`/`.timer` units present (`fr-firewall`,
  `fr-apply-helper.socket/.service`, `fr-webui`,
  `fr-ai-ids-retrain.service/.timer`, `fr-first-boot`)
- `fr-first-boot.service` enabled (symlinked under
  `/etc/systemd/system/multi-user.target.wants/`)
- the temporary `/opt/frfw-src` source directory correctly removed at
  the end of the hook (not left in the final image)

This is build/squashfs-level, static verification -- an actual USB boot
and a real run of the first-boot script on a fresh VM/machine hasn't been
tried yet (see ROADMAP.md's phase 5 open issues).

### Limitations of this particular live-build snapshot

The build host in this sandbox runs a very old, Ubuntu-patched live-build
package (`3.0~a57`, with 2012-era internal theme files), not Debian's own
current live-build package. Several source-level-verified incompatibilities
had to be worked around because of this -- each documented in detail
directly in the header of `installer/live-build/auto/config` and in
`installer/live-build/config/bootloaders/README.md`:

- Ubuntu-specific mirror/keyring/kernel-package-name defaults (`--mode
  debian` with explicit mirror/keyring/linux-flavour overrides)
- `--debian-installer false`: the built-in "install to disk" wizard would
  try to install a nonexistent package list (`lilo`,
  `linux-image-2.6-amd64`) in any non-Ubuntu mode without this override --
  which is why the current ISO is a complete, working **live** system,
  not a classic "copy to disk" install wizard
- a missing `rsvg` binary (splash-graphic rendering was dropped because
  of this -- a plain background color substitutes for it)
- a missing `bootlogo` cpio archive (an empty, valid archive substitutes
  for it)
- `isohybrid` looked for under the wrong package name (`syslinux`
  instead of the correct `syslinux-utils`) in the chroot
- the location of chroot hooks: this snapshot only looks at
  `config/hooks/*.chroot`, and doesn't know about the newer live-build
  `config/hooks/live/` subdirectory convention (it silently, with no
  error, skips hooks placed there -- this was the sneakiest bug: the
  first full build succeeded, but frfw wasn't in the image at all)

With a fresh (Debian's own, current) live-build package, several of these
would likely not come up on their own at all -- each point comes with its
own note on what's worth reverting/trying first there.

## Update mechanism (phase 6)

`frfw.update` splits cleanly into two halves, following the same
privilege pattern as the rest of the project:

**Checking** (`check_latest`, `list_releases`) is an unprivileged,
read-only HTTPS GET against the configured (or default,
`frfw.update.DEFAULT_REPO`) GitHub repo's Releases API. There's no
persisted "last checked" state -- every webUI page load queries fresh, the
same pattern as the AI IDS screen's live-computed progress bar. A repo
that has no release yet (like this project currently, at 0.1.0) isn't an
error, it's "no update available" -- the GitHub API simply returns a 404
in that case, which the module handles explicitly.

**Applying** (`apply_update`, `rollback_update`) requires real root
privileges: it downloads and unpacks a release tarball
(`https://github.com/<repo>/archive/refs/tags/<tag>.tar.gz`), `pip
install`s it, updates the systemd unit files, and restarts the affected
services. This half can only be invoked from the privileged
`fr-update-helper` daemon (see below), or directly via a `firewall-cli
update apply/rollback` command run as root over SSH -- the webUI process
itself never runs it directly.

### A separate daemon, not an extension of the existing apply-helper

The firewall-config apply-helper (`frfw.helper.server`, phase 2) is
deliberately minimal: "only touches `CONFIG_PATH`/`BACKUP_DIR`, no
general command execution" (see the `frfw.helper.protocol` docstring).
Package installation, systemd unit rewriting, and service restarts are a
far broader privilege surface -- bolting this onto the apply-helper would
needlessly widen ITS attack surface too. So there's a separate, dedicated
socket daemon (`fr-update-helper`, `frfw.helper.update_server` +
`update_protocol` + `update_client`), structurally almost identical
(systemd socket activation, one-JSON-object-per-line protocol, a
`StreamRequestHandler` per connection), but a physically independent
unit/socket/codebase -- a change to one can never accidentally affect the
other.

### The webUI updates itself -- the race this causes, and its fix

An update also restarts the webUI's *own* service (`fr-webui.service`),
so the new code actually takes effect -- but that's exactly the process
serving the HTTP request that asked for the update. If it restarted
synchronously, immediately, the browser would never get the response page
back (the connection would drop before anything came back). The fix:
`fr-apply-helper.service`/`fr-firewall.service` restart synchronously,
immediately; restarting `fr-webui.service` is scheduled a few seconds
later via `systemd-run --on-active=3s`, decoupled from this request -- so
the "update succeeded" page still renders before the webUI actually
restarts. For a similar reason, `fr-update-helper.service` itself also
doesn't restart itself as part of an update -- that would kill the
process before it could send the response back to the caller; this is a
documented, deliberate limitation (the daemon's own code only picks up
updates on the next natural restart, e.g. a reboot).

### Rollback

Goes back exactly one level: `apply_update` saves the version from
*before* the update as `previous_version` into persisted state
(`paths.UPDATE_STATE_PATH`, `root:fr_os-webui`, 0640 -- the same pattern
as `config.yaml`: only the privileged side writes it, the webUI only
reads it), BEFORE switching; `rollback_update` reinstalls that and clears
it -- a rollback can't itself be rolled back. If the previous version's
unpacked source is still present under `RELEASES_DIR`
(`/opt/fr_os/releases`) (a successful update never deletes old version
directories), rollback works again without a download, even without
network -- which matters exactly when the bad update itself is what broke
the network too.

On failure (of a download, unpacking, pip install, or a service restart)
the attempt and the error message get recorded in the state file's
`last_update` field, and the call raises `UpdateError` -- neither the CLI
nor the webUI page stays silent on a failed update.

### Known limitation: no cryptographic signature verification

There's no cryptographic signature check at all on the downloaded release
tarball, beyond the HTTPS connection to GitHub -- the same trust model as
a plain `git clone`/`pip install` from an unpinned index. Release signing
(`cosign` or a GPG-signed checksum file) is a reasonable next step, once
there are real, tagged releases to sign.

### Verification

The full mechanism (version parsing/comparison, every HTTP branch of
check_latest/list_releases with a real, live call against the project's
currently-empty repo -- correctly returning a "no release" 404 --, the
full apply/rollback flow on both the success and failure branch,
path-traversal protection on tarball extraction, the update-helper
socket protocol, webUI routes) is covered by unit tests (see
`tests/test_update*.py`, `tests/webui/test_update_routes.py`). What has
NOT been tried: an actual end-to-end update from a real older version to
an actual, published GitHub release on a live VM -- for that, the repo
first needs at least one real tagged release (see ROADMAP.md phase 6).

## System integration

Canonical paths (`frfw.paths`):

| What | Where |
|---|---|
| Configuration | `/etc/fr_os/config.yaml` (root:fr_os-webui, 0640 — the webUI only reads it) |
| Ruleset backups | `/etc/fr_os/backups/ruleset-<timestamp>.nft` (10 kept by default, root-only) |
| WebUI's own state | `/etc/fr_os/webui/` (TLS keypair, admin account, session secret, AI IDS mock state — owned by fr_os-webui, see below) |
| Apply-helper socket | `/run/fr_os/apply.sock` |
| ZTNA session state (display purposes only, see below) | `/etc/fr_os/ztna_state.json` |

systemd units (`systemd/`):

- `fr-firewall.service` — applies the canonical config at boot, ordered
  after Debian's own `nftables.service` (early boot, before
  `network-pre.target`, so the rules are already in effect before
  networking comes up).
- `fr-apply-helper.socket` + `fr-apply-helper.service` — the privileged
  apply-helper, with socket activation (see Security model below).
- `fr-webui.service` — the actual FastAPI app (`fr-webui` binary), runs
  as the unprivileged `fr_os-webui` user. Binding to port 443
  (sub-root) doesn't need root, just
  `AmbientCapabilities=CAP_NET_BIND_SERVICE` +
  `NoNewPrivileges=yes` — the same pattern Kea's own
  (`kea-dhcp4-server.service`) unit uses with the `_kea` user.
- `fr-ai-ids-retrain.timer` + `.service` — runs `firewall-cli
  ai-ids-retrain` daily (03:30 by default) as the `fr_os-webui` user (no
  root needed, see the AI IDS/IPS section above).

`scripts/install-system-integration.sh` handles system integration on a
fresh machine: creating `/etc/fr_os`, installing a base config (if there
isn't one yet), creating the `fr_os-webui` system user and group, making
`config.yaml` group-readable, creating `/etc/fr_os/webui` owned by
`fr_os-webui`, and installing the systemd units. The admin password has
to be set separately, interactively (`firewall-cli
set-admin-password`) — the installer deliberately doesn't automate this.

## Security model

The webUI can't run as root — it runs as the `fr_os-webui` system user,
with `AmbientCapabilities=CAP_NET_BIND_SERVICE` for port 443 (see
above). Every root-level operation (loading nftables, applying interface
addresses, writing+restarting the Kea config) is requested by the webUI
over a Unix socket (`/run/fr_os/apply.sock`, `frfw.helper`) from a
root-running "apply-helper" systemd service (`fr-apply-helper.service`,
started via socket activation by `fr-apply-helper.socket`). The socket
file's group owner is a dedicated `fr_os-webui` group (`SocketGroup=` in
the `.socket` unit) — this is the access control, not the protocol
itself.

The protocol is deliberately minimal: one JSON object per line, four
commands:

- `ping` — health check
- `apply` (with a `dry_run` option) — applies the canonical config
  (`frfw.provision.apply_all`: addresses → nftables → DHCP)
- `rollback` — restores the most recent ruleset backup
- `save_config` — takes a YAML string, validates it with
  `frfw.config.parse_config`, and only overwrites the canonical config
  with it on successful validation (atomically, via a tmp file + rename)

None of the commands accept a *file path* from the caller — the helper
always uses the canonical config/backup/Kea-config paths it was given at
its own startup (by default `frfw.paths.CONFIG_PATH` / `BACKUP_DIR` /
`frfw.kea.KEA_CONFIG_PATH`). This means that even if the webUI is
compromised, the helper doesn't become a general root-level
file-read/write or command-execution primitive — it's restricted strictly
to saving/applying/rolling back the firewall/DHCP configuration, and
every incoming YAML goes through full schema validation before anything
hits disk.

*Reading* `config.yaml` doesn't go through the helper (the webUI reads it
directly with its own user privileges, via group-read access — this isn't
a security-critical operation), only *writing* it does — this is the one
exception to the "every root operation goes through the helper" rule,
because reading alone can't modify system state.

See also: [`frfw/helper/`](src/frfw/helper/) (server + client),
[`systemd/fr-apply-helper.socket`](systemd/fr-apply-helper.socket),
[`systemd/fr-webui.service`](systemd/fr-webui.service).

## Identity-based Zero Trust network access (ZTNA, phase 7)

Goal: a homelab-friendly, 100% local (no Okta/Azure AD/cloud dependency)
identity-aware login gate that only lets the LAN, or a designated
"Production Server Zone", be reached after a successful login -- in a way
that the data plane (the actual traffic filtering) still runs 100% in
kernel space (nftables), without slowing anything down even at 40 Gbps
by routing it through a userspace proxy (Envoy/Squid). The control plane
(logging in) and the data plane (packet filtering) are strictly
separated -- this section covers both.

### Schema and reusing the `require_ztna` flag

`frfw.config.schema.ZtnaConfig` (`enabled`, `session_ttl_seconds`,
`users: list[ZtnaUser]`) gives the config its own user list storing
usernames and password hashes -- separate from the webUI's admin account
(`frfw.admin_account`), because it's a different audience (end users, not
the administrator). Instead of introducing a new "protected zone"
concept, the existing `Rule` dataclass got a `require_ztna: bool` field
-- a rule can thus *optionally* require, alongside its
from_zone/to_zone/proto/port/address match, that the source IP be in the
ZTNA set, reusing the same engine rather than a parallel abstraction.
Passwords are stored as a PBKDF2-HMAC-SHA256 hash (the same 200k-iteration
scheme as `frfw.admin_account`) -- this is *hashing*, not reversible
encryption, which is the right approach for stored passwords.

### Data plane: an nftables named set with a kernel-native timeout

`frfw.nft.builder` renders a set named `authenticated_ztna_users` with
`flags dynamic,timeout` (only if `ztna.enabled`), and appends an `ip
saddr @authenticated_ztna_users` match to every `require_ztna: true`
rule. Elements added to the set carry their own individual timeout (`add
element ... { <ip> timeout <n>s }`) -- meaning expired IPs are evicted by
the **kernel** itself, with zero cron jobs or userspace background
processes. This has also been confirmed with a real test: an element
added with a 5-second timeout was gone from the set within 6 seconds,
with no code running (see `tests/test_ztna.py`).

### Control plane: login via the privileged helper

The webUI can't run as root, so it can't modify kernel nftables state
directly -- this follows the project's existing privilege separation (see
Security model above). `GET/POST /ztna/login`
(`frfw.webui.routes.ztna`) checks against the hash stored in
`ZtnaConfig.users` (in a timing-safe way -- the hash computation also runs
for an unknown username, so the response time can't be used to guess a
username), then on a successful login sends the client request's source
IP via a new `authorize_ztna` unix-socket command
(`frfw.helper.protocol/server/client`) to the root-running
`fr-apply-helper`, which adds the IP to the kernel set with the TTL set
in the config.

An important finding, confirmed with a direct test: even a *read-only*
`nft list` requires root/`CAP_NET_ADMIN` (`runuser -u nobody -- nft list
ruleset` → "Operation not permitted"). Because of this, `GET
/ztna/status` (the public page showing a user's remaining session time)
also can't read kernel state directly -- it too goes through a new
`ztna_status` helper command, just like `authorize_ztna`. There's no
separate browser-side session cookie: the sole source of truth is whether
the source IP is *currently* in the kernel set, which every
`/ztna/status` call queries live through the helper -- deliberately, so
there's no second, driftable state source living in the browser.

The display-only `/etc/fr_os/ztna_state.json` (ip → {username,
authorized_at}) is *not* a source of truth, it only exists so the `/ztna`
admin screen can show a human name next to an IP -- the actual
authorization decision is always made by the kernel set.

### The `flush ruleset` problem and the snapshot/restore fix

`frfw.nft.builder.build_ruleset()` starts every apply with an unscoped
`flush ruleset`, which clears the *entire* kernel nftables state (every
table/family) on every apply -- this would log out a logged-in ZTNA
session as a side effect of a completely unrelated config change (e.g.
saving a DHCP setting). `frfw.provision.apply_all` fixes this: the
nftables-apply step is bracketed by
`frfw.ztna.snapshot_before_reload()` / `restore_after_reload()` (only if
`ztna.enabled` and not a dry run) -- the snapshot fetches the currently
live elements along with their *remaining* TTL before the `flush`, and
the restore writes them back after the new ruleset is loaded, so an
admin-side config save doesn't accidentally null out another user's
active session. This is also covered by a real, non-mocked integration
test (`test_ztna.py`): it flushes a real nft set, then confirms the
restore brings the sessions back with the correct remaining TTL.

### Open issues

- ~~No rate-limiting/lockout on `/ztna/login`~~ -- solved in phase 10
  (see [In-memory and kernel-level brute-force
  protection](#in-memory-and-kernel-level-brute-force-protection-phase-10)):
  both login endpoints (`/login` and `/ztna/login`) now share the same
  in-memory counter and kernel-level `nft` ban.
- The `/xdp` webUI screen (see phase 4) likely faces the same problem we
  deliberately avoided here: if any route makes an `nft`/`bpftool` call
  directly from the non-root webUI process, it either fails for lack of
  privilege, or (worse) the service running the webUI was given
  unnecessary privilege for it. This hasn't been fixed here -- it would
  need its own review/phase.

## Hybrid post-quantum key exchange on the management layer (phase 8)

Goal: have the webUI's own HTTPS, and (if installed) the host's sshd,
offer a hybrid (classical + post-quantum) key exchange -- `X25519MLKEM768`
in TLS 1.3, `mlkem768x25519-sha256` in SSH -- falling back to classical
unnoticed for an older client/host, runnable on homelab hardware with no
separate crypto accelerator needed. **This section documents an unusually
large number of "doesn't work the way it first looks" findings** --
precisely because this is the newest, least mature technology layer this
project has taken on so far, and wrong assumptions here are expensive (a
bad `KexAlgorithms` line simply keeps sshd from starting at all).

### Two hard version thresholds, both actually verified

- **TLS**: OpenSSL only knows the `X25519MLKEM768` group from **3.5.0**
  (2025-04) onward. Most currently packaged Debian -- including this
  project's own installer image (see the "Automated installer" phase) --
  links an older OpenSSL, and this can't be worked around from Python
  code: the `ssl` module bundles whichever libssl.so the interpreter was
  built against, and a pip package can't update a shared system library.
  `frfw.pqc.openssl_supports_hybrid_tls()` is a real version check,
  actually tested in the dev sandbox (this sandbox runs OpenSSL 3.0.13 --
  so the missing-support branch is not an assumption, it's a directly
  observed result).
- **SSH**: OpenSSH only knows the `mlkem768x25519-sha256` key-exchange
  method from **9.9** (2024-09) onward. An older sshd doesn't just fail
  to recognize it -- crucially -- an unknown algorithm name in
  `KexAlgorithms` keeps the daemon from **starting at all**, it doesn't
  silently skip it. `frfw.pqc.sync_ssh_kex` therefore freshly queries the
  installed sshd's actual, compiled-in list on every call (`sshd -Q
  kex`), and validates the generated drop-in with `sshd -t` before
  considering it applied -- on a failed validation it restores the
  previous content (or deletes the file, if it didn't exist before),
  never leaving sshd an unparseable config on disk.

### The expected (and seemingly offered) API doesn't exist: `SSLContext` can't take a group list

The request originally called for setting the group preference from code
via Python's `ssl.SSLContext`. This -- a verified, not assumed, fact --
is **not possible** with the CPython stdlib: `SSLContext.set_ecdh_curve()`
looks like it can do this, but it doesn't do what it appears to.
Confirmed with a direct test (see `tests/test_pqc.py`):

```python
ctx.set_ecdh_curve("X25519")           # a single name: works
ctx.set_ecdh_curve("X25519:P-256")     # two, colon-joined: ValueError
```

Both names are individually valid TLS 1.3 group names, yet the
colon-joined list is still rejected -- which shows this function can only
set a single classical EC curve (an `OBJ_sn2nid`-style lookup), never a
priority list, and a hybrid PQC group name isn't even in that classical
curve-name table to begin with, regardless of whether the underlying
OpenSSL otherwise supports it. The documented mechanism that actually
works for setting a TLS 1.3 group *list* is OpenSSL's own config file's
`[system_default_sect]` `Groups=` directive -- the same mechanism
Debian/Fedora already use today for system-wide `CipherString`-based
crypto-policy defaults (see `man 5 config`). Since OpenSSL only reads
this file once, at process start, changing this setting always requires
restarting `fr-webui` for it to take effect -- the same "a change needs
an apply/restart to take effect" reality that every other subsystem in
the project already lives with (see e.g. the update mechanism's own,
similar restart notice).

This mechanism is generated by `frfw.pqc.write_openssl_pqc_conf`
(`/etc/fr_os/webui_pqc_openssl.cnf`), which `fr-webui.service`
unconditionally points at via `OPENSSL_CONF=` (see the unit file) -- this
file always exists and is always valid (with classical groups, if hybrid
mode is off), so this environment variable never breaks anything, and it
only ever affects this one process, never the system-wide
`/etc/ssl/openssl.cnf`. The request's actually-supported
`ssl.SSLContext` setting (`minimum_version`/`maximum_version` pinned to
TLS 1.3) was implemented separately, as
`frfw.pqc.tls_ssl_context_factory`, wired in via uvicorn's own
`ssl_context_factory=` extension point (`frfw.webui.server`) -- this was
also tested with a real `uvicorn.Config(...).load()` call and an actual
generated certificate, not just an isolated unit test.

### SSH: an `sshd_config.d` drop-in, never the main file

`frfw.pqc.sync_ssh_kex` writes/deletes a
`/etc/ssh/sshd_config.d/50-fr_os-pqc-kex.conf` drop-in (taking advantage
of Debian's own, enabled-by-default `Include
/etc/ssh/sshd_config.d/*.conf` mechanism, see the generated file's own
header) -- it never touches `/etc/ssh/sshd_config` directly. It *reloads*
the running daemon, never restarts it: a reload re-reads the config for
new connections without dropping any already-live SSH session (including,
potentially, the one the admin is using to apply this very change).

### Control plane: a config flag, never a direct intervention

`config.pqc.enabled` (`frfw.config.schema.PqcConfig`) follows the same
"edit the raw YAML dict, validate, save through the privileged helper"
pattern as every other screen -- saving the setting never touches TLS or
sshd directly, that only happens on the next `apply`
(`frfw.provision.apply_all`'s step 6: `frfw.pqc.sync_tls_pqc_conf` +
`sync_ssh_kex`), exactly like an nftables rule or an XDP blocklist
change.

### Status screen (`/system`) and the real scope of the "quantum-safe" badge

`GET /system` (admin) and the dashboard's small badge
(`frfw.pqc.PqcStatus.quantum_safe`) combine two deliberately separate
concepts: *host capability* (does this particular machine's installed
OpenSSL/OpenSSH build support this at all -- a machine-dependent fact,
independent of the config) and *applied state* (what the most recently
generated file/drop-in actually says -- which can lag behind a
not-yet-applied config change, the same "config vs. applied state can
drift until you run apply" pattern that also exists on the XDP screen).
The "quantum-safe" badge does **not** claim that whatever browser/SSH
connection happens to be open right now is actually using the hybrid
group -- confirming that would need introspecting the negotiated group of
that specific TLS/SSH session, which neither Python's `ssl` module nor
this module does. The capability check itself
(`ssl.OPENSSL_VERSION_INFO`, `sshd -Q kex`) doesn't need any privilege,
so -- unlike the ZTNA gate's kernel-state reads -- it runs directly in
the unprivileged webUI process, not through the helper.

### Scope of verification -- stated honestly

This module was built and tested **without access to a real OpenSSL
3.5+ or OpenSSH 9.9+ build** (this dev sandbox runs OpenSSL 3.0.13, and
sshd isn't installed at all). Every capability check was verified
directly, against the real binary/interpreter, *for correctly detecting
the absence* (this sandbox's OpenSSL correctly identifies itself as
"unsupported", the missing sshd correctly as "not installed"), and the
`set_ecdh_curve` limitation was actually confirmed live. The positive
path -- "the hybrid group is actually, end-to-end negotiated against a
real client/sshd" -- should, on the other hand, be considered
*implemented to spec*, not independently verified the same way this
document has been able to claim for the project's other,
kernel-adjacent subsystems so far (nftables, XDP, ZTNA).

### Open issues

- **Never tested against a real OpenSSL 3.5+/OpenSSH 9.9+** (see above)
  -- once such a build is available (e.g. Debian trixie/13 or newer),
  it's worth confirming a real hybrid handshake at the
  Wireshark/`openssl s_client -groups` level too.
- **The live-build installer's base image** (see the "Automated
  installer" phase) currently uses an old, Ubuntu-patched snapshot whose
  OpenSSL/OpenSSH version is almost certainly below the threshold -- on
  this image, this feature today only runs the "TLS 1.3-only, classical
  groups" branch, which is real hardening on its own, just not the
  requested PQC hybrid.
- **No automatic `fr-webui` restart** when the TLS-side setting is
  applied -- this is a deliberate decision (see above, "a change needs
  an apply/restart to take effect"), not a missing feature, but it does
  need a manual admin-side step.

## Local DNS/XDP ad-blocker (phase 9)

Goal: download and dedupe hosts-format blocklists (the StevenBlack
"unified" list by default), and serve the resulting domain set from a
100% local DNS resolver -- a userspace hash table/text file for
high-volume (tens-of-thousands-scale) lists, not kernel memory -- with an
optional, small "critical" subset in the existing phase 4 XDP LPM trie.
**An important clarification, up front**: this phase's request was
phrased as if the project already had its own DNS resolver ("reload the
DNS resolver") -- verified: it **did not** (Kea, which handles DHCP,
never did DNS resolution, see `frfw.kea`'s own docstring, which
explicitly says "not dnsmasq"). This phase introduces the project's
first DNS resolver, it doesn't extend an existing one.

### Why dnsmasq, and why a dedicated instance of its own

The "lightweight, must run on legacy x86 hardware too" constraint points
to dnsmasq over unbound (substantially lower resource needs, native
hosts-file-based blocking via `addn-hosts=` -- exactly the requested
"host-file" mechanism). The `frfw.adblock.dns_service` module,
however, deliberately does **not** extend the Debian package's default
`dnsmasq.service`/`dnsmasq.conf` with a drop-in: the `/etc/dnsmasq.d/`
directory is only auto-loaded if the `conf-dir=` line is uncommented in
`/etc/dnsmasq.conf`, which isn't guaranteed on a fresh install, and the
machine might otherwise be running a system dnsmasq for something else
entirely. Instead it generates a complete, standalone configuration
(`frfw.paths.ADBLOCK_DNSMASQ_CONF_PATH`) and drives its own, dedicated
systemd unit (`fr-adblock-dns.service`) -- exactly the same "one complete
generated config, one dedicated service" pattern the Kea DHCP engine
uses (`frfw.kea.KEA_CONFIG_PATH`/`KEA_SERVICE_NAME`).

### Downloads never happen inside `apply`

Blocklists can be several megabytes and tens of thousands of lines long;
re-downloading them on every `firewall-cli apply` (which can run many
times during an admin session) would be wasteful and slow. Downloading +
parsing + deduping is therefore a separate, explicit operation:
`firewall-cli adblock-refresh` (invoked by the daily
`fr-adblock-refresh.timer`, see below) or the webUI's "Refresh now"
button (which goes through a new `refresh_adblock` apply-helper socket
command -- the download itself doesn't need privilege, but the final
write under `/etc/fr_os` does, and this whole operation should never run
directly from the webUI process, see below). `frfw.provision.apply_all`,
by contrast, only reconciles whether the dnsmasq instance is running (or
stopped) to match the config, and serves whatever was already
downloaded -- it never touches the network.

### Downloading: `urllib.request`, not a new dependency

The project's only existing "download something from the internet"
precedent (`frfw.update._fetch_json`) uses the stdlib's
`urllib.request`, with an explicit `timeout` parameter, no retries,
through a single "seam" function -- neither `requests` nor `httpx` is a
runtime dependency of this project (the `httpx` in `pyproject.toml`'s
`dev` extra is purely FastAPI's `TestClient`'s internal transport, not
application code). `frfw.adblock` follows the same pattern (`_fetch_url`),
and achieves the requested "async/non-blocking" behavior with a stdlib
`concurrent.futures.ThreadPoolExecutor` (an I/O-bound task, not
CPU-bound, so the GIL doesn't matter) -- instead of real
`asyncio`/`aiohttp`, which would be a new dependency this project has
never had reason for.

### Reusing the existing XDP LPM trie, not a second map

The request's "critical subset" idea was implemented literally, by
reusing the existing `frfw.xdp.sync_blocklist`/
`XdpSniFilterConfig.blocklist` mechanism -- **not** by introducing a
second BPF map. `frfw.provision.apply_all`, ahead of the XDP step,
merges `xdp_sni_filter.blocklist` in memory (never written back to
`config.yaml`) with the first `adblocker.xdp_critical_limit` (0, i.e.
off, by default) domains from the already-downloaded ad-block list, via
`dataclasses.replace` -- exactly the same way a ZTNA-authorized IP never
ends up in the firewall rules file either. With `xdp_critical_limit ==
0`, this step doesn't touch XDP at all -- turning on the ad-blocker never
silently turns on XDP too.

### Control plane: a config flag, never a direct intervention

`config.adblocker` follows the same "edit the raw YAML dict, validate,
save through the privileged helper" pattern as every other screen. The
live domain counter (`GET /adblock`) and the resolver running/not-running
badge are both computed directly, with no privilege, in the webUI process:
counting the lines of a hosts-format file and querying `systemctl
is-active` both need neither root nor `CAP_NET_ADMIN` (unlike the ZTNA
gate's kernel-state reads), so there's no need for a round trip through
the helper here.

### Real, hands-on verified confirmation

The actual blocking mechanism (not just the `dnsmasq --test` syntax
check, which also runs inside the test suite itself) was confirmed by
hand, for real: a real dnsmasq instance was started with the generated
config on a test port, and querying it with `dig`, a domain on the
blocklist resolved to `0.0.0.0`, while a non-listed domain had its query
forwarded upstream by dnsmasq (not served from addn-hosts) -- exactly the
expected behavior. This specific live-query scenario **wasn't** turned
into an automated test: it's repeatable from a plain shell and plain
`python3 -c` (with the same `subprocess.Popen` call), but not from inside
the project's own pytest run in this sandbox -- the dnsmasq child process
binds to the correct port (confirmed with `ss -ulnp`), yet doesn't
respond to a query coming from a completely separate shell, which rules
out this being an frfw code bug. This is a process-/network-namespace
quirk of this CI sandbox's child-process spawning under pytest, not a bug
that deserves a permanently skipped or flaky test -- see
`tests/test_adblock_dns_service.py`'s own detailed comment.

### Open issues

- **DHCP clients' DNS server isn't automatically pointed at this
  resolver.** `DhcpPool.dns_servers` still serves whatever the admin
  explicitly set -- automatically rewriting the Kea DHCP config to use
  the router's own LAN address as the DNS server would be a separate,
  non-trivial integration step (it would affect every existing DHCP
  pool's behavior), which this phase deliberately did not do as a silent
  side effect.
- **No real hybrid-handshake-level Wireshark analysis** of the download
  process (the HTTPS connection to GitHub/StevenBlack is the one trust
  boundary, the same limitation as the update mechanism).
- **Missing live-dnsmasq-query automated test** (see above) -- if a
  future CI environment doesn't have this sandbox quirk, it's worth
  trying to automate it again.

## In-memory and kernel-level brute-force protection (phase 10)

Goal: protect the `/login` (admin webUI) and `/ztna/login` (phase 7)
endpoints from password guessing, while staying within the project's
existing privilege separation -- the non-root webUI process must never
run an `nft` command directly, and the actual ban has to happen in
kernel space (nftables), not in a userspace middleware, so there's no
meaningful CPU load during a flood. This phase explicitly closes a gap
phase 7's "Open issues" section left open ("no rate-limiting/lockout on
`/ztna/login`") -- it now applies equally to both login paths.

### Two-layer defense: memory + kernel, with strict separation of responsibilities

The counting (how many failed attempts came from this IP, over what
time) is lightweight, purely userspace, in-memory state -- it needs
neither persistence (a webUI restart can wipe it) nor root privilege.
The *punishment* (actually dropping packets), on the other hand, can only
happen in the kernel, because that's the only place with access to the
raw network traffic before it even reaches the FastAPI application -- a
Python-level "if banned: return 403" wouldn't protect against any
resource exhaustion, because the TCP connection and HTTP request
processing would already have happened. These two layers repeat exactly
the control-plane/data-plane separation already proven at the ZTNA gate
(phase 7), just in reverse (there a successful login opens a path, here a
failed one closes one).

### `frfw.webui.auth_rate_limiter`: a thread-safe, sliding-window counter

The request's "async lock or thread-safe dict" phrasing was ambiguous --
directly confirmed via `grep` that every one of the project's webUI
routes is a plain `def`, with not a single `async def`
(`src/frfw/webui/routes/*.py`), meaning uvicorn/Starlette runs them in a
thread pool. Because of this, the correct primitive is `threading.Lock`,
not `asyncio.Lock` -- an `asyncio.Lock` called from a synchronous route
wouldn't provide actual mutual exclusion between threads. The
`BruteforceGuard` class maintains an IP → failure-timestamp-list
(`time.monotonic()`) mapping, prunes entries older than 5 minutes on
every call, and if an IP still reaches the threshold of 5, returns
`True` (and immediately clears the entry too -- after the `ban_ip` call
the kernel drops the packets, the Python-side counter has nothing more
to do with that IP). A test with concurrent threads (5 real
`threading.Thread`s, all hammering the same IP at once) (`tests/
test_auth_rate_limiter.py::test_thread_safety_exactly_one_ban_under_concurrent_failures`)
confirms the threshold is crossed exactly once, never zero times (a race
where two threads could both read 4 and neither would see 5) and never
more than once.

Memory bounding with no dedicated background thread/cron job: following
the project's convention (see e.g. the ZTNA set's kernel-native timeout,
there's no Python-side cleanup loop anywhere), a full-table sweep runs
every `_SWEEP_INTERVAL` (100) calls, on the calling thread, removing any
IP that no longer has *any* entry within the window -- this bounds
memory without needing to maintain a second, independently-scheduled
process.

### Unix-socket protocol: `ban_ip`, following the existing `"cmd"` convention

The request literally suggested a `{"action": "ban_ip", "ip": ...,
"duration_seconds": ...}` format, but the project's entire existing
protocol (`authorize_ztna`, `ztna_status`, `refresh_adblock`, ...)
uniformly uses a `"cmd"` field -- for consistency, that's what was
followed (`{"cmd": "ban_ip", "ip": ..., "duration_seconds": ...}`),
rather than introducing a parallel, differently-named field. The webUI
decides *when* to ban (via the `BruteforceGuard` threshold), but the
actual `nft add element` call always goes through the root-running
`fr-apply-helper` (`frfw.helper.server._handle_ban_ip` →
`frfw.bruteforce.ban_ip`) -- the webUI process itself never sees
`CAP_NET_ADMIN`.

### `frfw.bruteforce`: a deliberate structural mirror of `frfw.ztna`

The module deliberately doesn't share code with `frfw.ztna` through a
common abstraction -- the same pattern the project already follows for
`frfw.pqc`'s TLS/SSH halves and `frfw.kea`/`frfw.xdp`'s subprocess
wrapping: every kernel-facing subsystem stays independently testable,
with no premature, assumed shared abstraction. Public API:
`ban_ip(ip, duration_seconds)` (validates the IPv4 format and a positive
duration, then calls `nft add element ... { <ip> timeout <n>s }`),
`snapshot_before_reload()`/`restore_after_reload()` (see below).

**`flags timeout` vs. `flags dynamic,timeout`**: the request suggested
`flags timeout;` syntax, while the existing ZTNA set uses `flags
dynamic,timeout`. Rather than assume which was correct, both were
checked directly with real `nft` commands (`nft add set inet fr_os_test
jail_plain '{ type ipv4_addr; flags timeout; }'`, then `nft add element
... { 10.0.0.1 timeout 5s }'`) -- on this nftables version (1.0.9),
`flags timeout` on its own is enough for a per-element timeout override,
because the set is only ever populated by `frfw.bruteforce.ban_ip`'s
explicit `add element` calls, never a data-plane rule dynamically adding
to it (which is what would require the `dynamic` flag). The simpler form,
as literally requested, was used, and this is documented in a comment
in the test suite.

### Nftables schema: an unconditional set and rule, at the head of the chain

`frfw.nft.builder` always renders the `bruteforce_jail` set --
unlike the ZTNA set, which only appears if `ztna.enabled` -- regardless
of configuration: brute-force protection has no "off" state, because
there's no scenario where an admin would deliberately want to disable
protection for their own login endpoints. The `ip saddr @bruteforce_jail
drop` rule is literally the first line of `chain input`, even before
`iifname "lo" accept` -- this ensures an already-banned IP can't get in
alongside any other rule (including a possible future, overly permissive
loopback rule). Confirmed with a real `nft -j list chain` query
(`tests/test_bruteforce.py::test_real_generated_ruleset_puts_jail_drop_rule_first_in_input_chain`)
that the rule actually appears first in the kernel's own JSON listing,
not just in the Python source.

### The `flush ruleset` problem -- the same fix as ZTNA's

`frfw.nft.builder.build_ruleset()` starts every apply with `flush
ruleset` (see phase 7's own section for the detailed rationale), which
would also clear the `bruteforce_jail` set as a side effect of a
completely unrelated config change (e.g. editing a DHCP pool) -- silently
lifting an active, in-progress ban. `frfw.provision.apply_all` applies
the same snapshot-before-reload/restore-after-reload pattern already
introduced for ZTNA, with the difference that here the snapshot/restore
is unconditional (it's only skipped on a dry run, where there's no actual
reload) -- there's no "enabled" switch to gate it on. A real, hands-on
confirmed test (`test_real_snapshot_and_restore_preserves_remaining_time`):
an IP was banned, the set was cleared (simulating `flush ruleset`), and
the restore was confirmed to bring it back with the correct remaining
TTL -- not a fresh, full duration.

### Fail-safe: the kernel unbans on its own, no Python-side cleanup

The requested "auto-reset" mechanism was handed literally to nftables'
own native `timeout` flag -- there's no cron job, no systemd timer, no
Python-side background thread removing expired bans. Confirmed with a
real test (`test_real_kernel_evicts_expired_ban_on_its_own`): an element
added with a 2-second timeout is already gone from the set 3 seconds
later, with no code running between the test and the kernel touching the
set. A successful login (`guard.record_success(ip)`) immediately clears
the Python-side counter -- this is separate from the kernel-side ban: if
someone is already banned, a correct password after that resets the
webUI-side counter, but (correctly) doesn't lift the kernel-side ban
early, because the IP could be used by anyone, not necessarily the person
who just typed the correct password.

### Open issues

- **IP-based counting can be bypassed behind NAT/a shared outbound IP**
  (e.g. an entire office behind a single public IP): a legitimate user's
  typo falls into the same counter as an attacker's from the same
  address. This is a known, deliberately accepted tradeoff of any purely
  source-IP-based brute-force defense (fail2ban has the same one) --
  adding a secondary, username-based threshold would be a future
  refinement.
- **The ban duration (1 hour) and threshold (5/5 minutes) currently
  aren't configurable from `config.yaml`** -- `MAX_ATTEMPTS`/
  `WINDOW_SECONDS`/`BAN_DURATION_SECONDS` are module-level constants in
  `src/frfw/webui/auth_rate_limiter.py`. This is a deliberate
  simplification in this phase (the request didn't call for
  configurability either) -- making it configurable would be a separate,
  non-trivial schema extension (it would also need a decision on how the
  webUI and the helper share this value, since the threshold is decided
  webUI-side but the duration is passed to the helper as a parameter).
- **No admin-UI listing/manual unban** for currently banned IPs (unlike
  ZTNA's `/ztna` screen, which shows active sessions) -- a wrongly banned
  legitimate user currently has to wait out the 1-hour timeout, or an
  admin has to run `nft` by hand on the server. This would be a simple
  future webUI addition (`frfw.bruteforce.snapshot_before_reload()`
  already returns the data needed for it today).

## Open decisions

The points below get settled during their respective phase, once the
concrete hardware/environment is known — noted here only to flag that
they were deliberately left open:

- ~~Specific XDP program and eBPF loader library~~ -- settled: our own
  `bpf/xdp_sni_filter.c` (not adopted from an existing project) + an
  `ip`/`bpftool` CLI-based `frfw.xdp` orchestrator (not bcc), see the
  "XDP/eBPF fast path" section above.
- Whether DPDK is needed — only if XDP/eBPF isn't enough for the measured
  performance on the target hardware; this question remains open until
  real performance measurement happens (see "Open issues" above).
- Specific NIC driver list/test matrix — grows based on actually
  available homelab hardware.
