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

> **Superseded by phase 11** (see [Real-time, kernel-assisted AI
> IDS/IPS](#real-time-kernel-assisted-ai-idsips-phase-11) further down):
> once phase 4's XDP work existed and this project's connection-tracking
> data became available as a real telemetry source, the mock engine
> described in this section was replaced entirely with a real detector.
> This section is kept as a historical record of the original design and
> its constraints, not a description of the current system.

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

> **Correction (phase 16):** XDP only runs on packets an interface
> *receives*. To filter what LAN clients connect to, the program must be
> attached to the **LAN-side** interfaces their ClientHellos arrive on.
> Earlier guidance here and in the config docstring recommended the WAN
> interface; there it only ever sees connections coming *in* from the
> internet, so outbound filtering silently did nothing. Verified with
> real network namespaces and the real compiled program, now an automated
> test (`tests/test_xdp_live.py`) -- see the phase 16 section.

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

The file's own header comment (four separately highlighted "IMPORTANT"
sections) documents the real, deliberate limits — these are not gaps,
they're documented design decisions:

1. **No general TCP stream reassembly, but a split ClientHello is
   followed (ROADMAP SEC-17).** A ClientHello's first segment is parsed
   statelessly (a TLS handshake record header, 0x16, at payload byte 0).
   Every browser's ClientHello is larger than one segment now -- a
   post-quantum key share is over a kilobyte -- and browsers permute
   their extensions, so the name is often in a later segment. Until
   SEC-17 such a hello passed. Now, when the first segment ends before
   the server_name extension does, the program records where its
   extension walk stopped (an `sni_flow`: the bytes of an extension the
   segment cut, or how much of a skipped one is still to come), and each
   next in-order segment of the flow continues the walk until the name
   is found. A blocked name's segment is dropped, and so is every later
   data segment of that flow -- the client's retransmissions -- until an
   RST or a new connection's SYN; a flow still being followed is
   forgotten after 30 s.

   This runs in a second XDP program, `xdp_sni_split`, reached by a tail
   call (`split_prog`, filled by libbpf at load time): the verifier checks
   each program against its own 1,000,000-instruction budget, and the
   main program already uses about 770,000 of its own. The walk reads
   the packet only through `bpf_xdp_load_bytes()` into a per-CPU buffer,
   and its per-extension step is a `bpf_loop()` callback, verified once
   rather than once per iteration (a plain loop exceeded the budget).
   The budget is the kernel's, and the image's kernel is Debian 12's
   6.1, whose verifier prunes less than a current one. The first version
   of the main program's flow lookup cost 6.1 over the budget, while a
   6.18 kernel took it at 772,000; the boot test caught it. That lookup
   is now its own `__noinline` function (`follow_flow()`), whose paths
   all return to one caller state, and both programs were measured on
   6.1 itself: main about 756,000, split about 64,000. Only the boot
   test loads them on the image's kernel; a newer kernel accepting them
   says nothing about 6.1.
   Still out of reach, and failing open: segments out of order, a hello
   spread over several TLS records, one longer than 8 segments, and a
   jumbo segment past the first.
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
5. **VLAN tags: up to two (ROADMAP SEC-16).** 802.1Q and 802.1ad tags
   are unwrapped before the IPv4 parse, so the IoT and guest segments
   (VLANs on the LAN port, `frfw.segments`) are filtered like untagged
   traffic; before this, every tagged frame that reached the program
   with its tag still in the packet (generic XDP, or a NIC without VLAN
   receive offload) passed unfiltered. A deeper tag stack passes
   unparsed: the router has no VLAN device for the extra tags, so it
   never routes such a frame either. `tests/test_xdp_live.py` sends
   tagged frames through the real program (802.1Q, QinQ, the hello copy
   offset, and the deeper stack).
6. **The parse ends where the IPv4 datagram ends (ROADMAP SEC-7).**
   Bytes on the wire past the IP total length -- Ethernet padding on a
   short frame, or anything a sender appends -- are not part of the
   datagram and are never forwarded, so they are not parsed: a
   ClientHello there is not TLS, a name cut by the datagram's end is not
   matched, and a padded pure ACK does not count as a segment of a split
   hello for phase 19. Two bounds are kept apart: `data_end` is the
   memory-safety bound every read is checked against, for the verifier;
   the datagram's end is a plain scalar (`payload_len`, then `limit` and
   `room` inside `extract_sni()`), because a second packet pointer with a
   variable offset bounds nothing the verifier can use. The TLS record
   length bounds nothing: a ClientHello may legally span records, so it
   stays only the signal that a hello continues in the next segment.
7. **The name is copied at its own length (ROADMAP SEC-20).**
   `extract_sni()` walks the ClientHello and returns only where the
   server_name is (an offset and a length); the program then copies
   exactly that many bytes with `bpf_xdp_load_bytes()` and normalizes
   the copy on the stack (`normalize_name()`). The earlier code read a
   fixed `MAX_SNI_LEN` window from the name's start, so a short name at
   the very end of a frame -- the last extension, nothing after it --
   failed open. A frame that ends inside the name is counted as
   truncated, never matched as a shorter name. A per-byte bounds-checked
   copy was tried first; its 32 unrolled iterations took the program past
   the 512-byte stack limit and to 98% of the verifier's instruction
   budget, the helper costs neither.
8. **QUIC is rejected, not read (ROADMAP SEC-1, review R8).** HTTP/3
   runs over UDP/443, and its ClientHello is encrypted, so the program
   never sees the name in it -- and browsers use HTTP/3 with most large
   sites, so a blocked name stayed reachable with no user action. While
   the filter is on, the forward chain rejects UDP/443 from the filtered
   devices and the VLAN segments on them
   (`frfw.nft.builder.sni_filtered_devices()`): `reject`, not `drop`,
   so a browser falls back to TLS over TCP at once, where the filter
   sees the name. The rule comes right after the IDS quarantine drop,
   ahead of the IoT rules (internet-only isolation accepts a device's
   traffic to the WAN), of `ct state established,related accept` (a QUIC
   connection open when the filter is turned on ends then, not when it
   idles out) and of every admin rule. Reading QUIC instead would mean
   deriving the Initial packet's keys and decrypting it with AES-GCM in
   the XDP program, which the verifier budget has no room for. The XDP
   screen lists what the filter doesn't see: QUIC (and where it is
   rejected), ECH, TLS on ports other than 443, the split hellos point 1
   leaves out, names of 32 bytes or more, and IPv6 (not routed).

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

- **Compilation** (ROADMAP P4-1): `scripts/build-xdp-object.sh` is the
  one way the program is compiled. The image build runs it on the build
  host (`installer/build-live-image.sh`), the live-build hook installs the
  object at `frfw.paths.XDP_BPF_OBJ_PATH`, and the release workflow adds
  the same file to the signed source tarball at `bpf/xdp_sni_filter.o`
  (`git archive --add-file`). A router never compiles: it has no compiler,
  and root must not run whatever `clang` is first on its PATH (SEC-19).
  So `ensure_compiled` returns the shipped object on an installed frfw,
  and with none it says so -- the filter can't be turned on -- instead of
  looking for a compiler. Only a from-source checkout compiles, through
  the same script, when its object is missing or older than the source.
  An update installs the release's own object over the previous one
  (`frfw.update._install_xdp_object`); the old updater never replaced
  it -- it looked for the release's source where the release isn't
  extracted, and kept the image's object, so an update never changed the
  kernel program, and SEC-19's digest had nothing to notice. Now the new
  object's digest differs, and the apply that follows the update (the
  updater restarts fr-firewall) swaps the program in. A release built
  before P4-1 carries no object: installing it (a rollback) removes the
  newer one rather than run it under code it wasn't built for. The boot
  test turns the filter on with the image's program and checks that a
  blocked name's TLS handshake to the router is dropped, an allowed one's
  isn't, and the drop reaches the event file. Its first run found the XDP
  screen failing with HTTP 500 on every router: bpffs is root's (mode
  0700), so `Path.exists()` on a pin raised PermissionError in the
  unprivileged webUI. The screen and `/metrics` now read the counters
  through the apply-helper's read-only `xdp_stats` (the webUI role only;
  the sensor daemons' role can't send it), `get_stats` turns an
  unreadable pin into the XdpError its callers handle, and if the helper
  can't answer the screen says the counters are unavailable instead of
  showing zeros that look like "nothing dropped". The boot test checks
  the screen shows the drops it caused.
- **Loading + pinning** (`load_and_pin`): loads and pins the program and
  ALL its maps once, under `/sys/fs/bpf/fr_os_xdp` (`bpftool prog loadall
  ... pinmaps ...`) — this is what lets it attach to multiple interfaces
  (e.g. a wired LAN and a guest Wi-Fi interface) and have all of them see *the same*
  blocklist/stats/events maps, instead of a separate copy per map per
  interface. Which object the pinned program came from is recorded (its
  sha256, in the XDP state file); when `apply` runs with a different
  object -- after an upgrade -- or the origin is unknown, the program is
  replaced (`replace_pinned`, ROADMAP SEC-19): the new one is loaded into
  a staging directory first, so a verifier rejection changes nothing,
  then swapped in by rename, and every interface is moved to it (the
  attach loop compares program ids). Its maps start empty: the blocklist
  is synced again *before* any interface runs the program, the counters
  start over. Whenever new maps are pinned -- a first load, a re-enable,
  a replacement -- the two ring-buffer readers (`fr-xdp-sni-logger`,
  `fr-tls-fp`) are `try-restart`ed: each opened its map once as root and
  then dropped privileges, so it can neither notice nor reopen a map
  replaced under it.
- **Attachment state** (`sync_sni_filter`): the state file is written
  after *each* attach and detach, not once at the end, so an apply that
  fails part-way still records the interfaces it did attach and a later
  disable detaches them (ROADMAP SEC-19). `tests/test_xdp_lifecycle_live.py`
  runs both against the real kernel.
- **Attachment** (`attach`): tries native (`xdpdrv`) mode first (real
  driver-level speed on supported NICs), falls back to generic
  (`xdpgeneric`) mode on failure — this is the fallback chain the
  project's original plan called for, and one this sandbox's own `lo`
  interface actually forces in practice (loopback never supports native
  mode).
- **Blocklist sync** (`sync_blocklist`): reconciles the pinned LPM trie's
  contents with the config's desired state (add/remove), without
  clearing and rebuilding it on every `apply`.
- **Name canonicalization** (`normalize_sni`, ROADMAP `SEC-17`): both
  sides fold ASCII `A-Z` to lower case and strip trailing dots *before*
  building the LPM key, because DNS names are case-insensitive (RFC 4343)
  and `example.com.` is the same name as `example.com` written in full
  (RFC 1035 3.1). Without it the kernel keyed on the bytes the client
  happened to send and the userspace keyed on the bytes the operator
  happened to type, so a blocklisted name was reachable by changing its
  case or padding it with a dot. The kernel copy lives in `extract_sni()`
  (`bpf/xdp_sni_filter.c`), the mirror in `frfw.xdp.normalize_sni()`; the
  two are pinned against each other by tests rather than by convention.
  Normalization runs *after* the `MAX_SNI_LEN` length check, because that
  check is about the wire name and the kernel refuses an over-long name
  before it ever looks at case or dots -- so a >= 32-byte entry is refused
  at configuration time (`build_lpm_key` raises, `sync_blocklist` names
  every offending entry) instead of installing a key nothing will look up.
  Both new loops are `#pragma unroll` over the constant `MAX_SNI_LEN`, so
  the canonicalization costs no verifier loop-bound reasoning (the failure
  mode described above, where a packet-pointer bound accumulates across
  iterations, applies to unrolled loops too); the emitted program's deepest
  stack access is unchanged at 248 of 512 bytes, and clang compiles the
  range test as `c - 'A'`, mask, branch if `< 26`, `|= 0x20`, which keeps the
  "mask underflow first" rule from the section above intact.
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
does not run as root (`systemd/fr-webui.service`). Instead it follows
the already-decoded JSON lines `fr-xdp-sni-logger` writes to its event
file, `/var/log/fr_os-sni/events.jsonl` (`tail -n 50 -F`). That used to
be the logger's journal, read through the `systemd-journal` group --
which reads *every* unit's log and the kernel's (review v0.2.0 R10). The
event file is narrower (ROADMAP SEC-4): the logger opens it while still
root, under `Group=fr_os-feeds`, `LogsDirectory=fr_os-sni` (0750) and
`UMask=0027`, so it is root:fr_os-feeds 0640 -- the webUI and the sensor
daemons (`fr_os-webui` and `fr_os-sensor`, both in `fr_os-feeds`, ROADMAP
SEC-11) can read it, and
only the logger's already-open descriptor can write it, so no reader
can forge an event that another one acts on (the AI IDS quarantines on
them). The logger keeps it under 4 MiB by emptying it, which `tail -F`
follows; it also still prints each event to its journal for the admin.
A file the webUI may not read is reported in the stream (tail's
"Permission denied") instead of staying silent. Because each stream is a
child process, the route bounds them: one per webUI session -- every
live-log tab of a session reads the *same* child through the process-wide
`_LogStream` registry in `routes/xdp.py`, so N tabs mean one child, not N
-- and at most `LOG_STREAM_LIMIT` (8) live streams per webUI process, past
which a tab gets one `text/event-stream` error frame instead of a process
(review R19). The child is terminated when the session's last tab
disconnects, and *noticing* that disconnect is the part that needs care:
a server that has nothing to write to a closed tab is never told it is
gone, and a quiet journal gives it nothing to write. So the stream is
asyncio end to end -- `journalctl` runs under
`asyncio.create_subprocess_exec`, one pump task per session reads it and
fans each frame out to the tabs' bounded queues -- and each tab, between
frames and at least every `LOG_HEARTBEAT_SECONDS` (15 s, when it sends an
SSE keep-alive comment), asks Starlette whether its client is still
there. The last tab to leave cancels the pump task, whose own `finally`
terminates the child (SIGTERM, SIGKILL after 5 s) and frees the cap
slot; that cleanup runs in the pump's task rather than the cancelled
request's, which could not `await` it. (A first version drove the child
from a synchronous generator in Starlette's thread pool; it was never
closed on disconnect while the journal was quiet, so a closed tab kept
its child and its cap slot. `tests/webui/test_xdp_routes.py` now proves
the behaviour against a real uvicorn over real sockets.) On the frontend side, a native
`EventSource` (no WebSocket, no library) connects to this endpoint, and
appends every incoming JSON line to the bottom of the "terminal"
container, with auto-scroll and a cap of 300 lines (so the DOM doesn't
grow without bound on a tab left open) -- plain vanilla JS, no SPA
framework, consistent with the rest of the project's screens.

### Open issues

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
   --generate --show-on-console` -- non-interactive, cryptographically
   random, via the `secrets` module). It is shown on the console through
   `/etc/issue.d/fr_os-initial-admin.issue`, which is root-only (0600):
   agetty runs as root and prints `/etc/issue.d/*.issue` before every
   login prompt, no other account can read it, and it never passes
   through the shell or the journal. `fr-initial-password.path` watches
   the account file and removes it once the password no longer works
   (`frfw.initial_password`). It used to be prepended to the
   world-readable `/etc/issue` and stayed there (review triage A5); a box
   updated from v0.1.0 has that line moved out when the webUI starts.
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
privileges: it downloads the release's signed source tarball
(`https://github.com/<repo>/releases/download/<tag>/frfw-<version>.tar.gz`
plus `SHA256SUMS` and `SHA256SUMS.sig`, see "Signed releases" below),
verifies and unpacks it, `pip install`s it, updates the systemd unit files, and restarts the affected
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
reads it), once the release is downloaded and verified and before `pip
install` changes anything, with the attempt marked `in_progress`;
`rollback_update` reinstalls that and clears it -- a rollback can't
itself be rolled back. (The code used to record it only after a fully
successful install, so an update whose `pip install` worked but whose
service restart failed left new code installed and rollback refusing --
review triage C1. A failure before anything changed, e.g. a download or
signature failure, keeps the earlier rollback target.) If the previous version's
unpacked source is still present under `RELEASES_DIR`
(`/opt/fr_os/releases`) (a successful update never deletes old version
directories), rollback works again without a download, even without
network -- which matters exactly when the bad update itself is what broke
the network too.

On failure (of a download, unpacking, pip install, or a service restart)
the attempt and the error message get recorded in the state file's
`last_update` field, and the call raises `UpdateError` -- neither the CLI
nor the webUI page stays silent on a failed update.

### Signed releases

An update is installed only if it verifies (`frfw.release_signing`,
review triage A4). A release carries the source tarball
(`frfw-<version>.tar.gz`), a `SHA256SUMS` over it and the ISO, and an
Ed25519 signature over that file (`SHA256SUMS.sig`), made in CI with the
`FROS_RELEASE_SIGNING_KEY` secret. The updater checks the signature
against the public keys shipped in the *installed* package
(`src/frfw/release_keys/*.pem`, with the `openssl` CLI — no new Python
dependency) and the tarball against the signed checksum, before anything
is extracted. A cached copy is re-verified on every use, so a rollback
can't be fed a swapped cache either. With no trusted key in the build,
every update is refused. Key setup and the release procedure:
[docs/RELEASING.md](docs/RELEASING.md).

Still not verified: the Python dependencies `pip` resolves from PyPI for
the release (`>=` floors), and releases older than this mechanism
(v0.1.0 is unsigned, so a router won't update or roll back to it).

### Verification

The full mechanism (version parsing/comparison, every HTTP branch of
check_latest/list_releases with a real, live call against the project's
currently-empty repo -- correctly returning a "no release" 404 --, the
full apply/rollback flow on both the success and failure branch,
path-traversal protection on tarball extraction, the update-helper
socket protocol, webUI routes) is covered by unit tests (see
`tests/test_update*.py`, `tests/webui/test_update_routes.py`).

`tests/test_update_xdp_live.py` runs the path end to end, short of the
download and of `pip`/systemd (ROADMAP P4-1): a release tarball made by
the workflow's own `git archive` command, signed with a throwaway key
the test points `trusted_keys()` at, found in the release cache,
verified, extracted and installed by `apply_update`, and then its XDP
program swapped into the kernel by the next apply. Its first run found
every update failing: the source tree has symbolic links (live-build's
bootloader links, absolute paths into the build host's `/usr/lib`), and
`filter="data"` refuses an absolute link -- while on a Python without
that filter, the extraction's own check looked at member names, not at
where a link points. Extraction now takes regular files and directories
only; links are skipped, never created or followed.

What has NOT been tried: an update from a real older version to a
published GitHub release on a live VM -- for that, the repo first needs
a real tagged release built with P4-1 (see ROADMAP.md phase 6).

## System integration

Canonical paths (`frfw.paths`):

| What | Where |
|---|---|
| Configuration | `/etc/fr_os/config.yaml` (root:fr_os-webui, 0640 — the webUI only reads it) |
| Ruleset backups | `/etc/fr_os/backups/ruleset-<timestamp>.nft` (10 kept by default, root-only) |
| WebUI's own state | `/etc/fr_os/webui/` (TLS keypair, admin accounts, session secret, audit log — fr_os-webui, 0700, see below) |
| Network-parsing daemons' output | `/etc/fr_os/sensors/` (AI IDS events, IoT inventory, App-ID usage, TLS fingerprints — fr_os-sensor:fr_os-webui, 0750) |
| Network-parsing daemons' config | `/etc/fr_os/sensor-config.yaml` (config.yaml without its secrets — root:fr_os-sensor, 0640, ROADMAP SEC-11) |
| Apply-helper socket | `/run/fr_os/apply.sock` |
| ZTNA session state (display purposes only, see below) | `/etc/fr_os/ztna_state.json` |

systemd units (`systemd/`):

- `fr-firewall.service` — applies the canonical config at boot (early
  boot, before `network-pre.target`, so the rules are already in effect
  before networking comes up). Debian's own `nftables.service` also
  starts before `network-pre.target`, and its `/etc/nftables.conf`
  (`flush ruleset`) would replace the FR_OS ruleset, its stop action
  flush it. The `nftables` package stays (it provides `nft`); the unit is
  masked in the image (live-build hook) and by
  `install-system-integration.sh`, and `fr-firewall.service` is ordered
  `After=` it besides, so even an unmasked one can't load its file over
  the FR_OS ruleset. The QEMU boot test checks the mask in the built
  image, that persistence doesn't undo it, and that the unit never ran
  (ROADMAP SEC-18). It fails closed (`firewall-cli apply
  --fail-closed`): with no `config.yaml`, or when an apply fails while no
  FR_OS ruleset is loaded, it loads a baseline that lets in only
  loopback, replies to the router's own connections and IPv6 neighbour
  discovery, and forwards nothing (`frfw.apply.BASELINE_RULESET`). A
  failed reload never replaces a working ruleset, and stopping or
  restarting the unit leaves the ruleset loaded (no `ExecStop`). The
  live image enables it from the very first boot, so the WAN that
  live-boot brings up by DHCP is never unfiltered.
- `fr-apply-helper.socket` + `fr-apply-helper.service` — the privileged
  apply-helper, with socket activation (see Security model below).
- `fr-webui.service` — the actual FastAPI app (`fr-webui` binary), runs
  as the unprivileged `fr_os-webui` user. Binding to port 443
  (sub-root) doesn't need root, just
  `AmbientCapabilities=CAP_NET_BIND_SERVICE` +
  `NoNewPrivileges=yes` — the same pattern Kea's own
  (`kea-dhcp4-server.service`) unit uses with the `_kea` user.
- `fr-ai-ids.service` — the real-time AI IDS/IPS anomaly detection
  daemon (phase 11), running continuously as the `fr_os-sensor` user (no
  root needed -- see the "Real-time, kernel-assisted AI IDS/IPS" section
  below).

`scripts/install-system-integration.sh` handles system integration on a
fresh machine: creating `/etc/fr_os`, installing a base config (if there
isn't one yet), creating the `fr_os-webui` and `fr_os-sensor` system
accounts and their state directories (`firewall-cli ensure-accounts`,
`frfw.accounts`), making `config.yaml` group-readable, and installing the
systemd units. The admin password has
to be set separately, interactively (`firewall-cli
set-admin-password`) — the installer deliberately doesn't automate this.
The account first boot generates is flagged `must_change`: its first
sign-in reaches nothing but `/setup`, which turns it into the admin's own
account -- a username that isn't `admin`/`root`/... and a new password
(security-lessons G1); the generated login stops working at once.
The webUI never creates an account itself: with none on disk its sign-in
page only says to run that command on the console. (It used to let the
first visitor create the admin account over the network, unthrottled, on
every interface — review triage A3.)

## Security model

The webUI can't run as root — it runs as the `fr_os-webui` system user,
with `AmbientCapabilities=CAP_NET_BIND_SERVICE` for port 443 (see
above). Every root-level operation (loading nftables, applying interface
addresses, writing+restarting the Kea config) is requested by the webUI
over a Unix socket (`/run/fr_os/apply.sock`, `frfw.helper`) from a
root-running "apply-helper" systemd service (`fr-apply-helper.service`,
started via socket activation by `fr-apply-helper.socket`).

Access control has two layers. The socket file (0660, group
`fr_os-webui`) decides who can connect at all. Then the helper asks the
kernel who is on the other end (`SO_PEERCRED`, which the peer can't
forge) and allows each account only its own commands
(`frfw.helper.peer`):

| Peer | May send |
|---|---|
| root, the webUI (`fr_os-webui`) | everything |
| the network-parsing daemons (`fr_os-sensor`) | `ping`, `quarantine_ip`, `conntrack_sample`, `dhcp_leases`, `iot_sync_isolation` |
| anyone else | nothing |

The daemons that parse attacker-controlled input — `fr-ai-ids`,
`fr-appid`, `fr-iot-scan`, `fr-tls-fp` (after it drops root) — run as
`fr_os-sensor`, not as the webUI, and write to `/etc/fr_os/sensors`. They
can't read the webUI's session secret, TLS key or accounts
(`/etc/fr_os/webui`, 0700), and a bug in one of them can quarantine a
host but can't rewrite the config, apply it, or install an update.

**No secrets for the parsers either (ROADMAP SEC-11, review v0.2.0 R17).**
`config.yaml` holds the ZTNA users' password hashes and the metrics token
digest, and is root:fr_os-webui 0640. The sensor account used to be in
`fr_os-webui` -- for the helper socket and the event feeds -- and so could
read it, and the audit log and update state too. Now:

- `fr_os-sensor` is in no group of the webUI's. What the two share has a
  group of its own, `fr_os-feeds`: the apply-helper socket (where the
  per-uid check above still applies), the XDP SNI event file and the
  resolver's query log.
- The daemons read `/etc/fr_os/sensor-config.yaml`, root:fr_os-sensor
  0640: `config.yaml` without its secrets (`frfw.config.export.redacted`,
  the same as `firewall-cli config-export`). Root rewrites it on every
  save through the apply-helper (the daemons that re-read their config
  see a change without an apply) and on every apply, the boot-time one
  included -- the sensor units are ordered after `fr-firewall.service`.
- `fr-accounts` moves an older router over: it takes `fr_os-sensor` out
  of `fr_os-webui`, and moves the event files and the live helper socket
  to `fr_os-feeds` (a writer keeps a file's group; the SNI logger also
  sets it on every open). An update restarts `fr-accounts.service` first,
  so this happens without a reboot.

`tests/test_sensor_config_copy.py`, `tests/test_helper_peer.py` (the
accounts, the migration) and `tests/test_systemd_sandbox.py` (no unit
but the webUI's has its group) check it; the boot test checks the
router's own `/etc/group`, the copy's owner and mode, and that the
metrics token digest generated in boot 3 is in `config.yaml` and not in
the copy. The
webUI's "Scan now" on the IoT screen asks the helper (`iot_scan`) to run
`fr-iot-scan.service` instead of scanning in the webUI process.
`fr-accounts.service` (pulled in by every unit running as either account)
creates the accounts, so an update that brings these units also brings
the account they need. The update-helper's socket is 0600 and owned by
`fr_os-webui`, and that helper accepts only root and the webUI.

### Password hashing (security-lessons G2)

Passwords (webUI accounts, ZTNA users) are hashed with `hashlib.scrypt`
(OpenSSL through the standard library -- no compiled dependency, the
reason argon2 was avoided), N=2^15, r=8, p=3: OWASP's equivalent of
N=2^17 at a quarter of the memory, 32 MiB per check. The hash string
carries its parameters (`scrypt$N$r$p$salt$digest`). A hash from before
this (PBKDF2-SHA256, 200 000 iterations) still verifies at that floor and
is replaced in place on the next successful sign-in; the old hash is not
kept anywhere.

### Brute force and credential stuffing (security-lessons G6)

Two counters guard both sign-ins (`/login`, `/ztna/login`): per source
address (5 failures in 5 minutes jail it at the firewall for an hour)
and per account (10 failures in 15 minutes, from any number of
addresses, refuse that account's sign-in for the rest of the window --
what a botnet spreading one guess per address runs into). An address
the account signed in from in the last 90 days is a *known source* and
is never locked out, so the lock can't be turned against the owner;
unknown usernames lock like real ones, so the message tells nothing.
Both counters and the known sources live in `login_guard.json` (0600,
the webUI's state directory) and survive a restart.

New passwords -- webUI accounts, first-run setup, resets, `firewall-cli
set-admin-password`, ZTNA users -- must be 8+ characters, not among the
10,000 most common passwords (a local list, also matched with trailing
digits and punctuation removed: "Password123!" is "password"), not
repetitive, and must not contain the username (`frfw.passwords`).

### Detecting persistence (security-lessons G9)

The audit log is root's (`/var/log/fr_os/audit.log`, 0640
root:fr_os-webui). The webUI reads it but can't write it: its entries go
to the apply-helper (`audit_append`), which stamps the time and origin
itself and refuses anything but a small flat mapping -- so a compromised
webUI can add lines but not rewrite or delete the ones that show what it
did. `firewall-cli` (root) writes directly.

Some entries are **alerts**: the changes that give an intruder a way to
stay. A new admin account or a user made admin, an admin's password
reset by another admin, a new or changed ZTNA user, a sign-in from an
address the account hasn't used in 90 days (the G6 known sources),
second factors removed or reset, the admin-MFA requirement turned off,
management opened to the WAN, and account changes made on the console.
The dashboard lists the alerts an admin hasn't marked as seen (per
admin; viewers don't get them), and the audit table on the Users screen
marks them.

The software-integrity check (`frfw.integrity`) compares every file of
the installed package with the SHA-256 `pip` recorded in its `RECORD`:
a patched or deleted file shows on the dashboard and the System screen,
and `firewall-cli integrity` exits 1. It can't catch an attacker with
root who rewrites `RECORD` too -- that needs a manifest signed with the
release key -- and a development install (`pip install -e`) is reported
as not verifiable, not as clean.

### The security score (security-lessons K8)

`frfw.security_score` pulls the lessons together into a checklist. Each
item is worked out from what the router knows:

- no account has a default name (K1/G1);
- every admin has a second factor (G5);
- management is closed to the WAN (F2/G4/K5);
- no newer release is available (G10), and security releases install
  themselves (J3);
- the rule check finds no any-to-any, internet-wide or shadowed rules
  (K2);
- firewall drops are logged (K6);
- IoT isolation or segments are on (K4);
- nothing unneeded listens (K7);
- FR_OS's own files are intact (G9).

The Security score screen shows the score and every item, with a link to
the screen that fixes it. The dashboard shows the score and what's still
open. An item whose facts aren't available right now is "unknown" and
counts neither way: say, no update check has run yet, or the helper
didn't list the sockets.

### Nothing listening that isn't needed (security-lessons K7)

The attack-surface view (I3) shows what listens and who can reach it.
K7 adds a verdict for each socket: what in the configuration needs it
(`frfw.surface.needed_by`):

- the webUI and SSH (sshd runs only while someone has a key);
- the WAN's DHCP client;
- the DNS filter, only with `adblocker` on;
- the DHCP server, only with DHCP pools;
- the IoT scan, only with `iot` on;
- the WireGuard port, only with the VPN on;
- anything on loopback, which no zone can reach anyway.

A socket reachable from a zone with no such reason is flagged "not
needed". It appears at the top of the Attack surface page, and
`firewall-cli surface` exits 3 for it (2 still means reachable from the
internet). An unneeded socket the firewall closes everywhere isn't
flagged: it can't be attacked from any zone. The QEMU boot test opens
the page on a freshly set-up router and expects nothing flagged, so a
package that starts listening on its own fails the build.

### Logging on by default (security-lessons K6)

You can't investigate what nobody logged. Out of the box:

- **Firewall drops.** Each chain's last rule, right before its `policy
  drop`, logs what nothing accepted:
  `limit rate 10/minute burst 10 packets log prefix "fr_os/drop/<chain>: "`.
  The rate limit means a flood can't fill the disk. The lines go to the
  kernel log (`nf_log_syslog` is loaded at boot, so the sandboxed apply
  units never load it). The dashboard's "Recently dropped" card reads
  the latest ones through the apply-helper (`firewall_drops`), since
  the kernel log is root's. `logging.drops: false` turns it off.
- **Admin sign-ins and changes.** The audit log (G9) has recorded every
  sign-in and every change request since phase 18, root-owned since G9.
- **Retention.** The journal is capped at 200 MB and 90 days (a
  journald drop-in the image and the install script put in place),
  instead of journald's percentage-of-the-disk default. The audit log
  rotates at 1 MB, keeping one old generation.

The QEMU boot test sends a packet to a LAN port nothing allows. It then
finds the kernel's drop line for it in the persisted journal. Forwarding
logs to a SIEM is still ROADMAP OPS-2.

### Segmentation by default (security-lessons K4)

On a flat LAN, one hacked camera or a guest's infected laptop reaches
every device. Two changes make segments the default path:

- **New installs isolate IoT devices.** The first-boot config
  (`frfw.skeleton`) turns IoT isolation (phase 14) on for the LAN with
  `auto_isolate`. Devices classified as IoT reach the internet, but not
  the rest of the LAN or the router's management. The IoT Devices
  screen trusts one back with a click.
- **The Segments screen** (`frfw.segments`) is offered right after
  first-run setup, and stays in the sidebar. It adds an IoT segment
  (VLAN 30, 192.168.30.0/24) and/or a guest segment (VLAN 40,
  192.168.40.0/24) on the LAN port. Each gets:
  - its own zone and DHCP;
  - one rule to the internet and none towards the LAN or the router's
    management;
  - for IoT, isolation of the devices.
  Adding them pins `management.zones` to the zones that manage the
  router today, so a new segment never becomes a management zone. An
  interface can now be a VLAN (`vlan: {parent, id}`), which apply
  creates with `ip link add ... type vlan`. The access point or switch
  tags the IoT and guest Wi-Fi or ports with those IDs.

The QEMU boot test adds both segments through the webUI and applies them
on Debian's kernel (the unit-test sandbox has no 802.1Q support).

### The rule check and temporary rules (security-lessons K2)

Firewall rule sets grow by accretion. A rule opened "for a moment" stays
for years; a broad accept added above a narrow drop silently cancels
it. `frfw.rule_lint` checks the rules the way a reviewer would and
reports:

- **any-to-any** accept rules;
- accept rules that open all of a zone (or the router) to the internet,
  without a port or a source address;
- rules **shadowed** by an earlier rule in the same chain that matches
  everything they do and decides differently, so they never match; with
  the same decision, they are reported as **redundant**;
- rules **unused** for 90 days;
- **expired** temporary rules.

"Matches everything" is decided field by field and conservatively
(zones, protocol, port ranges, address containment, MAC, ZTNA,
schedule, expiry): the check never calls a rule shadowed when it isn't,
though a rule shadowed by a combination of others can slip through. It
runs on the Rules screen (with a badge on each flagged rule), when a
rule is added (a warning right away), and as `firewall-cli rule-check`.

Every rule in the ruleset has an nft `counter`. The kernel resets them
on each apply, so `fr-schedule-check.timer` (root, hourly) folds them
into `/etc/fr_os/rule_hits.json`: when each rule was first seen and
when its counter last went up. That record drives "unused for 90 days"
and the Rules screen's "last match" column.

A **temporary rule** has an `expires` time. The ruleset renders it with
`meta time < <Unix time>`, so the kernel itself stops matching it at
that second, without a reload or a timer. Tested in a network
namespace: a client gets in before the expiry and not after. Rulesets
built later leave it out. Its entry stays in config.yaml, marked
expired, until the Rules screen's "Remove expired rules" clears it. The
router never rewrites the admin's config on its own.

### Security updates are loud (security-lessons G10)

`fr-update-check.timer` runs `firewall-cli update auto` ten minutes
after boot and then every 12 hours (with up to an hour of random delay,
so a fleet doesn't hit GitHub at once). It records what it found in
`/etc/fr_os/update_check.json` (0644, nothing secret), so the webUI
never has to reach GitHub itself. A release is a **security release**
when its title carries `[security]` or its notes a `Security: yes` line
(docs/RELEASING.md). Every webUI page then shows a red "Security update
available" banner; an ordinary release is a quiet notice; the banner
goes once the new version is installed (the cache names the version it
was about). A failed check keeps the last finding, with the error, so a
network outage doesn't hide a pending security fix. How to report a
vulnerability, and how fast we fix one, is in `SECURITY.md`.

### Installing security releases without waiting (security-lessons J3)

With `update.auto_install_security: true` (off by default; a switch on
the Update screen), `firewall-cli update auto` also *installs* a security
release as soon as it finds one, through the same `apply_update` as a
manual update -- so the signature must verify (A4). A failure behaves
like a failed manual update: before the release is verified nothing has
changed; after that, the error says to roll back (one click on the
Update screen) -- it isn't rolled back by itself. Either outcome is a security alert on the
dashboard (the software changed without anyone clicking), and a failed
install is shown on the Update screen while the red banner stays. An
ordinary release is never installed by itself, and neither is anything
when the config can't be read. `fr-update-check.service` runs as root
with the same sandbox as `fr-update-helper.service` (it writes where an
update writes). `SECURITY.md` publishes the fix-time targets that make
this worth having: 7 days for a critical vulnerability.

### A VPN with keys, not passwords (security-lessons G8)

The 2026 firewall intrusions often started with VPN credentials:
phished, sprayed, or read on a compromised box and replayed. FR_OS's
remote access is WireGuard only. Each device has its own key pair, and
the router knows only the public half. A key copied off one device
doesn't unlock a second one, and nothing a user types can be sniffed
and reused.

- `wireguard:` in config.yaml lists the devices by public key. The
  router's private key is in `/etc/fr_os/wireguard/private.key` (0600
  root, directory 0700), generated on the first apply. It is never in
  config.yaml, which the webUI can read; a `private_key` there is
  refused. The webUI learns the router's public key and each device's
  last handshake from the apply-helper (`wireguard_status`).
- `frfw.wireguard.sync`, in `apply_all` right after the ruleset (like
  forwarding):
  - creates `wg0` if it's missing;
  - loads keys and peers with `wg syncconf` (existing sessions survive),
    with the private key on `wg`'s standard input, never in a file or
    on a command line;
  - sets the tunnel address and brings the link up.
  With WireGuard off, it removes `wg0`.
- The ruleset puts `wg0` in its zone's interface set and accepts the
  UDP port from anywhere. WireGuard stays silent to any packet that
  isn't from a known key, so the open port can't be told apart from a
  closed one. Everything else the VPN may reach is ordinary rules.
- The VPN screen adds a device in one of two ways:
  - the device's own public key is pasted, and its private key never
    leaves it;
  - the router makes the pair and shows the device's configuration
    once, as text and as a QR code for the WireGuard app. The page is
    `Cache-Control: no-store`, and the private key isn't stored or
    logged anywhere.
  Turning the VPN on, and every new device, is a security alert (G9).
- Tested for real: two network namespaces joined by a WireGuard tunnel
  (the userspace wireguard-go, since the test sandbox has no kernel
  module), with FR_OS's own ruleset on the router. A configured device
  reaches the router through the tunnel. The same port outside the
  tunnel is dropped, and a key the router doesn't know gets nowhere.
  The QEMU boot test turns the VPN on through the webUI and applies it
  on Debian's kernel module.

Not done: ZTNA still signs users in with local passwords; FIDO2 there
is future work.

### Managing from outside through the VPN (security-lessons K5)

The tunnel's zone doesn't face the internet, so it is a management zone
by default (F2/G4). The firewall doesn't drop the webUI and SSH from it,
and both listen on the router's tunnel address too: the webUI through
the listen addresses (it restarts on apply when they change), sshd
through its `ListenAddress` drop-in. The VPN screen's
`webui-from-vpn`/`ssh-from-vpn` rules let them in. An admin who
doesn't want management over the VPN lists only the other zones in
`management.zones`. The System screen points to the VPN wherever it
talks about remote management. When the WAN is opened while the VPN is
on, it says there is no need to. The warnings name the VPN screen as
the alternative. With MFA for admins (G5) this is K5's "VPN
misconfiguration" answer: a single remote-access path, key-based, and
nothing from the internet on the management plane.

### Sessions end on the server (security-lessons G7)

A session is a signed cookie *and* an entry in `sessions.json` next to
the session key (0600; only SHA-256s of the session ids, so the file
holds nothing a browser could present). A request needs both. Logout
removes the entry, so a copied cookie stops working at once; *Account ->
Log out everywhere* removes every entry of the account; a password
change removes all of them (the browser that made the change gets a new
one), and so do an admin's password reset and deleting the account.
Role changes need no revocation: every request re-reads the account.

### An explicit CSRF token and app-wide security headers (review R15)

`SameSite=Lax` on the session cookie blunts cross-site form posts, but
that is a side effect of the cookie, not a decision, and it doesn't help
if the router is opened by name (the token does: it is derived from the
session id with the webUI's secret key, so an attacker on another origin
can't compute it even if they can read the page). The token travels as a
hidden field in every POST form (`csrf_input(request)`), as the
`X-CSRF-Token` header (used by `webauthn.js` for its `fetch()` calls)
or in a JSON body, and is verified on every state-changing request in
`require_login` -- that is in one place, so a new POST route can't
forget it. The three public sign-in forms have no session, so they
carry no token. A URL query string is not one of the carriers on
purpose: a token in a query lands in the access log, in the browser
history and in the outgoing `Referer` of every link on the page, so it
stays in the body or the header, and `tests/webui/test_no_secret_leaks.py`
walks every page and the audit log to prove it appears nowhere else.
HTTP responses all carry `Content-Security-Policy`,
`frame-ancestors 'none'` with `X-Frame-Options: DENY`,
`Referrer-Policy`, `X-Content-Type-Options` and `Permissions-Policy` from
one app-level middleware; the policy names only `'self'` (and `data:` for
the inline SVG favicon) -- the UI itself serves the assets, no CDN
(security-lessons G11). `script-src` is exactly `'self'`: every script is
a static file (`forms.js`, `xdp.js`, `webauthn.js`), and no template
carries an inline `<script>` or an `on*=` handler, so an injected one
would not run. A destructive form asks first through a
`data-confirm="..."` attribute that `forms.js` turns into the prompt
(with `data-confirm-when-checked` for the allow-WAN switch) -- the text
is an attribute value, never JavaScript. Only `style-src` keeps
`'unsafe-inline'`, for inline `style` attributes, which can't run code. The other half is a
test: one walk proves every state-changing route behind the session
answers a token-free request with 403 "CSRF", and a template check
proves every POST form in every template that has a session carries the
hidden field (`tests/webui/test_csrf.py`).

### Second factor (security-lessons G5)

Every account (viewers too) can add **security keys / passkeys**
(FIDO2/WebAuthn, verified with `py_webauthn`) and an **authenticator
app** (TOTP, `pyotp`) under *Account -> Second factor*; adding or removing
one asks for the current password again. With a factor on the account,
`POST /login` with the right password sets no session, only a login
ticket (`fr_os_mfa` cookie, path `/login`): a random 256-bit id the
server keeps in memory for 5 minutes, bound to the account and its
password version, used up by the first successful second step (a lock
makes that single-use under parallel requests) and dropped after 5 wrong
codes, each of which also counts toward the brute-force guard; 10 wrong
second factors for one account within 15 minutes (over any tickets and
addresses) refuse its second step for that long. A TOTP
code is accepted once (the last used time step is stored; checking and
recording it is one locked step); a security key's signature counter
must grow, so a cloned key shows up.

WebAuthn binds a key to the name the router was opened by (the RP id),
and browsers refuse IP addresses there: keys can be added and used only
at a name such as `https://fr-router.lan/` (with a certificate for it).
Opened by IP, the page says so and TOTP still works. This is the
phishing resistance: a look-alike site gets a signature for its own
origin, which the router refuses.

*Users -> Second-factor policy* can require a factor for admins: an admin
without one can then reach only `/account/mfa` (and logout) until they
add one. Recovery: another admin's *Reset* on the Users screen, or
`firewall-cli mfa-reset USER` on the console; both end the user's
sessions. The TOTP secret and key public keys live only in `auth.json`
(0600) and never appear in a page after enrolment.

### Secrets stay on the box (security-lessons G3)

`auth.json` (webUI accounts) is created 0600, `config.yaml` stays 0640
root:fr_os-webui through every save (A6), the session key and TLS key
never leave `/etc/fr_os/webui` (0700). No webUI page or API response
carries a hash, salt, digest, token, or key -- a test renders every GET
route to prove it. Every export goes through
`frfw.config.export.redacted()` (`firewall-cli config-export`), which
leaves ZTNA password hashes and the metrics digest out.

### Review checklist for anything that authenticates (security-lessons H1)

- The client never chooses how strictly it is checked: no request field,
  header, cookie or negotiated option may skip or weaken a check.
- Every auth path fails closed and has negative tests -- forged, missing,
  replayed, expired and downgraded credentials -- next to
  `tests/webui/test_auth_negative.py`.
- Identity comes from the server side: the session signature and the
  account file, the TCP peer address (never `X-Forwarded-For`), the
  kernel's `SO_PEERCRED` -- never from what a request says about itself.
- Stored secrets can't downgrade the check either (a hash naming a weak
  algorithm or too few iterations never verifies).
- Every flow is tested as a state machine (security-lessons J1, next to
  `tests/webui/test_auth_flows.py`): steps skipped, requests reordered,
  tokens and codes replayed, requests raced. A token is used up
  atomically (one caller wins), and state shared between requests -- the
  account file, tickets, used TOTP steps -- changes only under a lock;
  `auth.json` under an `flock` on its directory, which also covers
  `firewall-cli` running at the same time.

### No argument injection (security-lessons F1)

No shell anywhere (`shell=True`, `os.system`). Every value that reaches
a command line -- interface names, addresses, MACs, unit names, versions,
repos, disk paths, host names -- passes a strict allow-list in
`frfw.validate` (anchored with `\Z`, never `$`, which lets a trailing
newline through), both where the config is parsed and at the call site.
Tools that support it get `--` before positional values; `ip` doesn't,
so the name always follows `dev`. `tests/test_argv_injection.py` throws
values starting with `-`, containing spaces, newlines, `;`, quotes and
nft/shell metacharacters at all of it.

### Management plane off the WAN (security-lessons F2/G4)

The webUI and sshd are reachable only from the management zones -- by
default every zone that doesn't face the internet (`frfw.management`).
Three layers: the input chain drops :22/:443 from every other zone
ahead of the admin's rules; the webUI binds loopback and the management
interfaces' static addresses instead of 0.0.0.0 (one socket each, with
`IP_FREEBIND` so a LAN address that isn't up yet doesn't stop it); sshd
gets a `ListenAddress` drop-in (validated with `sshd -t`, reloaded, never
restarted). The same drop-in hardens sshd's authentication
(security-lessons F3): `PasswordAuthentication no`, `AuthenticationMethods
publickey`, `PermitRootLogin no`, `AllowGroups fr_os-ssh` (a group
`ensure-accounts` creates empty -- no SSH login until the admin adds
someone with a key), `MaxAuthTries 3`, `LoginGraceTime 30`. It sorts
before distribution drop-ins (e.g. cloud-init's 50-), and sshd keeps the
first value it reads, so these win; `apply` says who can log in. It
also allows only strong crypto (security-lessons H3): KexAlgorithms
sntrup761x25519/curve25519/DH group 16-18 with SHA-512 (left to the PQC
drop-in, ML-KEM hybrid first, when PQC is on), Ciphers ChaCha20-Poly1305,
AES-GCM and AES-CTR, and only encrypt-then-MAC MACs -- a client asking
for SHA-1, CBC or MD5 can't negotiate. When the addresses change, `apply` restarts the webUI a few
seconds later. `management.allow_wan` is the explicit opt-in, confirmed
and warned on the System screen and in every `apply`.

### Attack-surface view (security-lessons I3)

*System -> Attack surface* (`frfw.surface`, `firewall-cli surface`) puts
two facts from the running box together: every listening socket (`ss
-Hlntup`, run by the apply-helper as root so it can name the processes
it may -- the helper has no `CAP_SYS_PTRACE`, so others' are named by
their well-known port) with the interface addresses, and what the input
chain does with a new connection from each zone to that port, evaluated
from the saved config in the same order the ruleset builder emits it
(isolated-IoT and scheduled cut rules, the DNS-filter accept, the
management drop, the admin's rules to `self`, `policy drop`). A socket
bound to loopback is reachable from no zone, one bound to an address from
the zones whose interfaces carry it, a wildcard one from all; conditional
accepts (source address or MAC, ZTNA, schedule) show as *restricted*, and
`ip saddr` rules count for IPv4 only. Anything open or restricted from an
internet-facing zone is flagged first; `firewall-cli surface` exits 2
then. What it can't see is said on the page: upstream NAT or the ISP,
and port forwards to other hosts -- for those it suggests an `nmap` of
the WAN address from outside (there is no built-in outside scanner).

### Routing: IPv4 forwarding

Found in review after step 4: nothing ever turned the kernel's IPv4
forwarding on, and Debian's default is off, so LAN traffic never reached
the WAN whatever the rules said. `apply` now turns it on
(`frfw.forwarding`) right after the ruleset is loaded -- never before, so
the kernel never routes without the forward chain in place -- and on
every apply, so no sysctl.d file is needed. The fail-closed baseline
leaves it off. The units that apply keep `/proc/sys` writable (no
`ProtectKernelTunables`) for this. Tested with three network namespaces
(client, router, server: a connection gets through only after it), and
the QEMU boot test checks the boot-time apply turned it on.

### Every service in a sandbox (security-lessons I1)

Every FR_OS unit runs in a systemd sandbox; `tests/test_systemd_sandbox.py`
checks each one (a new unit without one fails) and keeps its
`systemd-analyze security` exposure within a budget -- from 9-9.4
("UNSAFE") before to 1.1-2.6 for the daemons and 3.8-4.0 for the root
network helpers now.

- **Own unprivileged account** for everything that can do without root:
  the webUI (`fr_os-webui`, only `CAP_NET_BIND_SERVICE`), and the
  daemons that parse network input (`fr_os-sensor`, no capability at
  all). The two that read packet data out of BPF maps (TLS
  fingerprinting, the SNI event logger) start as root with nothing but
  `CAP_BPF` and what switching user takes, open their map and become
  `fr_os-sensor` before reading a byte (`frfw.privdrop`).
- **Common sandbox**: `NoNewPrivileges`, `ProtectSystem=strict` with
  only the paths a service writes, `ProtectHome`, `PrivateTmp`,
  `PrivateDevices`, the kernel tunables/modules/logs/clock/hostname
  protected, no namespaces, no realtime, no set-uid files, W^X memory
  (`MemoryDenyWriteExecute`; the whole test suite -- the real webUI,
  dnsmasq and XDP tests included -- also passes under `PR_SET_MDWE`), a
  seccomp filter (`@system-service`, without `@privileged` for the
  unprivileged ones), native syscalls only, and only the socket families
  used (`AF_UNIX`/`AF_INET(6)`, plus `AF_NETLINK` where `ip`/`nft` run).
- **Root where it must be**: the apply-helper, `fr-firewall` and the
  schedule check change the network, so they keep a reduced capability
  set (no module loading, ptrace, raw I/O, clock, reboot...) and write
  only `/etc/fr_os`, `/etc/kea`, `sshd_config.d`, the XDP object and
  bpffs. `fr-first-boot` and `fr-persistence-setup` (partitions the boot
  medium) are too broad for the strict set and get the baseline only.
- **Off unless used**: the DNS filter only exists when it is configured
  and binds only the DHCP zones' interfaces; sshd is stopped and
  disabled while nobody can log in (no `fr_os-ssh` member with
  `authorized_keys`), and `apply` starts it once someone can. `sshd -t`
  can't run without sshd's `/run/sshd`, so while sshd is stopped the
  check is ssh.service's own `ExecStartPre=sshd -t` as it starts, and a
  failed start rolls the drop-in back.

Not ours to sandbox: Kea and OpenSSH run under Debian's own units (Kea
as `_kea`). The QEMU boot test checks that no FR_OS service crashed, was
killed or hit a read-only path in its sandbox, and that sshd never
listened on a box without keys.

The protocol is deliberately minimal: one JSON object per line, four
commands:

- `ping` — health check
- `apply` (with a `dry_run` option) — applies the canonical config
  (`frfw.provision.apply_all`: nftables → addresses → DHCP; the ruleset
  goes first so a missing NIC can't keep it from loading)
- `rollback` — restores the most recent ruleset backup
- `save_config` — takes a YAML string, validates it with
  `frfw.config.parse_config`, and only overwrites the canonical config
  with it on successful validation (atomically, via a tmp file + rename,
  keeping the file's root:fr_os-webui 0640 owner and mode — review triage A6)

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

### The daily refresh is armed everywhere, and fetches only while on (ROADMAP SEC-21)

`fr-adblock-refresh.timer` was installed in the image but never enabled
(`fr-first-boot.sh` starts every other timer), so on a real router the
lists -- the malware and phishing categories included -- were only ever
as fresh as the admin's last "Refresh now". First boot now enables it on
every router, ad-blocking on or not, so turning ad-blocking on later
needs no unit change. The timer's run is `firewall-cli adblock-refresh
--scheduled`, which fetches nothing while `adblocker.enabled` is off:
FR_OS makes no internet call the admin didn't turn on (security-lessons
G11). An admin's own run -- the command without `--scheduled`, or "Refresh
now" -- still fetches whenever lists are configured, so the lists can be
looked at before ad-blocking is switched on.
`tests/test_system_units.py` now checks that every timer in `systemd/` is
enabled by both `fr-first-boot.sh` and `install-system-integration.sh`.

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
  *Update, phase 15*: now available as an explicit opt-in,
  `adblocker.serve_lan` -- still never a silent side effect.
- **No real hybrid-handshake-level Wireshark analysis** of the download
  process (the HTTPS connection to GitHub/StevenBlack is the one trust
  boundary, the same limitation as the update mechanism).
- **Missing live-dnsmasq-query automated test** (see above) -- if a
  future CI environment doesn't have this sandbox quirk, it's worth
  trying to automate it again.
  *Update, phase 15*: automated after all --
  `tests/test_dns_filtering.py::test_real_dnsmasq_blocks_logs_and_feeds_the_ai_ids`
  starts a real dnsmasq with the generated config and queries it from
  the test process itself, which works in this sandbox (the earlier
  failure was a query sent from a separate shell).

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

## Real-time, kernel-assisted AI IDS/IPS (phase 11)

Goal: replace the earlier explicit-mock AI IDS/IPS engine (see the "AI
IDS/IPS (mock)" section above) with an actual, production-ready anomaly
detector -- ultra-lightweight, 100% local, no heavy AI/ML dependency --
that profiles each source IP's connection-rate, destination-diversity,
and XDP SNI-blocklist-hit behavior against its own recent baseline, and
quarantines a flagged IP in the kernel via the same privilege-separated
pattern every other enforcement action in this project already uses.

### The literal request's assumption about fr-xdp-sni-logger, corrected

The request asked for the engine to "ingest the clean JSON log lines
generated by our Phase 4 `fr-xdp-sni-logger`" for all three features:
connection/SYN rate, destination diversity, and SNI-blocklist-hit
frequency. Checked against what that daemon and the kernel program
behind it actually do (`bpf/xdp_sni_filter.c`, `frfw.xdp.format_event_json`):
it logs **only** a packet whose TLS ClientHello SNI matched the
configured blocklist and was therefore dropped -- "the kernel program
never logs a pass" is stated explicitly in that module's own docstring.
There is no event for an ordinary connection, blocklisted or not, that
merely gets established. fr-xdp-sni-logger can therefore supply real
signal for exactly one of the three requested features (SNI-blocklist-
hit frequency) and structurally cannot supply the other two -- there is
nothing in this project's phase 4 work that observes plain connection
attempts or destination diversity at all.

Rather than fabricate the missing two features (which is precisely the
trap this phase exists to climb out of) or silently drop them, the
actual, already-running source of that signal was used instead: Linux's
own connection tracker. `ct state established,related accept`/`ct state
invalid drop` -- present in *every* ruleset `frfw.nft.builder` generates,
config-independent -- already requires conntrack to be active on this
router regardless of AI IDS. `/proc/net/nf_conntrack` exposes that same
table as a plain-text pseudo-file, one line per tracked flow, and
`frfw.conntrack.read_snapshot()` parses it directly in pure Python (no
`conntrack-tools` package, confirmed not installed by default in this
sandbox, and not worth adding as a dependency for a plain-text parse).
This is the honest correction: two of the three features come from
conntrack sampling, one comes from the SNI logger, and both are
documented here rather than one request-shaped assumption being quietly
implemented as if it were true.

### Privilege model: a second read-only kernel-state source

`/proc/net/nf_conntrack` is root-only -- confirmed by hand in this
sandbox (`ls -la /proc/net/nf_conntrack` → `-r--r----- root root`;
`runuser -u nobody -- cat /proc/net/nf_conntrack` → "Permission
denied"). This is exactly the same shape of finding this project has
already made twice for other kernel-state reads (even a read-only `nft
list` needs `CAP_NET_ADMIN`, per `frfw.ztna`'s docstring) -- so the same
fix applies: a new, read-only `conntrack_sample` command on the existing
privileged apply-helper socket (`frfw.helper.server._handle_conntrack_sample`),
returning the parsed flow list as JSON. The unprivileged `fr-ai-ids`
daemon polls this periodically; it never reads `/proc/net/nf_conntrack`
itself.

### `frfw.ai_ids.engine`: no ML library, on purpose

`frfw.ai_ids.engine.AnomalyEngine` uses only the stdlib: `collections.deque`
for sliding windows, `statistics.mean`/`pstdev` for scoring. No
scikit-learn, no pandas, no numpy -- the request explicitly ruled out the
first two and made the third optional "if necessary"; it turned out not
to be necessary at all. On the "legacy x86 homelab hardware" this
project targets, a handful of per-IP counters and a `statistics.pstdev`
over at most 30 samples costs nothing worth measuring, while
scikit-learn alone drags in numpy/scipy and a compiled BLAS for an input
that is three small numbers per host.

Design: per source IP, three sliding-window features over a
`WINDOW_SECONDS` (60s) window -- connection-attempt rate, the ratio of
unique destination IPs to total connection attempts (a portscan/lateral-
movement signature), and SNI-blocklist-hit count (a beaconing/malware
signature). Every window tick, each feature's current value is compared
against *that same IP's own* history of past window values via a
z-score, so "anomalous" means unusual for this specific host, not an
arbitrary cutoff a NAS and a laptop would be held to equally. A brand
new IP has no history yet; until it accumulates `MIN_BASELINE_SAMPLES`
(5) windows, it is instead checked against a fixed, deliberately
generous absolute floor, so a normal host's first few minutes on the
network do not trip a "3 standard deviations from a sample size of
zero" false positive.

Two guardrails were added directly in response to bugs a synthetic test
caught during development, both left in place as documented, deliberate
behavior rather than silently fixed and forgotten:

- **Zero-variance baseline guard.** If an IP's own history happens to be
  constant (e.g. exactly 10 connections every window, every window), its
  standard deviation is 0, and any deviation at all produces an enormous
  z-score by simple division. The scorer therefore also requires the raw
  value to clear at least half the feature's absolute floor before a
  statistically "anomalous" z-score is honored -- a `10 → 11` connection
  bump on a degenerate zero-variance baseline must not read as a
  million-sigma event.
- **Minimum sample size for the destination-ratio feature
  (`MIN_CONNS_FOR_RATIO`, 5).** With only one or two connections in a
  window, "unique destinations / total connections" is trivially 1.0 or
  0.5 -- not a meaningful scan signature, just small-sample noise. Below
  this many connections in the window, the ratio feature is skipped
  entirely for that window (neither scored nor folded into the
  baseline), rather than recording a near-meaningless data point.

### `frfw.ai_ids.daemon`: fully out-of-band, decoupled from `apply`

`fr-ai-ids.service` is its own long-running systemd unit, started once
and left running -- it is **not** attached/detached by `firewall-cli
apply`/`frfw.provision.apply_all` the way the XDP filter or the ad-block
resolver are. This matches the request's "Out-of-Band Processing"
requirement directly: detection and the 40 Gbps XDP data plane share
nothing except that one, read-only ring-buffer-fed log stream, consumed
well downstream of any packet-path code.

Two independent, decoupled inputs feed `AnomalyEngine`:

1. A background thread follows `fr-xdp-sni-logger`'s event file
   (`frfw.journal.follow_file_forever`, `tail -F`) -- the same file and
   permission model as the webUI's own `/xdp/logs/stream` route (ROADMAP
   SEC-4). The resolver's query log (with `adblocker.query_logging`) is
   followed the same way, from its own file -- see "DNS as an AI IDS
   signal" -- so this unit and `fr-appid` have no journal access at all.
2. The main loop polls `conntrack_sample` every `TICK_SECONDS` (5s) and
   diffs the returned flow list against the previous sample's flow keys
   (proto/src/sport/dst/dport) -- **only genuinely new flows are counted
   as connection attempts.** This diffing step matters: conntrack's table
   is a live snapshot of currently-tracked connections, not an event
   log, so re-sampling the same still-open, long-lived connection on
   every poll would otherwise make an ordinary, single legitimate
   connection look like an ever-climbing connection rate. This was
   caught and fixed via a direct test
   (`test_poll_conntrack_once_does_not_double_count_already_seen_flows`)
   before it could ever reach the scoring logic.

On a window tick, `evaluate_and_enforce()` scores every currently-
tracked IP; a flagged IP not in the resolved exclusion set (see below)
gets one `quarantine_ip` request sent to the privileged apply-helper,
and the event is appended to a small, capped, display-only JSON log
(`frfw.paths.AI_IDS_STATE_PATH`, repurposed from the old mock engine's
per-device state file) for the webUI's AI IDS screen.

### `excluded_macs`: resolved to IPs, because profiling is now IP-based

The mock engine's `ai_ids.excluded_macs` excluded a *device record*
(profiled by MAC, via its DHCP reservation). The real engine scores
*source IP addresses* drawn from conntrack/XDP data, which has no notion
of a MAC address once traffic has been routed. `frfw.ai_ids.daemon.
resolve_excluded_ips()` bridges this by resolving each configured MAC
against the current `dhcp.<zone>.reservations` at daemon startup, into
the actual IP the engine sees traffic from -- reusing the same "known
device" lookup the mock engine had, now feeding real exclusion logic
instead of a mock profile. A MAC with no matching reservation currently
excludes nothing; this is a known limitation (a static, non-DHCP host
cannot currently be excluded), not a silently swallowed case -- see Open
issues.

### Whom the IDS scores, and whom it never quarantines (ROADMAP SEC-2)

Every telemetry source -- conntrack, the XDP SNI events, the resolver's
query log -- is filtered to *internal* sources before the engine sees
it (`frfw.ai_ids.daemon.internal_networks`): the subnet of every
interface with a static address in a zone that isn't a NAT masquerade
target (the LAN, the IoT and guest segments), plus the WireGuard VPN's.
The engine used to score every conntrack source, so an ordinary inbound
scan from the internet, or the ISP's gateway, could be scored and
quarantined like a compromised LAN host (review v0.2.0 R7). A config with
no internal network scores nothing rather than guessing one.

Inside those networks, some hosts talk to many others by design -- what
the destination-diversity score counts -- and quarantining one would cut
every host off: the router's own addresses, the default gateways (read
from `/proc/net/route` at every evaluation, since a DHCP renewal can move
one) and the DNS servers (`/etc/resolv.conf` and every DHCP pool's
`dns_servers`). They are still scored and their verdict is logged, but
never enforced (`infrastructure_ips`). The apply-helper keeps its own,
narrower guard underneath (non-host and router addresses, the 7-day cap).

### `frfw.ids_quarantine` and the `ids_quarantine` nftables set

A close structural mirror of `frfw.bruteforce`/`frfw.ztna` -- same
`_nft`/`_run_nft`/`_list_set_elements`/snapshot-restore shape, against a
third, independent kernel set (`frfw.nft.builder.IDS_QUARANTINE_SET_NAME`).
Declared unconditionally (like the brute-force jail, unlike the ZTNA
set): IDS/IPS enforcement has no "off" switch independent of the
detection engine, because an admin later disabling `ai_ids.enabled`
should not silently amnesty hosts already quarantined by the engine
while it was on. The drop rule sits second in `chain input`, right after
the brute-force jail's own drop rule, both before even the loopback
accept -- confirmed directly against a real, loaded ruleset's `nft -j
list chain` output, not just the Python source. `flags timeout` alone is
sufficient for the identical reason documented for the brute-force jail
in phase 10: every element is added by an explicit `nft add element`
call from `frfw.ids_quarantine.quarantine_ip`, never by a data-path rule
that would need `dynamic`.

Same `flush ruleset` survival problem as the brute-force jail and ZTNA:
`frfw.provision.apply_all` brackets the nftables-apply step with
`frfw.ids_quarantine.snapshot_before_reload()`/`restore_after_reload()`,
unconditionally (except on a dry run), so an unrelated config save never
silently un-quarantines an active detection. Verified by hand: an IP
quarantined, the set flushed (simulating the reload), and the restore
confirmed to bring it back with the correct remaining TTL, not a fresh
full duration.

### Unix-socket protocol: three new commands

- `quarantine_ip` -- `ban_ip`'s IDS/IPS counterpart; the daemon decides
  *when*, this command does the actual `nft` touch.
- `ids_quarantine_status` -- read-only, live kernel-state query (like
  `ztna_status`) for the webUI's AI IDS screen and dashboard to show who
  is currently quarantined, without the unprivileged webUI process
  reading kernel state itself.
- `conntrack_sample` -- read-only dump of `frfw.conntrack.read_snapshot()`,
  for the reason explained above.

### WebUI: engine health, live quarantine list, and a display-only event log

The `/ai-ids` screen and the dashboard card are purely observational
plus a settings form -- all detection and enforcement happen in the
separate daemon:

- **Engine health** (`frfw.ai_ids.is_daemon_active`) is a plain
  `systemctl is-active fr-ai-ids.service` call, exactly the same
  reasoning and pattern as `frfw.adblock.dns_service.is_resolver_active`
  -- no privilege needed, so it runs directly in the webUI process.
- **Currently-quarantined hosts** comes from `ids_quarantine_status`
  through the privileged helper -- the kernel set is the sole authority
  on who is quarantined right now, the same "kernel is truth, a display
  file is not" split `frfw.ztna` already established.
- **Recent flagged events** is `frfw.ai_ids.load_recent_events()`,
  reading the daemon's own small, capped JSON log directly (no
  privilege needed -- the daemon wrote it as itself, an unprivileged
  decision, unlike `frfw.ztna`'s ztna_state.json which is written by
  the *privileged* helper because ZTNA authorization itself is a
  privileged act). Context only, never authoritative.

Saving `ai_ids` settings only picks up on the daemon's next (re)start --
the same "a change needs an apply/restart to take effect" reality this
project already lives with elsewhere (e.g. the PQC hybrid TLS setting) --
stated on the settings form itself via the success message, not left
implicit.

### Verification performed

- Real `nft -c` syntax check of the full generated ruleset, and a real
  loaded-ruleset `nft -j list chain` query confirming the quarantine
  drop rule's exact position (second in `chain input`).
- Real, hands-on `frfw.ids_quarantine` verification identical in kind to
  phase 10's brute-force jail: quarantine an IP, confirm the kernel
  itself evicts it after its timeout with no code running in between;
  flush the set (simulating a reload) and confirm restore brings it back
  with the correct remaining TTL.
- Real permission-boundary verification of `/proc/net/nf_conntrack`
  (root-only, confirmed both by direct inspection and by an actual
  `runuser -u nobody` read attempt failing).
- `frfw.conntrack._parse_line` tested against hand-written TCP, UDP, and
  ICMP conntrack lines matching the real kernel's `ct_seq_show()` field
  layout (a TCP line has an extra state token a UDP line lacks; ICMP
  lines have no ports at all) -- not assumed, checked against the actual
  positional/prefix structure those three protocols produce.
- `AnomalyEngine`'s scoring logic exercised with hand-constructed
  synthetic traffic patterns (a realistic "boring" baseline vs. a 20-
  distinct-destination scan burst; a repeated SNI-blocklist-hit beacon
  pattern) -- both of the guardrails described above (zero-variance
  baseline, minimum sample size for the ratio feature) were found and
  fixed *because* a test using realistic-looking synthetic data caught
  them, not by inspection.

### Scope of verification -- stated honestly

Unlike the kernel-level primitives above (which were verified against
real `nft`/procfs behavior), this module has **not** been tested against
real attack traffic or a real scanning tool (e.g. `nmap`) generating
actual portscan packets through a live conntrack table end-to-end -- this
sandbox has no attacker/target host pair to generate such traffic
against. The detection logic itself is verified deterministically
against synthetic data constructed to match the real shapes involved
(conntrack's actual line format, the XDP logger's actual JSON schema);
whether real-world attack traffic reliably produces the same
`unique_dst_ratio`/`conn_rate` shapes this engine was tuned against is,
honestly, implemented-to-spec rather than independently field-verified,
the same caveat phase 8's PQC work made for its own "never tested
against a real OpenSSL 3.5+/OpenSSH 9.9+" gap.

### Open issues

- **No manual early-release action for a quarantined IP** -- the same
  gap phase 10 left open for the brute-force jail, for the same reason:
  a quarantine expires on its own via the kernel's native timeout, and
  adding an admin override was deferred to keep this phase's scope
  bounded. `frfw.ids_quarantine.list_quarantined()` already returns
  everything a "release" admin action would need; adding the action
  itself is a small follow-up.
- **Detection thresholds are not yet configurable** -- `WINDOW_SECONDS`,
  `ZSCORE_THRESHOLD`, `MIN_BASELINE_SAMPLES`, and the `ABS_*_FLOOR`
  constants live in `frfw.ai_ids.engine` as module constants, not
  `config.yaml` fields. The same deliberate simplification phase 10 made
  for `frfw.webui.auth_rate_limiter`'s own thresholds.
- **A NAT/shared-IP host is scored as one IP** -- an entire office behind
  one public IP, or several containers behind one host's NAT, look like
  a single source IP to conntrack; a legitimate burst of activity from
  many real hosts behind that address could, in principle, cross a
  threshold meant for one host. The same accepted tradeoff any purely
  source-IP-based defense in this project makes (see phase 10's
  identical note for the brute-force jail).
- **A MAC with no current DHCP reservation cannot be excluded** -- since
  `excluded_macs` resolution depends entirely on `dhcp.<zone>.reservations`
  existing for that device, a statically-configured (non-DHCP) host has
  no way to be excluded today.
- **`frfw.conntrack` only extracts TCP/UDP flows, IPv4 only** --
  consistent with the rest of the project (`frfw.nft`, Kea DHCP are also
  IPv4-only today); ICMP and any IPv6 conntrack lines are silently
  skipped, not counted as connection attempts either way.

## Lightweight native Prometheus metrics exporter (phase 12)

Goal: a `GET /metrics` endpoint exposing both software (per-subsystem
counts already computed elsewhere in this project) and hardware
(CPU/RAM/storage) telemetry in Prometheus text exposition format, with
zero external dependencies -- no `prometheus_client`, no `psutil` -- to
keep the RAM/CPU footprint appropriate for the same legacy x86 hardware
every other phase targets.

**A numbering correction, stated up front**: the request that started
this phase called it "Phase 11". That number was already used, in this
same project history, for the real-time AI IDS/IPS work completed
immediately before this one (see the section above). This work is
therefore documented as **phase 12** instead, to keep ARCHITECTURE.md's
and ROADMAP.md's phase numbering sequential and unambiguous -- a purely
cosmetic correction, not a design change.

### Where every metric actually comes from

Every *software* metric is a thin read of state this project already
computes for its own webUI screens -- nothing new was invented to
produce them:

| Metric | Source |
|---|---|
| `fros_interface_bytes_total` | `/sys/class/net/<device>/statistics/{rx,tx}_bytes` (world-readable, confirmed `-r--r--r--` by hand) |
| `fros_xdp_status`, `fros_xdp_blocked_connections_total` | `frfw.xdp.get_attached()`/`get_stats()` -- already called unprivileged from `frfw.webui.routes.xdp` today |
| `fros_adblock_total_domains` | `frfw.adblock.count_blocked_domains()` -- already used on the dashboard |
| `fros_ztna_active_sessions` | a new `ztna_sessions_status` helper command wrapping a new `frfw.ztna.list_authorized()` |
| `fros_bruteforce_banned_ips` | a new `bruteforce_status` helper command wrapping a new `frfw.bruteforce.list_banned()` |
| `fros_ai_ids_quarantined_hosts` | the existing `ids_quarantine_status` helper command (phase 11) |

`list_authorized()`/`list_banned()` are the only genuinely new pieces of
kernel-facing code here, and both are one-line wrappers around each
module's existing, already-tested `_list_set_elements()` -- the exact
same function `frfw.ids_quarantine.list_quarantined()` already exposed
publicly for its own status command. No new kernel logic, just a second
public name for logic that already existed.

Every *hardware* metric is read directly from `/proc`, `/sys`, or
`os.statvfs` -- as the request specified, no library:

| Metric | Source |
|---|---|
| `fros_hw_cpu_info`, `fros_hw_cpu_mhz` | `/proc/cpuinfo` ("model name"/"cpu MHz"), with `/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq` preferred for MHz when present |
| `fros_hw_cpu_usage_ratio` | two samples of `/proc/stat`'s aggregate `cpu` line, 100ms apart (see below) |
| `fros_hw_ram_usage_bytes`, `fros_hw_ram_total_bytes` | `/proc/meminfo` (`MemTotal` - `MemAvailable`) |
| `fros_hw_storage_info`, `_usage_bytes`, `_total_bytes` | `/proc/mounts` (filtered to real block devices) + `os.statvfs()` per mount |
| `fros_hw_ram_info` (model/speed) | the one exception -- see below |

### The one genuinely privileged hardware fact: RAM module identity

Every hardware metric above needs no privilege at all -- confirmed by
hand, the same way this project always confirms a permission claim
rather than assuming one (`ls -la /sys/class/net/lo/statistics/rx_bytes`
→ `-r--r--r--`). The one exception the request itself named as an
example is real: a RAM module's part number and rated speed live in the
SMBIOS/DMI tables, readable only via `dmidecode`, which needs root (it
reads `/dev/mem` or `/sys/firmware/dmi/tables/DMI` depending on
kernel/distro) -- the same shape of finding this project has already
made for `nft` and `/proc/net/nf_conntrack`. `frfw.hwinfo.read_ram_modules()`
therefore only runs from a new `hw_ram_info` command on the privileged
apply-helper socket, following the identical privilege-separation
pattern the request itself asked for and every prior phase already
established -- the unprivileged webUI process never shells out to
`dmidecode` itself.

Each populated memory slot becomes one `fros_hw_ram_info{model=...,
speed_mhz=...}` sample (value always 1) rather than trying to collapse
multiple, possibly different, installed sticks into a single label pair
-- a machine with two identical modules produces one time series (both
map to the same label combination), two different modules produce two.

`dmidecode` is not installed in this project's own dev sandbox, so its
real-output code path could not be exercised end-to-end here -- see
"Scope of verification" below for the same honest disclosure this
project has made for every phase whose full positive path needed
hardware this sandbox doesn't have (phase 4's 10G NICs, phase 8's
OpenSSL 3.5+, phase 9's live dnsmasq queries).

### CPU usage: a deliberate 100ms blocking sample, not a background sampler

Computing a *rate* (CPU busy time / elapsed time) needs two points in
time, not one. Two designs were possible: keep a previous `/proc/stat`
sample in shared, cross-request state (the way `node_exporter` and
similar long-lived daemons do it), or take both samples inside the
request handler itself. The webUI is not a dedicated, single-purpose
metrics daemon -- it is the same process serving every other page -- so
the first option would mean either a module-level mutable dict (a
thread-safety hazard under uvicorn's thread pool, the same class of
issue `frfw.webui.auth_rate_limiter.BruteforceGuard` already had to
solve with an explicit lock) or a background thread whose sole job is
to keep a cache warm for a rarely-hit endpoint. A Prometheus scrape is,
by convention, a low-frequency (typically 15-30s interval),
latency-tolerant operation -- so `frfw.metrics._read_cpu_usage_ratio()`
simply reads `/proc/stat` twice, 100ms apart, inside the request itself.
This adds a fixed, small, predictable 100ms to that one endpoint's
response time and needs no shared state, no lock, and no background
thread -- the simpler and more robust choice for what this endpoint
actually is.

### Error isolation: one bad metric family must never break the whole scrape

`frfw.metrics.generate_metrics_text()` gathers each metric family
independently and discards (never fails) any one that raises --
documented in the module's own docstring as a deliberate, narrow
exception to this project's usual preference for catching specific
exception types (the same already-established exception this project
makes for `frfw.webui.config_store`'s/the test suite's own
`FakeHelper.save_config`'s catch-all). The reasoning is specific to this
one boundary: a dozen unrelated subsystems (`OSError` from a missing
`/proc` file on an unusual kernel, `HelperError` from a apply-helper
hiccup, `HwInfoError` from `dmidecode`, and whatever a *future* metric
source raises) all feed into one response, and enumerating every
possible exception type across all of them here would make adding a
future metric family a silent way to reintroduce exactly the fragility
this design avoids -- a new subsystem raising a type nobody added to an
explicit list would break the entire `/metrics` response instead of
just omitting its own family. Confirmed directly with a test that
injects a broken helper method and checks every *other* family still
renders (`test_generate_metrics_text_survives_a_broken_helper`).

An invalid on-disk `config.yaml` (fails `parse_config`) is handled the
same way the dashboard route already handles it: the two config-
dependent families (interface bytes, XDP status) are skipped, everything
else (hardware metrics, the helper-backed counts, none of which need
the *current* config to be valid) still renders -- a broken config must
never turn a monitoring endpoint into a 500, which is exactly the moment
an operator most needs it to still work.

### Public, unauthenticated -- a deliberate security tradeoff, stated honestly

> **Superseded (ROADMAP SEC-3, review v0.2.0 R11).** `/metrics` is now
> off until a bearer token (`metrics.token_sha256`, phase 20) is
> generated, and then answers only requests carrying it: without a token
> it answers 404 and gathers nothing. The exposure described below --
> banned and quarantined host counts, the IoT inventory, the hardware, to
> anyone who could reach the webUI's port -- was one finding; the other
> was that every request made the root helper run its `nft` reads, so
> any LAN client could keep it busy in a loop. An authenticated scrape's
> text is now cached for 15 s (`routes/metrics.py`, `CACHE_SECONDS`),
> keyed by the config, so not even an over-eager Prometheus makes the
> helper work more than once per window. Kept below for the reasoning
> it answered.

`GET /metrics` carries no `require_login` dependency, per the request's
explicit "unprivileged public/telemetry endpoint" wording -- this
matches how Prometheus itself, and essentially every metrics exporter in
existence, works: a scrape target is expected to sit behind network-
level access control, not a login form, because Prometheus's own scrape
configuration has no support for an interactive login flow (only static
bearer tokens/basic auth, which would need yet another credential to
manage). The tradeoff this creates: anyone who can reach the webUI's
HTTPS port at all -- not just an authenticated admin -- can read the
count of currently banned/quarantined hosts, interface byte counters,
and this machine's hardware inventory. On a homelab router whose webUI
is only reachable from a trusted LAN, this is the same exposure model as
the webUI's own self-signed TLS certificate warning: acceptable for the
target deployment, but worth stating rather than leaving implicit. A
production-minded deployment that wants network-level restriction can
gate the scrape source at the firewall layer (e.g. a rule permitting
port 443 from the monitoring host's zone only) -- this project's own
rule engine already supports exactly that kind of restriction.

### Scope of verification

- Real, hands-on confirmation (not assumed) that `/sys/class/net/*/
  statistics/*` is world-readable while `/proc/net/nf_conntrack` is not,
  the exact permission boundary this design depends on.
- `frfw.metrics.generate_metrics_text()` exercised end-to-end against
  this sandbox's real `/proc`, `/sys`, and `os.statvfs` -- not just a
  fake tree shaped like one -- confirming real CPU model/MHz/usage,
  real RAM totals, and real (correctly filtered) storage mounts render
  as valid Prometheus samples.
- The full rendered output verified structurally against the Prometheus
  text exposition format's actual grammar (a `# HELP`/`# TYPE` pair
  before any sample line for a given metric name, `name{labels} value`
  or `name value` for every sample line, escaped label values) via a
  dedicated regex-based structural check, not just "does it look right"
  -- this project doesn't have `promtool` or `prometheus_client`
  available to validate against (the latter is explicitly excluded by
  the request itself), so this hand-written structural check is the
  verification.
- `frfw.hwinfo`'s dmidecode-output parser tested against a hand-written
  sample matching real `dmidecode -t memory` output (the format is
  well-documented and stable; the sample includes both a populated slot
  and an empty "No Module Installed" slot) -- **not** run against a real
  `dmidecode` binary, since this sandbox doesn't have one installed (the
  same disclosed gap as phase 8's "no real OpenSSL 3.5+" and phase 9's
  "no live dnsmasq query in this sandbox"). A `shutil.which`-gated real
  test is included for a host that does have it.
- A real bug the parser's own unit tests caught before it shipped:
  `dmidecode` reports `"Configured Memory Speed: Unknown"` for an
  installed module whose speed wasn't auto-negotiated -- a naive `a or
  b` fallback chain never falls through to the `"Speed"` field in that
  case, because `"Unknown"` is a non-empty, truthy string. Fixed by
  checking whether the preferred field actually parses to a non-zero
  value before falling back, not just whether it's present.

### Open issues

- **`fros_hw_cpu_usage_ratio`/`fros_hw_cpu_mhz` are system-wide
  aggregates, not per-core** -- a deliberate simplification matching the
  single, unlabeled gauge the request specified; per-core breakdown
  would need a `core` label and a design decision this phase didn't need
  to make.
- ~~**The `/metrics` endpoint is unauthenticated**~~ -- off until a
  token is generated, since ROADMAP SEC-3 (see above).
- ~~**No caching/rate-limiting on the endpoint itself**~~ -- an
  authenticated scrape's text is cached for 15 s since ROADMAP SEC-3, and
  nothing is gathered for a request without the token.

## Hybrid BIOS + UEFI boot support (phase 13)

Goal: the FR_OS live ISO (phase 5) boots on modern UEFI-only hardware
(Intel NUCs, HP ProDesk/EliteDesk minis, Lenovo Tiny clients -- the
class of small-form-factor boxes this project targets) as well as it
already boots on legacy BIOS, from the same `dd`/Rufus-flashed USB
drive, without growing the image meaningfully or touching the working
BIOS path.

### Corrections to the original request, up front

Two parts of the request as literally written don't match this
project's actual build tooling or its actual boot configuration; both
are implemented correctly below rather than silently faked or left
broken:

- **`--bootloaders syslinux,grub-efi` does not exist on this project's
  live-build.** Checked directly against the source, not assumed: this
  project's live-build is the same very old, Ubuntu-patched `3.0~a57`
  snapshot documented throughout phase 5's own section above and in
  `installer/live-build/auto/config`'s header. Its `lb_config` getopt
  string defines only a *singular* `--bootloader grub|syslinux|yaboot`
  -- there is no plural `--bootloaders` option, and passing it aborts
  `lb config` with an argument-parsing error. Even the singular `grub`
  choice wouldn't have helped: `lb_binary_grub`'s "grub" case builds
  **GRUB Legacy** (`menu.lst`, `stage2_eltorito`), not GRUB 2 EFI, and
  `lb_binary_iso` packages the image with `genisoimage`
  (not even installed as a host binary in this sandbox -- this
  snapshot fetches it *inside the chroot* instead) with no EFI System
  Partition/GPT logic anywhere in it. UEFI support is therefore
  implemented entirely outside `lb_config`/`lb build`, as a new
  post-processing step (`installer/make-hybrid-uefi-iso.sh`, below)
  that repackages `lb build`'s already-assembled `binary/` tree with a
  current tool (`xorriso`, which *is* installed) that can actually do
  this. A real, current Debian live-build package's own
  `--bootloaders syslinux,grub-efi` may make this extra step
  unnecessary on a non-sandbox build host -- worth trying there first,
  noted directly in `auto/config`.
- **`boot=live components quiet splash enforcement=strict` does not
  match this project's real boot parameters.** This project's actual,
  working isolinux configuration
  (`config/bootloaders/isolinux/live.cfg.in`) boots with
  `boot=live config` -- `config` is a real live-boot(7) option (read
  `live.conf` from the medium); `LB_BOOTAPPEND_LIVE` is empty in
  `auto/config`. `components` and `enforcement=strict` are not
  live-boot(7) parameters this project (or live-boot itself, as far as
  its documented option list goes) recognizes, and `quiet`/`splash`
  are not currently part of this project's boot line either. The
  request's own stated goal was parameters "identical" to the legacy
  syslinux setup -- so the new GRUB menu boots with the *actual*
  current line (`boot=live config`, plus the real
  `LB_BOOTAPPEND_FAILSAFE` value for the fail-safe entry), not the
  requested-but-nonexistent one, to genuinely satisfy "identical"
  rather than silently diverging from it.
- **The four packages named for `config/package-lists/` are build-host
  tools, not chroot/live-system packages.** `grub-efi-amd64-bin` and
  `grub-common` provide `grub-mkstandalone` (confirmed:
  `dpkg -S /usr/bin/grub-mkstandalone` → `grub-common`) and its
  x86_64-efi module tree; `xorriso` does the actual repackaging. None
  of the three ever need to be installed *inside* the live system's
  own squashfs -- the running firewall OS has no use for ISO-building
  tools, and adding them to `frfw.list.chroot` would only bloat the
  shipped image. `isolinux` is the fourth named package, and it's
  already in `frfw.list.chroot` (added back in phase 5, for
  `isolinux.bin`/`isohdpfx.bin`) -- no change needed there. The three
  genuine build-host tools are documented as prerequisites in
  `installer/build-live-image.sh`'s own header instead, alongside the
  syslinux-utils/librsvg2-bin host tools phase 5 already documented
  there the same way.

### How it actually works

`installer/make-hybrid-uefi-iso.sh` runs after `lb build` (wired into
`installer/build-live-image.sh`) and:

1. Builds a small standalone GRUB EFI binary
   (`grub-mkstandalone -O x86_64-efi`) whose only embedded job is to
   search for the ISO by its volume label and `configfile` the real
   menu -- `config/includes.binary/boot/grub/grub.cfg`, a plain,
   human-editable file this project commits directly (copied
   byte-for-byte into `binary/boot/grub/grub.cfg` by live-build's own
   `config/includes.binary` mechanism, confirmed by reading
   `lb_binary_includes`: a plain tar/untar, no templating of its own --
   unlike isolinux's `live.cfg.in`, this file has no build-time
   variable substitution, so if `--bootappend-live`/
   `--bootappend-failsafe` in `auto/config` ever stop being empty, this
   file needs the same edit made by hand, a disclosed tradeoff rather
   than an invented templating layer this task didn't ask for).
2. Packs that EFI binary into a small (10 MiB) FAT-formatted EFI System
   Partition image (`mkfs.vfat`/`mtools`), placed at
   `binary/boot/grub/efi.img`, plus a plain copy at
   `binary/EFI/BOOT/BOOTX64.EFI` (xorriso itself warns this second copy
   is needed for some Windows/Rufus USB-imaging workflows that expect
   an ESP tree visible directly in the ISO filesystem, not just inside
   the appended partition image).
3. Re-invokes the ISO-packaging step itself via
   `xorriso -as mkisofs`, with the *same* BIOS El Torito flags
   `lb_binary_iso` already used (`-eltorito-boot isolinux/isolinux.bin
   ... -boot-info-table`, `-isohybrid-mbr` from the chroot's own
   `isolinux` package, so the legacy boot path is byte-for-byte what it
   already was) plus a second, UEFI El Torito entry
   (`-eltorito-alt-boot -e boot/grub/efi.img -isohybrid-gpt-basdat`)
   that also makes the ESP a real GPT partition on the disk image
   itself, not just an ISO9660 file.
4. Sources `installer/live-build/config/binary` (the file `lb config`
   itself generates) for the volume label/application/publisher
   strings and a `LB_BOOTLOADER` sanity check, so this script can't
   silently drift from `auto/config`'s actual `--iso-*` flags.

### Verification

Real, hands-on, not simulated -- run twice in this sandbox against two
different `binary/` trees:

- A synthetic minimal tree (fake kernel/initrd, the repo's real
  `isolinux.bin`) confirmed the underlying xorriso mechanism itself:
  `-report_el_torito` showed both a BIOS and a UEFI boot image, and
  `-report_system_area` showed a hybrid MBR *and* a GPT table with a
  `0xef`/ESP-GUID partition pointing at `boot/grub/efi.img`.
- The **real** `installer/live-build/binary/` tree left over from
  phase 5's own real end-to-end build (a genuine 312 MB staging tree:
  real kernel, real initrd, real 275 MB squashfs, real
  `isolinux.bin`) was repackaged by the actual, final
  `installer/make-hybrid-uefi-iso.sh` script, including a real
  `lb binary_includes --force` run to confirm the committed
  `config/includes.binary/boot/grub/grub.cfg` genuinely gets copied
  into place by live-build itself (not just by hand during testing).
  Result: a real 328 MB ISO (about 1 MB larger than phase 5's original
  327 MB -- the 10 MiB ESP image is mostly empty/compressible padding,
  not 10 MiB of real added data), `file` reports it as a bootable
  ISO 9660 image, `-report_el_torito` shows both boot platforms, and
  the appended `efi.img` mounts as a valid FAT filesystem containing a
  real, `file`-confirmed "PE32+ executable (EFI application) x86-64"
  binary at `EFI/BOOT/BOOTX64.EFI`.
- **Not verified**: actually booting the resulting ISO on a real or
  virtual UEFI machine (no such hardware/hypervisor access in this
  sandbox) -- the same class of disclosed gap as phase 5's own "not
  yet verified: actually booting the ISO" note. The boot *records*
  (El Torito catalog, GPT partition table, a valid signed... unsigned,
  see below... PE32+ binary) are all independently, structurally
  confirmed; a live UEFI boot exercising firmware's own El
  Torito/GPT parsing is the one remaining step.
- **Secure Boot is explicitly out of scope and will not work as-is**:
  the `BOOTX64.EFI` built by `grub-mkstandalone` here is unsigned. A
  UEFI firmware with Secure Boot enabled will refuse to execute it.
  Getting a Secure-Boot-chainloadable image working would need either
  a Microsoft-signed shim (`shim-signed`, `grub-efi-amd64-signed`) or
  the operator's own enrolled MOK key -- neither was part of this
  request, and both are real, separate follow-up work, not a
  five-minute flag. Operators on Secure-Boot-enabled hardware need to
  disable it (or set up shim/MOK themselves) to boot this image via
  UEFI, exactly the same situation as most small, from-scratch Linux
  live images.

### Open issues

- Real UEFI boot (physical or virtual) not yet exercised, as above.
- Secure Boot unsupported (unsigned GRUB EFI binary), as above.
- `config/includes.binary/boot/grub/grub.cfg` is a static file, not
  templated from `LB_BOOTAPPEND_LIVE`/`LB_BOOTAPPEND_FAILSAFE` the way
  isolinux's own menu is -- fine while both are their current fixed
  values, a manual-edit trap if they ever change.
- The ESP is sized at a fixed 10 MiB; if `grub-mkstandalone`'s output
  ever grows past that (a much larger module list, a future GRUB
  version) the build would fail loudly at the `mcopy` step, not
  silently truncate -- no dynamic sizing was added since the current,
  measured output (~6 MB) leaves comfortable headroom for this
  project's fixed, small module list.

## IoT device discovery and isolation (phase 14)

Goal: find the IoT gadgets on a home/small-office network, tell them
apart from phones and computers, and cut them off from everything they
don't need -- automatically if the admin wants, with a human-readable
reason for every verdict, and without any cloud service or device
database this project would have to maintain.

### Correction to the original idea, up front

The idea as first written was "move an unknown IoT device into a
separate VLAN/zone automatically". A router alone cannot do that: VLAN
membership is decided by the switch port or the Wi-Fi SSID a device is
on (or by 802.1X dynamic VLAN assignment, which needs managed switches
and APs this project doesn't control), and DHCP-class-based subnet
assignment would still leave the device on the same layer-2 segment as
everything else. What *is* achievable, and implemented here, is
**isolation enforced by this router's own firewall, keyed on the
device's MAC address**. That covers everything routed through the box:
other zones, the router's own services (webUI, SSH), and -- in `block`
mode -- the internet. It does not cover two devices talking directly on
the same switch or Wi-Fi network; for that, the documented answer is a
dedicated IoT zone on its own VLAN interface (e.g. `eth1.30`), which
this project already supports as an ordinary interface/zone. Both halves
of that are stated in the config reference and the webUI, not only here.

### Inventory: three sources, none needing decryption

- **DHCP leases** (`frfw.iot.leases`): Kea's memfile lease database, an
  append-only CSV where a renewal is a new row, so the last row per
  address wins and `state != 0` or an expired lease retires it. Columns
  are read by header name, so Kea 2.4's extra `pool_id` column doesn't
  matter. The file belongs to Kea's own user, so it is read by the
  privileged apply-helper (`dhcp_leases` command), which only returns
  parsed, sanitized fields (the hostname is client-supplied DHCP option
  12 -- printable ASCII only, capped at 253 characters).
- **ARP table** (`frfw.iot.arp`): `/proc/net/arp` is world-readable
  (checked), so the scanner reads it directly. It is the only source for
  devices with a static IP that never talk to the DHCP server.
- **mDNS / DNS-SD** (`frfw.iot.mdns`): one `_services._dns-sd._udp.local
  PTR` query per IoT-zone interface, collecting which service types each
  host advertises (`_hap._tcp` HomeKit, `_googlecast._tcp` Chromecast,
  `_esphomelib._tcp` ESPHome, `_ipp._tcp` printers, ...). The query goes
  out from a fixed non-5353 source port, which RFC 6762 section 6.7
  defines as a "legacy unicast" query: responders reply by unicast to
  that port. That means nothing has to listen on 5353 (no clash with an
  avahi-daemon on the router) and the firewall needs exactly one narrow
  input rule, `iifname @<iot zone> udp sport 5353 udp dport 53530
  accept`. The obvious alternative, accepting anything *from* source
  port 5353, was rejected on purpose: any LAN host could then reach
  every UDP service on the router just by choosing that source port.

mDNS runs *before* the ARP table is read: a device answering the query
first ARP-resolves the router, and Linux records the requester in its
own neighbour table, so static-IP devices found only via mDNS are
already in `/proc/net/arp` by the time it's parsed.

Vendor names come from the IEEE MA-L registry as packaged by Debian
(`ieee-data`, `/usr/share/ieee-data/oui.csv` -- installed in this
sandbox to check the real format: quoted organization names containing
commas, `MA-L`/`MA-M`/`MA-S` registries in one file). Nothing is bundled
into this project; without the package the vendor signal is just absent.
A locally administered ("randomized") MAC never gets a vendor, since its
prefix isn't a real assignment.

### Classification: a transparent point system, not a model

`frfw.iot.classify` adds and subtracts points and keeps a sentence for
each: +3 for a vendor that ships almost only IoT hardware (Espressif,
Tuya, Signify, Sonos, Hikvision, ...; names checked against the real
registry), +1 for mixed vendors (TP-Link, Amazon, Google, Xiaomi, ...),
+3 for advertising any IoT service type, -3 for computer services
(`_workstation._tcp`, `_smb._tcp`, `_ssh._tcp`, Apple
companion-link), +2/-2 for IoT-looking / phone-or-computer-looking DHCP
hostnames, and -2 for a randomized MAC (phones and laptops use them for
privacy; embedded devices practically never do). A score of 3 or more is
"iot", -2 or less "general", anything else "unknown". No single signal
decides on its own, and the webUI shows every reason next to the
verdict. It is a heuristic and is documented as one: the admin can
always override it with `trusted_macs` / `isolated_macs`.

### Enforcement: a MAC set in the kernel, same privilege split as IDS

The decision (`frfw.iot.scanner.decide_isolation`) is `isolated_macs`,
plus -- only with `auto_isolate` -- every device classified "iot", minus
`trusted_macs`. It is made in the unprivileged scanner, which is also
the process parsing untrusted network input; that is why it runs as
`fr_os-sensor` in `fr-iot-scan.service` (from its timer, or from the
webUI's "Scan now" through the helper) and never as root or in the webUI.
The kernel side (`frfw.iot_isolation`, a structural mirror of
`frfw.ids_quarantine`) is reached only through the helper's
`iot_sync_isolation` command, which drops any MAC the current config
marks trusted before touching the set -- a misbehaving scanner still
can't isolate a device the admin trusted.

The set is `type ether_addr`, matched with `ether saddr`, so a device
can't escape by taking a new DHCP lease, and it applies to IPv4 and IPv6
alike since the IP header is never consulted. Membership is replaced in
one `nft -f` transaction per sync (`flush set` + `add element`), so the
set is never half-updated. The rules sit ahead of `ct state
established,related accept` in both chains, so an isolated device's
already-open connections are cut immediately, and ahead of every
config-derived rule, so an admin accept rule can't accidentally reopen
it (`trusted_macs` is the one exemption). Isolated devices keep DHCP and
DNS from the router in both modes. The set has the same `flush ruleset`
problem as the ZTNA/jail/quarantine sets and the same answer: snapshot
and restore around the reload in `frfw.provision.apply_all`.

### Real, hands-on verification

Beyond unit tests with mocked I/O, this phase was verified on the wire,
and the checks are automated (`tests/test_iot_isolation.py`, run as
root): two network namespaces joined to the host by veth pairs, the host
routing between them with the *actual generated* FR_OS ruleset loaded.

- **block mode**: a TCP connection from the "IoT" namespace through the
  router succeeds, fails once `sync_isolated()` puts that namespace's
  real MAC into the set, fails against a router service as well, and
  succeeds again after the set is cleared.
- **flush survival**: a full ruleset reload (the same `flush ruleset`
  every apply does) lets the connection through again -- the exact
  problem -- and `restore_after_reload()` with the pre-reload snapshot
  cuts it off again.
- **internet_only mode**: while isolated, the connection to the
  masquerade ("internet") zone succeeds and the connection to a router
  service fails, even though an explicit admin rule accepts that service
  from the IoT zone.
- **mDNS discovery end to end**: a responder in the IoT namespace joins
  224.0.0.251 and answers with compression-pointer-encoded PTR records;
  `mdns.discover()` on the router finds `_hap._tcp` and
  `_googlecast._tcp` for it. With the generated ruleset minus the one
  `iot-mdns-replies` rule, the same discovery returns nothing -- proving
  the rule is both necessary and sufficient.
- The mDNS parser is fed hostile input in the unit tests: a
  self-referencing compression pointer, labels running past the packet,
  an absurd record count, truncated records -- all return an empty
  result without hanging.

Not verified: real IoT hardware (no physical devices in this sandbox --
the responder above is a faithful stand-in for the protocol, not for any
particular vendor's firmware), and Kea's lease file from a live Kea
server (the CSV format is from Kea's documented memfile layout; the
parser reads columns by header name to stay robust to version drift).

### Open issues

- Same-segment traffic between devices is out of reach of router-side
  enforcement (see the correction above).
- IPv6-only devices are isolated (the match is on the MAC), but not
  *discovered*: inventory sources are DHCPv4 leases, the IPv4 ARP table
  and IPv4 mDNS. Adding `ip -6 neigh` and IPv6 mDNS is future work.
- mDNS finds only devices that implement it; a silent device is
  classified on vendor and hostname alone.
- The point weights are hand-picked, not tuned on a real device corpus.

## Categorized DNS filtering and DNS threat signals (phase 15)

Goal: take phase 9's single ad-block list to something closer to
"advanced URL filtering" and "DNS security" for a home or small office --
block by category, see which category blocked what, make sure clients
actually use the filtering resolver, and use DNS as a detection signal
for the AI IDS -- without any cloud lookup service.

### Categories: separate files, verified sources

`adblocker.categories` maps a category name to source URLs. Each
category is written to its own hosts file (`/etc/fr_os/adblock.d/<name>.hosts`)
instead of being merged into one, for two reasons: per-category counts
(webUI, `fros_dns_blocked_domains{category}`), and attribution -- dnsmasq's
query log names the hosts file that answered a blocked lookup, which is
how a lookup is known to have hit "malware" rather than "social".

The webUI's presets were each fetched and checked while writing this,
and some obvious guesses turned out wrong: StevenBlack's
`extensions/gambling/hosts`, `extensions/social/hosts` and
`extensions/porn/hosts` are all 404; the real per-category files are
`alternates/<x>-only/hosts`, whose own header confirms "The unified hosts
file was not used while generating this file". URLhaus is hosts format
with `127.0.0.1` and tabs; Phishing Army and the DoH-resolver list are
plain one-domain-per-line lists, which phase 9's parser (hosts format
only) would have silently read as empty -- so the parser now accepts both
formats, and still rejects adblock filter syntax rather than guessing. A
real refresh of all eight lists took 3.4 s and produced 316,576 domains.
License terms are the publishers' and are shown next to each preset;
Phishing Army's header says CC BY-NC 4.0, which matters in an office.

One category's outage doesn't cost the others: every list is fetched
and written independently, a category whose every source fails keeps
its previous file, and a category removed from the config has its file
deleted so it really stops blocking.

### Allowlist, and a real bug found end to end

`adblocker.allowlist` removes names (and their subdomains) at refresh
time and again on every `apply` (about 1 s over those 316k entries), so
an allowlist edit takes effect without a re-download.

Running a real dnsmasq with the real lists exposed an interaction no
unit test would have: the DoH-resolver list contains
`use-application-dns.net`, Firefox's DoH canary domain. With `force_dns`
the config also has `address=/use-application-dns.net/`, which makes
dnsmasq answer NXDOMAIN (checked: A and AAAA both rcode 3) -- but a
hosts-file entry wins over that rule, so the canary resolved to
`0.0.0.0`. A positive answer tells Firefox the network does *not* want
DoH disabled, silently defeating the feature. Fix: the canary is removed
from every list we write, unconditionally, like an allowlist entry that
can't be switched off; re-verified with real dnsmasq.

### Making clients actually use it: `serve_lan` and `force_dns`

Phase 9 deliberately left DHCP clients' DNS server alone. That is still
the default, now with an explicit opt-in:

- `serve_lan`: Kea announces the router's own address as the DNS server
  in every pool; the pools' configured `dns_servers` become the
  resolver's upstreams (excluding the router's own addresses, so an
  admin who already listed the router doesn't get a forwarding loop);
  the input chain accepts DNS from the DHCP zones.
- `force_dns`: a `redirect to :53` in the NAT prerouting chain catches
  clients with a hard-coded resolver (8.8.8.8 and friends);
  DNS-over-TLS/QUIC on port 853 is *rejected* (not dropped) so clients
  that try it opportunistically, like Android's "automatic" Private DNS,
  fall back immediately; and the Firefox canary answers NXDOMAIN. What it
  cannot do: stop DoH to an arbitrary server on port 443 without
  breaking HTTPS. The `doh-bypass` category (well-known DoH server names)
  is the practical complement, not a guarantee.

### DNS as an AI IDS signal

With `query_logging`, dnsmasq runs with `log-queries=extra`. The real
format (dnsmasq 2.91) puts a per-query serial and the client address on
every line and names the hosts file for blocked answers:

```
3 10.0.0.5/46443 reply www.nxtest.example is NXDOMAIN
1 10.0.0.5/33904 /etc/fr_os/adblock.d/malware.hosts bad.example is 0.0.0.0
```

(dnsmasq's own log file adds a `Oct  3 17:25:19 dnsmasq[489]: ` prefix,
which `frfw.adblock.dns_service.dnsmasq_message` removes.) The log is a
file of the resolver's own, `/var/log/fr_os-dns/queries.log`, not its
journal (ROADMAP SEC-4): `fr-adblock-dns.service` runs under
`Group=fr_os-webui` with `LogsDirectory=fr_os-dns` (0750), and dnsmasq
opens the file as root and then hands it to its own unprivileged user,
so it is nobody:fr_os-webui 0640 -- only dnsmasq writes it, `fr-ai-ids`
and `fr-appid` (in that group) read it, neither needs the
`systemd-journal` group that reads every unit's log. dnsmasq only ever
appends, so `fr-dns-log-trim.timer` empties the file hourly once it is
past 16 MiB (root with `CAP_DAC_OVERRIDE` alone, no network); the
readers' `tail -F` follows the truncation. `fr-ai-ids` follows it and
feeds three new per-host counters into the same
z-score-against-own-baseline engine:

- **distinct NXDOMAIN names** per window (floor 30) -- distinct, because
  an app retrying one dead name in a loop is not the signal, a host
  walking through dozens of different names is;
- **distinct DGA-like NXDOMAIN names** (floor 10), using
  `frfw.adblock.dga`;
- **lookups answered from a malware or phishing category** (floor 3) --
  the DNS counterpart of phase 11's SNI-blocklist beacon feature. Other
  categories (social, gambling) are policy, not compromise, and don't
  count.

Query logging is off by default: it writes which client looked up which
name into the system journal, for as long as the journal keeps it.

### The DGA heuristic, measured

`frfw.adblock.dga.looks_generated` scores the *registered* label (a DGA
must register its random part, whereas CDNs randomize subdomains of an
ordinary name like `cloudfront.net`), skips single-label names
(Chromium's random start-up probes NXDOMAIN by design) and punycode
labels, and flags a label of at least 10 characters with character
entropy of at least 3.0 bits and fewer than 40% frequent-English-bigram
pairs. Thresholds were chosen against real data, favouring few false
positives over recall, because the verdict always comes from a *burst*:

| Input | Flagged |
|---|---|
| random letters, 12-20 chars | 57.9% |
| random letters, 10-11 chars | 32.1% |
| random alphanumeric, 10-16 chars | 51.1% |
| random hex, 16 chars | 40.0% |
| StevenBlack gambling list, one name per registered label (3,040) | 0.03% |
| StevenBlack fakenews list (2,160) | 0.00% |
| StevenBlack adult list (38,861) | 0.03% |
| StevenBlack unified ad list (33,844) | 0.30% (mostly generated spam domains themselves) |

A first attempt (vowel ratio / consonant runs) flagged 0.4-1.1% of the
human-named lists (e.g. `mrjackpotspins.com`) and was discarded. At
~50% per name, a DGA burst of 50 lookups still yields ~25 flagged names,
well over the floor of 10. Known blind spot: dictionary DGAs
(concatenated real words) look like ordinary names.

### Verification

- Unit tests for every piece (parsing both list formats, refresh with
  categories/allowlist/failure/stale-file cases, config validation,
  dnsmasq/Kea/nftables rendering, the DGA rule, the engine's distinct-name
  counting, the daemon's parsing of the real log format), `nft -c` on the
  `force_dns` ruleset, `dnsmasq --test` on the full-featured config.
- One automated end-to-end test with a **real dnsmasq**: a malware-category
  name is answered `0.0.0.0` and logged with its category file, the DoH
  canary is NXDOMAIN even though a list contains it, 25 random names are
  forwarded to an NXDOMAIN-only upstream, and that real log, fed line by
  line to the AI IDS daemon, gets the client flagged for "DGA-like
  NXDOMAIN lookups" with one threat lookup counted.
- By hand: a real refresh of all eight preset lists through the network.

Not verified: real DGA malware traffic (no samples run in this sandbox --
the positives are synthetic random names), and journald delivery of the
query log under load (the tests read dnsmasq's `log-facility` file, whose
message format is the one journald carries).

### Open issues

- DoH to arbitrary servers on 443 is out of reach (see above).
- No per-zone or per-device category policy: categories apply to every
  client of the resolver.
- No Public Suffix List; a handful of common second-level suffixes is
  hard-coded.
- Journald may rate-limit a very chatty resolver's query log (systemd's
  default burst limit); detection then sees a sample, not everything.

## Coarse application identification (phase 16)

Goal: tell a home or small-office admin *which apps* the network uses --
Netflix, TikTok, Steam, Zoom -- and let them block an app with one
checkbox, without decrypting anything and without a cloud service.

### Correction to the original idea, up front

The request was "App-ID lite, built on the existing XDP SNI parser". Two
facts about that parser, checked before building on it, changed the
design:

1. **It was attached on the wrong side.** XDP runs on packets an
   interface *receives*. The phase 4 docs said to attach it to the WAN
   interface -- where a LAN client's ClientHello is never seen (it is
   *transmitted* there). Reproduced with three network namespaces
   (client / router / server) and the real compiled program: on the
   router's WAN-side veth a blocklisted SNI reached the server and the
   program's counters did not move; on the LAN-side veth it was dropped.
   The docs, the schema docstring and the webUI now say LAN-side, and the
   namespace setup is an automated test.
2. **It only reported drops**, and can only see SNIs shorter than 32
   bytes, TCP only (QUIC/HTTP-3 is UDP), never behind Encrypted Client
   Hello. That is too narrow to be the *only* source. The resolver's query
   log (phase 15) sees every name a client resolves through the router,
   whatever its length or transport.

So identification uses **both**: DNS lookups as the main signal, XDP SNIs
as an optional second one that also catches clients resolving names
elsewhere (their own DNS-over-HTTPS, hard-coded addresses).

### Kernel change: optional pass events

`bpf/xdp_sni_filter.c` gained a one-entry `settings` array map. With its
`SETTING_REPORT_PASS` bit set (`frfw.xdp.set_report_pass`, driven by
`app_control.observe_sni` on every `apply`), an extracted SNI that did
*not* match the blocklist is also pushed to the ring buffer, as action 0.
Two safeguards:

- The map is zero-initialised, so a freshly loaded program behaves exactly
  as before -- only drops are reported.
- A pass event is only queued while less than half the 256 KiB ring
  buffer holds unread data (`bpf_ringbuf_query`). Pass events vastly
  outnumber drops; without this cap a busy network could starve the drop
  events the AI IDS scores. Drops always keep the upper half.

The AI IDS keeps counting drops only (it already ignored anything that
wasn't `"action": "drop"`). A program pinned by an older frfw has no
`settings` map; `apply` then says so ("disable and re-enable the filter to
reload it") instead of failing.

### The catalog: generated from v2fly, pinned to a commit

Per-app domain lists come from
[v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)
(MIT), which maintains one list per service. `scripts/update_app_signatures.py`
(run by a developer, never on the router) downloads 41 of them at an exact
commit and writes `src/frfw/appid/signatures.json` (about 1,850 names),
recording the commit. What it keeps and why:

- plain/`domain:` entries as suffix matches, `full:` entries as exact
  names; `keyword:`/`regexp:` entries are dropped (not expressible as a
  suffix lookup), and so are `@ads` entries (they belong to the ad
  blocker and would inflate an app's usage);
- `include:` is followed only where it really is the same app (Disney+ ->
  BAMTech, EA -> Origin) -- Disney's list includes ESPN, Hulu and ABC,
  which would misattribute traffic;
- a name claimed by two lists goes to the first app in a fixed order, so
  Messenger and Instagram keep their own names instead of the umbrella
  Facebook list taking them. The generated catalog was checked for
  over-broad entries: every CDN name in it is an app-specific host
  (`steamcdn-a.akamaihd.net`), never a shared suffix like `akamaihd.net`.

Matching (`frfw.appid.AppMatcher`) is an exact-name table plus a suffix
walk from the longest suffix down, so the most specific entry wins.

### Observation: `fr-appid`

An unprivileged daemon (user `fr_os-sensor`, journal read access only, like
`fr-ai-ids`) follows `fr-adblock-dns`'s query log (the real dnsmasq 2.91
line is `2 10.0.0.5/46381 query[A] www.netflix.com from 10.0.0.5`) and,
with `observe_sni`, `fr-xdp-sni-logger`'s events. Each attributed name is
a "hit" for that app and client, kept in hourly buckets for 24 hours;
the same name from the same client and source within 10 seconds counts
once (browsers ask for A, AAAA and HTTPS records together). The summary
goes to `/etc/fr_os/webui/appid_usage.json` every 30 seconds and survives
restarts. A hit is an activity signal, not bandwidth or time spent.

The unit is enabled unconditionally and follows `config.yaml` itself:
it idles while the feature is off and re-executes itself when the set of
enabled sources changes, so no manual restart is needed.

### Blocking

`app_control.blocked_apps` becomes `address=/<name>/` lines in the
resolver config -- NXDOMAIN for the name and all its subdomains, the same
mechanism as the Firefox DoH canary. It therefore requires the resolver
to serve the LAN (`serve_lan`) and, to be hard to bypass, `force_dns`.
`block_via_xdp` additionally merges the blocked apps' names (those under
the 32-byte limit) into the XDP blocklist in memory at `apply`, like the
phase 9 "critical" subset; `apply` now refuses a merged list larger than
the kernel map's 4,096 entries up front instead of failing half-way.

### Found along the way

- **The installed webUI had no templates.** `pip install` of the source
  tree (the live image's hook, `frfw.update`) only copies `.py` files
  unless package data is declared; every page would have failed with
  `TemplateNotFound` on a real install. Verified by building a wheel (0
  templates before, 16 after); `tests/test_packaging.py` now fails for any
  undeclared non-Python file.
- **`fr-xdp-sni-logger.service` was never installed** by either installer,
  and the live image also lacked the ad-block units -- so on a real
  install the XDP event log, and everything reading it, never ran.
  `tests/test_system_units.py` now requires every unit in `systemd/` in
  both installers.

### Verification

- `tests/test_xdp_live.py` (root, clang, bpftool, libbpf): three network
  namespaces and the real compiled program -- WAN-side attachment never
  sees a LAN client's ClientHello; LAN-side attachment drops the
  blocklisted SNI (drop event on the ring buffer with the client's
  address); a non-matching SNI produces a pass event only while reporting
  is switched on, and the connection still goes through.
- `tests/test_appid.py`: the catalog's invariants and real-name spot
  checks (and look-alikes that must not match), usage accounting and
  pruning, the daemon's parsing and de-duplication, config validation,
  resolver/XDP merging, and a **real dnsmasq** run: a blocked app's names
  answer NXDOMAIN, others resolve, and the real query log fed to the
  daemon is attributed to the right apps (blocked lookups still count as
  attempts).
- Route tests for `/apps` and the new `/metrics` families.

Not verified: real client apps (no phones or consoles in this sandbox --
the traffic is synthetic lookups and handshakes), and the catalog's
completeness for any given app; v2fly's lists are community-maintained.

### Open issues

- Coarse by design: a shared CDN name not in any list is unattributed, and
  an app using a name also used by another service is attributed to one.
- Blocking is per resolver, for every client -- no per-device or
  time-based app policy (phase 17's time-based rules act on firewall
  rules, not on the resolver).
- Blocking an app through DNS does not end connections already open, and a
  client with a cached answer keeps working until it expires.
- QUIC/HTTP-3 SNIs are invisible to XDP; DNS observation still covers them
  when the client uses the router's resolver. While the SNI filter is on,
  QUIC from its ports is rejected (phase 4, point 8), so clients there
  use TLS over TCP, which XDP does see.

## Time-based rules (phase 17)

Goal: "granular policy" for a home or small office -- a rule that only
applies at certain times ("no internet for the kids' tablets on school
nights after 21:30", "SSH to the router only during office hours"),
optionally tied to a device by MAC address rather than an IP that DHCP
may change.

### Corrections found before writing any rule, up front

nftables has `meta day` and `meta hour`, so the obvious implementation is
to write `meta hour "21:30"-"06:30"` and be done. Checked against the
real `nft` 1.0.9 binary and the kernel source (net/netfilter/nft_meta.c),
that is wrong in three ways:

1. **`meta hour` is UTC in the kernel.** The `nft` tool converts the
   written time using *its own process's* time zone when the ruleset is
   loaded (loading the same file with `TZ=Europe/Budapest` stored 06:00
   UTC for "08:00", with `TZ=UTC` 08:00). The result depends on the
   environment of whoever ran nft, and after every daylight-saving change
   the loaded rule is an hour off until something reloads it.
2. **`meta day` uses a different clock.** `nft_meta_weekday()` computes
   the weekday from UTC shifted by the kernel's own time zone (`sys_tz`,
   set via settimeofday -- 0 on this machine, but systemd sets it to the
   local offset when the RTC keeps local time), while `nft_meta_hour()`
   uses plain UTC. Near midnight the two disagree about which day it is,
   so "Monday 23:30-24:00" in UTC+2 would match on the wrong day.
3. **A time rule never ends a connection.** Rules sit after the chain's
   `ct state established,related accept`, so a stream opened at 21:29
   keeps running through a 21:30 block.

### How it works

- `frfw.nft.schedule` converts each local weekly window to UTC with the
  configured zone's *current* offset, cuts it wherever either UTC or the
  kernel's day clock crosses midnight, and renders each piece as the
  kernel's day name(s) plus a UTC hour range; pieces with the same hours
  are grouped into one `meta day { ... }` set and adjacent ranges merged.
  A scheduled rule becomes one nft line per piece, all with the rule's
  comment. The kernel zone is read with gettimeofday(2).
- `frfw.apply` runs every ruleset load and listing with `TZ=UTC`, so nft
  leaves those hour values alone and backups round-trip unchanged.
- `apply` records the offset it rendered for (`/etc/fr_os/
  schedule_state.json`, with a fingerprint of the applied config). The
  hourly `fr-schedule-check.timer` re-applies when the offset or kernel
  zone has changed -- but refuses when config.yaml no longer matches the
  applied config, so an edit saved in the webUI but not yet applied is
  never put live behind the admin's back; it says so instead.
- `cut_established` (drop/reject only) places a scheduled rule ahead of
  the established-connection accept, like the IoT isolation rules, so
  open connections are cut when the window starts. Those rules are
  evaluated before all ordinary rules, which the webUI states.
- Rules gained `src_mac` (`ether saddr`, already proven in the `inet`
  forward and input hooks by phase 14).
- The webUI's rule form has day checkboxes, from/until times, the cut
  option and the MAC field; the rule list shows each schedule and whether
  it is active right now; a time zone field shows the router's current
  time. `tzdata` joined the live image's package list.

### Verification

- **The conversion against a reference, every minute of the week:**
  random schedules (days, start, end, wrap-around) under offsets including
  +05:30, +05:45, +12:45 and -10:00 and several kernel zones; for every
  minute, the reference "is the local time inside the window" agrees with
  a simulation of what the kernel decides for the rendered pieces.
- **The real kernel, now:** `tests/test_schedule_live.py` loads rendered
  rules into a network namespace with `TZ=UTC nft`, sends a packet through
  each and compares the kernel's counters with the reference, in five
  zones (UTC, Budapest, Los Angeles, Kolkata, Chatham). Checked by hand
  that it is not vacuous: rendering with the offset ignored fails it in
  all three non-UTC zones tried.
- **The kernel time zone, by hand:** with `sys_tz` set to UTC+10 through
  settimeofday (after a first zero-offset call, so the kernel's one-time
  clock warp could not move the clock -- it didn't, and `sys_tz` was put
  back to 0), the compensated rendering matched the kernel in three zones
  and the uncompensated one failed in all three.
- `nft -c` on a ruleset with scheduled and cut rules (an odd +05:45 offset
  with a non-zero kernel zone), unit tests for parsing, rendering, rule
  placement, the refresh check's decisions, apply recording and clearing
  the record, the CLI, and the webUI routes.

Not verified: an actual DST transition on a running router (the refresh
logic is tested with injected offsets), and systemd's handling of
`sys_tz` on a real local-time-RTC machine (the compensation itself was
tested on the real kernel).

### Open issues

- Time-based *app* blocking (phase 16) is not covered: app blocking lives
  in the DNS resolver, which has no notion of time. A scheduled firewall
  rule can cut a device's internet access, not a single app.
- Between a DST change and the next hourly check (at most ~2 minutes past
  the hour, when the switch happens on the hour) the rules are an hour
  off.
- IPv6 is still out of scope for rules as a whole (see Known limitations
  in docs/CONFIG_SCHEMA.md).

## Multiple webUI accounts with roles (phase 18)

Goal: more than one person can manage the router -- a second admin, a
helpdesk colleague or a curious family member who may look but not
touch -- and it is visible afterwards who changed what.

### What it is

- **Accounts and roles** (`frfw.admin_account`): any number of local
  accounts, each `admin` (everything, including account management) or
  `viewer` (every screen read-only; may only change its own password).
  The store refuses any change that would leave no admin, and the first
  account is always an admin. The pre-phase-18 single-account file is
  read as one admin and rewritten in the new format on the next change.
- **One enforcement point** (`frfw.webui.deps.require_login`): every
  protected route already depended on it, so the role check lives there
  rather than in each route -- a viewer gets 403 for any non-GET request
  except `/logout` and `/account/password`. A per-route check would be
  one forgotten decorator away from a hole; this can't be forgotten on a
  new route. `tests/webui/test_rbac.py` enumerates *every* registered
  route (two independent listings: the router tree and the OpenAPI
  schema, which must agree) and sends each change route as a viewer:
  all 35 answer 403 and neither the config nor the account file changes.
  Removing the check makes that test fail (tried).
- **Sessions follow the account.** The signed cookie carries the username
  and a version derived from the password hash, and every request
  re-reads the account. Deleting an account, changing its role or
  resetting its password therefore applies to its open sessions on the
  next request; changing your own password keeps your current session
  (fresh cookie) and ends the others.
- **Audit log** (`frfw.webui.audit`, `/etc/fr_os/webui/audit.log`): one
  JSON line per change request by a logged-in account (user, role,
  client address, method, path, HTTP status -- a refused viewer attempt
  shows as 403) and per login attempt, successful or not. Form contents
  are never written (they can hold passwords; a test checks that a
  password set through the UI does not appear in the log). Capped at
  1 MiB with one rotated generation. Admins see the latest 200 entries on
  `/users`.
- **UI**: `/users` (admin only) to add accounts, change roles, reset
  passwords, delete; `/account` for everyone's own password; viewers see
  a read-only banner and no change forms (cosmetic -- the server enforces
  it regardless). `firewall-cli users` lists accounts; `firewall-cli
  set-admin-password`, run as root, always grants the admin role -- the
  recovery path if the last admin's password is lost.

### Honest boundaries

- Roles are enforced in the webUI process. The privileged apply-helper
  trusts whatever the `fr_os-webui` account sends over its socket (it
  only narrows what the network-parsing daemons may send): a compromised
  webUI process is not stopped by roles. What roles add is separation *between people using the webUI*.
- "Read-only" still means seeing everything the screens show, including
  per-client data: which apps each device used (phase 16), the live XDP
  SNI log, DHCP leases and the IoT inventory. Give the viewer role only
  to people who may see that.
- No per-screen permissions and no external identity provider (LDAP,
  OIDC) -- two roles are what a home or small office needs; anything
  finer would be a different project.
- The webUI accounts are separate from the ZTNA gate's users (phase 7),
  which grant network access, not router management.

### Verification

18 new tests: the all-routes viewer walk above, the anonymous walk (every
change route except `/login`, `/logout` and `/ztna/login` sends an
anonymous caller to the login page), account management, last-admin
protection, session invalidation on role/password/deletion, own-password
change, legacy file migration, store validation, audit contents
(including denied attempts and failed logins), and the CLI recovery path.

## TLS client fingerprinting without decryption (phase 19)

Goal: know *which TLS software* each device uses -- a browser, an app, a
library, a script -- and notice when that changes, without decrypting
anything or installing certificates on clients. Everything needed is in
the cleartext ClientHello: which cipher suites, extensions, groups and
signature algorithms the client's TLS library offers.

### Method and licensing, up front

- **JA3** (Salesforce, BSD 3-Clause): MD5 of those lists in wire order.
- **JA4** (FoxIO, BSD 3-Clause): sorted lists hashed with SHA-256 plus a
  readable prefix (`t13d1516h2_...`: TCP, TLS 1.3, SNI present, 15
  ciphers, 16 extensions, ALPN h2).
- **Not implemented: JA4+** (JA4S, JA4H, JA4T, JA4X, ...). Unlike JA4
  itself these are under the FoxIO License 1.1, which forbids
  monetization without an OEM license, and are patent pending -- checked
  in FoxIO's own License FAQ before starting. An Apache-2.0 router OS that
  anyone may sell should not ship them.
- Both implemented from the published specifications, no code copied.

JA3 is shown for compatibility, but it is a weak identifier today: Chrome
(since v110) and Firefox shuffle their extension order per connection, so
a browser's JA3 changes on almost every connection (a unit test shows the
shuffle changing JA3 and not JA4). JA4 is the one inventory, events and
the blocklist key on.

### Correction to the naive approach: hellos no longer fit one packet

The phase 4 XDP program inspects one packet at a time. That was fine for
the SNI, but a modern browser's ClientHello often doesn't fit a packet:
the hybrid post-quantum key share (X25519MLKEM768, on by default in
Chrome and Firefox) alone is 1,216 bytes, and with a GREASE ECH extension
a Chrome hello is ~1.8 KB -- two TCP segments on a 1500-byte MTU. The
extension list, which JA3 and JA4 need entirely, runs into the second
segment. So:

- **Kernel** (`bpf/xdp_sni_filter.c`, `SETTING_REPORT_HELLO`): the first
  segment of every ClientHello is copied (up to 2 KB) to a new 1 MiB ring
  buffer, `hello_pkts`, separate from the drop-event buffer. If the TLS
  record is longer than the segment, the flow goes into an LRU map and
  its next (at most 3) segments are copied too. This is copying, not
  parsing; the forwarding decision never depends on it. The verifier
  needed three adjustments (pointer-based bounds for the first-byte read,
  payload offset/length from IP/TCP header fields instead of pointer
  differences, and a mask bound on the copy length) -- all found by
  loading the real program, not guessed.
- **Userspace** (`frfw.tlsfp`): a reassembler places segments by TCP
  sequence number (reordering, retransmissions and sequence wraparound
  are handled; everything is bounded by flow count, bytes and a 5-second
  timeout), reassembles handshake messages across TLS records, parses the
  ClientHello strictly (malformed input can only raise `ParseError`; a
  fuzz test throws 3,000 mutated hellos at it) and computes JA3/JA4.

### Validated against the reference

The JA4 code was run over FoxIO's public capture set (39 pcaps, cloned
into the sandbox only for this, not bundled) with a small pcap reader and
this project's own reassembler: **151 of 152 TCP streams match the
reference output exactly**, including multi-segment hellos. The single
difference is a spec/reference disagreement: for a non-ASCII ALPN value
the published specification says to use hex characters (this gives
`bd`), while FoxIO's Rust and Python implementations substitute `9`
(giving `99`). frfw follows the specification; real clients don't send
such ALPN values. JA3 matches the JA3 README's worked example.

### `fr-tls-fp` and privilege separation

Opening the pinned ring buffer needs CAP_BPF (this kernel has
`unprivileged_bpf_disabled=2`). The daemon therefore starts as root,
opens the buffer, and **drops to fr_os-sensor for good before reading any
packet data** -- untrusted bytes are never parsed with privileges.
Checked by hand: the open ring buffer keeps delivering after `setuid`,
and CAP_BPF + CAP_SETUID + CAP_SETGID are the only capabilities needed
(tried under `setpriv` with just those), which is what the unit's
`CapabilityBoundingSet` grants. Since the pinned path can't be reopened
afterwards, `apply` restarts the daemon whenever fingerprinting is on.

It keeps a per-device inventory (JA4s, their JA3 variants, a few server
names, counts, first/last seen), reports **new fingerprints** -- a JA4
never seen on the network -- after a 24-hour learning period, and
reports **blocklist matches** (JA4 or JA3), optionally quarantining the
device through the helper's existing `quarantine_ip` command.

### Verification

- `tests/test_xdp_live.py`: a synthetic Chrome-sized (post-quantum, ~1.8
  KB) ClientHello is sent in two TCP segments through the real XDP
  program in network namespaces, plus a real OpenSSL handshake; a
  separate process opens the buffer as root, drops to `nobody`, and
  produces the expected JA4 for both. Disabling the continuation-segment
  copy in the C code makes the test fail (tried).
- `tests/test_tlsfp.py` (35): the JA4 spec example end to end, the JA3
  example, GREASE, extension shuffling, every ALPN rule from the spec,
  records, reassembly (order, retransmits, wraparound, bounds, expiry),
  the fuzz test, inventory, daemon decisions (blocklist, quarantine
  rate-limit, config updates), decoding, settings bits, config, CLI.
- Route and metrics tests for `/tls`; the phase 18 viewer walk now covers
  its change routes automatically.

### Open issues

- **QUIC/HTTP-3 is not fingerprinted.** Its ClientHello travels in UDP,
  encrypted with keys derivable from the packet itself (RFC 9001) --
  public, but decrypting it needs AES-GCM, which Python's standard library
  lacks. JA4's `q` prefix is ready for it.
- IPv6 isn't seen (the XDP program is IPv4-only, see phase 4).
- Fingerprints identify TLS *libraries*, not apps: every app built on the
  same OS TLS stack shares one. Useful for "this device suddenly speaks
  TLS differently", not as proof of identity -- a client can copy
  another's fingerprint.
- No public fingerprint database is bundled. The best-known free one,
  abuse.ch's SSLBL JA3 list, is stale (checked: last updated August 2021,
  97 entries) and keys on JA3; FoxIO's JA4 database is a separate service
  with its own terms. Blocklist entries are the admin's own.

## Multi-site read-only monitoring (phase 20)

Goal: someone looking after a few sites -- home, the office, a parent's
flat, two branch offices -- sees all FR_OS routers on one read-only
screen: which are up, which config fails validation, load, throughput,
security enforcement, and can drill into one site. Deliberately built on
the phase 12 Prometheus exporter rather than a new FR_OS-to-FR_OS
protocol: Prometheus and Grafana already do fleet monitoring well, and a
second, home-grown management channel between routers would be one more
thing to secure.

### What was missing for that, found by trying it

- **/metrics was public by design** (phase 12: "put it behind network
  access control"). Scraping across sites means crossing networks the
  admin may not fully control, so /metrics can now require a bearer
  token (`metrics.token_sha256`). Only the token's SHA-256 is stored --
  the token itself is shown once (CLI or webUI, rendered in the response,
  never put in a redirect URL where it would land in browser history and
  access logs). It is 32 random bytes, so no rate limiting is needed;
  comparison is constant-time. The check reads the *raw* config, so an
  otherwise-invalid config.yaml can't turn a protected endpoint public,
  and a malformed digest fails closed.
- **The generated webUI certificate couldn't be verified by Prometheus.**
  It had only `CN=fr-router` and no subjectAltName; Go-based clients
  (Prometheus, Grafana) have ignored the CN since Go 1.15. Reproduced with
  the real Prometheus: with the old certificate every target is down with
  an x509 error. New certificates carry SAN entries (`fr-router`, the
  hostname, the static interface addresses); a certificate recognised as
  this project's own pre-phase-20 one is regenerated once, and any other
  certificate (an admin's) is never touched. A scraper trusts exactly one
  router certificate (`ca_file`), whose SHA-256 the System screen shows
  and offers for download.
- **Nothing said which router a series came from** beyond Prometheus's
  target labels. `fros_info{site_name, hostname, version, codename}` and
  `fros_config_valid` are always exported.

### What ships

- `telemetry/prometheus-multisite.yml`: one job per router (tokens and
  certificates differ per router), a `site` target label, TLS verified
  against that router's certificate, and a note to reach routers over a
  VPN or an address-restricted rule -- the token protects /metrics, not
  the webUI port.
- `telemetry/grafana-fleet-dashboard.json`: sites reporting/down,
  configs failing validation, fleet-wide quarantined hosts, banned login
  sources and blocklisted TLS fingerprints; a per-site table (up, version,
  config valid, CPU, RAM, throughput, XDP mode, quarantined) whose site
  names link to the per-router dashboard; throughput, CPU and enforcement
  trends per site; the most-used apps across sites.
- `telemetry/grafana-dashboard.json` gained a `Site` selector; every query
  is filtered by it (a single-router setup without a `site` label still
  works: the filter matches an absent label).
- Read-only by construction: Prometheus only reads /metrics, and nothing
  on the dashboards can change a router. For per-site webUI access, the
  phase 18 `viewer` role is the matching read-only login.

### Verification

`tests/test_multisite_prometheus.py` runs a **real Prometheus 3.14**
(downloaded into the sandbox; the test skips when no binary is available)
against two live webUI instances, each with its own certificate, token
and site name, using the job layout of the example config:

- both targets come up over verified TLS with their bearer tokens; a third
  job with a wrong token is down with a 401;
- `fros_info` carries both sites;
- **every query in both dashboards** is evaluated by Prometheus against
  the scraped data and must succeed, and the core fleet panels must
  return data for both sites (2 sites up, info and config-valid for both,
  4 throughput series, CPU for both);
- promtool accepts the example config.

Removing the subjectAltName from the generated certificate makes the test
fail with Prometheus's x509 error (tried). Unit/route tests cover the
token check (including the invalid-config and malformed-digest cases),
one-time token display, the audit log not containing the token, the
certificate fingerprint and download, legacy-certificate replacement and
the CLI.

Not verified: Grafana itself (not available here -- the dashboards'
PromQL is verified, their JSON structure is checked, rendering is
Grafana's), and scraping over a real WAN/VPN.

### Open issues

- Alerting (Alertmanager rules for "site down", "config invalid") is left
  to the operator; the fleet dashboard shows the state, it doesn't page.
- Helper-backed families (bans, quarantines, ZTNA, RAM modules) need the
  privileged helper running on each router, as before.
- Metrics stay IPv4-centric like the rest of the project.

## WebUI look and feel: dark control plane

The webUI's design comes from the FR_OS Google Stitch project; DESIGN.md
holds the design system (tokens, components, rules) in the Google Labs
DESIGN.md format.

### Decisions

- **Hand-written CSS on the existing templates, not Stitch's HTML.**
  Stitch exports every screen as a standalone page built with the Tailwind
  CDN script, Google Fonts and the Material Symbols web font -- several
  hundred remote references across the project, and sample data in the
  markup. Copying that would make the UI depend on the internet (a router
  UI must work with the WAN down) and replace real templates with
  mock-ups. Instead the Stitch theme's tokens were carried into one
  stylesheet (`src/frfw/webui/static/fros.css`, ~400 lines) that styles
  the small class vocabulary the templates already used (`card`, `badge`,
  `flash-*`, `muted`, tables, forms). No build step, no Node dependency at
  runtime.
- **Everything local.** Geist and JetBrains Mono ship as variable woff2
  subsets (latin + latin-ext, ~100 KB, OFL licences alongside), icons as
  one SVG sprite of the 47 Material Symbols in use (~21 KB, Apache-2.0),
  rebuilt by `scripts/build-webui-icons.py`. `/static` is mounted without
  login -- the sign-in page needs it and it holds nothing about the
  router. A test fails if any template or the stylesheet loads a remote
  resource.
- **Navigation lives in one place**: `frfw.webui.templating.NAV` feeds the
  sidebar, the active-item highlight and the breadcrumb. The off-canvas
  menu on phones is a checkbox and CSS, no script.
- **Real data only.** The dashboard's new figures come from
  `frfw.sysinfo` (unprivileged /proc and statvfs reads, no sampling
  delay) and the saved config; a service is "running"/"not running" only
  where its daemon can actually be checked (AI IDS, TLS fingerprinting),
  otherwise "on"/"off" from the config. Stitch screens for features that
  don't exist are listed in ROADMAP.md instead of being shipped as
  mock-ups.
- **Viewer role**: besides hiding change forms, CSS now hides a card that
  would contain nothing but its title for a read-only account.

### What's honestly limited

- Dark theme only (as designed); there is no light variant.
- No charts yet (the Stitch dashboard has throughput graphs): the webUI
  keeps no time series. Grafana (phase 12/20) is the place for history.
- The two-column form layout relies on CSS `:has()`, supported by current
  Chrome, Edge, Firefox and Safari; an older browser shows the forms
  stacked, which still works.

## Booting the image for real: persistence and first-boot fixes

Until this point the ISO had only been checked statically (its squashfs
contents, the unit symlinks). Booting it in QEMU -- the way a user would:
written to a disk, two NICs, no keyboard -- showed that it could not have
worked, for reasons no static check caught. Each is now fixed and has a
regression test (`tests/test_installer_bootparams.py`), and the whole flow
is checked end to end by `installer/qemu-boot-test.py`.

### What the first real boots found

1. **BIOS boot stopped at "Failed to load ldlinux.c32".** syslinux 6's
   `isolinux.bin` loads `ldlinux.c32` first and `vesamenu.c32` needs
   `libcom32.c32`/`libutil.c32`; the bootloader directory only had
   `isolinux.bin` and `vesamenu.c32`. Added as symlinks to the build
   host's syslinux 6.04 modules, like the two existing ones.
2. **The menu waited forever** (`timeout 0` means no timeout in syslinux)
   -- a headless router never booted. Now 5 s.
3. **It booted the fail-safe entry**: `live.cfg.in` marked both entries
   `menu default` and vesamenu took the last -- one CPU (`nosmp`), no APIC,
   and a reboot that hung in QEMU. Only the normal entry is default now.
4. **PID 1 was sysvinit**, not systemd: this live-build snapshot defaults
   `LB_INITSYSTEM` to sysvinit, so every FR_OS unit was dead weight.
   `auto/config` now passes `--initsystem systemd`.
5. **live-config would have created a `user` account with the password
   `live` and sudo** -- on a router running sshd. The boot options now
   include `live-config.nocomponents=user-setup,sudo`; there is no
   console login at all (root is locked), which is what an appliance
   wants.
6. **Nothing survived a reboot** (no persistence -- see below).
7. **First boot always failed**: `install-system-integration.sh` copied
   `examples/config.yaml` from a repo checkout that doesn't exist on the
   image, and `set -e` stopped everything. It now works without one (the
   units are already installed by the image hook, and first boot writes
   the config itself).
8. **The first apply failed**: `fr-firewall`/`fr-apply-helper` run with
   `ProtectSystem=full`, which makes `/etc` read-only except the
   `ReadWritePaths`; Kea's config is in `/etc/kea`. Added (plus the
   optional sshd PQC drop-in and XDP object directories).
9. **A fresh router was unreachable**: the generated config gave the LAN
   no address and the input policy (drop) had no rule for the webUI; and
   live-boot configures every NIC for DHCP, the LAN included. The first
   boot now puts the LAN at 192.168.1.1/24 with a DHCP pool (.100-.199)
   and a `webui-from-lan` rule, and switches the LAN's DHCP client off;
   the WAN keeps DHCP from upstream.
10. **The power button did nothing**: without D-Bus there is no
    systemd-logind to handle it. `dbus` is in the package list now.
11. `dnsmasq` was missing although DNS filtering needs it:
    `dnsmasq-base` (the binary only -- no second dnsmasq.service to fight
    over port 53).
12. **Every webUI page was a 500**: `firewall-cli set-admin-password`
    runs as root and wrote `auth.json` as root:root 0640, which the webUI's
    own account can't read. A root write now hands the file to the owner
    of the state directory (the webUI's account) -- the same fix covers
    a hand install following the README.
13. **tty1 looped on an autologin into the `user` account** that no
    longer exists (live-config's getty generator), until systemd gave up
    and the screen had no login prompt: `live-config.noautologin`.
14. **The third boot hung forever** -- the first one with a config
    already in place. `fr-firewall.service` applies it in sysinit, before
    network-pre.target, and an apply ran a blocking `systemctl restart
    kea-dhcp4-server`: a job systemd had ordered after fr-firewall, so
    each waited for the other ("Job fr-firewall.service/start running
    (8min / no limit)"). The same trap was in the sshd reload, the
    DNS-filter restart/stop and the TLS-fingerprinting restart. They all
    go through `frfw.svc` now: while the system is still booting the job
    is only queued (`--no-block`, the config it loads was validated
    before); once it's up -- an Apply from the webUI -- the call waits,
    so a failure is still reported.

Items 1-11 showed up over the first boots, 12-14 only once the router got
as far as serving its webUI and rebooting with a config -- which is why
the test boots three times.

First boot also no longer aborts when one service fails to start: it
reports it, keeps going, and still marks itself done -- otherwise it would
rerun, with a new admin password, at every boot.

### Persistence: live-boot's own mechanism, set up automatically

The image stays a live system (no installer), and keeps its state with
Debian live-boot's standard persistence: with `persistence` on the kernel
command line, a filesystem labelled `persistence` holding a
`persistence.conf` is overlaid on the running system.

- **What persists: the whole root** (`/ union`). First boot touches much
  more than `/etc/fr_os` -- enabled units under `/etc/systemd`, SSH host
  keys, `/etc/issue`, Kea leases, the journal, update releases under
  `/opt` and `/usr/local` -- and a router should behave like an installed
  system. Writing a new image to the stick is a factory reset.
- **Where: created automatically on the boot medium.** A stick written
  with `dd` has everything after the image unallocated.
  `fr-persistence-setup.service` (before `fr-first-boot`) appends a
  partition there, formats it ext4 with the label, writes
  `persistence.conf`, and reboots once -- before anything was configured,
  so nothing is lost. It never modifies an existing partition: it only
  appends in free space after the last one (the hybrid ISO's MBR has the
  image as partition 1 from sector 0 and the EFI image inside it; the new
  one is 3), refuses CD/loop/read-only devices, needs 256 MiB, and does
  nothing if a `persistence` filesystem already exists anywhere. On the
  real image only the 16-byte partition entry in the MBR changes.
- **Other media**: `firewall-cli persistence create DISK --yes` makes a
  whole internal disk the persistence disk (refuses disks with partitions
  unless `--wipe`, and anything mounted); `persistence status` reports.
  The webUI's System screen and the dashboard warn when changes would be
  lost at reboot.

### Honest limits

- Verified in QEMU: the full three-boot test on BIOS (virtio disk and
  NICs, TCG -- all 19 checks pass), and the first boot on UEFI (OVMF,
  Secure Boot off: GRUB menu with the same options, persistence created,
  reboot). Not yet on physical hardware.
- The WAN is the port where a DHCP server already answers (ROADMAP
  SEC-8, review v0.2.0 R14): `firewall-cli detect-wan-lan` sends a
  DHCPDISCOVER on every port at once from a packet socket -- no address
  and nothing configured on the port, no REQUEST so no lease taken -- and
  `frfw.netdetect.choose_wan_lan` decides. One port answering: that is
  the WAN, the LAN is another (one with a link if there is one). Several
  answering: no assignment at all, DHCP clients on every port and no
  DHCP server anywhere -- the LAN is where FR_OS serves DHCP, and serving
  it onto a network that already has a server (the ISP's side, cabled
  the other way round) is the failure this prevents. None answering (a
  static or PPPoE upstream, a modem still booting): the old port order,
  first WAN, second LAN, with the console saying so. The first-boot log
  and the console say which rule picked the ports; reassign with
  `firewall-cli assign-interfaces` or the webUI's Interfaces screen. The
  QEMU boot test runs the LAN port on a host tap with no DHCP server --
  QEMU's user network always runs one -- so the choice is tested, not
  given by NIC order.

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
