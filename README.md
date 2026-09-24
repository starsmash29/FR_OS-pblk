# FR_OS 🚀 (Firewall-Router Operating System)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](pyproject.toml)
[![100%25 Local](https://img.shields.io/badge/Cloud%20dependency-none-brightgreen.svg)](ARCHITECTURE.md)

**FR_OS** is an ultra-lightweight, **100% local** firewall & router operating system for **homelab hardware** — old or new, x86 desktops and mini PCs included — built around modern Linux kernel primitives (**eBPF/XDP**, **nftables**) instead of legacy userspace packet filtering. No telemetry phones home, no feature sits behind a cloud subscription, and the whole thing boots from a single **~328 MB hybrid BIOS+UEFI live ISO**.

Design decisions and the phase-by-phase development plan:

- [ARCHITECTURE.md](ARCHITECTURE.md) — technical decisions and rationale
- [ROADMAP.md](ROADMAP.md) — phase-by-phase plan and acceptance criteria
- [docs/CONFIG_SCHEMA.md](docs/CONFIG_SCHEMA.md) — full YAML config schema reference

---

## 🌟 Core pillars

- **⚡ Kernel-space TLS ClientHello / SNI filtering.** A `bpf/xdp_sni_filter.c` eBPF/XDP program parses TLS ClientHello SNI extensions and matches against a blocklist held in a BPF LPM Trie map, entirely in kernel space — no userspace copy, no TLS termination/MITM decryption. Designed for multi-gigabit NICs up to 40GbE; real hardware throughput benchmarking is still an open item (see ROADMAP.md phase 4) — this project is honest about what's built vs. what's measured.
- **🔒 Zero Trust Network Access.** Identity-aware login gate (`/ztna/login`) for any zone flagged `require_ztna`; authenticated sessions become entries in a kernel-native nftables set with a real per-element timeout — enforcement stays at wire speed, no userspace session lookup on the packet path.
- **🛡️ Local AI IDS/IPS.** A pure-stdlib (no scikit-learn/pandas/numpy) sliding-window anomaly detector profiles each source IP's connection rate, destination diversity, and SNI-blocklist-hit frequency against its own recent baseline, entirely offline. A flagged IP is quarantined straight into the kernel via the same privileged Unix-socket helper every other enforcement path uses.
- **⚛️ Post-quantum-ready management plane.** Hybrid classical + post-quantum key exchange — `X25519MLKEM768` for the WebUI's TLS 1.3, `mlkem768x25519-sha256` for OpenSSH 9.9+ — protecting the *management* layer against harvest-now-decrypt-later, with automatic, disclosed fallback to classical-only on older OpenSSL/OpenSSH.
- **🚫 Local, categorized DNS filtering.** A dedicated `dnsmasq` instance blocks ads plus whole categories — malware, phishing, gambling, adult, social, DoH bypass — each list verified and reported separately, with an allowlist. Optionally it becomes every DHCP client's resolver and can't be bypassed with a hard-coded DNS server, DNS-over-TLS or Firefox's automatic DoH. With query logging on, NXDOMAIN bursts, random-looking (DGA) lookups and malware/phishing lookups feed the AI IDS.
- **📡 IoT discovery and isolation.** Finds the smart plugs, cameras and speakers in chosen zones (DHCP leases, ARP, mDNS service discovery, IEEE vendor registry), explains every "this is IoT" verdict, and can isolate a device by MAC address in the router's firewall — internet-only or fully blocked — automatically or with one click.
- **📱 App identification and blocking.** Shows which apps (Netflix, TikTok, Steam, Zoom and ~40 others) each client used in the last 24 hours, from the names it looks up and, optionally, the TLS server names the XDP program sees — nothing is decrypted. Any app can be blocked with one checkbox: the resolver refuses all of its names, and optionally the XDP filter drops its TLS connections too.
- **⏰ Time-based rules.** Any firewall rule can apply only on chosen days and times — "no internet for the kids' tablets on school nights", "SSH only during office hours" — per device by MAC address, optionally cutting connections that were already open. Rendered correctly for the kernel's UTC clocks and kept right across daylight-saving changes.
- **👥 Multiple admins with roles and an audit log.** Any number of webUI accounts, each `admin` or read-only `viewer`, enforced in one place for every change endpoint; role changes and password resets end open sessions at once; every change and login is recorded (who, when, from where, result — never form contents).
- **🧩 Real privilege separation, not just a warning label.** The FastAPI + Jinja2 WebUI runs unprivileged, full stop. Every root-level action — nftables reload, interface addressing, DHCP config, package updates, hardware queries — goes through one locked-down, protocol-validated JSON Unix socket to `fr-apply-helper`. The WebUI process cannot escalate even if fully compromised; it simply has no path to root.
- **📊 Built-in, dependency-free Prometheus exporter.** `GET /metrics` in real Prometheus text format, written with plain string formatting against `/proc`, `/sys`, and `os.statvfs` — no `prometheus_client`, no `psutil`, no extra runtime weight. A ready-to-import Grafana dashboard ships in [`telemetry/grafana-dashboard.json`](telemetry/grafana-dashboard.json).

---

## 🛠️ System architecture

FR_OS strictly separates the **control plane** (Python, unprivileged where possible) from the **data plane** (kernel-native structures the control plane only ever configures, never sits in the path of):

```text
       [ Unprivileged WebUI / CLI ]  (FastAPI / Jinja2 / firewall-cli)
                    │
            (validated JSON Unix socket)
                    ▼
       [ Privileged fr-apply-helper ] (root daemon, the only root process)
         │              │              │
         ▼              ▼              ▼
   ┌───────────┐  ┌───────────┐  ┌───────────┐
   │ nftables  │  │ eBPF/XDP  │  │  dnsmasq  │  <─── [ control plane ]
   └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
  ───────┼──────────────┼──────────────┼───────────────────────────────
         ▼              ▼              ▼
   [ Dynamic sets ] [ LPM tries ] [ Host records ]   <─── [ data plane ]
   (ZTNA, jail,          │
    IDS quarantine)      ▼
         └──────────────► kernel packet path (no userspace round-trip)
```

The `fr-ai-ids` daemon and the metrics exporter both *read* kernel/procfs state through the same helper socket or directly from world-readable `/proc`/`/sys` paths — neither ever needs root itself.

---

## 💿 Installation & deployment

FR_OS packages into an offline-first hybrid live ISO supporting both **legacy BIOS** (isolinux/syslinux) and **modern UEFI** (a GRUB 2 EFI boot path + real GPT EFI System Partition, added by a custom `xorriso` post-build step — see ARCHITECTURE.md's phase 13 section) from the *same* image.

### Flashing the image

```bash
dd if=fr_os_hybrid.iso of=/dev/sdX bs=4M status=progress oflag=sync
```

(or use Rufus/balenaEtcher on Windows/macOS — the image is a real hybrid ISO, not BIOS-only.)

### First boot

A first-boot service auto-detects your NICs (`/sys/class/net/`), generates a random admin password, and enables every FR_OS service — no interactive install wizard to click through:

```bash
# Interactive or scriptable network card assignment, if you'd rather do it by hand
firewall-cli detect-interfaces
firewall-cli assign-interfaces --wan eth0 --lan eth1
```

---

## 📊 Telemetry & Grafana

`GET /metrics` (no login required, matching how every Prometheus scrape target works) exposes:

- `fros_xdp_status` & `fros_xdp_blocked_connections_total`
- `fros_ztna_active_sessions` & `fros_ai_ids_quarantined_hosts`
- `fros_bruteforce_banned_ips` (active `/login`/`/ztna/login` rate-limit bans)
- `fros_dns_blocked_domains{category}`, `fros_iot_devices{category}`, `fros_iot_isolated_devices`
- `fros_app_active_clients{app,category}`, `fros_app_hits_24h{app,category}`, `fros_app_blocked{app}`
- `fros_interface_bytes_total{device,direction}` (per-NIC throughput)
- `fros_hw_cpu_usage_ratio`, `fros_hw_cpu_mhz`, `fros_hw_ram_usage_bytes`, `fros_hw_storage_info` and friends — all parsed straight from `/proc`/`/sys`/`os.statvfs`, no `psutil`

A real, importable dashboard (stat tiles, throughput graphs, hardware gauges) is checked into [`telemetry/grafana-dashboard.json`](telemetry/grafana-dashboard.json) — every panel queries a metric name this project actually emits, nothing aspirational.

---

## 🧪 Testing

```bash
# Full suite (also runs a real `nft -c` syntax check if the `nft` binary is available)
python3 -m pytest
```

868 tests pass as of the latest phase (1 skipped, gated on a `dmidecode` binary this dev sandbox doesn't have installed — see ARCHITECTURE.md). Wherever the target environment allows it, tests exercise the real thing instead of a mock: real `nft` ruleset loading and rollback, real kernel-set timeouts (ZTNA sessions, the brute-force jail, AI IDS quarantine), real filesystem-permission checks (e.g. confirming `/proc/net/nf_conntrack` really is root-only before relying on that boundary). IoT isolation is tested on the wire: two network namespaces routed through the actual generated ruleset, with TCP connections and a real mDNS exchange. DNS filtering is tested against a real dnsmasq, whose real query log drives the AI IDS in the same test. The XDP program is loaded into the running kernel and fed real TLS handshakes across three network namespaces (client, router, server), which is how the phase 4 attach-direction mistake was caught. The eBPF/XDP C code is written and commented specifically to satisfy the kernel's static verifier — bounded loops, explicit range checks — and is checked against a real packet-capture integration test, not just compiled.

Config changes are never a one-way door: every real (non-dry-run) apply snapshots the previous ruleset first, keeping the last 10 versions under `/etc/fr_os/backups/` for `firewall-cli rollback`.

---

## Quick start

Requires: Debian (or another Linux distro) with the `nftables` package, Python 3.11+.

```bash
pip install -e ".[dev,webui]"

# Validate the config (schema validation only, doesn't touch nftables)
firewall-cli validate examples/config.yaml

# Print the generated nftables ruleset (doesn't apply it)
firewall-cli render examples/config.yaml

# Apply: interface addresses, nftables ruleset, DHCP (Kea) -- needs root
sudo firewall-cli apply examples/config.yaml

# Dry run only, no actual changes
firewall-cli apply examples/config.yaml --dry-run
```

## System integration (phase 2)

On an actual router box (not just a dev machine), the config loads by
default from the canonical `/etc/fr_os/config.yaml`:

```bash
# Detect interfaces (sysfs-based, no root needed)
firewall-cli detect-interfaces

# Generate a minimal, valid config from the detected NICs
sudo firewall-cli assign-interfaces --wan eth0 --lan eth1 --opt dmz:eth2

# Install systemd units + /etc/fr_os
sudo scripts/install-system-integration.sh
sudo systemctl enable --now fr-firewall
sudo systemctl enable --now fr-apply-helper.socket

# If an applied config breaks the network: roll back to the previous one
sudo firewall-cli rollback --list
sudo firewall-cli rollback
```

The apply-helper (`fr-apply-helper.socket`/`.service`) listens on a Unix
socket for `apply`/`rollback`/`save_config` requests with root
privileges, so the unprivileged webUI never needs root itself. Details:
[ARCHITECTURE.md](ARCHITECTURE.md#security-model).

## WebUI (phase 3)

The install script already sets up the `fr_os-webui` user and the
required permissions; after that:

```bash
sudo firewall-cli set-admin-password   # set the admin password (interactive)
sudo firewall-cli users                # list webUI accounts; add more (admin/viewer) on the /users screen
sudo systemctl enable --now fr-webui
```

From a browser: `https://<router-ip>/` — the browser will warn about
the self-signed certificate until you replace it with a real one
(`/etc/fr_os/webui/`). Dev/test run without root/systemd:

```bash
fr-webui --host 127.0.0.1 --port 8443 --config examples/config.yaml
```

## IoT devices (phase 14)

Enable it in YAML (`iot: {enabled: true, zones: [lan]}`, see
[docs/CONFIG_SCHEMA.md](docs/CONFIG_SCHEMA.md#iot)) or on the `/iot`
screen, apply, then:

```bash
sudo systemctl enable --now fr-iot-scan.timer   # scan every 10 minutes
sudo apt-get install ieee-data                  # optional: vendor names

# Currently isolated MAC addresses
sudo firewall-cli iot-status
```

Nothing is isolated until you turn on `auto_isolate` or isolate a device
yourself -- review the inventory first.

## Applications (phase 16)

Needs the local resolver with query logging (`adblocker: {enabled: true,
serve_lan: true, query_logging: true}`); then enable it on the `/apps`
screen or in YAML (`app_control: {enabled: true, blocked_apps: [tiktok]}`,
see [docs/CONFIG_SCHEMA.md](docs/CONFIG_SCHEMA.md#app_control)) and apply.

```bash
sudo systemctl enable --now fr-appid   # idles until app_control is enabled
firewall-cli apps-status               # apps used in the last 24 hours
```

If you also use the XDP SNI filter, attach it to the **LAN-side**
interfaces: XDP only sees packets an interface receives.

## Time-based rules (phase 17)

Add a `schedule` to any rule (see
[docs/CONFIG_SCHEMA.md](docs/CONFIG_SCHEMA.md#schedules-phase-17)) or use
the schedule fields on the `/rules` screen:

```yaml
timezone: Europe/Budapest
rules:
  - name: kids-bedtime
    action: reject
    from_zone: lan
    to_zone: wan
    src_mac: aa:bb:cc:dd:ee:01
    schedule: {days: [weekdays], start: "21:30", end: "06:30", cut_established: true}
```

```bash
sudo systemctl enable --now fr-schedule-check.timer   # keeps schedules right across DST
```

## AI IDS/IPS (phase 11)

Real-time, kernel-assisted anomaly detection: a separate `fr-ai-ids`
daemon scores each source IP's connection-rate, destination-diversity
and XDP SNI-blocklist-hit patterns against its own recent baseline, and
quarantines a flagged IP in the kernel. Turn it on from the `/ai-ids`
screen, or in YAML: `ai_ids: {enabled: true}` (see
[docs/CONFIG_SCHEMA.md](docs/CONFIG_SCHEMA.md#ai_ids)).

```bash
sudo systemctl enable --now fr-ai-ids

# Currently quarantined hosts
firewall-cli ids-status
```

---

## How FR_OS compares

pfSense and OPNsense are mature, FreeBSD-based projects with a much larger driver/hardware compatibility surface and a long production track record — that maturity isn't something a new project should claim to match. Where FR_OS is genuinely different:

| | FR_OS | pfSense / OPNsense (stock) |
|---|---|---|
| Kernel packet fast path | Native Linux XDP/eBPF, in-kernel TLS SNI matching | FreeBSD `pf`, no XDP/eBPF equivalent |
| Zero Trust network access | Built in (`/ztna/login` + kernel-enforced sessions) | Needs a third-party package or external IdP integration |
| AI-based anomaly detection / auto-quarantine | Built in, 100% local, no cloud/telemetry | Not built in |
| Post-quantum key exchange (mgmt plane) | Built in (`X25519MLKEM768`, `mlkem768x25519-sha256`), with disclosed classical fallback | Not available |
| Category DNS filtering + DGA detection | Built in (verified category lists, allowlist, DNS enforcement, DGA/NXDOMAIN signals into the IDS) | pfBlockerNG / Zenarmor add-ons |
| IoT device discovery / isolation | Built in (vendor + mDNS + hostname classification, MAC-keyed firewall isolation) | Manual (aliases, VLANs) or third-party packages |
| Application identification / blocking | Built in (DNS + SNI names, 41-app catalog, one-click resolver/XDP blocking) | Zenarmor / Suricata add-ons |
| Time-based rules | Built in (per-rule schedules, per-device MAC matching, DST-safe) | Built in (schedules) |
| Multiple admins / read-only role / audit log | Built in (admin + viewer roles, per-request enforcement, audit log) | Built in (users, groups, privileges) |
| Prometheus metrics | Native `/metrics`, zero extra packages | Needs a community package (`node_exporter` et al.) |
| Live image size | ~328 MB hybrid BIOS+UEFI | Multi-hundred-MB to several GB installer images |
| Config model | One YAML file, plain-text diffable, versioned rollback | XML config, less diff-friendly |

None of this makes FR_OS a drop-in pfSense replacement today — driver coverage, community size, and years of edge-case hardening are real gaps this project doesn't pretend to have closed. What it does offer, out of the box and without extra packages, is a genuinely modern Linux kernel data plane plus security features (ZTNA, local AI IDS/IPS, PQC) that are either unavailable or bolt-on extras elsewhere.

---

<details>
<summary><h2 style="display:inline">Phase-by-phase status (click to expand)</h2></summary>

**Phase 1 (firewall engine core)** — done. The `frfw` Python package
generates and loads an nftables ruleset from YAML config; this is the
single "config → firewall rules" translation logic shared by the CLI,
the systemd integration and the webUI.

**Phase 2 (system integration)** — done. Canonical config location
(`/etc/fr_os/config.yaml`), automatic apply on boot via systemd, ruleset
backup/rollback, network interface auto-detection and a WAN/LAN/OPT
assignment helper, plus a privileged apply-helper reached over a Unix
socket.

**Phase 3 (webUI)** — done. FastAPI + server-rendered UI (dashboard,
interfaces, rules, NAT, DHCP), local admin login, HTTPS with a
self-signed certificate, static interface addressing (`frfw.ifaddr`) and
DHCP service via Kea (`frfw.kea`).

**AI IDS/IPS (mock)** — superseded by phase 11 below. Originally shipped
as groundwork for phase 4's real traffic analysis, showing entirely
fabricated data — see [ARCHITECTURE.md](ARCHITECTURE.md#ai-idsips-mock)
for that earlier design.

**Phase 4 (XDP/eBPF fast path)** — the kernel program, the Python
orchestrator and the webUI screen are done; 10/40GbE performance
benchmarking is still open. A kernel-space TLS ClientHello SNI filter
(`bpf/xdp_sni_filter.c`) with a `frfw.xdp` control-plane counterpart.

**Phase 5 (automated installer)** — done, verified with a real
end-to-end build. A live-build-based hybrid live ISO with the full frfw
stack preinstalled, and a non-interactive first boot (automatic admin
password generation).

**Phase 6 (update mechanism)** — done. Version checking, a dedicated
privileged `fr-update-helper` daemon (apply/rollback), CLI and webUI
front-ends.

**Phase 7 (Zero Trust network access, ZTNA)** — done. A fully local
identity-aware login gate (`/ztna/login`) for zones protected by a
`require_ztna` rule flag; the data plane runs as a kernel-native
nftables named set with a native timeout, the control plane goes
through the privileged helper.

**Phase 8 (hybrid post-quantum key exchange)** — done, tested without a
real PQC build. The webUI's HTTPS and (if installed) the host's sshd
use a hybrid classical + post-quantum key exchange on the management
layer.

**Phase 9 (local DNS/XDP ad-blocker)** — done. Downloads and dedupes
hosts-format blocklists, serves them from a dedicated, 100% local
dnsmasq instance, with an optional "critical" subset pushed into the
existing XDP LPM trie.

**Phase 10 (in-memory + kernel-level brute-force protection)** — done.
`/login` and `/ztna/login` are protected by a thread-safe, in-memory
counter (5 failed attempts / 5 minutes) and a kernel-native nftables
`bruteforce_jail` set with a native timeout (1 hour by default) — zero
userspace overhead under a flood, no Redis/fail2ban required.

**Phase 11 (real-time, kernel-assisted AI IDS/IPS)** — done. Replaces
the phase 3 mock engine with a real, ultra-lightweight, pure-stdlib
anomaly detector (no scikit-learn/pandas/numpy): a separate `fr-ai-ids`
daemon scores each source IP's connection-rate, destination-diversity
and XDP SNI-blocklist-hit patterns against its own recent baseline, and
quarantines a flagged IP in the kernel (`ids_quarantine` nftables set)
via the privileged apply-helper.

**Phase 12 (lightweight native Prometheus metrics exporter)** — done. A
public, unauthenticated `GET /metrics` endpoint in Prometheus text
exposition format, zero external dependencies (no `prometheus_client`,
no `psutil`) — software metrics (interfaces, XDP, ad-block, ZTNA,
brute-force, AI IDS/IPS) read from state this project already computes,
hardware metrics (CPU/RAM/storage) parsed directly from `/proc`, `/sys`
and `os.statvfs`, with RAM module identity (the one fact that needs
root, via `dmidecode`) routed through the privileged apply-helper.

**Phase 13 (hybrid BIOS + UEFI boot support)** — done. The live ISO now
boots on modern UEFI-only hardware (Intel NUCs, HP ProDesk/EliteDesk
minis, Lenovo Tiny clients) as well as legacy BIOS, from the same
`dd`/Rufus-flashed USB drive, via a new post-processing step
(`installer/make-hybrid-uefi-iso.sh`) that adds a real GRUB 2 EFI boot
path and GPT EFI System Partition on top of the existing, unchanged
isolinux/BIOS path — under 1 MB of size overhead on the ~327 MB image.

**Phase 14 (IoT device discovery and isolation)** — done. Inventory from
DHCP leases, ARP and mDNS; transparent point-based classification with
stated reasons; MAC-keyed isolation (`internet_only` or `block`) in the
router's own nftables ruleset, decided by an unprivileged scanner and
enforced through the privileged helper.

**Phase 15 (categorized DNS filtering and DNS threat signals)** — done.
Per-category blocklists with verified presets and an allowlist, optional
LAN DNS serving and enforcement (port-53 redirect, DoT reject, Firefox
DoH canary), and NXDOMAIN / DGA-like / malware-lookup signals from the
resolver's query log feeding the AI IDS.

**Phase 16 (coarse application identification)** — done. A 41-app
catalog generated from v2fly/domain-list-community, an unprivileged
`fr-appid` daemon attributing resolver lookups and (new) XDP pass events
to apps per client, and one-click app blocking in the resolver and
optionally the XDP blocklist. Also corrected phase 4's advice to attach
XDP on the WAN side (it must be the LAN side), proven with a
three-namespace real-packet test.

**Phase 17 (time-based rules)** — done. Per-rule schedules in a
configurable time zone, rendered for the kernel's actual clocks (UTC
`meta hour`, `sys_tz`-shifted `meta day`), an hourly DST refresh that
never applies unapplied edits, optional cutting of open connections, and
MAC-based rule matching; verified against the real kernel in five time
zones.

**Phase 18 (multiple webUI accounts with roles)** — done. Admin and
read-only viewer accounts, one central enforcement point proven against
every registered route, sessions that follow account changes, and an
audit log of every change and login.

Full rationale for every phase: [ARCHITECTURE.md](ARCHITECTURE.md).

</details>

---

## License

[Apache License 2.0](LICENSE).

---

*Built for the homelab community. Contributions — especially real 10/40GbE hardware benchmarking and UEFI Secure Boot support — are welcome; see ROADMAP.md's open items.*
