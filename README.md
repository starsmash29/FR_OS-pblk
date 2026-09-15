# FR_OS

A custom, Linux-based firewall/router operating system for homelab use,
with a pfSense-like user experience — but with broader NIC support and a
native Linux XDP/eBPF fast path for 10G/40GbE traffic.

Design decisions and the phase-by-phase development plan:

- [ARCHITECTURE.md](ARCHITECTURE.md) — technical decisions and rationale
- [ROADMAP.md](ROADMAP.md) — phase-by-phase plan and acceptance criteria
- [docs/CONFIG_SCHEMA.md](docs/CONFIG_SCHEMA.md) — full YAML config schema reference

## Status

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

Full rationale for every phase: [ARCHITECTURE.md](ARCHITECTURE.md).

## Quick start

Requires: Debian (or another Linux distro) with the `nftables` package,
Python 3.11+.

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

Run the tests (also runs a real `nft -c` syntax check if the `nft`
binary is available):

```bash
python3 -m pytest
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
sudo systemctl enable --now fr-webui
```

From a browser: `https://<router-ip>/` — the browser will warn about
the self-signed certificate until you replace it with a real one
(`/etc/fr_os/webui/`). Dev/test run without root/systemd:

```bash
fr-webui --host 127.0.0.1 --port 8443 --config examples/config.yaml
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

## License

[Apache License 2.0](LICENSE).
