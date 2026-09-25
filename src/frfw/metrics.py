"""`GET /metrics`'s data layer: a native Prometheus text-exposition-format
generator (phase 12 -- see ARCHITECTURE.md for why this isn't "phase
11": that number was already used by the AI IDS/IPS work completed
earlier).

Zero external dependencies by design, per the request: no
`prometheus_client`, no `psutil`. Every software metric is read from
data this project already computes for its own webUI screens
(`frfw.xdp`, `frfw.adblock`, and three privileged-helper status
commands mirroring `frfw.ids_quarantine`'s own "ids_quarantine_status"
pattern); every hardware metric is read directly from `/proc`, `/sys`,
or `os.statvfs` -- no library, just stdlib file I/O and string parsing,
exactly the same "shell out to /read the kernel's own exposed state"
philosophy every other privileged-adjacent module in this project
already follows (frfw.conntrack's `/proc/net/nf_conntrack` parsing is
the closest precedent).

The one hardware fact that genuinely needs root -- RAM module part
number/speed, which only `dmidecode` (reading the SMBIOS/DMI tables)
can supply -- goes through the privileged apply-helper's "hw_ram_info"
command (see frfw.hwinfo), the identical privilege-separation pattern
every other root-only kernel/hardware read in this project already
uses. Everything else here runs unprivileged, in the webUI process,
because it only ever touches world-readable files or `os.statvfs`
(confirmed by hand: `/sys/class/net/*/statistics/*` is `-r--r--r--`,
unlike `/proc/net/nf_conntrack`'s `-r--r-----`).

Per-metric-family error isolation: `generate_metrics_text()` gathers
each family independently and discards (not fails) any one that raises
-- a single misbehaving subsystem (a missing `/proc` file on an
unusual kernel, a transient apply-helper hiccup, `dmidecode` not
installed) must never turn the whole `/metrics` response into a 500. A
broad `except Exception` is used deliberately for that one boundary
(mirroring the identical, already-documented rationale in
`frfw.webui.config_store`/`tests/webui/conftest.py`'s own
catch-all-and-report call sites) -- the alternative, enumerating every
possible exception type across a dozen unrelated subsystems (`OSError`,
`ValueError`, `HelperError`, `XdpError`, `HwInfoError`, ...) here would
be strictly more fragile, not less: a future subsystem raising a new
exception type would silently break the whole endpoint instead of just
losing one metric family.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

from frfw import __codename__, __version__, paths
from frfw import xdp as xdp_mod
from frfw.adblock import category_counts, count_blocked_domains
from frfw.appid import load_catalog
from frfw.appid.daemon import load_usage
from frfw.tlsfp.daemon import load_state as load_tlsfp_state
from frfw.config.schema import Config

_PROC_STAT_PATH = Path("/proc/stat")
_PROC_MEMINFO_PATH = Path("/proc/meminfo")
_PROC_CPUINFO_PATH = Path("/proc/cpuinfo")
_PROC_MOUNTS_PATH = Path("/proc/mounts")
_SYS_NET_DIR = Path("/sys/class/net")
_CPUFREQ_CUR_PATH = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")

#: How long to wait between the two /proc/stat samples
#: `_read_cpu_usage_ratio` takes. A Prometheus scrape is a low-frequency
#: (typically 15-30s interval), latency-tolerant operation, so a 100ms
#: blocking sample is a simpler and more robust choice than maintaining
#: shared, thread-safety-sensitive state between requests just to avoid
#: it -- there is no long-lived exporter *process* here to keep a
#: previous sample in (the webUI serves this from the same process as
#: every other page, not a dedicated node_exporter-style daemon).
_CPU_SAMPLE_INTERVAL_SECONDS = 0.1

#: Filesystem types that are never a real, physical storage device --
#: skipped when enumerating mounts for fros_hw_storage_*, the same way
#: `df` filters them out of its default output.
_VIRTUAL_FSTYPES = frozenset(
    {
        "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2",
        "pstore", "bpf", "tracefs", "debugfs", "mqueue", "hugetlbfs",
        "securityfs", "autofs", "configfs", "fusectl", "overlay", "squashfs",
    }
)


# --- Prometheus text exposition format -----------------------------------


@dataclass(frozen=True)
class _Sample:
    value: float | int
    labels: dict[str, str]


@dataclass
class MetricFamily:
    """One `# HELP`/`# TYPE` block plus its samples -- the Prometheus
    text exposition format's unit of grouping. `metric_type` is
    "counter" or "gauge" (the only two this project emits)."""

    name: str
    help_text: str
    metric_type: str
    samples: list[_Sample] = field(default_factory=list)

    def add(self, value: float | int, **labels: str) -> None:
        self.samples.append(_Sample(value=value, labels=labels))


def render(families: list[MetricFamily]) -> str:
    """Render `families` as Prometheus text exposition format (version
    0.0.4) -- a `# HELP` line, a `# TYPE` line, and zero or more sample
    lines per family, in that order, matching the format Prometheus
    itself documents and every scraper expects."""
    lines: list[str] = []
    for fam in families:
        lines.append(f"# HELP {fam.name} {fam.help_text}")
        lines.append(f"# TYPE {fam.name} {fam.metric_type}")
        for sample in fam.samples:
            lines.append(f"{fam.name}{_format_labels(sample.labels)} {_format_value(sample.value)}")
    return "\n".join(lines) + "\n"


def _format_labels(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    parts = ",".join(f'{key}="{_escape_label_value(value)}"' for key, value in labels.items())
    return f"{{{parts}}}"


def _escape_label_value(value: str) -> str:
    # Per the exposition format spec: backslash and double-quote must be
    # escaped, and a literal newline must become a two-character "\n".
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _format_value(value: float | int) -> str:
    if isinstance(value, bool):  # bool is an int subclass -- check first
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    return repr(float(value))


# --- software metrics: network interfaces, XDP, ad-block, ZTNA, brute-force, AI IDS ---


def _read_interface_bytes_family(config: Config) -> MetricFamily:
    fam = MetricFamily(
        "fros_interface_bytes_total",
        "Total bytes transferred per network interface and direction.",
        "counter",
    )
    for iface in config.interfaces.values():
        for direction, stat_file in (("rx", "rx_bytes"), ("tx", "tx_bytes")):
            path = _SYS_NET_DIR / iface.device / "statistics" / stat_file
            try:
                value = int(path.read_text().strip())
            except (OSError, ValueError):
                continue
            fam.add(value, device=iface.device, direction=direction)
    return fam


def _read_xdp_status_family(config: Config) -> MetricFamily:
    fam = MetricFamily(
        "fros_xdp_status",
        "XDP TLS SNI filter attach status per interface (0=disabled/not attached, 1=native, 2=generic).",
        "gauge",
    )
    if not config.xdp_sni_filter.enabled or not config.xdp_sni_filter.interfaces:
        return fam
    attached = xdp_mod.get_attached()
    mode_values = {"xdpdrv": 1, "xdpgeneric": 2}
    for name in config.xdp_sni_filter.interfaces:
        device = config.interfaces[name].device
        fam.add(mode_values.get(attached.get(device), 0), device=device)
    return fam


def _read_xdp_blocked_family() -> MetricFamily:
    fam = MetricFamily(
        "fros_xdp_blocked_connections_total",
        "Total connections dropped by the XDP TLS SNI filter for matching the blocklist.",
        "counter",
    )
    stats = xdp_mod.get_stats()
    fam.add(stats.get("drop_match", 0))
    return fam


def _read_adblock_family(hosts_path: Path) -> MetricFamily:
    fam = MetricFamily(
        "fros_adblock_total_domains",
        "Number of unique domains currently in the ad-block hosts list.",
        "gauge",
    )
    fam.add(count_blocked_domains(hosts_path))
    return fam


def _read_ztna_family(helper) -> MetricFamily:
    fam = MetricFamily(
        "fros_ztna_active_sessions",
        "Number of currently authorized ZTNA client sessions.",
        "gauge",
    )
    status = helper.ztna_sessions_status()
    if status.get("ok"):
        fam.add(status.get("count", 0))
    return fam


def _read_bruteforce_family(helper) -> MetricFamily:
    fam = MetricFamily(
        "fros_bruteforce_banned_ips",
        "Number of source IPs currently banned in the brute-force jail.",
        "gauge",
    )
    status = helper.bruteforce_status()
    if status.get("ok"):
        fam.add(status.get("count", 0))
    return fam


def _read_ai_ids_family(helper) -> MetricFamily:
    fam = MetricFamily(
        "fros_ai_ids_quarantined_hosts",
        "Number of hosts currently quarantined by the AI IDS/IPS engine.",
        "gauge",
    )
    status = helper.ids_quarantine_status()
    if status.get("ok"):
        fam.add(status.get("count", 0))
    return fam


def _read_dns_category_family(config: Config, hosts_path: Path, category_dir: Path) -> MetricFamily:
    """Phase 15: domains loaded per blocklist category (the base list is
    reported as category="ads"). Unprivileged file reads only."""
    fam = MetricFamily(
        "fros_dns_blocked_domains",
        "Domains currently loaded into the DNS resolver, per blocklist category.",
        "gauge",
    )
    counts = category_counts(
        list(config.adblocker.categories), hosts_path=hosts_path, category_dir=category_dir
    )
    for category, n in counts.items():
        fam.add(n, category=category)
    return fam


def _read_iot_families(config: Config, helper, inventory_path: Path) -> list[MetricFamily]:
    """Phase 14. Device counts per category come from the scanner's
    display-only inventory file (unprivileged read); the isolated count
    is the live kernel set, via the helper, like every other enforcement
    count on this endpoint. Nothing is emitted while IoT discovery is off."""
    if not config.iot.enabled:
        return []
    devices = MetricFamily(
        "fros_iot_devices",
        "Devices found by the last IoT scan, by classification.",
        "gauge",
    )
    counts = {"iot": 0, "general": 0, "unknown": 0}
    try:
        inventory = json.loads(inventory_path.read_text())
        for device in inventory.get("devices", []):
            category = device.get("category")
            if category in counts:
                counts[category] += 1
    except (OSError, ValueError, AttributeError):
        pass
    for category, n in counts.items():
        devices.add(n, category=category)

    isolated = MetricFamily(
        "fros_iot_isolated_devices",
        "Devices currently isolated by MAC address in the kernel iot_isolated set.",
        "gauge",
    )
    status = helper.iot_isolation_status()
    if status.get("ok"):
        isolated.add(status.get("count", 0))
    return [devices, isolated]


def _read_appid_families(config: Config, usage_path: Path) -> list[MetricFamily]:
    """Phase 16, from fr-appid's display-only usage summary (unprivileged
    read). Only apps seen in the last 24 hours are emitted, so the series
    count stays proportional to what the network actually uses. Nothing
    is emitted while app identification is off."""
    if not config.app_control.enabled:
        return []
    catalog = load_catalog().by_id()
    active = MetricFamily(
        "fros_app_active_clients",
        "Clients that used the app in the last 15 minutes (DNS lookups / TLS SNIs).",
        "gauge",
    )
    hits = MetricFamily(
        "fros_app_hits_24h",
        "DNS lookups and TLS connections attributed to the app in the last 24 hours.",
        "gauge",
    )
    for app_id, stats in sorted(load_usage(usage_path)["apps"].items()):
        app = catalog.get(app_id)
        category = app.category if app else "unknown"
        active.add(stats.get("active_clients", 0), app=app_id, category=category)
        hits.add(stats.get("hits_24h", 0), app=app_id, category=category)
    blocked = MetricFamily(
        "fros_app_blocked",
        "Apps currently on the blocked list (1 per blocked app).",
        "gauge",
    )
    for app_id in config.app_control.blocked_apps:
        blocked.add(1, app=app_id)
    return [active, hits, blocked]


def _read_tlsfp_families(config: Config, state_path: Path, now: float | None = None) -> list[MetricFamily]:
    """Phase 19, from fr-tls-fp's display-only state file. Nothing is
    emitted while fingerprinting is off."""
    if not config.tls_fingerprint.enabled:
        return []
    state = load_tlsfp_state(state_path)
    clients = state.get("clients") or {}
    distinct = {ja4 for fps in clients.values() for ja4 in fps}
    now = now if now is not None else time.time()
    counts = {"new_fingerprint": 0, "blocklist": 0}
    for event in state.get("events") or []:
        if event.get("type") in counts and now - float(event.get("ts", 0)) <= 24 * 3600:
            counts[event["type"]] += 1
    fam_clients = MetricFamily("fros_tls_fingerprinted_clients", "Clients with at least one TLS fingerprint recorded.", "gauge")
    fam_clients.add(len(clients))
    fam_distinct = MetricFamily("fros_tls_distinct_fingerprints", "Distinct JA4 fingerprints recorded across all clients.", "gauge")
    fam_distinct.add(len(distinct))
    fam_events = MetricFamily("fros_tls_fingerprint_events_24h", "TLS fingerprint events in the last 24 hours, by type.", "gauge")
    for event_type, n in counts.items():
        fam_events.add(n, type=event_type)
    return [fam_clients, fam_distinct, fam_events]


def _read_info_families(config: Config | None) -> list[MetricFamily]:
    """Phase 20: which router this is, for multi-site dashboards. Always
    emitted -- with an invalid config the site falls back to "unknown" and
    fros_config_valid says why the other families are missing."""
    info = MetricFamily(
        "fros_info", "Constant 1; labels identify this router (site name, hostname, version, release codename).", "gauge"
    )
    if config is None:
        info.add(1, site_name="unknown", hostname="unknown", version=__version__,
                 codename=__codename__ or "")
    else:
        info.add(1, site_name=config.metrics.site or config.hostname, hostname=config.hostname,
                 version=__version__, codename=__codename__ or "")
    valid = MetricFamily(
        "fros_config_valid", "1 if the on-disk config.yaml passes validation, else 0.", "gauge"
    )
    valid.add(1 if config is not None else 0)
    return [info, valid]


def hash_metrics_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_metrics_token() -> tuple[str, str]:
    """(token, its SHA-256 digest). 32 random bytes: long enough that
    guessing is hopeless, so no rate limiting is needed on /metrics."""
    token = secrets.token_urlsafe(32)
    return token, hash_metrics_token(token)


def metrics_token_ok(raw_config: dict, authorization: str | None) -> bool:
    """Whether a /metrics request may be answered. Reads the digest from
    the *raw* config on purpose: an otherwise-invalid config.yaml must not
    silently turn a protected endpoint public. A present but malformed
    digest fails closed."""
    section = raw_config.get("metrics") if isinstance(raw_config, dict) else None
    expected = section.get("token_sha256") if isinstance(section, dict) else None
    if expected is None:
        return True
    if not isinstance(expected, str) or len(expected) != 64:
        return False
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        return False
    return hmac.compare_digest(hash_metrics_token(token.strip()), expected.lower())


# --- hardware metrics: CPU, RAM, storage -----------------------------------


def _read_cpu_model() -> str | None:
    try:
        text = _PROC_CPUINFO_PATH.read_text()
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return None


def _read_cpu_mhz() -> float | None:
    # Prefer the live scaling frequency (reflects actual current clock
    # under CPU frequency scaling); not every kernel/VM exposes it (this
    # project's own dev sandbox doesn't), so fall back to /proc/cpuinfo's
    # static "cpu MHz" field, which is always present on x86.
    try:
        khz = int(_CPUFREQ_CUR_PATH.read_text().strip())
        return khz / 1000
    except (OSError, ValueError):
        pass
    try:
        text = _PROC_CPUINFO_PATH.read_text()
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("cpu MHz"):
            try:
                return float(line.split(":", 1)[1].strip())
            except ValueError:
                return None
    return None


def _read_proc_stat_cpu_totals() -> tuple[int, int] | None:
    """(busy_jiffies, total_jiffies) from /proc/stat's aggregate "cpu"
    line (the sum across all cores) -- an intentional simplification to
    one system-wide utilization figure, not per-core breakdown, matching
    the single (unlabeled) `fros_hw_cpu_usage_ratio` gauge requested."""
    try:
        text = _PROC_STAT_PATH.read_text()
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("cpu "):
            values = [int(v) for v in line.split()[1:]]
            idle = values[3] + (values[4] if len(values) > 4 else 0)  # idle + iowait
            total = sum(values)
            return total - idle, total
    return None


def _read_cpu_usage_ratio(sample_interval: float = _CPU_SAMPLE_INTERVAL_SECONDS) -> float | None:
    first = _read_proc_stat_cpu_totals()
    if first is None:
        return None
    time.sleep(sample_interval)
    second = _read_proc_stat_cpu_totals()
    if second is None:
        return None
    total_delta = second[1] - first[1]
    if total_delta <= 0:
        return 0.0
    busy_delta = second[0] - first[0]
    return max(0.0, min(1.0, busy_delta / total_delta))


def _read_cpu_families() -> list[MetricFamily]:
    info_fam = MetricFamily(
        "fros_hw_cpu_info", "CPU model identification (value is always 1).", "gauge"
    )
    model = _read_cpu_model()
    if model:
        info_fam.add(1, model=model)

    usage_fam = MetricFamily(
        "fros_hw_cpu_usage_ratio",
        "Current CPU utilization ratio (0-1), sampled over a short interval.",
        "gauge",
    )
    ratio = _read_cpu_usage_ratio()
    if ratio is not None:
        usage_fam.add(round(ratio, 4))

    mhz_fam = MetricFamily("fros_hw_cpu_mhz", "Current CPU clock speed in MHz.", "gauge")
    mhz = _read_cpu_mhz()
    if mhz is not None:
        mhz_fam.add(round(mhz, 1))

    return [info_fam, usage_fam, mhz_fam]


def _read_ram_totals() -> tuple[int, int] | None:
    try:
        text = _PROC_MEMINFO_PATH.read_text()
    except OSError:
        return None
    values: dict[str, int] = {}
    for line in text.splitlines():
        key, sep, rest = line.partition(":")
        if not sep:
            continue
        rest = rest.strip()
        if not rest.endswith("kB"):
            continue
        try:
            values[key.strip()] = int(rest[:-2].strip()) * 1024
        except ValueError:
            continue
    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    if total is None or available is None:
        return None
    return max(0, total - available), total


def _read_ram_families(helper) -> list[MetricFamily]:
    info_fam = MetricFamily(
        "fros_hw_ram_info",
        "Installed RAM module identification (value is always 1); requires root via dmidecode.",
        "gauge",
    )
    ram_status = helper.hw_ram_info()
    if ram_status.get("ok"):
        for module in ram_status.get("modules", []):
            info_fam.add(1, model=module.get("part_number", "unknown"), speed_mhz=str(module.get("speed_mhz", 0)))

    usage_fam = MetricFamily(
        "fros_hw_ram_usage_bytes", "Currently used RAM in bytes (MemTotal - MemAvailable).", "gauge"
    )
    total_fam = MetricFamily("fros_hw_ram_total_bytes", "Total installed RAM in bytes.", "gauge")
    totals = _read_ram_totals()
    if totals is not None:
        used, total = totals
        usage_fam.add(used)
        total_fam.add(total)

    return [info_fam, usage_fam, total_fam]


def _read_storage_mounts() -> list[tuple[str, str]]:
    """(mount_point, device) pairs for real, physical block-device-backed
    filesystems -- filters out virtual filesystems the same way `df`
    does by default. Each mount point is reported once even if bind-
    mounted multiple times."""
    try:
        text = _PROC_MOUNTS_PATH.read_text()
    except OSError:
        return []
    mounts: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        device, mount_point, fstype = parts[0], parts[1], parts[2]
        if fstype in _VIRTUAL_FSTYPES or not device.startswith("/dev/") or mount_point in seen:
            continue
        seen.add(mount_point)
        mounts.append((mount_point, device))
    return mounts


def _read_storage_families() -> list[MetricFamily]:
    info_fam = MetricFamily(
        "fros_hw_storage_info", "Mounted storage device identification (value is always 1).", "gauge"
    )
    usage_fam = MetricFamily(
        "fros_hw_storage_usage_bytes", "Used storage space in bytes for this mount.", "gauge"
    )
    total_fam = MetricFamily(
        "fros_hw_storage_total_bytes", "Total storage space in bytes for this mount.", "gauge"
    )

    for mount_point, device in _read_storage_mounts():
        info_fam.add(1, mount=mount_point, device_name=device)
        try:
            st = os.statvfs(mount_point)
        except OSError:
            continue
        usage_fam.add(st.f_frsize * (st.f_blocks - st.f_bfree), mount=mount_point)
        total_fam.add(st.f_frsize * st.f_blocks, mount=mount_point)

    return [info_fam, usage_fam, total_fam]


# --- top-level entry point ---------------------------------------------------


def generate_metrics_text(
    config: Config | None,
    helper,
    *,
    adblock_hosts_path: Path,
    iot_inventory_path: Path = paths.IOT_INVENTORY_PATH,
    adblock_category_dir: Path = paths.ADBLOCK_CATEGORY_DIR,
    appid_usage_path: Path = paths.APPID_USAGE_PATH,
    tlsfp_state_path: Path = paths.TLSFP_STATE_PATH,
) -> str:
    """The `GET /metrics` route's entire job: gather every metric family
    and render them as one Prometheus text-exposition-format response.

    `config` may be `None` (an on-disk config that currently fails
    validation) -- metrics that need it (interface bytes, XDP status)
    are skipped in that case, everything else (hardware metrics, and the
    helper-backed status counts, none of which depend on the *current*
    config being valid) is still reported. See this module's own
    docstring for why each family is gathered inside its own try/except.
    """
    families: list[MetricFamily] = []

    def collect(builder) -> None:
        try:
            result = builder()
        except Exception:  # noqa: BLE001 -- see module docstring
            return
        families.extend(result if isinstance(result, list) else [result])

    collect(lambda: _read_info_families(config))
    if config is not None:
        collect(lambda: _read_interface_bytes_family(config))
        collect(lambda: _read_xdp_status_family(config))
        collect(lambda: _read_iot_families(config, helper, iot_inventory_path))
        collect(lambda: _read_dns_category_family(config, adblock_hosts_path, adblock_category_dir))
        collect(lambda: _read_appid_families(config, appid_usage_path))
        collect(lambda: _read_tlsfp_families(config, tlsfp_state_path))

    collect(_read_xdp_blocked_family)
    collect(lambda: _read_adblock_family(adblock_hosts_path))
    collect(lambda: _read_ztna_family(helper))
    collect(lambda: _read_bruteforce_family(helper))
    collect(lambda: _read_ai_ids_family(helper))
    collect(_read_cpu_families)
    collect(lambda: _read_ram_families(helper))
    collect(_read_storage_families)

    return render(families)
