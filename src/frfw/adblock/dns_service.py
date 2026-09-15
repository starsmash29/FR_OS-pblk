"""Generates and manages the dedicated dnsmasq instance
(`fr-adblock-dns.service`) that serves `frfw.adblock`'s deduped
hosts-format blocklist to LAN clients.

Deliberately a *dedicated* frfw-owned instance, not a drop-in under
Debian's `/etc/dnsmasq.d/` for the system's default `dnsmasq.service`:
that directory is only auto-loaded if a `conf-dir=` line happens to be
uncommented in `/etc/dnsmasq.conf`, which is not guaranteed on a stock
install, and a homelab box might already run the system dnsmasq for
something unrelated. Instead this writes one complete, self-contained
config (`frfw.paths.ADBLOCK_DNSMASQ_CONF_PATH`) and controls its own
service by name (`frfw.paths.ADBLOCK_DNS_SERVICE_NAME`) -- the exact
same "one complete generated config, one dedicated systemd service"
shape `frfw.kea` already uses for Kea, never touching whatever else may
or may not already be configured on the host.

**Known scope limitation, stated plainly**: this module makes the
resolver exist and serve the blocklist -- it does not yet also point
LAN DHCP clients at it. `frfw.kea`'s `DhcpPool.dns_servers` is left
exactly as the admin configured it; wiring Kea to hand out the router's
own IP as the DNS server (so clients actually query this resolver) is a
separate, not-yet-automated integration step -- see ARCHITECTURE.md's
phase 9 "Nyitott pontok" for the full reasoning on why that wasn't done
silently as a side effect here.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from frfw import paths
from frfw.adblock import count_blocked_domains
from frfw.config.schema import Config

#: Used when no DHCP pool configures its own dns_servers (nothing else
#: in the schema currently expresses "upstream resolvers" -- reusing
#: DhcpPool.dns_servers when available keeps this module needing no new
#: config surface beyond `adblocker` itself; this is only the fallback).
_DEFAULT_UPSTREAM_SERVERS = ("1.1.1.1", "9.9.9.9")

#: Must stay under this module's own MAX_SNI_LEN-equivalent bound so a
#: critical-subset domain handed to frfw.xdp.sync_blocklist can never be
#: rejected by it -- duplicated from frfw.xdp.MAX_SNI_LEN the same way
#: frfw.config.loader's own copy is (see that module's comment): this
#: side mirrors a constant the C program defines, not something to
#: import across modules that otherwise have no reason to depend on
#: each other.
_MAX_SNI_LEN = 32


class DnsServiceError(Exception):
    pass


def _upstream_servers(config: Config) -> list[str]:
    servers: list[str] = []
    for pool in config.dhcp.zones.values():
        for server in pool.dns_servers:
            if server not in servers:
                servers.append(server)
    return servers or list(_DEFAULT_UPSTREAM_SERVERS)


def _listen_devices(config: Config) -> list[str]:
    """`lo` (so the router itself benefits) plus every interface backing
    a DHCP zone (config.dhcp.zones' keys are zone names, not interface
    names -- multiple interfaces can share a zone, so this maps through
    every interface whose zone has a pool, not just one)."""
    devices = ["lo"]
    for iface in config.interfaces.values():
        if iface.zone in config.dhcp.zones and iface.device not in devices:
            devices.append(iface.device)
    return devices


_DNSMASQ_CONF_TEMPLATE = """\
# Managed by FR_OS (frfw.adblock.dns_service) -- regenerated on every
# `apply`, do not edit by hand. A dedicated, frfw-owned dnsmasq
# instance (fr-adblock-dns.service) -- never the system's own
# dnsmasq.service/dnsmasq.conf, which this never touches.
port=53
no-resolv
no-hosts
addn-hosts={hosts_path}
{listen_lines}
bind-interfaces
{server_lines}
user=nobody
group=nogroup
"""


def render_dnsmasq_config(config: Config, *, hosts_path: Path = paths.ADBLOCK_HOSTS_PATH) -> str:
    listen_lines = "\n".join(f"interface={d}" for d in _listen_devices(config))
    server_lines = "\n".join(f"server={s}" for s in _upstream_servers(config))
    return _DNSMASQ_CONF_TEMPLATE.format(
        hosts_path=hosts_path, listen_lines=listen_lines, server_lines=server_lines
    )


def _ensure_hosts_placeholder(hosts_path: Path) -> None:
    """dnsmasq's `addn-hosts=` fails the whole config if the file
    doesn't exist at all -- create an empty (header-only) one if
    `adblocker` is enabled before it's ever been refreshed, so enabling
    the feature never itself breaks the resolver's startup. Never
    overwrites existing content -- that's frfw.adblock.refresh's job."""
    if hosts_path.exists():
        return
    hosts_path.parent.mkdir(parents=True, exist_ok=True)
    hosts_path.write_text("# (empty -- run `firewall-cli adblock-refresh` to populate)\n")


def _require_root() -> None:
    if os.geteuid() != 0:
        raise DnsServiceError("Applying the ad-block DNS resolver requires root privileges.")


def _test_dnsmasq_config(conf_path: Path, *, dnsmasq_binary: str = "dnsmasq") -> None:
    try:
        proc = subprocess.run(
            [dnsmasq_binary, "--test", f"--conf-file={conf_path}"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise DnsServiceError(f"{dnsmasq_binary!r} binary not found; install dnsmasq") from exc
    if proc.returncode != 0:
        raise DnsServiceError(proc.stderr.strip() or proc.stdout.strip() or "dnsmasq --test failed")


def _restart_dns_service() -> None:
    try:
        proc = subprocess.run(
            ["systemctl", "restart", paths.ADBLOCK_DNS_SERVICE_NAME],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise DnsServiceError("'systemctl' not found") from exc
    if proc.returncode != 0:
        raise DnsServiceError(
            proc.stderr.strip() or f"failed to restart {paths.ADBLOCK_DNS_SERVICE_NAME}"
        )


def _stop_dns_service() -> None:
    try:
        proc = subprocess.run(
            ["systemctl", "stop", paths.ADBLOCK_DNS_SERVICE_NAME], capture_output=True, text=True
        )
    except FileNotFoundError as exc:
        raise DnsServiceError("'systemctl' not found") from exc
    if proc.returncode != 0:
        raise DnsServiceError(
            proc.stderr.strip() or f"failed to stop {paths.ADBLOCK_DNS_SERVICE_NAME}"
        )


@dataclass(frozen=True)
class DnsSyncResult:
    applied: bool
    message: str


def sync_dns_resolver(
    config: Config,
    *,
    dry_run: bool = False,
    hosts_path: Path = paths.ADBLOCK_HOSTS_PATH,
    conf_path: Path = paths.ADBLOCK_DNSMASQ_CONF_PATH,
    dnsmasq_binary: str = "dnsmasq",
) -> DnsSyncResult:
    """Reconcile the dedicated dnsmasq instance with `config.adblocker`.
    Called from `frfw.provision.apply_all`. Never fetches anything from
    the network -- that's `frfw.adblock.refresh`'s job, on its own
    schedule (see this package's `__init__.py` docstring); this only
    (re)writes dnsmasq's config to match current settings and the
    already-on-disk blocklist, validating with `dnsmasq --test` before
    treating the new config as applied, then restarts the service.
    """
    if not config.adblocker.enabled:
        # A real no-op (no subprocess call at all) unless there's
        # actually something to tear down -- mirrors frfw.xdp's own
        # "check state, only act if something would change" pattern.
        # Matters in practice: this function is called with the real
        # system default conf_path from several tests/CLI paths that
        # never touch the ad-blocker at all, and a bare `systemctl stop`
        # would needlessly fail loudly on a host that has never even
        # installed dnsmasq.
        if not conf_path.exists() and not is_resolver_active():
            return DnsSyncResult(False, "Ad-block DNS resolver disabled")
        if dry_run:
            return DnsSyncResult(False, "Would stop the ad-block DNS resolver (dry-run)")
        _require_root()
        _stop_dns_service()
        conf_path.unlink(missing_ok=True)
        return DnsSyncResult(False, "Ad-block DNS resolver disabled")

    if dry_run:
        return DnsSyncResult(
            True,
            f"Would (re)start the ad-block DNS resolver "
            f"({count_blocked_domains(hosts_path)} domains currently loaded, dry-run)",
        )

    _require_root()
    _ensure_hosts_placeholder(hosts_path)
    conf_text = render_dnsmasq_config(config, hosts_path=hosts_path)
    conf_path.parent.mkdir(parents=True, exist_ok=True)
    conf_path.write_text(conf_text)
    _test_dnsmasq_config(conf_path, dnsmasq_binary=dnsmasq_binary)
    _restart_dns_service()

    return DnsSyncResult(
        True,
        f"Ad-block DNS resolver active, {count_blocked_domains(hosts_path)} domains loaded",
    )


def is_resolver_active() -> bool:
    """`systemctl is-active` is a read-only status query any user can
    run (no root, no CAP_NET_ADMIN) -- unlike frfw.ztna's kernel-state
    reads, this needs no privileged round trip through the apply-helper,
    so the webUI's status page calls this directly."""
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", paths.ADBLOCK_DNS_SERVICE_NAME],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return False
    return proc.stdout.strip() == "active"


def critical_domains(hosts_path: Path, limit: int) -> list[str]:
    """Up to `limit` domains from the already-refreshed blocklist,
    suitable for merging into `Config.xdp_sni_filter.blocklist` (see
    `frfw.provision.apply_all`) -- reuses the *existing* Phase 4 XDP LPM
    trie (`frfw.xdp.sync_blocklist`) rather than a second kernel map, per
    the "don't bloat the kernel stack" design constraint. Sorted for
    determinism (which N domains get kernel-level treatment shouldn't
    change from run to run just because a set iterated differently), and
    silently drops anything that wouldn't fit the kernel filter's
    MAX_SNI_LEN bound -- this is a best-effort subset, not a guarantee
    every one of `limit` domains makes it in.
    """
    if limit <= 0:
        return []
    try:
        text = hosts_path.read_text()
    except FileNotFoundError:
        return []

    domains = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        domain = parts[1]
        if len(domain) < _MAX_SNI_LEN:
            domains.append(domain)
    return sorted(domains)[:limit]
