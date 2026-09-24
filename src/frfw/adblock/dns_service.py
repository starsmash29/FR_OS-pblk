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

Pointing LAN clients at this resolver is opt-in (phase 15,
`adblocker.serve_lan`): frfw.kea then announces the router's own address
as the DNS server and the pools' configured `dns_servers` become this
instance's upstreams, and the firewall accepts DNS from those zones.
Without it, phase 9's behavior stands: `DhcpPool.dns_servers` is handed
out exactly as configured -- see ARCHITECTURE.md's phase 9 open issues
for why that was never done silently as a side effect.
"""

from __future__ import annotations

import ipaddress
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from frfw import paths
from frfw.adblock import (
    FIREFOX_DOH_CANARY,
    apply_allowlist,
    category_path,
    count_blocked_domains,
    read_hosts_file,
    write_hosts_file,
)
from frfw.appid import blocking_names
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
    # Never forward to one of the router's own addresses: with serve_lan an
    # admin may well have listed the router as a pool's DNS server already,
    # and dnsmasq forwarding to itself would loop every query.
    own = {
        str(ipaddress.IPv4Interface(i.address).ip) for i in config.interfaces.values() if i.address
    }
    servers: list[str] = []
    for pool in config.dhcp.zones.values():
        for server in pool.dns_servers:
            if server not in servers and server not in own:
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
{hosts_lines}
{listen_lines}
bind-interfaces
{server_lines}
{extra_lines}user=nobody
group=nogroup
"""

# FIREFOX_DOH_CANARY (see frfw.adblock): `address=/<name>/` with no address
# makes dnsmasq answer NXDOMAIN for it -- checked against real dnsmasq 2.91
# (A and AAAA both rcode 3) -- as long as no hosts file also lists it,
# which frfw.adblock.apply_allowlist guarantees.


def blocked_app_names(config: Config) -> list[str]:
    """Catalog names of `app_control.blocked_apps`, while the feature is on."""
    app_control = config.app_control
    if not (app_control.enabled and app_control.blocked_apps):
        return []
    return blocking_names(app_control.blocked_apps)


def render_dnsmasq_config(
    config: Config,
    *,
    hosts_path: Path = paths.ADBLOCK_HOSTS_PATH,
    category_dir: Path = paths.ADBLOCK_CATEGORY_DIR,
) -> str:
    adblocker = config.adblocker
    hosts_files = [hosts_path] + [category_path(n, category_dir) for n in sorted(adblocker.categories)]
    hosts_lines = "\n".join(f"addn-hosts={p}" for p in hosts_files)
    listen_lines = "\n".join(f"interface={d}" for d in _listen_devices(config))
    server_lines = "\n".join(f"server={s}" for s in _upstream_servers(config))
    extra = []
    if adblocker.query_logging:
        # "extra" puts the client address and a per-query serial on every
        # line, and names the hosts file for a blocked answer -- which is
        # what lets frfw.ai_ids attribute NXDOMAINs and threat-category
        # blocks to a host (format checked against real dnsmasq output).
        extra.append("log-queries=extra")
    if adblocker.force_dns:
        extra.append(f"address=/{FIREFOX_DOH_CANARY}/")
    # Phase 16 app blocking: the same NXDOMAIN form, which also covers
    # every subdomain. Deliberately not subject to `allowlist` -- blocking
    # an app is an explicit choice, the allowlist exists to fix list noise.
    extra.extend(f"address=/{name}/" for name in blocked_app_names(config))
    extra_lines = "".join(f"{line}\n" for line in extra)
    return _DNSMASQ_CONF_TEMPLATE.format(
        hosts_lines=hosts_lines,
        listen_lines=listen_lines,
        server_lines=server_lines,
        extra_lines=extra_lines,
    )


def enforce_allowlist(config: Config, *, hosts_path: Path, category_dir: Path) -> int:
    """Remove allowlisted names from the already-downloaded lists, so an
    allowlist edit takes effect on the next `apply` without a refresh.
    Removal only: an entry taken *off* the allowlist comes back at the
    next refresh, since the local files no longer contain it. Returns
    how many entries were removed."""
    allowlist = config.adblocker.allowlist
    removed = 0
    files = [hosts_path] + [category_path(n, category_dir) for n in config.adblocker.categories]
    for path in files:
        domains = read_hosts_file(path)
        kept = apply_allowlist(domains, allowlist)
        if len(kept) != len(domains):
            removed += len(domains) - len(kept)
            write_hosts_file(kept, path)
    return removed


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
    category_dir: Path = paths.ADBLOCK_CATEGORY_DIR,
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
    for name in config.adblocker.categories:
        _ensure_hosts_placeholder(category_path(name, category_dir))
    removed = enforce_allowlist(config, hosts_path=hosts_path, category_dir=category_dir)
    conf_text = render_dnsmasq_config(config, hosts_path=hosts_path, category_dir=category_dir)
    conf_path.parent.mkdir(parents=True, exist_ok=True)
    conf_path.write_text(conf_text)
    _test_dnsmasq_config(conf_path, dnsmasq_binary=dnsmasq_binary)
    _restart_dns_service()

    total = count_blocked_domains(hosts_path) + sum(
        count_blocked_domains(category_path(n, category_dir)) for n in config.adblocker.categories
    )
    message = f"Ad-block DNS resolver active, {total} domains loaded"
    if config.adblocker.categories:
        message += f" ({len(config.adblocker.categories)} categories)"
    if removed:
        message += f", {removed} allowlisted entries removed"
    if config.app_control.enabled and config.app_control.blocked_apps:
        message += f", {len(config.app_control.blocked_apps)} app(s) blocked"
    return DnsSyncResult(True, message)


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
