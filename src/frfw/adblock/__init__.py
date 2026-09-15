"""Local DNS-level ad/tracker blocker (phase 9).

Downloads one or more hosts-format blocklists (StevenBlack's unified
hosts list is the built-in default), strips comments/IPs, extracts and
dedupes the raw domains, and writes them back out as a clean,
deterministic hosts-format file (`frfw.paths.ADBLOCK_HOSTS_PATH`) that
`frfw.adblock.dns_service`'s dedicated dnsmasq instance serves from.

This module intentionally does the network fetch with the same
dependency-free pattern `frfw.update` already uses (`urllib.request`, a
single `_fetch_*` seam, an explicit `timeout` kwarg, a module-specific
error class) rather than adding `requests`/`httpx` as a new runtime
dependency -- see that module for the precedent. "Non-blocking" for
multiple source URLs is achieved with a stdlib
`concurrent.futures.ThreadPoolExecutor` (network-bound, not CPU-bound,
so the GIL is a non-issue) rather than `asyncio`/`aiohttp`, which would
be a new dependency this project has never needed for anything else.

Downloading is deliberately *not* wired into `firewall-cli apply`/
`frfw.provision.apply_all`: these lists can be several megabytes and
tens of thousands of lines, and re-fetching them on every firewall apply
(which can happen many times in a session while an admin edits rules)
would be slow and needlessly hammer the source URLs. Refreshing is its
own explicit operation instead -- `firewall-cli adblock-refresh` (called
by a daily systemd timer, see systemd/fr-adblock-refresh.timer) or the
webUI's "Refresh now" button (via the privileged apply-helper's
`refresh_adblock` socket command, see frfw.helper.server) -- and
`apply_all` only reconciles the *resolver's* running state (and, if
configured, the XDP critical subset) against whatever was fetched most
recently (see frfw.adblock.dns_service.sync_dns_resolver).
"""

from __future__ import annotations

import ipaddress
import os
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from frfw import paths

#: StevenBlack's unified hosts list -- ads + malware + fakenews (the
#: "unified" variant), the same list format/source the request named
#: explicitly. Used as the default when an admin enables the feature
#: without specifying their own source_urls.
DEFAULT_SOURCE_URLS = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]

#: Entries every stock hosts file (and most blocklists, which are built
#: by appending to one) carries for purposes unrelated to ad-blocking --
#: never worth blocking, and blocking "localhost" itself would break the
#: resolver's own host.
_IGNORED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "ip6-localnet",
        "ip6-mcastprefix",
        "ip6-allnodes",
        "ip6-allrouters",
        "ip6-allhosts",
    }
)

#: Same shape as frfw.config.loader's own _HOSTNAME_RE -- duplicated
#: rather than imported, since this module deliberately doesn't depend
#: on frfw.config (a malformed line here should be dropped, not raise a
#: ConfigError; a blocklist download is untrusted third-party data, not
#: this router's own configuration).
_HOSTNAME_RE = re.compile(r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*$")

#: Default per-URL fetch timeout and concurrency, mirroring
#: frfw.update's explicit-timeout convention.
DEFAULT_TIMEOUT = 15.0
DEFAULT_MAX_WORKERS = 4


class AdblockError(Exception):
    pass


def _fetch_url(url: str, timeout: float) -> str:
    """The one seam every network call in this module goes through --
    see frfw.update._fetch_json's identical rationale."""
    request = urllib.request.Request(url, headers={"User-Agent": "fr_os-adblock"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise AdblockError(f"could not fetch {url}: {exc}") from exc


def parse_hosts_text(text: str) -> set[str]:
    """Parse one hosts-format blocklist's raw text into a set of
    unique, lowercased domains: strips comments, skips blank lines,
    requires the first whitespace-separated token to be a valid IP
    address (the "0.0.0.0"/"127.0.0.1" blocking address -- any address
    works, since it's discarded either way and some lists use "::" for
    IPv6), and validates every remaining token on the line as a
    hostname (hosts-format allows multiple hostnames per IP)."""
    domains: set[str] = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = line.split()
        if len(tokens) < 2:
            continue
        try:
            ipaddress.ip_address(tokens[0])
        except ValueError:
            continue
        for hostname in tokens[1:]:
            hostname = hostname.lower()
            if hostname in _IGNORED_HOSTNAMES or not _HOSTNAME_RE.match(hostname):
                continue
            domains.add(hostname)
    return domains


@dataclass(frozen=True)
class FetchResult:
    domains: set[str]
    failed_urls: list[str]


def fetch_and_parse(
    source_urls: list[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> FetchResult:
    """Fetch and parse every URL in `source_urls` concurrently
    (thread-per-URL: this is network-bound I/O, not CPU-bound, so the
    GIL is irrelevant), union the resulting domains, and report which
    URLs (if any) failed rather than aborting the whole refresh for one
    bad source -- a StevenBlack mirror hiccup shouldn't also cost the
    admin's own manually-added `source_urls` entry. Raises `AdblockError`
    only if *every* URL failed, since a completely empty result would
    silently blank out the blocklist on the next write."""
    domains: set[str] = set()
    failed: list[str] = []
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
        futures = {pool.submit(_fetch_url, url, timeout): url for url in source_urls}
        for future in as_completed(futures):
            url = futures[future]
            try:
                domains |= parse_hosts_text(future.result())
            except AdblockError:
                failed.append(url)

    if failed and len(failed) == len(source_urls):
        raise AdblockError(f"all {len(source_urls)} source_urls failed to fetch: {failed}")

    return FetchResult(domains=domains, failed_urls=failed)


_HOSTS_FILE_HEADER = (
    "# Managed by FR_OS (frfw.adblock) -- regenerated by `firewall-cli\n"
    "# adblock-refresh`, do not edit by hand. One deduped entry per\n"
    "# blocked domain, hosts-format (\"0.0.0.0 <domain>\"), served by the\n"
    "# fr-adblock-dns dnsmasq instance via addn-hosts= (see\n"
    "# frfw.adblock.dns_service).\n"
)


def write_hosts_file(domains: set[str], path: Path) -> None:
    """Write `domains` back out as a clean, deterministic (sorted)
    hosts-format file. Plain overwrite, no atomic tmp+rename -- this
    file is a one-way "hand this to dnsmasq" artifact re-read by another
    process only after an explicit reload, the same non-atomic-write
    precedent frfw.kea.apply_dhcp_config already sets for exactly that
    kind of file (see that module's docstring for why atomicity is
    reserved for state a process reads back for itself)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [_HOSTS_FILE_HEADER]
    lines += [f"0.0.0.0 {domain}\n" for domain in sorted(domains)]
    path.write_text("".join(lines))


def count_blocked_domains(path: Path = paths.ADBLOCK_HOSTS_PATH) -> int:
    """Live count of domains currently loaded, for the webUI's status
    display. Safe to call unprivileged (the file is world-readable, like
    frfw.xdp's/frfw.ztna's own state files) and returns 0 rather than
    raising if the blocklist has never been refreshed yet."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return 0
    return sum(1 for line in text.splitlines() if line.strip() and not line.startswith("#"))


def _require_root() -> None:
    if os.geteuid() != 0:
        raise AdblockError("Refreshing the ad-block list requires root privileges.")


@dataclass(frozen=True)
class RefreshResult:
    domain_count: int
    failed_urls: list[str]
    message: str


def refresh(
    source_urls: list[str],
    *,
    hosts_path: Path = paths.ADBLOCK_HOSTS_PATH,
    timeout: float = DEFAULT_TIMEOUT,
    dry_run: bool = False,
) -> RefreshResult:
    """Fetch, parse, dedupe and (unless `dry_run`) write `hosts_path`.
    The one function `firewall-cli adblock-refresh` and the apply-helper's
    `refresh_adblock` socket command both call -- see this module's
    docstring for why this is deliberately decoupled from `apply_all`.

    Fetching needs no privilege (it's an outbound HTTPS request); only
    the final write is root-gated, mirroring frfw.kea's
    "validate/prepare first, `_require_root()` immediately before the
    real write" ordering.
    """
    if not source_urls:
        raise AdblockError("adblocker.source_urls is empty; nothing to fetch")

    result = fetch_and_parse(source_urls, timeout=timeout)

    if dry_run:
        return RefreshResult(
            domain_count=len(result.domains),
            failed_urls=result.failed_urls,
            message=(
                f"Would write {len(result.domains)} deduped domains to "
                f"{hosts_path} (dry-run)"
            ),
        )

    _require_root()
    write_hosts_file(result.domains, hosts_path)

    message = f"{len(result.domains)} deduped domains written to {hosts_path}"
    if result.failed_urls:
        message += f" ({len(result.failed_urls)} source(s) failed: {result.failed_urls})"
    return RefreshResult(
        domain_count=len(result.domains), failed_urls=result.failed_urls, message=message
    )
