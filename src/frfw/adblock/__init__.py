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
    """Parse one blocklist's raw text into a set of unique, lowercased
    domains. Two real-world formats are accepted, line by line:

    - hosts format, "<ip> <name> [<name> ...]" (StevenBlack, URLhaus):
      the first token must be a valid IP address (the "0.0.0.0" /
      "127.0.0.1" blocking address -- discarded either way; some lists
      use "::"), every remaining token is validated as a hostname;
    - plain domain lists, one name per line (Phishing Army, the DoH
      resolver list), checked against the real files in phase 15.

    Comments and blank lines are skipped; anything else (adblock filter
    syntax like `||example.com^`, URLs) fails hostname validation and is
    dropped rather than guessed at."""
    domains: set[str] = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = line.split()
        if len(tokens) == 1:
            hostname = tokens[0].lower().rstrip(".")
            if "." in hostname and hostname not in _IGNORED_HOSTNAMES and _HOSTNAME_RE.match(hostname):
                domains.add(hostname)
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


#: The unnamed base list (`adblocker.source_urls`) is reported under this
#: category name everywhere per-category counts appear (metrics, webUI,
#: DNS log attribution); `adblocker.categories` may not reuse it.
BASE_CATEGORY = "ads"

#: Firefox's documented DoH "canary" domain: Firefox leaves DNS-over-HTTPS
#: off by default when this name does NOT resolve (NXDOMAIN). A blocklist
#: entry for it would answer 0.0.0.0 -- a positive answer -- and silently
#: defeat that. Found the hard way in phase 15: the public DoH-resolver
#: list contains it, and dnsmasq's hosts-file answer wins over the
#: `address=/<name>/` NXDOMAIN rule frfw.adblock.dns_service sets. So it is
#: removed from every list we write, like an allowlist entry that can't
#: be switched off.
FIREFOX_DOH_CANARY = "use-application-dns.net"


def is_allowlisted(domain: str, allowlist: list[str] | set[str]) -> bool:
    """True if `domain` is an allowlist entry or a subdomain of one."""
    return any(domain == a or domain.endswith("." + a) for a in allowlist)


def apply_allowlist(domains: set[str], allowlist: list[str]) -> set[str]:
    effective = [*allowlist, FIREFOX_DOH_CANARY]
    return {d for d in domains if not is_allowlisted(d, effective)}


def read_hosts_file(path: Path) -> set[str]:
    """Domains in one of our own generated hosts files (the inverse of
    write_hosts_file); empty if it doesn't exist."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return set()
    return parse_hosts_text(text)


def category_path(category: str, category_dir: Path = paths.ADBLOCK_CATEGORY_DIR) -> Path:
    return category_dir / f"{category}.hosts"


def category_counts(
    categories: list[str],
    *,
    hosts_path: Path = paths.ADBLOCK_HOSTS_PATH,
    category_dir: Path = paths.ADBLOCK_CATEGORY_DIR,
) -> dict[str, int]:
    """{category: domains currently loaded}, base list included as
    BASE_CATEGORY -- unprivileged, for the webUI and metrics."""
    counts = {BASE_CATEGORY: count_blocked_domains(hosts_path)}
    for name in categories:
        counts[name] = count_blocked_domains(category_path(name, category_dir))
    return counts


@dataclass(frozen=True)
class RefreshResult:
    domain_count: int
    failed_urls: list[str]
    message: str
    category_counts: dict[str, int] | None = None


def refresh(
    source_urls: list[str],
    *,
    hosts_path: Path = paths.ADBLOCK_HOSTS_PATH,
    categories: dict[str, list[str]] | None = None,
    category_dir: Path = paths.ADBLOCK_CATEGORY_DIR,
    allowlist: list[str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    dry_run: bool = False,
) -> RefreshResult:
    """Fetch, parse, dedupe, drop allowlisted names and (unless
    `dry_run`) write the base list to `hosts_path` plus one file per
    category under `category_dir`. The one function `firewall-cli
    adblock-refresh` and the apply-helper's `refresh_adblock` command
    both call -- see this module's docstring for why this is
    deliberately decoupled from `apply_all`.

    Each list is fetched and written independently: one category whose
    every source is down keeps its previous file and is reported, it
    doesn't cost the others their refresh. Category files no longer in
    the config are removed, so dropping a category actually unblocks it.

    Fetching needs no privilege (outbound HTTPS); only the writes are
    root-gated, mirroring frfw.kea's "prepare first, `_require_root()`
    right before the real write" ordering.
    """
    categories = categories or {}
    allowlist = allowlist or []
    if not source_urls and not categories:
        raise AdblockError("adblocker.source_urls and adblocker.categories are both empty; nothing to fetch")

    lists: list[tuple[str, list[str], Path]] = []
    if source_urls:
        lists.append((BASE_CATEGORY, source_urls, hosts_path))
    for name, urls in sorted(categories.items()):
        lists.append((name, urls, category_path(name, category_dir)))

    fetched: dict[str, set[str]] = {}
    failed_urls: list[str] = []
    problems: list[str] = []
    for name, urls, _path in lists:
        try:
            result = fetch_and_parse(urls, timeout=timeout)
        except AdblockError as exc:
            problems.append(f"{name}: {exc}")
            failed_urls.extend(urls)
            continue
        fetched[name] = apply_allowlist(result.domains, allowlist)
        failed_urls.extend(result.failed_urls)

    if not fetched:
        raise AdblockError("; ".join(problems) or "nothing fetched")

    counts = {name: len(domains) for name, domains in fetched.items()}
    total = sum(counts.values())
    summary = ", ".join(f"{name}={n}" for name, n in counts.items())

    if dry_run:
        return RefreshResult(
            domain_count=total,
            failed_urls=failed_urls,
            message=f"Would write {total} deduped domains ({summary}) (dry-run)",
            category_counts=counts,
        )

    _require_root()
    for name, _urls, path in lists:
        if name in fetched:
            write_hosts_file(fetched[name], path)
    if not source_urls:
        write_hosts_file(set(), hosts_path)  # base list removed from config: stop blocking it
    if category_dir.is_dir():
        for stale in category_dir.glob("*.hosts"):
            if stale.stem not in categories:
                stale.unlink()

    message = f"{total} deduped domains written ({summary})"
    if problems:
        message += f"; kept previous list for: {'; '.join(problems)}"
    elif failed_urls:
        message += f" ({len(failed_urls)} source(s) failed: {failed_urls})"
    return RefreshResult(
        domain_count=total, failed_urls=failed_urls, message=message, category_counts=counts
    )
