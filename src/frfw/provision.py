"""Applies a whole `Config` to the running system: addresses, firewall, DHCP.

This is the single "make the system match the config" entrypoint used by
both `firewall-cli apply` and the apply-helper's `apply` command, so the
CLI and the (phase 3) webUI can never drift into applying things in a
different order or forgetting a step.

Steps run in order and stop at the first failure (no cross-subsystem
rollback is attempted -- if step 2 fails, step 1's effects stand, and the
error says which step failed and that later steps were not attempted).
The ruleset goes first, so a failure anywhere else still leaves the box
filtered:

1. nftables ruleset, backing up the previous one first (`frfw.apply`),
   with scheduled rules rendered for the current UTC offset and that
   offset recorded for the hourly DST check (`frfw.schedule_refresh`) --
   carrying the brute-force jail, the AI IDS quarantine, ZTNA sessions
   and isolated IoT devices over the reload in the same transaction (see
   the comment at the top of apply_all and `frfw.bruteforce`/`frfw.ids_quarantine`/
   `frfw.ztna`'s module docstrings for why)
2. Interface static addresses (`frfw.ifaddr`) -- after the ruleset, so a
   device the config names but this machine lacks can't stop the
   firewall from loading
3. Kea DHCP config, if any zone has a DHCP pool (`frfw.kea`)
4. Ad-block DNS resolver: (re)start/stop the dedicated dnsmasq instance
   to match `config.adblocker.enabled`, serving whatever
   `firewall-cli adblock-refresh` most recently downloaded -- never
   fetches anything from the network itself (`frfw.adblock.dns_service`)
5. XDP TLS SNI filter attach/detach + blocklist sync (`frfw.xdp`) --
   the effective blocklist is `xdp_sni_filter.blocklist` plus, if
   `adblocker.xdp_critical_limit` is set, up to that many domains from
   the already-refreshed ad-block list, and with
   `app_control.block_via_xdp` the blocked apps' catalog names, merged
   in-memory only (never written back to config.yaml -- see step 5's
   own comment below)
6. ZTNA gate: report how many active sessions survived step 2's reload,
   then the same for isolated IoT devices (`frfw.iot_isolation`, only
   when `iot.enabled`)
7. Hybrid PQC management-layer key exchange: refresh the webUI's
   OpenSSL config fragment and, if sshd is installed, its KexAlgorithms
   drop-in (`frfw.pqc`)
8. Management plane: sshd's ListenAddress drop-in and, when its
   addresses changed, a delayed webUI restart (`frfw.management`) --
   the webUI and SSH listen only on the management zones' addresses
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import Path

from frfw import (
    bruteforce,
    forwarding,
    ids_quarantine,
    ifaddr,
    iot_isolation,
    kea,
    management,
    paths,
    pqc,
    schedule_refresh,
    wireguard,
    xdp,
    ztna,
)
from frfw.adblock import dns_service as adblock_dns
from frfw.apply import NftError, apply_ruleset
from frfw.config.schema import Config
from frfw.nft import RuntimeSets, build_ruleset
from frfw.nft.schedule import current_clock
from frfw.tlsfp import daemon as tlsfp_daemon


@dataclass(frozen=True)
class ProvisionResult:
    messages: list[str]


def apply_all(
    config: Config,
    *,
    dry_run: bool = False,
    backup_dir: Path = paths.BACKUP_DIR,
    kea_config_path: Path = kea.KEA_CONFIG_PATH,
    xdp_state_path: Path = paths.XDP_STATE_PATH,
    pqc_conf_path: Path = paths.PQC_OPENSSL_CONF_PATH,
    ssh_kex_dropin_path: Path = paths.SSHD_PQC_DROPIN_PATH,
    adblock_hosts_path: Path = paths.ADBLOCK_HOSTS_PATH,
    adblock_dnsmasq_conf_path: Path = paths.ADBLOCK_DNSMASQ_CONF_PATH,
    adblock_category_dir: Path = paths.ADBLOCK_CATEGORY_DIR,
    schedule_state_path: Path = paths.SCHEDULE_STATE_PATH,
    ssh_management_dropin_path: Path | None = None,
) -> ProvisionResult:
    messages = []

    # Phase 17: scheduled rules are rendered for the offset in effect now;
    # the same clock is recorded below so the hourly schedule-check can
    # spot a DST change (frfw.schedule_refresh).
    schedule_clock = (
        current_clock(config.timezone) if schedule_refresh.has_schedules(config) else None
    )
    # Step 1's `nft -f` reload does `flush ruleset` first (see
    # frfw.nft.builder's docstring), which wipes the brute-force jail, the
    # AI IDS quarantine, ZTNA sessions and isolated IoT devices along with
    # everything else. Their live members are read here and written into
    # the new ruleset itself (RuntimeSets), so they come back in the same
    # nft transaction as the flush: an unrelated config change never
    # un-bans an attacker, releases a quarantined host or logs a ZTNA
    # session out, not even for a moment (review FR-002). A read that
    # fails stops the apply before anything is reloaded -- the running
    # ruleset keeps enforcing -- rather than silently releasing everyone.
    # The jail and the quarantine are always declared (the detection
    # engine and the enforcement set are independent: turning AI IDS off
    # must not amnesty quarantined hosts); ZTNA and IoT isolation only
    # while their feature is on. A dry run reloads nothing, so it reads
    # nothing either.
    runtime = RuntimeSets() if dry_run else _read_runtime_sets(config)
    ruleset = build_ruleset(config, clock=schedule_clock, runtime=runtime)

    nft_result = apply_ruleset(ruleset, dry_run=dry_run, backup_dir=backup_dir)
    messages.append(nft_result.message)
    if schedule_clock is not None:
        scheduled = sum(1 for r in config.rules if r.schedule is not None)
        zone = config.timezone or "system local time"
        messages.append(
            f"Scheduled rules: {scheduled}, rendered for {schedule_clock.describe()} ({zone})"
        )
        if not dry_run:
            schedule_refresh.record_applied(config, schedule_clock, schedule_state_path)
    elif not dry_run:
        schedule_refresh.clear_record(schedule_state_path)

    bruteforce_preserved = sum(1 for _, left in runtime.bruteforce_jail if left > 0)
    ids_quarantine_preserved = sum(1 for _, left in runtime.ids_quarantine if left > 0)
    ztna_preserved = sum(1 for _, left in runtime.ztna if left > 0) if config.ztna.enabled else 0
    iot_preserved = len(runtime.iot_isolated) if config.iot.enabled else 0

    # Routing only once the forward chain is loaded (frfw.forwarding).
    messages.append(forwarding.enable(dry_run=dry_run))

    # The VPN tunnel (security-lessons G8), also only behind the ruleset,
    # and before the management sync below, which may listen on its
    # address.
    messages.append(wireguard.sync(config, dry_run=dry_run).message)

    # Addresses only after the ruleset is in: a device name in the config
    # that doesn't exist on this machine fails here, and must not leave
    # the box without a firewall (nft matches interfaces by name, so the
    # ruleset loads fine without them). It also means no address is
    # brought up before the rules that filter it.
    addr_result = ifaddr.sync_addresses(config, dry_run=dry_run)
    messages.append(addr_result.message)

    dhcp_result = kea.apply_dhcp_config(config, dry_run=dry_run, config_path=kea_config_path)
    messages.append(dhcp_result.message)

    adblock_dns_result = adblock_dns.sync_dns_resolver(
        config,
        dry_run=dry_run,
        hosts_path=adblock_hosts_path,
        conf_path=adblock_dnsmasq_conf_path,
        category_dir=adblock_category_dir,
    )
    messages.append(adblock_dns_result.message)

    # The kernel-level "critical" adblock subset (if configured) is
    # merged into the XDP blocklist here, in memory only -- never
    # persisted back into config.yaml -- so the file on disk always
    # reflects exactly what the admin actually configured, the same way
    # a ZTNA-authorized IP never gets written into the firewall rules
    # themselves. If xdp_sni_filter.enabled is False, this has no
    # effect: enabling adblocker never silently turns XDP on.
    extra_xdp_names: set[str] = set()
    if config.adblocker.enabled and config.adblocker.xdp_critical_limit > 0:
        extra_xdp_names.update(
            adblock_dns.critical_domains(adblock_hosts_path, config.adblocker.xdp_critical_limit)
        )
    # Phase 16: blocked apps' catalog names, same in-memory-only merge.
    if config.app_control.block_via_xdp:
        extra_xdp_names.update(
            name
            for name in adblock_dns.blocked_app_names(config)
            if len(name) < xdp.MAX_SNI_LEN
        )
    xdp_config = config
    if extra_xdp_names:
        merged_blocklist = sorted(set(config.xdp_sni_filter.blocklist) | extra_xdp_names)
        xdp_config = dataclasses.replace(
            config,
            xdp_sni_filter=dataclasses.replace(config.xdp_sni_filter, blocklist=merged_blocklist),
        )

    xdp_result = xdp.sync_sni_filter(xdp_config, dry_run=dry_run, state_path=xdp_state_path)
    messages.append(xdp_result.message)
    if config.tls_fingerprint.enabled and not dry_run:
        tlsfp_daemon.restart_service()  # phase 19, see its docstring

    if dry_run:
        messages.append("Brute-force jail: would preserve active bans across reload (dry-run)")
    else:
        messages.append(f"Brute-force jail: {bruteforce_preserved} active ban(s) preserved across reload")

    if dry_run:
        messages.append("AI IDS quarantine: would preserve active quarantines across reload (dry-run)")
    else:
        messages.append(
            f"AI IDS quarantine: {ids_quarantine_preserved} active quarantine(s) preserved across reload"
        )

    if not config.ztna.enabled:
        messages.append("ZTNA gate disabled")
    elif dry_run:
        messages.append("ZTNA gate: would preserve active sessions across reload (dry-run)")
    else:
        messages.append(f"ZTNA gate: {ztna_preserved} active session(s) preserved across reload")

    if not config.iot.enabled:
        messages.append("IoT isolation disabled")
    elif dry_run:
        messages.append("IoT isolation: would preserve isolated devices across reload (dry-run)")
    else:
        messages.append(f"IoT isolation: {iot_preserved} isolated device(s) preserved across reload")

    tls_pqc_result = pqc.sync_tls_pqc_conf(config, dry_run=dry_run, conf_path=pqc_conf_path)
    messages.append(tls_pqc_result.message)

    ssh_pqc_result = pqc.sync_ssh_kex(
        config, dry_run=dry_run, dropin_path=ssh_kex_dropin_path
    )
    messages.append(ssh_pqc_result.message)

    # Security-lessons F2/G4: the webUI and sshd listen on the management
    # zones' addresses only (the input chain above already drops them
    # from everywhere else).
    messages.append(management.sync_sshd(config, dry_run=dry_run, dropin_path=ssh_management_dropin_path).message)
    messages.append(management.sync_webui(config, dry_run=dry_run).message)
    if config.management.allow_wan:
        messages.append("WARNING: " + management.WAN_WARNING)

    return ProvisionResult(messages=messages)


def _read_runtime_sets(config: Config) -> RuntimeSets:
    """The members to carry over the reload (see apply_all's step 1)."""
    readers = [
        ("the brute-force jail", bruteforce.snapshot_before_reload, bruteforce.BruteforceError, True),
        ("the AI IDS quarantine", ids_quarantine.snapshot_before_reload, ids_quarantine.IdsQuarantineError, True),
        ("ZTNA sessions", ztna.snapshot_before_reload, ztna.ZtnaError, config.ztna.enabled),
        ("isolated IoT devices", iot_isolation.snapshot_before_reload, iot_isolation.IotIsolationError,
         config.iot.enabled),
    ]
    found = []
    for what, read, error, wanted in readers:
        if not wanted:
            found.append(())
            continue
        try:
            found.append(tuple(read()))
        except error as exc:
            raise NftError(f"could not read {what} before reloading the firewall, so nothing was "
                           f"changed (the running ruleset keeps enforcing): {exc}") from exc
    return RuntimeSets(*found)
