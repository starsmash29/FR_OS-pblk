"""Applies a whole `Config` to the running system: addresses, firewall, DHCP.

This is the single "make the system match the config" entrypoint used by
both `firewall-cli apply` and the apply-helper's `apply` command, so the
CLI and the (phase 3) webUI can never drift into applying things in a
different order or forgetting a step.

Steps run in order and stop at the first failure (no cross-subsystem
rollback is attempted -- if step 2 fails, step 1's effects stand, and the
error says which step failed and that later steps were not attempted):

1. Interface static addresses (`frfw.ifaddr`)
2. nftables ruleset, backing up the previous one first (`frfw.apply`) --
   bracketed by a brute-force jail snapshot/restore, an AI IDS
   quarantine snapshot/restore, and a ZTNA session snapshot/restore (see
   step 5's comment and `frfw.bruteforce`/`frfw.ids_quarantine`/
   `frfw.ztna`'s module docstrings for why)
3. Kea DHCP config, if any zone has a DHCP pool (`frfw.kea`)
4. Ad-block DNS resolver: (re)start/stop the dedicated dnsmasq instance
   to match `config.adblocker.enabled`, serving whatever
   `firewall-cli adblock-refresh` most recently downloaded -- never
   fetches anything from the network itself (`frfw.adblock.dns_service`)
5. XDP TLS SNI filter attach/detach + blocklist sync (`frfw.xdp`) --
   the effective blocklist is `xdp_sni_filter.blocklist` plus, if
   `adblocker.xdp_critical_limit` is set, up to that many domains from
   the already-refreshed ad-block list, merged in-memory only (never
   written back to config.yaml -- see step 5's own comment below)
6. ZTNA gate: report how many active sessions survived step 2's reload,
   then the same for isolated IoT devices (`frfw.iot_isolation`, only
   when `iot.enabled`)
7. Hybrid PQC management-layer key exchange: refresh the webUI's
   OpenSSL config fragment and, if sshd is installed, its KexAlgorithms
   drop-in (`frfw.pqc`)
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import Path

from frfw import bruteforce, ids_quarantine, ifaddr, iot_isolation, kea, paths, pqc, xdp, ztna
from frfw.adblock import dns_service as adblock_dns
from frfw.apply import apply_ruleset
from frfw.config.schema import Config
from frfw.nft import build_ruleset


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
) -> ProvisionResult:
    messages = []

    addr_result = ifaddr.sync_addresses(config, dry_run=dry_run)
    messages.append(addr_result.message)

    ruleset = build_ruleset(config)
    # Step 2's `nft -f` reload does `flush ruleset` first (see
    # frfw.nft.builder's docstring), which wipes both the brute-force
    # jail and the ZTNA gate's authorized-clients set along with
    # everything else -- snapshot each immediately before the reload and
    # restore immediately after, so an unrelated firewall change (a new
    # rule, a DHCP pool edit, ...) never silently un-bans an active
    # attacker mid-attempt or logs every ZTNA session out. The jail
    # snapshot/restore is unconditional (BRUTEFORCE_JAIL_SET_NAME is
    # always declared, unlike ZTNA's set) except in a dry run, where
    # nothing is actually reloaded so there is nothing to preserve.
    preserve_bruteforce = not dry_run
    bruteforce_snapshot = bruteforce.snapshot_before_reload() if preserve_bruteforce else []

    # Same reasoning and same unconditional treatment as the brute-force
    # jail immediately above: IDS_QUARANTINE_SET_NAME is always declared
    # (see frfw.nft.builder), so it needs the same flush-survival
    # bracketing regardless of whether config.ai_ids.enabled -- a
    # quarantine already in effect must survive an unrelated config
    # change even if AI IDS detection itself is later turned off (the
    # enforcement set and the detection engine are independent: turning
    # the daemon off should not silently amnesty already-quarantined
    # hosts).
    preserve_ids_quarantine = not dry_run
    ids_quarantine_snapshot = (
        ids_quarantine.snapshot_before_reload() if preserve_ids_quarantine else []
    )

    preserve_ztna = not dry_run and config.ztna.enabled
    ztna_snapshot = ztna.snapshot_before_reload() if preserve_ztna else []

    # IoT isolation (phase 14): only declared when iot.enabled, so only
    # bracketed then -- same reasoning as ZTNA just above. Without this,
    # every unrelated config save would silently release every isolated
    # device until the next scan re-synced the set.
    preserve_iot = not dry_run and config.iot.enabled
    iot_snapshot = iot_isolation.snapshot_before_reload() if preserve_iot else []

    nft_result = apply_ruleset(ruleset, dry_run=dry_run, backup_dir=backup_dir)
    messages.append(nft_result.message)

    bruteforce_preserved = 0
    if preserve_bruteforce and bruteforce_snapshot:
        bruteforce.restore_after_reload(bruteforce_snapshot)
        bruteforce_preserved = len(bruteforce_snapshot)

    ids_quarantine_preserved = 0
    if preserve_ids_quarantine and ids_quarantine_snapshot:
        ids_quarantine.restore_after_reload(ids_quarantine_snapshot)
        ids_quarantine_preserved = len(ids_quarantine_snapshot)

    ztna_preserved = 0
    if preserve_ztna and ztna_snapshot:
        ztna.restore_after_reload(ztna_snapshot)
        ztna_preserved = len(ztna_snapshot)

    iot_preserved = 0
    if preserve_iot and iot_snapshot:
        iot_isolation.restore_after_reload(iot_snapshot)
        iot_preserved = len(iot_snapshot)

    dhcp_result = kea.apply_dhcp_config(config, dry_run=dry_run, config_path=kea_config_path)
    messages.append(dhcp_result.message)

    adblock_dns_result = adblock_dns.sync_dns_resolver(
        config,
        dry_run=dry_run,
        hosts_path=adblock_hosts_path,
        conf_path=adblock_dnsmasq_conf_path,
    )
    messages.append(adblock_dns_result.message)

    # The kernel-level "critical" adblock subset (if configured) is
    # merged into the XDP blocklist here, in memory only -- never
    # persisted back into config.yaml -- so the file on disk always
    # reflects exactly what the admin actually configured, the same way
    # a ZTNA-authorized IP never gets written into the firewall rules
    # themselves. If xdp_sni_filter.enabled is False, this has no
    # effect: enabling adblocker never silently turns XDP on.
    xdp_config = config
    if config.adblocker.enabled and config.adblocker.xdp_critical_limit > 0:
        critical = adblock_dns.critical_domains(
            adblock_hosts_path, config.adblocker.xdp_critical_limit
        )
        merged_blocklist = sorted(set(config.xdp_sni_filter.blocklist) | set(critical))
        xdp_config = dataclasses.replace(
            config,
            xdp_sni_filter=dataclasses.replace(config.xdp_sni_filter, blocklist=merged_blocklist),
        )

    xdp_result = xdp.sync_sni_filter(xdp_config, dry_run=dry_run, state_path=xdp_state_path)
    messages.append(xdp_result.message)

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

    return ProvisionResult(messages=messages)
