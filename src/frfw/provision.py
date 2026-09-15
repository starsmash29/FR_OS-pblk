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
   bracketed by a ZTNA session snapshot/restore (see step 5's comment
   and `frfw.ztna`'s module docstring for why)
3. Kea DHCP config, if any zone has a DHCP pool (`frfw.kea`)
4. XDP TLS SNI filter attach/detach + blocklist sync (`frfw.xdp`)
5. ZTNA gate: report how many active sessions survived step 2's reload
6. Hybrid PQC management-layer key exchange: refresh the webUI's
   OpenSSL config fragment and, if sshd is installed, its KexAlgorithms
   drop-in (`frfw.pqc`)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from frfw import ifaddr, kea, paths, pqc, xdp, ztna
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
) -> ProvisionResult:
    messages = []

    addr_result = ifaddr.sync_addresses(config, dry_run=dry_run)
    messages.append(addr_result.message)

    ruleset = build_ruleset(config)
    # Step 2's `nft -f` reload does `flush ruleset` first (see
    # frfw.nft.builder's docstring), which wipes the ZTNA gate's
    # authorized-clients set along with everything else -- snapshot it
    # immediately before the reload and restore it immediately after, so
    # an unrelated firewall change (a new rule, a DHCP pool edit, ...)
    # never silently logs every ZTNA session out. Skipped entirely in a
    # dry run (nothing is actually reloaded) or when the *new* config
    # disables ZTNA (then dropping every session is the correct,
    # config-is-the-source-of-truth behavior, not a bug to work around).
    preserve_ztna = not dry_run and config.ztna.enabled
    ztna_snapshot = ztna.snapshot_before_reload() if preserve_ztna else []

    nft_result = apply_ruleset(ruleset, dry_run=dry_run, backup_dir=backup_dir)
    messages.append(nft_result.message)

    ztna_preserved = 0
    if preserve_ztna and ztna_snapshot:
        ztna.restore_after_reload(ztna_snapshot)
        ztna_preserved = len(ztna_snapshot)

    dhcp_result = kea.apply_dhcp_config(config, dry_run=dry_run, config_path=kea_config_path)
    messages.append(dhcp_result.message)

    xdp_result = xdp.sync_sni_filter(config, dry_run=dry_run, state_path=xdp_state_path)
    messages.append(xdp_result.message)

    if not config.ztna.enabled:
        messages.append("ZTNA gate disabled")
    elif dry_run:
        messages.append("ZTNA gate: would preserve active sessions across reload (dry-run)")
    else:
        messages.append(f"ZTNA gate: {ztna_preserved} active session(s) preserved across reload")

    tls_pqc_result = pqc.sync_tls_pqc_conf(config, dry_run=dry_run, conf_path=pqc_conf_path)
    messages.append(tls_pqc_result.message)

    ssh_pqc_result = pqc.sync_ssh_kex(
        config, dry_run=dry_run, dropin_path=ssh_kex_dropin_path
    )
    messages.append(ssh_pqc_result.message)

    return ProvisionResult(messages=messages)
