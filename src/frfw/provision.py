"""Applies a whole `Config` to the running system: addresses, firewall, DHCP.

This is the single "make the system match the config" entrypoint used by
both `firewall-cli apply` and the apply-helper's `apply` command, so the
CLI and the (phase 3) webUI can never drift into applying things in a
different order or forgetting a step.

Steps run in order and stop at the first failure (no cross-subsystem
rollback is attempted -- if step 2 fails, step 1's effects stand, and the
error says which step failed and that later steps were not attempted):

1. Interface static addresses (`frfw.ifaddr`)
2. nftables ruleset, backing up the previous one first (`frfw.apply`)
3. Kea DHCP config, if any zone has a DHCP pool (`frfw.kea`)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from frfw import ifaddr, kea, paths
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
) -> ProvisionResult:
    messages = []

    addr_result = ifaddr.sync_addresses(config, dry_run=dry_run)
    messages.append(addr_result.message)

    ruleset = build_ruleset(config)
    nft_result = apply_ruleset(ruleset, dry_run=dry_run, backup_dir=backup_dir)
    messages.append(nft_result.message)

    dhcp_result = kea.apply_dhcp_config(config, dry_run=dry_run, config_path=kea_config_path)
    messages.append(dhcp_result.message)

    return ProvisionResult(messages=messages)
