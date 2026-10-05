"""Applies a whole `Config` to the running system: addresses, firewall, DHCP.

This is the single "make the system match the config" entrypoint used by
both `firewall-cli apply` and the apply-helper's `apply` command, so the
CLI and the (phase 3) webUI can never drift into applying things in a
different order or forgetting a step.

An apply is one transaction across all of them (ROADMAP SEC-5, review
v0.2.0 R6; `frfw.transaction` has the machinery):

- **Checked before anything changes** (`preflight`): the ruleset with
  `nft -c`, the Kea config with `kea-dhcp4 -t`, the resolver's with
  `dnsmasq --test`, the network devices the steps will touch, the XDP
  blocklist. A config that fails here changes nothing at all.
- **Journalled, then rolled back on failure.** Each step records how to
  undo itself before it changes anything; when one fails, the steps done
  so far are undone in reverse order -- the firewall last, so the box is
  filtered throughout. The error names the step, what was rolled back
  and anything that couldn't be.
- **Recorded on success.** The text of a config applied in full is kept
  root-only (`paths.APPLIED_CONFIG_PATH`): it is what the steps that
  reconcile the system with a config are rolled back to, and what the
  router boots into when config.yaml fails at boot (`firewall-cli apply
  --fail-closed`).

Steps run in this order. The ruleset goes first, so the box is filtered
before anything else comes up:

1. nftables ruleset, backing up the previous one first (`frfw.apply`),
   with scheduled rules rendered for the current UTC offset and that
   offset recorded for the hourly DST check (`frfw.schedule_refresh`) --
   carrying the brute-force jail, the AI IDS quarantine, ZTNA sessions
   and isolated IoT devices over the reload in the same transaction (see
   the comment at the top of apply_all and `frfw.bruteforce`/`frfw.ids_quarantine`/
   `frfw.ztna`'s module docstrings for why)
2. IPv4 forwarding, and the WireGuard tunnel (`frfw.forwarding`,
   `frfw.wireguard`) -- only behind the loaded ruleset
3. Interface static addresses (`frfw.ifaddr`) -- after the ruleset, so
   no address is brought up before the rules that filter it
4. Kea DHCP config, if any zone has a DHCP pool (`frfw.kea`)
5. Ad-block DNS resolver: (re)start/stop the dedicated dnsmasq instance
   to match `config.adblocker.enabled`, serving whatever
   `firewall-cli adblock-refresh` most recently downloaded -- never
   fetches anything from the network itself (`frfw.adblock.dns_service`)
6. XDP TLS SNI filter attach/detach + blocklist sync (`frfw.xdp`) --
   the effective blocklist is `xdp_sni_filter.blocklist` plus, if
   `adblocker.xdp_critical_limit` is set, up to that many domains from
   the already-refreshed ad-block list, and with
   `app_control.block_via_xdp` the blocked apps' catalog names, merged
   in-memory only (never written back to config.yaml -- see
   `xdp_config_for`)
7. ZTNA gate: report how many active sessions survived step 1's reload,
   then the same for isolated IoT devices (`frfw.iot_isolation`, only
   when `iot.enabled`)
8. Hybrid PQC management-layer key exchange: refresh the webUI's
   OpenSSL config fragment and, if sshd is installed, its KexAlgorithms
   drop-in (`frfw.pqc`)
9. Management plane: sshd's ListenAddress drop-in and, when its
   addresses changed, a delayed webUI restart (`frfw.management`) --
   the webUI and SSH listen only on the management zones' addresses
"""

from __future__ import annotations

import dataclasses
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

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
from frfw import apply as apply_mod
from frfw.adblock import dns_service as adblock_dns
from frfw.apply import NftError, apply_ruleset
from frfw.config import parse_config
from frfw.config.schema import Config
from frfw.nft import RuntimeSets, build_ruleset
from frfw.nft.schedule import current_clock
from frfw.tlsfp import daemon as tlsfp_daemon
from frfw.transaction import (
    ApplyError,
    FileState,
    LinkState,
    ServiceState,
    Transaction,
    write_private,
)


@dataclass(frozen=True)
class ProvisionResult:
    messages: list[str]


@dataclass(frozen=True)
class _Paths:
    backup_dir: Path
    kea_config_path: Path
    xdp_state_path: Path
    pqc_conf_path: Path
    ssh_kex_dropin_path: Path
    adblock_hosts_path: Path
    adblock_dnsmasq_conf_path: Path
    adblock_category_dir: Path
    schedule_state_path: Path
    ssh_management_dropin_path: Path | None


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
    source_text: str | None = None,
    applied_config_path: Path | None = None,
    transactional: bool = True,
) -> ProvisionResult:
    """Make the system match `config`, as one transaction (see the module
    docstring). Raises `ApplyError` when it fails; a dry run changes
    nothing and raises whatever its checks raise.

    `source_text` is the YAML `config` was parsed from: once the apply
    succeeds it becomes the record of the applied config. Without it the
    record is left as it is. `transactional=False` is the boot's last
    resort only (`firewall-cli apply --fail-closed`, when neither
    config.yaml nor the last applied config could be applied): no
    preflight and no rollback, so the ruleset loads even when a later
    step can't succeed on this hardware."""
    where = _Paths(backup_dir, kea_config_path, xdp_state_path, pqc_conf_path, ssh_kex_dropin_path,
                   adblock_hosts_path, adblock_dnsmasq_conf_path, adblock_category_dir, schedule_state_path,
                   ssh_management_dropin_path)
    if dry_run:
        return ProvisionResult(_Run(config, where, dry_run=True).run())

    record = applied_config_path or paths.APPLIED_CONFIG_PATH
    if transactional:
        preflight(config, adblock_hosts_path=adblock_hosts_path, adblock_category_dir=adblock_category_dir)
    run = _Run(config, where, dry_run=False, previous=load_applied_config(record),
               journal=Transaction() if transactional else None)
    messages = run.run()
    if source_text is not None:
        write_private(record, source_text)
    return ProvisionResult(messages)


def load_applied_config(path: Path | None = None) -> Config | None:
    """The config last applied in full, or None: never recorded (first
    boot, or the first apply after an update to this version), or no
    longer a valid config (an update changed the schema)."""
    text = applied_config_text(path)
    if text is None:
        return None
    try:
        return parse_config(yaml.safe_load(text))
    except Exception:
        return None


def applied_config_text(path: Path | None = None) -> str | None:
    try:
        return (path or paths.APPLIED_CONFIG_PATH).read_text()
    except (FileNotFoundError, NotADirectoryError):
        return None


# --- preflight -------------------------------------------------------------


def preflight(config: Config, *, adblock_hosts_path: Path = paths.ADBLOCK_HOSTS_PATH,
              adblock_category_dir: Path = paths.ADBLOCK_CATEGORY_DIR) -> None:
    """Everything that can be checked without changing anything, before
    anything changes (ROADMAP SEC-5). Raises ApplyError(changed=False)."""
    checks: list[tuple[str, Callable[[], None]]] = [
        ("the firewall ruleset", lambda: apply_mod.check_syntax(
            build_ruleset(config, clock=_schedule_clock(config), runtime=RuntimeSets()))),
        ("network devices", lambda: _check_devices(config)),
    ]
    if config.dhcp.zones:
        checks.append(("DHCP (Kea)", lambda: kea.check_syntax(kea.render_kea_config(config))))
    if config.adblocker.enabled:
        checks.append(("the ad-block DNS resolver", lambda: _check_dnsmasq(
            config, adblock_hosts_path, adblock_category_dir)))
    if config.xdp_sni_filter.enabled:
        checks.append(("the XDP SNI filter", lambda: _check_xdp(config, adblock_hosts_path)))
    for step, check in checks:
        try:
            check()
        except Exception as exc:
            raise ApplyError(step, exc, changed=False) from exc


def _check_devices(config: Config) -> None:
    """The devices a step will act on must be there (a VLAN device is
    created from its parent, so the parent must be). Devices only named
    in rules are not required: nft matches interfaces by name."""
    wanted = set()
    for iface in config.interfaces.values():
        if iface.vlan_id is not None:
            wanted.add(iface.vlan_parent)
        elif iface.address:
            wanted.add(iface.device)
    vlans = {i.device for i in config.interfaces.values() if i.vlan_id is not None}
    if config.xdp_sni_filter.enabled:
        wanted.update(config.interfaces[name].device for name in config.xdp_sni_filter.interfaces
                      if config.interfaces[name].device not in vlans)
    missing = sorted(d for d in wanted if not ifaddr.device_exists(d))
    if missing:
        raise ifaddr.IfaddrError(f"no such network device on this machine: {', '.join(missing)}")


def _check_dnsmasq(config: Config, hosts_path: Path, category_dir: Path) -> None:
    text = adblock_dns.render_dnsmasq_config(config, hosts_path=hosts_path, category_dir=category_dir)
    with tempfile.TemporaryDirectory() as tmp:
        conf = Path(tmp) / "dnsmasq.conf"
        conf.write_text(text)
        adblock_dns.test_dnsmasq_config(conf)


def _check_xdp(config: Config, hosts_path: Path) -> None:
    xdp_config, _ = xdp_config_for(config, hosts_path)
    names = xdp_config.xdp_sni_filter.blocklist
    if len(names) > xdp.BLOCKLIST_MAX_ENTRIES:
        raise xdp.XdpError(f"XDP blocklist has {len(names)} names, more than the kernel map's "
                           f"{xdp.BLOCKLIST_MAX_ENTRIES}")
    for name in names:
        xdp.build_lpm_key(name)


# --- the steps -------------------------------------------------------------


class _Run:
    """One pass of the steps, journalled unless it is a dry run or the
    boot's last resort."""

    def __init__(self, config: Config, where: _Paths, *, dry_run: bool,
                 previous: Config | None = None, journal: Transaction | None = None) -> None:
        self.config = config
        self.where = where
        self.dry_run = dry_run
        self.previous = previous
        self.journal = journal
        self.step = ""
        self.changed = False

    def begin(self, step: str, undo: Callable[[], object] | None = None, why_not: str = "") -> None:
        self.step = step
        if self.journal is not None and not self.dry_run:
            self.changed = True
            self.journal.begin(step, undo, why_not=why_not)

    def run(self) -> list[str]:
        try:
            return self._steps()
        except ApplyError:
            raise
        except Exception as exc:
            if self.dry_run:
                raise
            if self.journal is None:
                raise ApplyError(self.step, exc, changed=True, not_rolled_back=(
                    "everything before it (boot's last-resort apply, no rollback)",)) from exc
            rolled_back, not_rolled_back = self.journal.roll_back()
            raise ApplyError(self.step, exc, changed=self.changed, rolled_back=rolled_back,
                             not_rolled_back=not_rolled_back) from exc

    def _steps(self) -> list[str]:
        config, where, dry_run = self.config, self.where, self.dry_run
        messages: list[str] = []

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
        self.step = "reading the firewall's live sets"
        if dry_run:
            runtime = RuntimeSets()
        else:
            try:
                runtime = _read_runtime_sets(config)
            except NftError as exc:
                raise ApplyError(self.step, exc, changed=False) from exc

        if not dry_run:
            self.begin("the firewall", *self._firewall_undo())
        messages += _firewall(config, where, runtime=runtime, dry_run=dry_run)
        bruteforce_preserved = sum(1 for _, left in runtime.bruteforce_jail if left > 0)
        ids_quarantine_preserved = sum(1 for _, left in runtime.ids_quarantine if left > 0)
        ztna_preserved = sum(1 for *_, left in runtime.ztna if left > 0) if config.ztna.enabled else 0
        iot_preserved = len(runtime.iot_isolated) if config.iot.enabled else 0

        # Routing only once the forward chain is loaded (frfw.forwarding).
        if not dry_run:
            switch = forwarding.IP_FORWARD_PATH
            was = _read(switch)
            self.begin("IPv4 forwarding", lambda: _write_back(switch, was))
        messages.append(forwarding.enable(dry_run=dry_run))

        # The VPN tunnel (security-lessons G8), also only behind the ruleset,
        # and before the management sync below, which may listen on its
        # address.
        if not dry_run:
            self.begin("WireGuard", *self._wireguard_undo())
        messages.append(wireguard.sync(config, dry_run=dry_run).message)

        # Addresses only after the ruleset is in: it also means no address
        # is brought up before the rules that filter it.
        if not dry_run:
            links = [LinkState.capture(d) for d in _address_devices(config)]
            self.begin("interface addresses", lambda: [link.restore() for link in reversed(links)])
        messages.append(ifaddr.sync_addresses(config, dry_run=dry_run).message)

        if not dry_run and config.dhcp.zones:
            kea_file = FileState.capture(where.kea_config_path)
            kea_unit = ServiceState.capture(kea.KEA_SERVICE_NAME)
            self.begin("DHCP (Kea)", lambda: _restore_service(kea_file, kea_unit))
        messages.append(kea.apply_dhcp_config(config, dry_run=dry_run, config_path=where.kea_config_path).message)

        if not dry_run:
            dns_file = FileState.capture(where.adblock_dnsmasq_conf_path)
            dns_unit = ServiceState.capture(paths.ADBLOCK_DNS_SERVICE_NAME)
            self.begin("the ad-block DNS resolver", lambda: _restore_service(dns_file, dns_unit))
        messages.append(adblock_dns.sync_dns_resolver(
            config,
            dry_run=dry_run,
            hosts_path=where.adblock_hosts_path,
            conf_path=where.adblock_dnsmasq_conf_path,
            category_dir=where.adblock_category_dir,
        ).message)

        xdp_config, too_long = xdp_config_for(config, where.adblock_hosts_path)
        if too_long:
            # The names are shown in full, not abbreviated and not moved to
            # debug level: they come from this router's own app catalog, so
            # they are the operator's own configuration being echoed back to
            # them, and naming them *is* the finding -- a name not named is a
            # name the operator believes is blocked and is not (ROADMAP SEC-17).
            messages.append(
                f"XDP blocklist: {len(too_long)} name(s) are {xdp.MAX_SNI_LEN} bytes or "
                f"longer and are NOT blocked in XDP (the kernel filter's MAX_SNI_LEN "
                f"limit): {xdp.sample_names(too_long)}. They are still blocked at the "
                f"app-level DNS layer, which is a later and coarser one."
            )
        if not dry_run:
            self.begin("the XDP SNI filter", *self._xdp_undo())
        messages.append(xdp.sync_sni_filter(xdp_config, dry_run=dry_run, state_path=where.xdp_state_path).message)
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

        if not dry_run:
            tls_file = FileState.capture(where.pqc_conf_path)
            self.begin("the webUI's TLS key exchange", tls_file.restore)
        messages.append(pqc.sync_tls_pqc_conf(config, dry_run=dry_run, conf_path=where.pqc_conf_path).message)

        if not dry_run:
            kex_file = FileState.capture(where.ssh_kex_dropin_path)
            self.begin("SSH key exchange", lambda: _restore_ssh_file(kex_file))
        messages.append(pqc.sync_ssh_kex(config, dry_run=dry_run, dropin_path=where.ssh_kex_dropin_path).message)

        # Security-lessons F2/G4: the webUI and sshd listen on the management
        # zones' addresses only (the input chain above already drops them
        # from everywhere else).
        if not dry_run:
            self.begin("SSH listen addresses", self._sshd_undo())
        messages.append(management.sync_sshd(config, dry_run=dry_run,
                                             dropin_path=where.ssh_management_dropin_path).message)
        # Last: it only schedules a webUI restart, so it runs only once
        # everything before it succeeded, and has nothing to undo.
        self.step = "the webUI's listen addresses"
        messages.append(management.sync_webui(config, dry_run=dry_run).message)
        if config.management.allow_wan:
            messages.append("WARNING: " + management.WAN_WARNING)
        return messages

    # -- how each step is undone ---------------------------------------------

    def _firewall_undo(self) -> tuple[Callable[[], object] | None, str]:
        schedule = FileState.capture(self.where.schedule_state_path)
        if self.previous is not None:
            previous = self.previous

            def rebuild() -> None:
                # The last applied config, with the live sets read again
                # now: a ban or session added since the apply began is kept.
                _firewall(previous, self.where, runtime=_read_runtime_sets(previous), dry_run=False)
            return rebuild, ""
        before = apply_mod.capture_running_ruleset()
        if before.strip():
            def reload() -> None:
                apply_mod.load_captured(before)
                schedule.restore()
            return reload, ""
        return None, "nothing was loaded before it, so the new ruleset stays: the router is never left unfiltered"

    def _wireguard_undo(self) -> tuple[Callable[[], object] | None, str]:
        if self.previous is not None:
            previous = self.previous
            return (lambda: wireguard.sync(previous)), ""
        if not wireguard.tunnel_exists():
            off = dataclasses.replace(self.config, wireguard=dataclasses.replace(self.config.wireguard, enabled=False))
            return (lambda: wireguard.sync(off)), ""
        return None, "no config was recorded as applied before, so the tunnel as it was is unknown"

    def _xdp_undo(self) -> tuple[Callable[[], object] | None, str]:
        state_path = self.where.xdp_state_path
        if self.previous is not None:
            before, _ = xdp_config_for(self.previous, self.where.adblock_hosts_path)
            return (lambda: xdp.sync_sni_filter(before, state_path=state_path)), ""
        if not xdp.get_attached(state_path) and not xdp.is_loaded():
            off = dataclasses.replace(self.config, xdp_sni_filter=dataclasses.replace(
                self.config.xdp_sni_filter, enabled=False))
            return (lambda: xdp.sync_sni_filter(off, state_path=state_path)), ""
        return None, "no config was recorded as applied before, so its blocklist and devices are unknown"

    def _sshd_undo(self) -> Callable[[], object]:
        dropin_path = self.where.ssh_management_dropin_path or paths.SSHD_MANAGEMENT_DROPIN_PATH
        dropin = FileState.capture(dropin_path)
        if shutil.which(management.SSHD_BINARY) is None:
            return dropin.restore  # sync_sshd is a no-op without sshd
        unit = ServiceState.capture(management.SSH_UNITS[0])
        enabled = ServiceState.enabled(management.SSH_UNITS[0])

        def undo() -> None:
            changed = dropin.differs()
            dropin.restore()
            ServiceState.set_enabled(management.SSH_UNITS[0], enabled)
            unit.restore(config_changed=changed, how="reload-or-restart")
        return undo


def _firewall(config: Config, where: _Paths, *, runtime: RuntimeSets, dry_run: bool) -> list[str]:
    # Phase 17: scheduled rules are rendered for the offset in effect now;
    # the same clock is recorded below so the hourly schedule-check can
    # spot a DST change (frfw.schedule_refresh).
    clock = _schedule_clock(config)
    ruleset = build_ruleset(config, clock=clock, runtime=runtime)
    messages = [apply_ruleset(ruleset, dry_run=dry_run, backup_dir=where.backup_dir).message]
    if clock is not None:
        scheduled = sum(1 for r in config.rules if r.schedule is not None)
        zone = config.timezone or "system local time"
        messages.append(f"Scheduled rules: {scheduled}, rendered for {clock.describe()} ({zone})")
        if not dry_run:
            schedule_refresh.record_applied(config, clock, where.schedule_state_path)
    elif not dry_run:
        schedule_refresh.clear_record(where.schedule_state_path)
    return messages


def _schedule_clock(config: Config):
    return current_clock(config.timezone) if schedule_refresh.has_schedules(config) else None


def xdp_config_for(config: Config, adblock_hosts_path: Path) -> tuple[Config, list[str]]:
    """`config` with the XDP blocklist the kernel gets, and the names left
    out of it.

    The kernel-level "critical" adblock subset (if configured) is merged
    into the XDP blocklist here, in memory only -- never persisted back
    into config.yaml -- so the file on disk always reflects exactly what
    the admin actually configured, the same way a ZTNA-authorized IP never
    gets written into the firewall rules themselves. If
    xdp_sni_filter.enabled is False, this has no effect: enabling
    adblocker never silently turns XDP on. Phase 16: blocked apps' catalog
    names, the same in-memory-only merge.

    A name of MAX_SNI_LEN bytes or more can never match in the kernel
    filter (bpf/xdp_sni_filter.c's parse_sni_body() refuses it before it
    builds a key), so it is left out rather than handed to sync_blocklist,
    which would abort the whole apply on it -- and returned, so the apply
    names it: the app-level DNS blocking still covers it, a different,
    much later layer (ROADMAP SEC-17)."""
    extra: set[str] = set()
    if config.adblocker.enabled and config.adblocker.xdp_critical_limit > 0:
        extra.update(adblock_dns.critical_domains(adblock_hosts_path, config.adblocker.xdp_critical_limit))
    if config.app_control.block_via_xdp:
        extra.update(adblock_dns.blocked_app_names(config))
    too_long = sorted(n for n in extra if len(n) >= xdp.MAX_SNI_LEN)
    extra.difference_update(too_long)
    if not extra:
        return config, too_long
    merged = sorted(set(config.xdp_sni_filter.blocklist) | extra)
    return dataclasses.replace(
        config, xdp_sni_filter=dataclasses.replace(config.xdp_sni_filter, blocklist=merged)), too_long


def _address_devices(config: Config) -> list[str]:
    """What frfw.ifaddr may change: the devices it addresses or creates
    (VLANs), and the VLANs' parents, which it brings up."""
    devices: list[str] = []
    for iface in config.interfaces.values():
        if iface.vlan_id is not None and iface.vlan_parent not in devices:
            devices.append(iface.vlan_parent)
    for iface in config.interfaces.values():
        if (iface.address or iface.vlan_id is not None) and iface.device not in devices:
            devices.append(iface.device)
    return devices


def _read(path: Path) -> str | None:
    try:
        return path.read_text()
    except OSError:
        return None


def _write_back(path: Path, text: str | None) -> None:
    if text is not None and _read(path) != text:
        path.write_text(text)


def _restore_service(file: FileState, unit: ServiceState) -> None:
    changed = file.differs()
    file.restore()
    unit.restore(config_changed=changed)


def _restore_ssh_file(file: FileState) -> None:
    if not file.differs():
        return
    file.restore()
    if shutil.which(management.SSHD_BINARY) is not None:
        ServiceState.capture(management.SSH_UNITS[0]).restore(config_changed=True, how="reload-or-restart")


def _read_runtime_sets(config: Config) -> RuntimeSets:
    """The members to carry over the reload (see the firewall step)."""
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
