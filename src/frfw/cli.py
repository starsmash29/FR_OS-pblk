"""`firewall-cli`: command-line entry point for the frfw engine.

    firewall-cli validate [config.yaml]
    firewall-cli render   [config.yaml]
    firewall-cli config-export [config.yaml]
    firewall-cli apply    [config.yaml] [--dry-run] [--fail-closed]
    firewall-cli rollback [--list]
    firewall-cli detect-interfaces [--include-virtual]
    firewall-cli detect-wan-lan
    firewall-cli assign-interfaces --wan DEV --lan DEV [--opt NAME:DEV ...] [--out PATH]
    firewall-cli set-admin-password [--username admin] [--generate [--show-on-console]]
    firewall-cli initial-password
    firewall-cli ensure-accounts
    firewall-cli users
    firewall-cli surface [config.yaml]
    firewall-cli integrity
    firewall-cli mfa-reset USER
    firewall-cli ids-status
    firewall-cli iot-status
    firewall-cli apps-status [--limit N]
    firewall-cli tls-fingerprints
    firewall-cli metrics-token (--generate | --disable) [--site NAME] [config.yaml]
    firewall-cli schedule-check [config.yaml]
    firewall-cli rule-check [config.yaml]
    firewall-cli update check [config.yaml]
    firewall-cli update auto [config.yaml]
    firewall-cli update apply VERSION [--repo OWNER/REPO]
    firewall-cli update rollback [--repo OWNER/REPO]
    firewall-cli xdp-status
    firewall-cli adblock-refresh [--scheduled] [config.yaml]
    firewall-cli dns-log-trim
    firewall-cli persistence status
    firewall-cli persistence auto [--reboot]
    firewall-cli persistence create DISK [--wipe] --yes

`config.yaml` defaults to the canonical /etc/fr_os/config.yaml location
(see frfw.paths) wherever a config path is optional, so that on a real
router `firewall-cli apply` with no arguments does the expected thing.

`update apply`/`update rollback` do real, privileged work (pip install,
systemd unit/service changes) and are meant for the update-helper daemon
or an admin recovering manually over SSH -- like `apply`/`rollback` for
the firewall config, they assume they are already running with whatever
privilege the operator invoked them with (see frfw.update's docstring).
The webUI never calls these directly; it goes through
frfw.helper.update_client's separate privileged socket instead.
"""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import subprocess
import sys
from pathlib import Path

import yaml

from frfw import __version__, codename_for, netdetect, paths, schedule_refresh, skeleton, xdp as xdp_mod
from frfw import accounts as accounts_mod
from frfw import initial_password, passwords, rule_hits, rule_lint
from frfw import persistence as persistence_mod
from frfw import update as update_mod
from frfw.adblock import AdblockError
from frfw.adblock import refresh as adblock_refresh
from frfw.admin_account import ROLE_ADMIN, AccountError, AdminStore
from frfw.appid import load_catalog
from frfw.appid.daemon import load_usage
from frfw import apply as apply_mod
from frfw.apply import NftError, list_backups, rollback_last
from frfw.tlsfp.daemon import load_state as load_tlsfp_state
from frfw.config import ConfigError, load_config, parse_config, read_config
from frfw.config import export as export_mod
from frfw.forwarding import ForwardingError
from frfw.wireguard import WireguardError
from frfw.metrics import generate_metrics_token
from frfw.ids_quarantine import IdsQuarantineError, list_quarantined
from frfw.iot_isolation import IotIsolationError, list_isolated
from frfw.ifaddr import IfaddrError
from frfw.kea import KeaError
from frfw.nft import build_ruleset
from frfw import provision
from frfw.provision import apply_all
from frfw.transaction import ApplyError


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 1
    except NftError as exc:
        print(f"nft error: {exc}", file=sys.stderr)
        return 1
    except IfaddrError as exc:
        print(f"interface address error: {exc}", file=sys.stderr)
        return 1
    except KeaError as exc:
        print(f"DHCP (Kea) error: {exc}", file=sys.stderr)
        return 1
    except update_mod.UpdateError as exc:
        print(f"update error: {exc}", file=sys.stderr)
        return 1
    except xdp_mod.XdpError as exc:
        print(f"XDP SNI filter error: {exc}", file=sys.stderr)
        return 1
    except IdsQuarantineError as exc:
        print(f"AI IDS quarantine error: {exc}", file=sys.stderr)
        return 1
    except IotIsolationError as exc:
        print(f"IoT isolation error: {exc}", file=sys.stderr)
        return 1
    except ForwardingError as exc:
        print(f"routing error: {exc}", file=sys.stderr)
        return 1
    except WireguardError as exc:
        print(f"WireGuard error: {exc}", file=sys.stderr)
        return 1
    except ApplyError as exc:
        print(f"apply error: {exc}", file=sys.stderr)
        return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="firewall-cli")
    parser.add_argument("--version", action="version", version=f"FR_OS {_with_codename(__version__)}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_config_arg(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "config",
            nargs="?",
            default=str(paths.CONFIG_PATH),
            help=f"path to config.yaml (default: {paths.CONFIG_PATH})",
        )

    p_validate = sub.add_parser("validate", help="validate a config file")
    add_config_arg(p_validate)
    p_validate.set_defaults(handler=_cmd_validate)

    p_render = sub.add_parser("render", help="print the generated nftables ruleset")
    add_config_arg(p_render)
    p_render.set_defaults(handler=_cmd_render)

    p_export = sub.add_parser(
        "config-export", help="print the config without its secrets (ZTNA hashes, metrics token), safe to share"
    )
    add_config_arg(p_export)
    p_export.set_defaults(handler=_cmd_config_export)

    p_apply = sub.add_parser(
        "apply", help="apply interface addresses, the nftables ruleset, and DHCP"
    )
    add_config_arg(p_apply)
    p_apply.add_argument(
        "--dry-run",
        action="store_true",
        help="check syntax and print what would happen, but don't load it",
    )
    p_apply.add_argument(
        "--fail-closed",
        action="store_true",
        help="if there is no config, or the apply fails with no FR_OS ruleset loaded, "
        "load the drop-everything baseline (fr-firewall.service uses this)",
    )
    p_apply.set_defaults(handler=_cmd_apply)

    p_rollback = sub.add_parser(
        "rollback", help="reload the most recently backed-up ruleset"
    )
    p_rollback.add_argument(
        "--list", action="store_true", help="list available backups and exit"
    )
    p_rollback.set_defaults(handler=_cmd_rollback)

    p_detect = sub.add_parser(
        "detect-interfaces", help="list network interfaces available for assignment"
    )
    p_detect.add_argument(
        "--include-virtual",
        action="store_true",
        help="also list virtual interfaces (veth, docker0, tun/tap, ...)",
    )
    p_detect.set_defaults(handler=_cmd_detect_interfaces)

    p_wan_lan = sub.add_parser(
        "detect-wan-lan",
        help="pick the WAN and LAN ports by asking each whether a DHCP server answers (first boot; needs root)",
    )
    p_wan_lan.set_defaults(handler=_cmd_detect_wan_lan)

    p_assign = sub.add_parser(
        "assign-interfaces",
        help="generate a minimal config from a WAN/LAN/OPT role assignment",
    )
    p_assign.add_argument("--wan", required=True, metavar="DEVICE", help="WAN device, e.g. eth0")
    p_assign.add_argument("--lan", required=True, metavar="DEVICE", help="LAN device, e.g. eth1")
    p_assign.add_argument(
        "--opt",
        action="append",
        default=[],
        metavar="ZONE:DEVICE",
        help="additional zone, e.g. dmz:eth2 (repeatable)",
    )
    p_assign.add_argument("--hostname", default="fr-router")
    p_assign.add_argument(
        "--out",
        default=str(paths.CONFIG_PATH),
        help=f"where to write the generated config (default: {paths.CONFIG_PATH})",
    )
    p_assign.add_argument(
        "--force", action="store_true", help="overwrite --out if it already exists"
    )
    p_assign.set_defaults(handler=_cmd_assign_interfaces)

    p_admin = sub.add_parser(
        "set-admin-password",
        help="create or reset a webUI account as admin (recovery path: always grants the admin role)",
    )
    p_admin.add_argument("--username", default="admin")
    p_admin.add_argument(
        "--generate",
        action="store_true",
        help="generate a random password instead of prompting, and print only "
        "the password to stdout (for non-interactive first-boot use)",
    )
    p_admin.add_argument(
        "--show-on-console",
        action="store_true",
        help="with --generate: don't print it, put it on the console's login screen "
        "instead (a root-only /etc/issue.d file, removed once the password is changed)",
    )
    p_admin.set_defaults(handler=_cmd_set_admin_password)

    p_mfa_reset = sub.add_parser(
        "mfa-reset",
        help="remove every second factor of a webUI account (recovery when a key or phone is lost)",
    )
    p_mfa_reset.add_argument("username")
    p_mfa_reset.set_defaults(handler=_cmd_mfa_reset)

    p_initial = sub.add_parser(
        "initial-password",
        help="remove the generated password from the console once it was changed (root; "
        "fr-initial-password.service runs this)",
    )
    p_initial.set_defaults(handler=_cmd_initial_password)

    p_accounts = sub.add_parser(
        "ensure-accounts",
        help="create the fr_os-webui/fr_os-sensor system users and their state directories (root)",
    )
    p_accounts.set_defaults(handler=_cmd_ensure_accounts)

    p_users = sub.add_parser("users", help="list the webUI accounts and their roles")
    p_users.set_defaults(handler=_cmd_users)

    p_surface = sub.add_parser(
        "surface",
        help="list every listening service and which zones can reach it (run as root to see process names)",
    )
    p_surface.add_argument("config", nargs="?", type=Path, default=paths.CONFIG_PATH)
    p_surface.set_defaults(handler=_cmd_surface)

    p_integrity = sub.add_parser(
        "integrity",
        help="check FR_OS's installed files against the signed release they came from (ROADMAP SEC-15)",
        description="Compares FR_OS's installed files -- the Python package and its compiled files, the "
                    "systemd units, the scripts, the XDP program -- with the signed release of the running "
                    "version under /opt/fr_os/releases, and pip's install record for the rest. Without a "
                    "signed release on the router, pip's record only. A check that doesn't trust the "
                    "router at all: scripts/verify-medium.py, from another computer.",
    )
    p_integrity.set_defaults(handler=_cmd_integrity)

    p_ids_status = sub.add_parser(
        "ids-status",
        help="show the AI IDS/IPS engine's currently quarantined hosts",
    )
    p_ids_status.set_defaults(handler=_cmd_ids_status)

    p_iot_status = sub.add_parser(
        "iot-status",
        help="show the MAC addresses currently isolated by IoT isolation (needs root)",
    )
    p_iot_status.set_defaults(handler=_cmd_iot_status)

    p_persist = sub.add_parser(
        "persistence", help="keep a live-booted router's state across reboots (live-boot persistence)"
    )
    persist_sub = p_persist.add_subparsers(dest="persistence_command", required=True)
    persist_sub.add_parser("status", help="show whether changes survive a reboot").set_defaults(
        handler=_cmd_persistence_status
    )
    p_persist_auto = persist_sub.add_parser(
        "auto", help="boot-time step: create a persistence partition on the boot medium if there is room (root)"
    )
    p_persist_auto.add_argument("--reboot", action="store_true", help="reboot when one was created, to start using it")
    p_persist_auto.set_defaults(handler=_cmd_persistence_auto)
    p_persist_create = persist_sub.add_parser(
        "create", help="turn a whole disk (e.g. an internal SSD) into the persistence disk (root, destructive)"
    )
    p_persist_create.add_argument("disk", help="whole disk, e.g. /dev/sdb or /dev/nvme0n1")
    p_persist_create.add_argument("--wipe", action="store_true", help="allowed to erase a disk that has partitions")
    p_persist_create.add_argument("--yes", action="store_true", help="confirm: everything on DISK is erased")
    p_persist_create.set_defaults(handler=_cmd_persistence_create)

    p_kernel = sub.add_parser(
        "kernel", help="a kernel staged on the persistence partition, tried once at the next reboot (ROADMAP SEC-14)"
    )
    kernel_sub = p_kernel.add_subparsers(dest="kernel_command", required=True)
    kernel_sub.add_parser("status", help="the running kernel and the staged one").set_defaults(
        handler=_cmd_kernel_status
    )
    p_kernel_stage = kernel_sub.add_parser(
        "stage", help="stage a kernel and its initrd; the next reboot tries it once (root; never reboots)"
    )
    p_kernel_stage.add_argument("kernel", type=Path, help="the kernel image (vmlinuz)")
    p_kernel_stage.add_argument("initrd", type=Path, help="its initrd, built with live-boot")
    p_kernel_stage.add_argument("--version", required=True, help="its release, e.g. 6.1.0-28-amd64")
    p_kernel_stage.set_defaults(handler=_cmd_kernel_stage)
    kernel_sub.add_parser("unstage", help="back to the image's own kernel at the next reboot (root)").set_defaults(
        handler=_cmd_kernel_unstage
    )
    kernel_sub.add_parser(
        "confirm-boot", help="boot-time step (fr-kernel-confirm.service): keep a staged kernel the router came up on"
    ).set_defaults(handler=_cmd_kernel_confirm_boot)

    p_mtoken = sub.add_parser(
        "metrics-token",
        help="turn GET /metrics on with a bearer token for a Prometheus (phase 20; off without one, ROADMAP SEC-3)",
    )
    add_config_arg(p_mtoken)
    mode = p_mtoken.add_mutually_exclusive_group()
    mode.add_argument("--generate", action="store_true", help="create a new token (printed once) and require it")
    mode.add_argument("--disable", action="store_true", help="remove the token: /metrics is off again")
    p_mtoken.add_argument("--site", help="set metrics.site, this router's name in the fleet")
    p_mtoken.set_defaults(handler=_cmd_metrics_token)

    p_tlsfp = sub.add_parser(
        "tls-fingerprints", help="show the TLS client fingerprints (JA4/JA3) seen per device (from fr-tls-fp)"
    )
    p_tlsfp.set_defaults(handler=_cmd_tls_fingerprints)

    p_schedule = sub.add_parser(
        "schedule-check",
        help="re-apply if scheduled rules are stale after a DST/time zone change (hourly timer)",
    )
    add_config_arg(p_schedule)
    p_schedule.set_defaults(handler=_cmd_schedule_check)

    p_rule_check = sub.add_parser(
        "rule-check",
        help="the rule check: any-to-any, shadowed, unused and expired rules (exit 1 on a warning)",
    )
    add_config_arg(p_rule_check)
    p_rule_check.set_defaults(handler=_cmd_rule_check)

    p_apps_status = sub.add_parser(
        "apps-status",
        help="show which apps clients used in the last 24 hours (from fr-appid)",
    )
    p_apps_status.add_argument("--limit", type=int, default=20, help="show at most N apps")
    p_apps_status.set_defaults(handler=_cmd_apps_status)

    p_update = sub.add_parser("update", help="check for / apply / roll back FR_OS updates")
    update_sub = p_update.add_subparsers(dest="update_command", required=True)

    p_update_check = update_sub.add_parser(
        "check", help="check the configured repo for a newer release"
    )
    add_config_arg(p_update_check)
    p_update_check.set_defaults(handler=_cmd_update_check)

    p_update_auto = update_sub.add_parser(
        "auto",
        help="the periodic check (fr-update-check.timer): record what's available for the webUI's banner",
    )
    add_config_arg(p_update_auto)
    p_update_auto.set_defaults(handler=_cmd_update_auto)

    p_update_apply = update_sub.add_parser(
        "apply", help="download, install and activate a specific version (needs root)"
    )
    p_update_apply.add_argument("version", help="target version, e.g. 0.2.0 or v0.2.0")
    p_update_apply.add_argument("--repo", default=update_mod.DEFAULT_REPO)
    p_update_apply.set_defaults(handler=_cmd_update_apply)

    p_update_rollback = update_sub.add_parser(
        "rollback", help="reinstall the previously active version (needs root)"
    )
    p_update_rollback.add_argument("--repo", default=update_mod.DEFAULT_REPO)
    p_update_rollback.set_defaults(handler=_cmd_update_rollback)

    p_xdp_status = sub.add_parser(
        "xdp-status",
        help="show the XDP TLS SNI filter's attach state and packet counters",
    )
    p_xdp_status.set_defaults(handler=_cmd_xdp_status)

    p_adblock_refresh = sub.add_parser(
        "adblock-refresh",
        help="download+dedupe the configured ad-block lists (needs root); "
        "run daily by fr-adblock-refresh.timer, or on demand from the webUI",
    )
    p_adblock_refresh.add_argument(
        "--scheduled",
        action="store_true",
        help="the timer's run: fetch nothing while ad-blocking is off",
    )
    add_config_arg(p_adblock_refresh)
    p_adblock_refresh.set_defaults(handler=_cmd_adblock_refresh)

    p_dns_log_trim = sub.add_parser(
        "dns-log-trim",
        help="empty the resolver's query log once it is too big (hourly, by fr-dns-log-trim.timer)",
    )
    p_dns_log_trim.set_defaults(handler=_cmd_dns_log_trim)

    return parser


def _cmd_validate(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    print(f"OK: {args.config} is valid ({len(config.rules)} rule(s))")
    return 0


def _cmd_render(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    print(build_ruleset(config), end="")
    return 0


def _cmd_config_export(args: argparse.Namespace) -> int:
    from frfw.config.export import export_text

    raw = yaml.safe_load(Path(args.config).read_text()) or {}
    sys.stdout.write(export_text(raw))
    return 0


def _cmd_apply(args: argparse.Namespace) -> int:
    fail_closed = args.fail_closed and not args.dry_run
    if fail_closed and not Path(args.config).is_file():
        # Expected on a live image before first boot writes the config.
        apply_mod.load_baseline()
        print(f"No config at {args.config}: fail-closed baseline loaded "
              "(only loopback and replies to the router's own connections get in; nothing is forwarded)")
        return 0
    try:
        config, text = read_config(args.config)
        try:
            result = apply_all(config, dry_run=args.dry_run, source_text=text)
        except ApplyError as exc:
            if not fail_closed:
                raise
            result = _boot_without(config, exc)
        if not args.dry_run:
            # ROADMAP SEC-11: the parser daemons' copy without secrets --
            # also at boot, where fr-firewall.service runs this.
            problem = export_mod.refresh_sensor_copy(Path(args.config))
            if problem:
                result.messages.append(problem)
    except Exception:
        # Never leave the box unfiltered because of a bad config or a
        # missing NIC -- but never replace a working ruleset either
        # (nft -f is atomic, so a failed reload keeps the previous one).
        if fail_closed and not apply_mod.fr_os_table_loaded():
            apply_mod.load_baseline()
            print("apply failed with no FR_OS ruleset loaded: fail-closed baseline loaded", file=sys.stderr)
        raise
    for message in result.messages:
        print(message)
    return 0


def _boot_without(config, failure: ApplyError):
    """config.yaml failed at boot (`apply --fail-closed`) and was rolled
    back (ROADMAP SEC-5). Boot into the last config applied in full, if
    there is one and it is another config; and when that fails too, or
    there is none, apply config.yaml as far as it goes, without a
    preflight or rollback -- the ruleset first, so the router is filtered
    whatever fails after it. Either way it is a security alert."""
    print(f"config.yaml could not be applied: {failure}", file=sys.stderr)
    last = provision.load_applied_config()
    if last is not None and last != config:
        try:
            result = apply_all(last)
        except ApplyError as again:
            print(f"the last applied config could not be applied either: {again}", file=sys.stderr)
        else:
            warning = ("config.yaml could not be applied at boot, so the router runs the last config that was "
                       f"applied in full: {failure}")
            _console_alert(warning, user="boot", client="boot")
            result.messages.insert(0, "WARNING: " + warning)
            return result
    _console_alert(f"config.yaml could not be applied at boot; applied as far as it goes: {failure}",
                   user="boot", client="boot")
    return apply_all(config, transactional=False)


def _cmd_rollback(args: argparse.Namespace) -> int:
    if args.list:
        backups = list_backups()
        if not backups:
            print(f"No backups found in {paths.BACKUP_DIR}")
        for backup in backups:
            print(backup)
        return 0

    restored = rollback_last()
    print(f"Rolled back to {restored}")
    return 0


def _cmd_detect_interfaces(args: argparse.Namespace) -> int:
    interfaces = netdetect.list_interfaces(include_virtual=args.include_virtual)
    if not interfaces:
        print("No network interfaces detected")
        return 0

    print(f"{'NAME':<10} {'DRIVER':<16} {'MAC':<18} {'LINK':<6} SPEED")
    for iface in interfaces:
        link = "up" if iface.link_up else ("down" if iface.link_up is not None else "?")
        speed = f"{iface.speed_mbps}Mb/s" if iface.speed_mbps else "-"
        print(
            f"{iface.name:<10} {iface.driver or '?':<16} "
            f"{iface.mac_address or '?':<18} {link:<6} {speed}"
        )
    return 0


def _cmd_detect_wan_lan(args: argparse.Namespace) -> int:
    """For fr-first-boot.sh: line 1 is "WAN LAN" (nothing when there is no
    safe choice), line 2 says why (ROADMAP SEC-8). Exit 1 without a choice."""
    choice = netdetect.choose_wan_lan(netdetect.list_interfaces(), netdetect.dhcp_server_answers)
    print(f"{choice.wan} {choice.lan}" if choice.wan and choice.lan else "")
    print(choice.basis)
    return 0 if choice.wan and choice.lan else 1


def _cmd_assign_interfaces(args: argparse.Namespace) -> int:
    opt_devices: dict[str, str] = {}
    for entry in args.opt:
        if ":" not in entry:
            print(f"error: --opt expects ZONE:DEVICE, got {entry!r}", file=sys.stderr)
            return 1
        zone, device = entry.split(":", 1)
        opt_devices[zone] = device

    out_path = Path(args.out)
    if out_path.exists() and not args.force:
        print(f"error: {out_path} already exists (use --force to overwrite)", file=sys.stderr)
        return 1

    config_text = skeleton.build_skeleton_config(
        wan_device=args.wan,
        lan_device=args.lan,
        opt_devices=opt_devices,
        hostname=args.hostname,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(config_text)
    print(f"Wrote {out_path}")
    return 0


def _cmd_set_admin_password(args: argparse.Namespace) -> int:
    if args.generate:
        # Non-interactive path for fr-first-boot.sh: no prompts, and the
        # only thing printed to stdout is the password itself, so a
        # caller can safely capture it (e.g. `pw=$(firewall-cli
        # set-admin-password --generate)`) without scraping other output.
        password = secrets.token_urlsafe(18)
        # The first sign-in then asks for the admin's own username and
        # password (security-lessons G1).
        AdminStore().set_password(args.username, password, ROLE_ADMIN, must_change=True)
        if args.show_on_console:
            initial_password.write(args.username, password)
            print(f"Generated a password for {args.username!r}; it is shown on the console "
                  f"({initial_password.ISSUE_PATH}, root-only) until it is changed")
        else:
            print(password)
        return 0
    if args.show_on_console:
        print("error: --show-on-console only goes with --generate", file=sys.stderr)
        return 1

    password = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("error: passwords do not match", file=sys.stderr)
        return 1
    weak = passwords.problem(password, args.username)  # security-lessons G6
    if weak:
        print(f"error: {weak}", file=sys.stderr)
        return 1

    AdminStore().set_password(args.username, password, ROLE_ADMIN)
    _console_alert(f"admin account {args.username!r} set from the console (firewall-cli set-admin-password)")
    print(f"Admin account {args.username!r} set")
    return 0


def _console_alert(message: str, *, user: str = "console", client: str = "console") -> None:
    """Security-lessons G9: what is done on the console shows up in the
    webUI's security alerts like what is done in the webUI."""
    from frfw.webui import audit

    try:
        audit.prepare(paths.AUDIT_LOG_PATH)
        audit.alert(paths.AUDIT_LOG_PATH, message, user=user, client=client)
    except OSError:
        pass  # e.g. not root: the change itself stands


def _cmd_mfa_reset(args: argparse.Namespace) -> int:
    store = AdminStore()
    try:
        store.reset_mfa(args.username)
    except AccountError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    # Their open sessions end with it, as when an admin resets it in the webUI:
    # a session secured by the lost factor shouldn't outlive it.
    from frfw.webui.auth import SessionStore  # webUI extra, present wherever accounts are

    SessionStore(paths.WEBUI_SECRET_KEY_PATH.with_name("sessions.json")).revoke_user(args.username)
    _console_alert(f"second factors of {args.username!r} removed from the console (firewall-cli mfa-reset)")
    print(f"Second factors of {args.username!r} removed; they sign in with the password alone until they add one")
    return 0


def _cmd_initial_password(args: argparse.Namespace) -> int:
    if initial_password.migrate_legacy():
        print(f"fr-initial-password: moved the password line out of {initial_password.LEGACY_ISSUE_PATH}")
    if initial_password.clear_if_changed():
        print("fr-initial-password: the initial password was changed; removed it from the console")
    return 0


def _cmd_ensure_accounts(args: argparse.Namespace) -> int:
    try:
        done = accounts_mod.ensure()
    except (accounts_mod.AccountsError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for line in done:
        print(f"fr-accounts: {line}")
    print("fr-accounts: accounts and state directories in place")
    return 0


def _cmd_surface(args: argparse.Namespace) -> int:
    from frfw import management, surface

    try:
        config = load_config(args.config)
        listeners, addresses = surface.collect()
    except (ConfigError, OSError, surface.SurfaceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    internet = management.internet_zones(config)
    rows = surface.surface(config, listeners, addresses)
    for row in rows:
        l = row.listener
        where = f"{l.address}%{l.device}" if l.device else l.address
        reach = ", ".join(f"{zone}: {v.state}" for zone, v in row.zones.items()) or "no zone (loopback/unbound)"
        flag = "  <-- reachable from the internet side" if row.internet else ""
        if row.unneeded:
            flag += "  <-- nothing in the config needs it"
        print(f"{l.proto}/{l.port:<6} {l.label:<24} {where:<22} {reach}{flag}")
    exposed = [r for r in rows if r.internet]
    unneeded = [r for r in rows if r.unneeded]
    if unneeded:
        names = ", ".join(f"{r.listener.proto}/{r.listener.port} {r.listener.label}" for r in unneeded)
        print(f"\nWARNING: not needed by FR_OS, stop it: {names}", file=sys.stderr)
    if exposed:
        print(f"\nWARNING: {len(exposed)} service(s) reachable from {', '.join(sorted(internet))}", file=sys.stderr)
        return 2
    return 3 if unneeded else 0


def _cmd_integrity(args: argparse.Namespace) -> int:
    from frfw import integrity

    report = integrity.check()
    print(f"FR_OS software integrity: {report.summary}")
    for name in report.modified:
        print(f"  modified: {name}")
    for name in report.missing:
        print(f"  missing:  {name}")
    for name in report.added:
        print(f"  added:    {name}")
    if report.ok and not report.basis:
        print("  (against pip's install record only -- see `firewall-cli integrity --help`)")
    if not report.verifiable:
        return 2
    return 0 if report.ok else 1


def _cmd_users(args: argparse.Namespace) -> int:
    accounts = AdminStore().users()
    if not accounts:
        print("No webUI accounts yet: run 'firewall-cli set-admin-password'")
        return 0
    for name in sorted(accounts):
        print(f"{name:<32} {accounts[name].role}")
    return 0


def _cmd_ids_status(args: argparse.Namespace) -> int:
    quarantined = list_quarantined()
    if not quarantined:
        print("AI IDS/IPS: no hosts currently quarantined")
        return 0

    print("AI IDS/IPS: currently quarantined hosts:")
    for ip, remaining in sorted(quarantined):
        print(f"  {ip}: {remaining}s remaining")
    return 0


def _cmd_iot_status(args: argparse.Namespace) -> int:
    isolated = list_isolated()
    if not isolated:
        print("IoT isolation: no devices currently isolated")
        return 0
    print("IoT isolation: currently isolated devices:")
    for mac in sorted(isolated):
        print(f"  {mac}")
    return 0


def _cmd_persistence_status(args: argparse.Namespace) -> int:
    state = persistence_mod.status()
    print(f"Persistence: {state.summary}")
    if state.live:
        print(f"  boot medium: {state.boot_device or '-'}")
        print(f"  'persistence' boot option: {'yes' if state.requested else 'no'}")
    return 0


def _cmd_persistence_auto(args: argparse.Namespace) -> int:
    outcome, device = persistence_mod.auto()
    print(f"fr-persistence: {outcome}{f' ({device})' if device else ''}")
    if outcome == "created":
        print("fr-persistence: rebooting once to start using it -- nothing has been configured yet, so nothing is lost")
        if args.reboot:
            subprocess.run(["systemctl", "reboot"], check=False)
    return 0


def _cmd_persistence_create(args: argparse.Namespace) -> int:
    if not args.yes:
        print(f"error: this erases {args.disk}; add --yes to confirm", file=sys.stderr)
        return 1
    try:
        partition = persistence_mod.create_on_disk(args.disk, wipe=args.wipe)
    except persistence_mod.PersistenceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Created the persistence filesystem on {partition}.")
    print("Reboot: FR_OS will keep its state there from the next boot on.")
    print("Note: what was changed during this boot is not copied over.")
    return 0


def _cmd_kernel_status(args: argparse.Namespace) -> int:
    from frfw import kernel_boot

    state = kernel_boot.status()
    print(f"Kernel: {state.summary}")
    path = kernel_boot.boot_dir()
    if state.state and path is not None:
        for name, digest in sorted(kernel_boot.staged_files(path).items()):
            print(f"  {name}: sha256 {digest}")
    return 0


def _kernel_boot_dir():
    from frfw import kernel_boot

    path = kernel_boot.boot_dir()
    if path is None:
        print("error: no persistence partition in use -- a kernel can only be staged on a live router with "
              "persistence (firewall-cli persistence status)", file=sys.stderr)
    return path


def _cmd_kernel_stage(args: argparse.Namespace) -> int:
    from frfw import kernel_boot

    path = _kernel_boot_dir()
    if path is None:
        return 1
    try:
        kernel_boot.stage(args.kernel, args.initrd, args.version, boot_dir=path)
    except (kernel_boot.KernelBootError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    # Security-lessons G9: what boots the router is the most valuable thing to change.
    _console_alert(f"kernel {args.version} staged: the next reboot tries it once (firewall-cli kernel stage)")
    print(f"Kernel {args.version} staged. The router does not reboot by itself: the next reboot tries it once,")
    print("and keeps it only if the router comes up on it; otherwise the image's own kernel boots again.")
    return 0


def _cmd_kernel_unstage(args: argparse.Namespace) -> int:
    from frfw import kernel_boot

    path = _kernel_boot_dir()
    if path is None:
        return 1
    if not kernel_boot.unstage(boot_dir=path):
        print("Nothing was staged.")
        return 0
    _console_alert("staged kernel removed: the image's own kernel boots from the next reboot (firewall-cli kernel "
                   "unstage)")
    print("Staged kernel removed: the image's own kernel boots from the next reboot.")
    return 0


def _cmd_kernel_confirm_boot(args: argparse.Namespace) -> int:
    """Never fails the unit and never reboots, but for the one case the
    design asks for: a trial boot the router didn't come up on."""
    from frfw import kernel_boot

    path = kernel_boot.boot_dir()
    if path is None:
        print("fr-kernel: no persistence partition in use; nothing to confirm")
        return 0
    try:
        outcome = kernel_boot.confirm_boot(boot_dir_path=path)
    except Exception as exc:  # noqa: BLE001 -- a bug here must not cost the router its boot
        print(f"fr-kernel: could not check this boot: {exc}")
        return 0
    print(f"fr-kernel: {outcome.message}")
    if outcome.alert:
        _console_alert(outcome.alert, user="fr-kernel-confirm", client="boot")
    if outcome.reboot:
        subprocess.run(["systemctl", "reboot"], check=False)
    return 0


def _cmd_metrics_token(args: argparse.Namespace) -> int:
    if not (args.generate or args.disable or args.site):
        print("error: give --generate, --disable and/or --site", file=sys.stderr)
        return 1
    path = Path(args.config)
    raw = yaml.safe_load(path.read_text()) or {}
    section = dict(raw.get("metrics") or {})
    token = None
    if args.generate:
        token, section["token_sha256"] = generate_metrics_token()
    if args.disable:
        section.pop("token_sha256", None)
    if args.site:
        section["site"] = args.site
    raw["metrics"] = section
    parse_config(raw)  # never write a config firewall-cli itself would reject
    text = yaml.safe_dump(raw, sort_keys=False, default_flow_style=False)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    stat = path.stat()
    os.chmod(tmp, stat.st_mode & 0o7777)
    if os.geteuid() == 0:
        os.chown(tmp, stat.st_uid, stat.st_gid)
    tmp.replace(path)
    problem = export_mod.refresh_sensor_copy(path)
    if problem:
        print(problem, file=sys.stderr)
    if token is not None:
        # The only time the token exists anywhere but in this output.
        print(token)
        print(
            "Put this token in the scraping Prometheus's credentials_file; only its SHA-256 "
            "is stored on the router. Takes effect immediately (no apply needed).",
            file=sys.stderr,
        )
    else:
        print("metrics settings saved")
    return 0


def _cmd_tls_fingerprints(args: argparse.Namespace) -> int:
    state = load_tlsfp_state()
    clients = state.get("clients") or {}
    if not clients:
        print("TLS fingerprinting: nothing recorded yet (is tls_fingerprint enabled and fr-tls-fp running?)")
        return 0
    for client in sorted(clients):
        print(client)
        for ja4, seen in sorted(clients[client].items(), key=lambda kv: -kv[1].get("last_seen", 0)):
            names = ", ".join(seen.get("sni", [])) or "-"
            print(f"  {ja4}  {seen.get('count', 0):>6}x  {names}")
    blocklisted = [e for e in state.get("events") or [] if e.get("type") == "blocklist"]
    if blocklisted:
        print(f"\n{len(blocklisted)} blocklist match(es) in the recent event log")
    return 0


def _cmd_schedule_check(args: argparse.Namespace) -> int:
    config, text = read_config(args.config)
    # Security-lessons K2: the same hourly run keeps the per-rule hit
    # record the rule check uses for "unused for 90 days".
    try:
        rule_hits.record(rule_hits.read_counters(), [r.name for r in config.rules])
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"rule hit counters not recorded: {exc}", file=sys.stderr)
    result = schedule_refresh.check(config)
    print(result.message)
    if result.status == "config_changed":
        return 1
    if result.status != "refresh":
        return 0
    for message in apply_all(config, source_text=text).messages:
        print(message)
    return 0


def _cmd_rule_check(args: argparse.Namespace) -> int:
    findings = rule_lint.lint(load_config(args.config))
    if not findings:
        print("Rule check: no problems found")
        return 0
    for f in findings:
        print(f"{f.severity:<7} {f.rule}: {f.message}")
    return 1 if any(f.severity == rule_lint.WARNING for f in findings) else 0


def _cmd_apps_status(args: argparse.Namespace) -> int:
    usage = load_usage()
    apps = usage["apps"]
    if not apps:
        print("App identification: no usage recorded yet (is app_control enabled and fr-appid running?)")
        return 0
    names = {app.id: app.name for app in load_catalog().apps}
    ranked = sorted(apps.items(), key=lambda kv: (-kv[1].get("active_clients", 0), -kv[1].get("hits_24h", 0)))
    print(f"{'App':<22} {'Active':>6} {'Hits 24h':>9}  Clients")
    for app_id, stats in ranked[: max(args.limit, 0)]:
        clients = ", ".join(sorted(stats.get("clients", {})))
        print(
            f"{names.get(app_id, app_id):<22} {stats.get('active_clients', 0):>6} "
            f"{stats.get('hits_24h', 0):>9}  {clients}"
        )
    return 0


def _resolve_update_repo(config_path: str) -> str:
    """config.yaml's `update.repo`, falling back to the built-in default
    if unset, unreadable, or the file doesn't parse -- checking for
    updates should not require a perfectly valid firewall config."""
    try:
        config = load_config(config_path)
    except (FileNotFoundError, ConfigError):
        return update_mod.DEFAULT_REPO
    return config.update.repo or update_mod.DEFAULT_REPO


def _with_codename(version: str) -> str:
    codename = codename_for(version)
    return f'{version} "{codename}"' if codename else version


def _cmd_update_check(args: argparse.Namespace) -> int:
    repo = _resolve_update_repo(args.config)
    result = update_mod.check_latest(__version__, repo=repo)
    print(f"Installed version: {_with_codename(result.current_version)}")
    print(f"Repo checked:      {repo}")
    if result.latest is None:
        print("No releases published for this repo yet.")
        return 0
    print(f"Latest release:    {_with_codename(result.latest.version)} ({result.latest.tag})")
    if result.update_available:
        print("Update available.")
        if result.latest.notes:
            print("\nRelease notes:")
            print(result.latest.notes)
    else:
        print("Already up to date.")
    return 0


def _cmd_update_auto(args: argparse.Namespace) -> int:
    """fr-update-check.timer's job. Security-lessons G10: check once and
    record the result for the webUI's "update available" banner (red for
    a security release); a failed check keeps what the last good one
    found, with the error. J3: with `update.auto_install_security`, also
    install a security release -- apply_update verifies its signature
    first, as for any update -- and tell the admins either way."""
    repo = _resolve_update_repo(args.config)
    try:
        result = update_mod.check_latest(__version__, repo=repo)
    except update_mod.UpdateError as exc:
        previous = update_mod.read_check_cache(current_version=__version__) or {}
        update_mod.write_json_cache({**previous, "current_version": __version__, "error": str(exc)})
        print(f"update check failed: {exc}", file=sys.stderr)
        return 1
    update_mod.write_check_cache(result)
    if result.latest is None or not result.update_available:
        print(f"FR_OS {__version__} is up to date")
        return 0
    version = result.latest.version
    if not result.latest.security:
        print(f"update available: {version}")
        return 0
    print(f"SECURITY update available: {version}")
    if not _auto_install_security(args.config):
        return 0
    try:
        installed = update_mod.apply_update(version, repo=repo)
    except update_mod.UpdateError as exc:
        update_mod.write_check_cache(result, auto_install_error=str(exc))
        _console_alert(f"automatic install of security release {version} failed: {exc}", **_TIMER)
        print(f"automatic install of {version} failed: {exc}", file=sys.stderr)
        return 1
    # The software changed without anyone clicking: that is an alert (G9).
    _console_alert(f"security release {installed} installed automatically (was {__version__})", **_TIMER)
    print(f"installed security release {installed}")
    return 0


_TIMER = {"user": "fr-update-check", "client": "timer"}


def _auto_install_security(config_path: str) -> bool:
    try:
        return load_config(config_path).update.auto_install_security
    except (FileNotFoundError, ConfigError):
        return False  # never install on a guess


def _cmd_update_apply(args: argparse.Namespace) -> int:
    new_version = update_mod.apply_update(args.version, repo=args.repo)
    print(f"Updated to {new_version}")
    return 0


def _cmd_update_rollback(args: argparse.Namespace) -> int:
    restored = update_mod.rollback_update(repo=args.repo)
    print(f"Rolled back to {restored}")
    return 0


def _cmd_xdp_status(args: argparse.Namespace) -> int:
    attached = xdp_mod.get_attached()
    if not attached:
        print("XDP TLS SNI filter: not attached to any interface")
    else:
        print("XDP TLS SNI filter attached to:")
        for device, mode in sorted(attached.items()):
            print(f"  {device}: {mode}")

    stats = xdp_mod.get_stats()
    print("\nPacket counters:")
    for name, count in stats.items():
        print(f"  {name}: {count}")
    return 0


def _cmd_dns_log_trim(args: argparse.Namespace) -> int:
    from frfw.adblock.dns_service import QUERY_LOG_MAX_BYTES, trim_query_log

    if trim_query_log():
        print(f"emptied {paths.DNS_QUERY_LOG_PATH} (it was over {QUERY_LOG_MAX_BYTES} bytes)")
    return 0


def _cmd_adblock_refresh(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    # ROADMAP SEC-21: fr-adblock-refresh.timer is enabled on every router,
    # but FR_OS fetches nothing from the internet the admin didn't turn on
    # (security-lessons G11): the daily run downloads only while ad-blocking
    # is on (and on, it has lists: the config loader refuses it without).
    # An admin's own run -- this command, the webUI's "Refresh now" --
    # still fetches whenever lists are configured.
    if args.scheduled and not config.adblocker.enabled:
        print("ad-blocking is off: nothing fetched")
        return 0
    try:
        result = adblock_refresh(
            config.adblocker.source_urls,
            categories=config.adblocker.categories,
            allowlist=config.adblocker.allowlist,
        )
    except AdblockError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(result.message)
    if result.failed_urls:
        print(f"warning: {len(result.failed_urls)} source(s) failed: {result.failed_urls}",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
