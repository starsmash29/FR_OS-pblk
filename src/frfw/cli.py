"""`firewall-cli`: command-line entry point for the frfw engine.

    firewall-cli validate [config.yaml]
    firewall-cli render   [config.yaml]
    firewall-cli apply    [config.yaml] [--dry-run]
    firewall-cli rollback [--list]
    firewall-cli detect-interfaces [--include-virtual]
    firewall-cli assign-interfaces --wan DEV --lan DEV [--opt NAME:DEV ...] [--out PATH]
    firewall-cli set-admin-password [--username admin] [--generate]
    firewall-cli users
    firewall-cli ids-status
    firewall-cli iot-status
    firewall-cli apps-status [--limit N]
    firewall-cli tls-fingerprints
    firewall-cli metrics-token (--generate | --disable) [--site NAME] [config.yaml]
    firewall-cli schedule-check [config.yaml]
    firewall-cli update check [config.yaml]
    firewall-cli update apply VERSION [--repo OWNER/REPO]
    firewall-cli update rollback [--repo OWNER/REPO]
    firewall-cli xdp-status
    firewall-cli adblock-refresh [config.yaml]

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
import sys
from pathlib import Path

import yaml

from frfw import __version__, codename_for, netdetect, paths, schedule_refresh, skeleton, xdp as xdp_mod
from frfw import update as update_mod
from frfw.adblock import AdblockError
from frfw.adblock import refresh as adblock_refresh
from frfw.admin_account import ROLE_ADMIN, AdminStore
from frfw.appid import load_catalog
from frfw.appid.daemon import load_usage
from frfw.apply import NftError, list_backups, rollback_last
from frfw.tlsfp.daemon import load_state as load_tlsfp_state
from frfw.config import ConfigError, load_config, parse_config
from frfw.metrics import generate_metrics_token
from frfw.ids_quarantine import IdsQuarantineError, list_quarantined
from frfw.iot_isolation import IotIsolationError, list_isolated
from frfw.ifaddr import IfaddrError
from frfw.kea import KeaError
from frfw.nft import build_ruleset
from frfw.provision import apply_all


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

    p_apply = sub.add_parser(
        "apply", help="apply interface addresses, the nftables ruleset, and DHCP"
    )
    add_config_arg(p_apply)
    p_apply.add_argument(
        "--dry-run",
        action="store_true",
        help="check syntax and print what would happen, but don't load it",
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
    p_admin.set_defaults(handler=_cmd_set_admin_password)

    p_users = sub.add_parser("users", help="list the webUI accounts and their roles")
    p_users.set_defaults(handler=_cmd_users)

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

    p_mtoken = sub.add_parser(
        "metrics-token",
        help="protect GET /metrics with a bearer token for a remote Prometheus (phase 20)",
    )
    add_config_arg(p_mtoken)
    mode = p_mtoken.add_mutually_exclusive_group()
    mode.add_argument("--generate", action="store_true", help="create a new token (printed once) and require it")
    mode.add_argument("--disable", action="store_true", help="remove the token: /metrics is public again")
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
    add_config_arg(p_adblock_refresh)
    p_adblock_refresh.set_defaults(handler=_cmd_adblock_refresh)

    return parser


def _cmd_validate(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    print(f"OK: {args.config} is valid ({len(config.rules)} rule(s))")
    return 0


def _cmd_render(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    print(build_ruleset(config), end="")
    return 0


def _cmd_apply(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    result = apply_all(config, dry_run=args.dry_run)
    for message in result.messages:
        print(message)
    return 0


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
        AdminStore().set_password(args.username, password, ROLE_ADMIN)
        print(password)
        return 0

    password = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("error: passwords do not match", file=sys.stderr)
        return 1
    if len(password) < 8:
        print("error: password must be at least 8 characters", file=sys.stderr)
        return 1

    AdminStore().set_password(args.username, password, ROLE_ADMIN)
    print(f"Admin account {args.username!r} set")
    return 0


def _cmd_users(args: argparse.Namespace) -> int:
    accounts = AdminStore().users()
    if not accounts:
        print("No webUI accounts yet (the first login creates one, or run set-admin-password)")
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
    config = load_config(args.config)
    result = schedule_refresh.check(config)
    print(result.message)
    if result.status == "config_changed":
        return 1
    if result.status != "refresh":
        return 0
    for message in apply_all(config).messages:
        print(message)
    return 0


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


def _cmd_adblock_refresh(args: argparse.Namespace) -> int:
    config = load_config(args.config)
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
