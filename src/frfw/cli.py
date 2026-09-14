"""`firewall-cli`: command-line entry point for the frfw engine.

    firewall-cli validate [config.yaml]
    firewall-cli render   [config.yaml]
    firewall-cli apply    [config.yaml] [--dry-run]
    firewall-cli rollback [--list]
    firewall-cli detect-interfaces [--include-virtual]
    firewall-cli assign-interfaces --wan DEV --lan DEV [--opt NAME:DEV ...] [--out PATH]
    firewall-cli set-admin-password [--username admin]
    firewall-cli ai-ids-retrain [config.yaml] [--mac AA:BB:CC:DD:EE:FF]

`config.yaml` defaults to the canonical /etc/fr_os/config.yaml location
(see frfw.paths) wherever a config path is optional, so that on a real
router `firewall-cli apply` with no arguments does the expected thing.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from frfw import netdetect, paths, skeleton
from frfw.admin_account import AdminStore
from frfw.ai_ids import AIIDSEngine
from frfw.apply import NftError, list_backups, rollback_last
from frfw.config import ConfigError, load_config
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="firewall-cli")
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
        "set-admin-password", help="set/reset the webUI's local admin account"
    )
    p_admin.add_argument("--username", default="admin")
    p_admin.set_defaults(handler=_cmd_set_admin_password)

    p_retrain = sub.add_parser(
        "ai-ids-retrain",
        help="reset the (mock) AI IDS learning clock; run daily by fr-ai-ids-retrain.timer",
    )
    add_config_arg(p_retrain)
    p_retrain.add_argument(
        "--mac", default=None, help="retrain only this device (default: all known devices)"
    )
    p_retrain.set_defaults(handler=_cmd_ai_ids_retrain)

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
    password = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("error: passwords do not match", file=sys.stderr)
        return 1
    if len(password) < 8:
        print("error: password must be at least 8 characters", file=sys.stderr)
        return 1

    AdminStore().set_password(args.username, password)
    print(f"Admin account {args.username!r} set")
    return 0


def _cmd_ai_ids_retrain(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    engine = AIIDSEngine(config)
    try:
        engine.force_retrain(args.mac)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    target = args.mac or "all known devices"
    print(f"AI IDS: retrain clock reset for {target} (mock engine, see ROADMAP.md)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
