"""`firewall-cli`: command-line entry point for the frfw engine.

    firewall-cli validate <config.yaml>
    firewall-cli render   <config.yaml>
    firewall-cli apply    <config.yaml> [--dry-run]
"""

from __future__ import annotations

import argparse
import sys

from frfw.apply import NftError, apply_ruleset
from frfw.config import ConfigError, load_config
from frfw.nft import build_ruleset


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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="firewall-cli")
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate", help="validate a config file")
    p_validate.add_argument("config", help="path to config.yaml")
    p_validate.set_defaults(handler=_cmd_validate)

    p_render = sub.add_parser("render", help="print the generated nftables ruleset")
    p_render.add_argument("config", help="path to config.yaml")
    p_render.set_defaults(handler=_cmd_render)

    p_apply = sub.add_parser("apply", help="generate and load the nftables ruleset")
    p_apply.add_argument("config", help="path to config.yaml")
    p_apply.add_argument(
        "--dry-run",
        action="store_true",
        help="check syntax and print what would happen, but don't load it",
    )
    p_apply.set_defaults(handler=_cmd_apply)

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
    ruleset = build_ruleset(config)
    result = apply_ruleset(ruleset, dry_run=args.dry_run)
    print(result.message)
    return 0


if __name__ == "__main__":
    sys.exit(main())
