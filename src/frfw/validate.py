"""Strict allow-lists for every value that ends up on a command line
(security-lessons F1).

MikroTik's "MikroTrick" chain ended in a login program that took the
username as an unvalidated argument: `-2` was parsed as an option. FR_OS
never uses a shell (`shell=True`, `os.system`), but it passes interface
names, addresses, unit names, versions, disk paths and hostnames from
the config or from requests as argv to nft, ip, systemctl, pip, sfdisk,
openssl... Each such value goes through one of these validators first,
and callers put `--` before positional values where the tool supports it
(`ip` does not -- there the value always follows a keyword such as
`dev`, which makes iproute2 take it literally).

Every pattern uses `\\Z`, never `$`: in Python `$` also matches before a
trailing newline, so `^...$` accepts "eth0\\n" -- and a newline in an
`nft -f -` script starts a new command.
"""

from __future__ import annotations

import ipaddress
import re

_IFNAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z")
_UNIT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_.@-]{0,254}\Z")
_VERSION_RE = re.compile(r"v?\d{1,6}\.\d{1,6}\.\d{1,6}\Z")
_REPO_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_][A-Za-z0-9._-]{0,99}\Z")
_BLOCK_DEVICE_RE = re.compile(r"/dev/[A-Za-z0-9][A-Za-z0-9_-]{0,62}\Z")
_HOST_LABEL_RE = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)\Z")
_MAC_RE = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}\Z")

#: systemctl verbs frfw uses.
SYSTEMCTL_ACTIONS = frozenset({
    "start", "stop", "restart", "reload", "try-restart", "try-reload-or-restart",
    "reload-or-restart", "enable", "disable", "is-active", "is-enabled",
})


class ArgumentError(ValueError):
    """A value refused before it could reach a command line."""


def _text(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise ArgumentError(f"{what} must be a string, got {type(value).__name__}")
    return value


def ifname(value: object) -> str:
    """A Linux interface name: 1-15 characters, letters/digits/`_.-`,
    starting with a letter or digit (so never an option), not `.`/`..`."""
    value = _text(value, "interface name")
    if not _IFNAME_RE.match(value) or value in (".", ".."):
        raise ArgumentError(f"invalid interface name {value!r}")
    return value


def ipv4(value: object) -> str:
    value = _text(value, "IPv4 address")
    try:
        parsed = ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ArgumentError(f"invalid IPv4 address {value!r}") from exc
    if str(parsed) != value:
        raise ArgumentError(f"invalid IPv4 address {value!r}")
    return value


def ipv4_interface(value: object) -> str:
    """An address with prefix, e.g. 192.168.1.1/24."""
    value = _text(value, "IPv4 address/prefix")
    try:
        parsed = ipaddress.IPv4Interface(value)
    except ValueError as exc:
        raise ArgumentError(f"invalid IPv4 address/prefix {value!r}") from exc
    if str(parsed) != value:
        raise ArgumentError(f"invalid IPv4 address/prefix {value!r}")
    return value


def mac(value: object) -> str:
    value = _text(value, "MAC address").lower()
    if not _MAC_RE.match(value):
        raise ArgumentError(f"invalid MAC address {value!r}")
    return value


def systemd_unit(value: object) -> str:
    value = _text(value, "systemd unit")
    if not _UNIT_RE.match(value):
        raise ArgumentError(f"invalid systemd unit name {value!r}")
    return value


def systemctl_action(value: object) -> str:
    value = _text(value, "systemctl action")
    if value not in SYSTEMCTL_ACTIONS:
        raise ArgumentError(f"systemctl action {value!r} is not one frfw uses")
    return value


def version(value: object) -> str:
    value = _text(value, "version")
    if not _VERSION_RE.match(value):
        raise ArgumentError(f"invalid version {value!r} (expected MAJOR.MINOR.PATCH)")
    return value


def github_repo(value: object) -> str:
    """OWNER/NAME, as GitHub allows them."""
    value = _text(value, "repository")
    if not _REPO_RE.match(value) or ".." in value:
        raise ArgumentError(f"invalid GitHub repository {value!r} (expected OWNER/NAME)")
    return value


def block_device(value: object) -> str:
    """/dev/sda, /dev/nvme0n1, /dev/mmcblk0p1, /dev/loop3 -- a plain
    device node, no path tricks."""
    value = _text(value, "block device")
    if not _BLOCK_DEVICE_RE.match(value):
        raise ArgumentError(f"invalid block device {value!r}")
    return value


def hostname(value: object) -> str:
    """An RFC 1123 host name (dot-separated labels, at most 253 chars)."""
    value = _text(value, "hostname")
    if not value or len(value) > 253 or not all(_HOST_LABEL_RE.match(label) for label in value.split(".")):
        raise ArgumentError(f"invalid hostname {value!r}")
    return value


def nft_argv(args: list[str]) -> list[str]:
    """`nft` argv with `--` between frfw's own leading options (`-j`, `-c`)
    and everything else, so no later value can be read as an option."""
    options = []
    rest = list(args)
    while rest and rest[0].startswith("-") and rest[0] != "-":
        option = rest.pop(0)
        options.append(option)
        if option == "-f" and rest:  # takes a file argument
            options.append(rest.pop(0))
    return ["nft", *options, *(["--", *rest] if rest else [])]
