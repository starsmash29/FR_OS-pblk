"""IPv4 forwarding: the kernel switch that makes the box a router.

Found in review: nothing ever turned it on. Debian's (and the live
image's) default is `net.ipv4.ip_forward = 0`, so LAN clients' traffic
was never forwarded to the WAN, whatever the rules said.

`apply` turns it on right after the ruleset is loaded -- never before,
so there is no moment in which the kernel routes and no forward chain
filters it -- and on every apply, so it holds across reboots without a
sysctl.d file. The fail-closed baseline (no config yet) leaves it off.
"""

from __future__ import annotations

from pathlib import Path

IP_FORWARD_PATH = Path("/proc/sys/net/ipv4/ip_forward")


class ForwardingError(Exception):
    pass


def enable(*, dry_run: bool = False, path: Path | None = None) -> str:
    path = IP_FORWARD_PATH if path is None else path
    if dry_run:
        return "Would turn IPv4 forwarding on (dry-run)"
    try:
        if path.read_text().strip() == "1":
            return "IPv4 forwarding on"
        path.write_text("1\n")
    except OSError as exc:
        raise ForwardingError(f"cannot turn IPv4 forwarding on ({path}): {exc}") from exc
    return "IPv4 forwarding turned on"
