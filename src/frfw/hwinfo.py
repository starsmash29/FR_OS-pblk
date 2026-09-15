"""Privileged hardware inventory helpers for the metrics exporter (phase
12, see frfw.metrics) -- currently just RAM module identification via
`dmidecode`, the one hardware fact this project cannot get from `/proc`
or `/sys` (see frfw.metrics's own docstring for everything else, all of
which needs no privilege at all).

`dmidecode` reads the SMBIOS/DMI tables (via `/dev/mem` or
`/sys/firmware/dmi/tables/DMI`, depending on kernel/distro), which
requires root on real hardware -- the same shape of finding this project
has already documented by hand for `nft` and `/proc/net/nf_conntrack`.
This module is therefore only ever called from `frfw.helper.server` (the
privileged apply-helper's "hw_ram_info" command), never directly from
the unprivileged webUI process or `frfw.metrics`.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


class HwInfoError(Exception):
    """Raised when `dmidecode` runs but fails for a real reason (a
    non-zero exit status) -- NOT raised when it's simply not installed,
    see `read_ram_modules`'s own handling of that case."""


@dataclass(frozen=True)
class RamModule:
    part_number: str
    speed_mhz: int


def read_ram_modules() -> list[RamModule]:
    """Every populated (non-empty) memory slot's part number and
    configured speed, parsed from `dmidecode -t memory`'s "Memory
    Device" records.

    Returns an empty list -- not an error -- if `dmidecode` isn't
    installed. This project deliberately does not add it as a runtime
    dependency (it exists on this system, if at all, purely for this one
    cosmetic identification field), so a minimal image without it
    degrades to reporting no `fros_hw_ram_info` series rather than
    failing the whole /metrics response.
    """
    try:
        proc = subprocess.run(["dmidecode", "-t", "memory"], capture_output=True, text=True)
    except FileNotFoundError:
        return []
    if proc.returncode != 0:
        raise HwInfoError(proc.stderr.strip() or f"dmidecode exited with status {proc.returncode}")
    return _parse_dmidecode_memory(proc.stdout)


def _parse_dmidecode_memory(output: str) -> list[RamModule]:
    """dmidecode's plain-text output has one paragraph per DMI record,
    each starting with a non-indented "Handle 0x...," line, followed by
    a non-indented type name ("Memory Device" for what we want), then
    tab-indented "Field: value" lines until the next non-indented line
    or end of output. Confirmed against real dmidecode 3.x output
    format (this sandbox has no `dmidecode` installed to run it live
    against -- see tests/test_hwinfo.py for a hand-verified sample of
    that real, documented output format instead, and ARCHITECTURE.md
    for the honest scope-of-verification note this implies)."""
    modules: list[RamModule] = []
    current: dict[str, str] = {}
    in_memory_device = False

    def flush() -> None:
        if not in_memory_device:
            return
        size = current.get("Size", "")
        if not size or "No Module Installed" in size:
            return
        part_number = current.get("Part Number", "").strip() or "unknown"
        configured_speed = current.get("Configured Memory Speed", "")
        # "Configured Memory Speed" is preferred (the speed it's actually
        # running at), but dmidecode reports "Unknown" there -- a
        # non-empty string, so a plain `or` chain would never fall
        # through to "Speed" (the module's rated maximum) -- for an
        # empty *or* placeholder value.
        speed_raw = configured_speed if _parse_speed_mhz(configured_speed) else current.get("Speed", "")
        modules.append(RamModule(part_number=part_number, speed_mhz=_parse_speed_mhz(speed_raw)))

    for line in output.splitlines():
        if line.strip() == "Memory Device":
            flush()
            current = {}
            in_memory_device = True
            continue
        if line and not line.startswith(("\t", " ")):
            # A new record's header line (or any other non-indented
            # line) -- closes whichever "Memory Device" block we were
            # in, if any.
            flush()
            current = {}
            in_memory_device = False
            continue
        if in_memory_device and ":" in line:
            key, _, value = line.strip().partition(":")
            current[key.strip()] = value.strip()

    flush()
    return modules


def _parse_speed_mhz(raw: str) -> int:
    # "2667 MT/s" -> 2667; "Unknown"/"" -> 0.
    tokens = raw.split()
    if not tokens:
        return 0
    digits = "".join(ch for ch in tokens[0] if ch.isdigit())
    return int(digits) if digits else 0
