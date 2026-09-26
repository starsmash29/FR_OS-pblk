"""Tests for frfw.hwinfo: dmidecode output parsing.

Unit tests parse a hand-written sample matching real `dmidecode -t
memory` output (this sandbox has no `dmidecode` installed to run it
live against -- see the module's own docstring for the honest
scope-of-verification note this implies); a `shutil.which`-gated real
test is included for completeness on a host that does have it, mirroring
this project's `requires_nft`-style convention for optional real tools.
"""

from __future__ import annotations

import shutil

import pytest

from frfw.hwinfo import HwInfoError, RamModule, _parse_dmidecode_memory, read_ram_modules

requires_dmidecode = pytest.mark.skipif(
    shutil.which("dmidecode") is None, reason="dmidecode binary not installed"
)

_SAMPLE_OUTPUT = """# dmidecode 3.3
Getting SMBIOS data from sysfs.
SMBIOS 2.8 present.

Handle 0x0032, DMI type 17, 40 bytes
Memory Device
\tArray Handle: 0x002F
\tError Information Handle: Not Provided
\tTotal Width: 64 bits
\tData Width: 64 bits
\tSize: 8192 MB
\tForm Factor: SODIMM
\tSet: None
\tLocator: ChannelA-DIMM0
\tBank Locator: BANK 0
\tType: DDR4
\tType Detail: Synchronous
\tSpeed: 2667 MT/s
\tManufacturer: Samsung
\tSerial Number: 12345678
\tAsset Tag: 9876543210
\tPart Number: M471A1K43CB1-CTD
\tRank: 1
\tConfigured Memory Speed: 2667 MT/s
\tMinimum Voltage: 1.2 V
\tMaximum Voltage: 1.2 V
\tConfigured Voltage: 1.2 V

Handle 0x0033, DMI type 17, 40 bytes
Memory Device
\tArray Handle: 0x002F
\tError Information Handle: Not Provided
\tTotal Width: Unknown
\tData Width: Unknown
\tSize: No Module Installed
\tForm Factor: SODIMM
\tSet: None
\tLocator: ChannelB-DIMM0
\tBank Locator: BANK 2
\tType: DDR4
\tType Detail: Synchronous
\tSpeed: Unknown
\tManufacturer: Not Specified
\tSerial Number: Not Specified
\tAsset Tag: Not Specified
\tPart Number: Not Specified
\tRank: Unknown
\tConfigured Memory Speed: Unknown
\tMinimum Voltage: Unknown
\tMaximum Voltage: Unknown
\tConfigured Voltage: Unknown

"""


def test_parses_installed_module():
    modules = _parse_dmidecode_memory(_SAMPLE_OUTPUT)
    assert modules == [RamModule(part_number="M471A1K43CB1-CTD", speed_mhz=2667)]


def test_skips_empty_slot():
    modules = _parse_dmidecode_memory(_SAMPLE_OUTPUT)
    assert len(modules) == 1  # the "No Module Installed" slot is never included


def test_parses_multiple_installed_modules():
    two_sticks = _SAMPLE_OUTPUT.replace("Size: No Module Installed", "Size: 8192 MB").replace(
        "Part Number: Not Specified", "Part Number: M471A1K43CB1-CTD"
    ).replace("Configured Memory Speed: Unknown", "Configured Memory Speed: 2667 MT/s")
    modules = _parse_dmidecode_memory(two_sticks)
    assert len(modules) == 2
    assert all(m.part_number == "M471A1K43CB1-CTD" for m in modules)


def test_falls_back_to_speed_field_when_configured_speed_is_unknown():
    sample = """Memory Device
\tSize: 4096 MB
\tPart Number: KVR-TEST
\tSpeed: 1600 MT/s
\tConfigured Memory Speed: Unknown
"""
    modules = _parse_dmidecode_memory(sample)
    assert modules == [RamModule(part_number="KVR-TEST", speed_mhz=1600)]


def test_missing_part_number_reports_unknown():
    sample = """Memory Device
\tSize: 4096 MB
\tSpeed: 1600 MT/s
"""
    modules = _parse_dmidecode_memory(sample)
    assert modules[0].part_number == "unknown"


def test_empty_output_returns_empty_list():
    assert _parse_dmidecode_memory("") == []


def test_read_ram_modules_returns_empty_list_when_dmidecode_missing(monkeypatch):
    import subprocess

    def raise_not_found(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(subprocess, "run", raise_not_found)
    assert read_ram_modules() == []


def test_read_ram_modules_raises_on_nonzero_exit(monkeypatch):
    import subprocess


    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess([], 1, stdout="", stderr="No SMBIOS entry point found"),
    )
    with pytest.raises(HwInfoError, match="No SMBIOS entry point"):
        read_ram_modules()


@requires_dmidecode
def test_real_dmidecode_does_not_raise():
    """Only runs on a host that actually has dmidecode installed (not
    this sandbox) -- confirms real output parses without crashing,
    whatever the local hardware's actual RAM configuration is."""
    try:
        modules = read_ram_modules()
    except HwInfoError as exc:
        # dmidecode is installed but the host gives it no DMI data (a
        # container without /dev/mem or /sys/firmware/dmi): nothing to parse.
        if "/dev/mem" in str(exc) or "SMBIOS" in str(exc):
            pytest.skip(f"no DMI access here: {exc}")
        raise
    assert isinstance(modules, list)
