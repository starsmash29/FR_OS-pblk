"""ROADMAP SEC-18: Debian's nftables.service never touches the FR_OS ruleset.

The unit loads /etc/nftables.conf, which starts with `flush ruleset`, and
its stop action flushes the ruleset too; it starts before
network-pre.target, as fr-firewall does. FR_OS keeps the `nftables`
package for `nft` and masks the unit. The QEMU boot test checks the
built image and the running router (installer/qemu-boot-test.py); these
check the sources that produce them, and the boot test's own check.
"""

from __future__ import annotations

import configparser
import importlib.util
import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HOOK = REPO / "installer" / "live-build" / "config" / "hooks" / "0100-install-frfw.hook.chroot"


def _commands(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")]


def test_the_image_masks_debians_nftables_unit_and_keeps_the_package():
    assert "systemctl mask nftables.service" in _commands(HOOK)
    packages = (REPO / "installer" / "live-build" / "config" / "package-lists" / "frfw.list.chroot").read_text().split()
    assert "nftables" in packages  # it provides `nft`, which fr-firewall runs


def test_a_non_image_install_masks_it_too():
    assert "systemctl mask nftables.service" in _commands(REPO / "scripts" / "install-system-integration.sh")


def test_fr_firewall_loads_after_it_even_if_it_were_unmasked():
    unit = configparser.ConfigParser(strict=False)
    unit.read(REPO / "systemd" / "fr-firewall.service")
    assert "nftables.service" in unit["Unit"]["After"].split()


@pytest.fixture
def boot_test():
    spec = importlib.util.spec_from_file_location("qemu_boot_test", REPO / "installer" / "qemu-boot-test.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tree(base: Path, target: str | None) -> Path:
    unit_dir = base / "etc" / "systemd" / "system"
    unit_dir.mkdir(parents=True)
    if target == "file":
        (unit_dir / "nftables.service").write_text("[Service]\n")
    elif target is not None:
        os.symlink(target, unit_dir / "nftables.service")
    return base


@pytest.mark.parametrize("image, upper, masked", [
    ("/dev/null", None, True),                                  # masked, persistence untouched
    ("/dev/null", "/dev/null", True),                           # masked again on the persistence layer
    (None, None, False),                                        # never masked
    ("/lib/systemd/system/nftables.service", None, False),      # enabled-style link, not a mask
    ("/dev/null", "file", False),                               # a unit file on persistence shadows the mask
    ("/dev/null", "/lib/systemd/system/nftables.service", False),
], ids=["masked", "masked-twice", "not-masked", "linked", "shadowed-by-file", "shadowed-by-link"])
def test_the_boot_tests_mask_check(boot_test, tmp_path, image, upper, masked):
    root = _tree(tmp_path / "root", image)
    persistence = _tree(tmp_path / "upper", upper)
    assert boot_test.nftables_unit_masked(root, persistence) is masked
