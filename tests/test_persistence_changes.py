"""The rest of the persistence layer (ROADMAP SEC-22, review v0.2.1 #3).

The comparison with the signed release covers FR_OS's own files only; a
root attacker's persistence elsewhere on the persistence partition -- a
systemd unit, another program, an SSH key, a patched Debian file -- went
unreported. frfw.integrity.persistence_changes lists everything the
persistence layer adds, changes or removes outside FR_OS's own files and
what a router writes by itself. An image (lower) and a persistence layer
(upper) here as overlayfs keeps them, links included.
"""

from __future__ import annotations

import importlib.util
import marshal
import os
import sys
from pathlib import Path

import pytest

from frfw import integrity

EXPECTED = ("/var/log/**", "/etc/fr_os/*.yaml")


@pytest.fixture
def layers(tmp_path):
    lower, upper = tmp_path / "lower", tmp_path / "upper"
    for path, text in {
        "usr/bin/ping": "ELF ping",
        "etc/ssh/sshd_config": "PermitRootLogin no\n",
        "etc/systemd/system/multi-user.target.wants/.keep": "",
        "usr/local/lib/python3.11/dist-packages/frfw/cli.py": "def main(): ...\n",
        "var/log/.keep": "",
    }.items():
        (lower / path).parent.mkdir(parents=True, exist_ok=True)
        (lower / path).write_text(text)
    os.symlink("usr/bin", lower / "bin")  # merged /usr, as on Debian 12
    upper.mkdir()
    return lower, upper


def put(upper: Path, path: str, text: str = "") -> Path:
    target = upper / path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    return target


OWN = {"/etc/systemd/system/fr-webui.service"}  # the release's targets


def changes(layers):
    return integrity.persistence_changes(*layers, own_files=OWN, expected=EXPECTED).changes


def test_an_empty_persistence_layer_changes_nothing(layers):
    assert changes(layers) == []


def test_what_a_router_writes_by_itself_and_fr_os_own_files_are_not_reported(layers):
    _lower, upper = layers
    put(upper, "/var/log/fr_os/audit.log", "x")
    put(upper, "/etc/fr_os/config.yaml", "version: 1\n")
    # FR_OS's own files: the signed release vouches for these.
    put(upper, "/usr/local/lib/python3.11/dist-packages/frfw/cli.py", "patched\n")
    put(upper, "/etc/systemd/system/fr-webui.service", "[Service]\n")
    put(upper, "/opt/fr_os/releases/0.2.2/SHA256SUMS", "x")
    (upper / "etc/systemd/system/multi-user.target.wants").mkdir()
    os.symlink("/etc/systemd/system/fr-webui.service",
               upper / "etc/systemd/system/multi-user.target.wants/fr-webui.service")
    assert changes(layers) == []


def test_a_unit_named_like_fr_os_but_not_in_the_release_is_reported(layers):
    _lower, upper = layers
    put(upper, "/etc/systemd/system/fr-backdoor.service", "[Service]\n")
    wants = upper / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True)
    os.symlink("/etc/systemd/system/fr-backdoor.service", wants / "fr-backdoor.service")
    os.symlink("/usr/local/bin/b.service", wants / "fr-webui.service")  # an FR_OS name, elsewhere
    assert changes(layers) == [
        ("added", "/etc/systemd/system/fr-backdoor.service"),
        ("added", "/etc/systemd/system/multi-user.target.wants/fr-backdoor.service"),
        ("added", "/etc/systemd/system/multi-user.target.wants/fr-webui.service"),
    ]


def test_debians_compiled_modules_must_hold_their_sources_code(layers):
    lower, upper = layers
    source = "import os\nVALUE = 1\n"
    (lower / "usr/lib/python3.11").mkdir(parents=True)
    (lower / "usr/lib/python3.11/secrets.py").write_text(source)
    tag = sys.implementation.cache_tag
    cache = upper / "usr/lib/python3.11/__pycache__"
    cache.mkdir(parents=True)
    good = importlib.util.MAGIC_NUMBER + b"\0" * 12 + marshal.dumps(compile(source, "secrets.py", "exec", dont_inherit=True))
    (cache / f"secrets.{tag}.pyc").write_bytes(good)
    assert changes(layers) == []
    bad = importlib.util.MAGIC_NUMBER + b"\0" * 12 + marshal.dumps(
        compile("import os; os.system('x')", "s", "exec", dont_inherit=True))
    (cache / f"secrets.{tag}.pyc").write_bytes(bad)
    (cache / f"implant.{tag}.pyc").write_bytes(good)  # no source in the image
    assert changes(layers) == [("added", f"/usr/lib/python3.11/__pycache__/implant.{tag}.pyc"),
                               ("added", f"/usr/lib/python3.11/__pycache__/secrets.{tag}.pyc")]
    # Offline, with another Python than the router's: counted, not checked.
    report = integrity.persistence_changes(lower, upper, own_files=OWN, expected=EXPECTED, pyc_tag="cpython-399")
    assert report.unchecked_pyc == 0  # these are not the router's Python's files
    (cache / "secrets.cpython-399.pyc").write_bytes(bad)
    report = integrity.persistence_changes(lower, upper, own_files=OWN, expected=EXPECTED, pyc_tag="cpython-399")
    assert report.unchecked_pyc == 1


def test_an_attackers_unit_program_and_ssh_key_are_reported(layers):
    _lower, upper = layers
    put(upper, "/etc/systemd/system/backdoor.service", "[Service]\nExecStart=/usr/local/bin/b\n")
    os.symlink("/etc/systemd/system/backdoor.service",
               put(upper, "/etc/systemd/system/multi-user.target.wants/.keep").parent / "backdoor.service")
    put(upper, "/usr/local/bin/b", "#!/bin/sh\n")
    put(upper, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAA attacker\n")
    put(upper, "/etc/fr_os/notes.txt", "a pattern names config files only\n")
    assert changes(layers) == [
        ("added", "/etc/fr_os/notes.txt"),
        ("added", "/etc/systemd/system/backdoor.service"),
        ("added", "/etc/systemd/system/multi-user.target.wants/backdoor.service"),
        ("added", "/root/.ssh/authorized_keys"),
        ("added", "/usr/local/bin/b"),
    ]


def test_a_patched_debian_file_is_reported_and_one_copied_up_unchanged_is_not(layers):
    lower, upper = layers
    put(upper, "/usr/bin/ping", "ELF ping, patched")
    copied = put(upper, "/etc/ssh/sshd_config", "PermitRootLogin no\n")
    os.chmod(copied, (lower / "etc/ssh/sshd_config").stat().st_mode)
    assert changes(layers) == [("changed", "/usr/bin/ping")]


def test_a_mode_change_alone_is_a_change(layers):
    lower, upper = layers
    copied = put(upper, "/usr/bin/ping", "ELF ping")
    os.chmod(copied, 0o4755)  # setuid
    assert (lower / "usr/bin/ping").stat().st_mode != copied.stat().st_mode
    assert changes(layers) == [("changed", "/usr/bin/ping")]


def test_a_link_is_judged_by_its_target_and_never_followed(layers, tmp_path):
    _lower, upper = layers
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("the checking computer's file\n")
    os.symlink(outside, upper / "usr")  # rw/usr -> a directory off the medium
    os.symlink("/etc/shadow", upper / "etc_shadow_link")
    assert changes(layers) == [("added", "/etc_shadow_link"), ("changed", "/usr")]


def test_a_path_through_a_link_in_the_image_is_not_the_images_file(layers):
    _lower, upper = layers
    # /bin is a link in the image: an upper bin/ directory is not merged
    # /usr, and its files are not the image's.
    put(upper, "/bin/ping", "ELF ping")
    assert changes(layers) == [("changed", "/bin"), ("added", "/bin/ping")]


@pytest.mark.skipif(os.geteuid() != 0, reason="whiteouts are character devices: mknod needs root")
def test_a_deleted_debian_file_is_reported(layers):
    _lower, upper = layers
    (upper / "etc/ssh").mkdir(parents=True)
    os.mknod(upper / "etc/ssh/sshd_config", 0o600 | 0o020000, os.makedev(0, 0))  # overlayfs' whiteout
    os.mknod(upper / "etc/ssh/never_there", 0o600 | 0o020000, os.makedev(0, 0))
    assert changes(layers) == [("removed", "/etc/ssh/sshd_config")]


@pytest.mark.skipif(os.geteuid() != 0, reason="trusted.* extended attributes need root")
def test_an_opaque_directory_removes_the_images_files_and_its_own_are_added(layers):
    _lower, upper = layers
    ssh = upper / "etc/ssh"
    ssh.mkdir(parents=True)
    try:
        os.setxattr(ssh, "trusted.overlay.opaque", b"y")
    except OSError as exc:
        pytest.skip(f"this filesystem keeps no trusted.* attributes: {exc}")
    (ssh / "sshd_config").write_text("PermitRootLogin no\n")
    assert changes(layers) == [("removed", "/etc/ssh/"), ("added", "/etc/ssh/sshd_config")]
