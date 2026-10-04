"""The XDP SNI filter's program ships compiled (ROADMAP P4-1).

The image had no compiled program, no source and no compiler, so turning
the SNI filter on failed on every router; and an update never replaced
the program at all (the updater looked for the release's source where it
isn't, and kept the image's object). Now:

- `scripts/build-xdp-object.sh` is the one way the program is compiled:
  by the image build, into the image and the release tarball;
- a router never compiles (`frfw.xdp.ensure_compiled`): no compiler,
  and root must not run whatever `clang` is first on its PATH (SEC-19);
- an update installs the release's own compiled program
  (`frfw.update._install_xdp_object`).

The boot test turns the filter on with the image's program and checks a
blocked name's TLS handshake is dropped (installer/qemu-boot-test.py).
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from frfw import paths, update, xdp

REPO_ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build-xdp-object.sh"
SOURCE = REPO_ROOT / "bpf" / "xdp_sni_filter.c"
HOOK = REPO_ROOT / "installer" / "live-build" / "config" / "hooks" / "0100-install-frfw.hook.chroot"
IMAGE_BUILD = REPO_ROOT / "installer" / "build-live-image.sh"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "build-installer.yml"


def _can_compile() -> bool:
    return shutil.which("clang") is not None and Path("/usr/include/bpf/bpf_helpers.h").is_file()


def _is_bpf_object(path: Path) -> bool:
    """An ELF relocatable for the BPF machine (EM_BPF = 247)."""
    header = path.read_bytes()[:20]
    return header[:4] == b"\x7fELF" and int.from_bytes(header[18:20], "little") == 247


@pytest.fixture
def poisoned_clang(tmp_path, monkeypatch):
    """A `clang` first on PATH that records being run: what SEC-19 says
    root must never pick up on a router."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "clang-ran"
    clang = bin_dir / "clang"
    clang.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
    clang.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    return marker


# --- a router never compiles ----------------------------------------------------


def test_an_installed_router_loads_the_shipped_program_and_compiles_nothing(tmp_path, monkeypatch, poisoned_clang):
    monkeypatch.setattr(xdp, "_checkout_source", lambda: None)  # no source next to an installed frfw
    shipped = tmp_path / "xdp_sni_filter.o"
    shipped.write_bytes(b"\x7fELF compiled by the image build")
    assert xdp.ensure_compiled(obj_path=shipped) == shipped
    assert not poisoned_clang.exists()


def test_without_a_shipped_program_the_filter_says_so_and_compiles_nothing(tmp_path, monkeypatch, poisoned_clang):
    monkeypatch.setattr(xdp, "_checkout_source", lambda: None)
    with pytest.raises(xdp.XdpError, match=r"No compiled XDP program.*\(ROADMAP P4-1\)"):
        xdp.ensure_compiled(obj_path=tmp_path / "missing.o")
    assert not poisoned_clang.exists()


def test_an_installed_frfw_finds_no_checkout_source(tmp_path, monkeypatch):
    """The source is looked for next to frfw only (src/frfw -> repo root);
    an installed frfw under site-packages has none there."""
    installed = tmp_path / "lib" / "python3.11" / "dist-packages" / "frfw" / "xdp.py"
    installed.parent.mkdir(parents=True)
    installed.write_text("")
    monkeypatch.setattr(xdp, "__file__", str(installed))
    assert xdp._checkout_source() is None


# --- the one build script -----------------------------------------------------------


@pytest.mark.skipif(not _can_compile(), reason="needs clang and libbpf-dev")
def test_the_build_script_makes_a_bpf_object(tmp_path):
    out = tmp_path / "nested" / "xdp_sni_filter.o"
    subprocess.run([str(BUILD_SCRIPT), str(SOURCE), str(out)], check=True)
    assert _is_bpf_object(out)


@pytest.mark.skipif(not _can_compile(), reason="needs clang and libbpf-dev")
def test_a_checkout_compiles_with_the_build_script_once(tmp_path):
    obj = tmp_path / "xdp_sni_filter.o"
    assert xdp.ensure_compiled(obj_path=obj) == obj and _is_bpf_object(obj)
    built = obj.stat().st_mtime_ns
    xdp.ensure_compiled(obj_path=obj)
    assert obj.stat().st_mtime_ns == built  # up to date: not compiled again


def test_a_checkout_compiles_only_through_the_build_script(tmp_path, monkeypatch):
    """frfw.xdp has no compile flags of its own that could drift from the
    image's: it runs the build script."""
    ran = []
    monkeypatch.setattr(xdp.subprocess, "run",
                        lambda argv, **kw: ran.append(argv) or subprocess.CompletedProcess(argv, 0, "", ""))
    obj = tmp_path / "xdp_sni_filter.o"
    xdp.ensure_compiled(obj_path=obj)
    assert ran == [[str(BUILD_SCRIPT), str(SOURCE), str(obj)]]
    assert BUILD_SCRIPT.stat().st_mode & stat.S_IXUSR


# --- the image and the release carry it -----------------------------------------------


def test_the_image_build_compiles_the_program_before_staging_the_source():
    text = IMAGE_BUILD.read_text()
    compile_at = text.index('scripts/build-xdp-object.sh" "$REPO_ROOT/bpf/xdp_sni_filter.c" "$REPO_ROOT/bpf/xdp_sni_filter.o"')
    assert compile_at < text.index("rsync -a")


def test_the_image_installs_the_program_where_frfw_loads_it():
    """The hook's destination is frfw.paths.XDP_BPF_OBJ_PATH (as shipped,
    not as tests/conftest.py points it), and it is installed before the
    staged source is removed."""
    text = HOOK.read_text()
    shipped = Path("/usr/local/share/fr_os/bpf/xdp_sni_filter.o")
    assert re.search(r"^XDP_BPF_OBJ_PATH = Path\(\"" + re.escape(str(shipped)) + r"\"\)$",
                     (REPO_ROOT / "src" / "frfw" / "paths.py").read_text(), re.M)
    line = f"install -D -m 0644 /opt/frfw-src/bpf/xdp_sni_filter.o {shipped}"
    assert line in text
    assert text.index(line) < text.index("rm -rf /opt/frfw-src")


def test_the_image_has_what_loads_the_program():
    """bpftool loads and pins it (frfw.xdp.load_and_pin), libbpf reads its
    ring buffers (frfw.xdp.RingBufferReader); the image had neither."""
    package_list = REPO_ROOT / "installer" / "live-build" / "config" / "package-lists" / "frfw.list.chroot"
    packages = {line.strip() for line in package_list.read_text().splitlines() if line.strip() and not line.startswith("#")}
    assert {"bpftool", "libbpf1", "iproute2"} <= packages


def test_the_release_tarball_carries_the_program_under_bpf():
    text = WORKFLOW.read_text()
    assert re.search(r'--prefix="frfw-\$\{version\}/bpf/" --add-file=bpf/xdp_sni_filter\.o \\\n\s*'
                     r'--prefix="frfw-\$\{version\}/" HEAD', text)
    assert "clang libbpf-dev" in text
    # where the updater takes it from
    assert update.XDP_OBJECT == Path("bpf") / "xdp_sni_filter.o"


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_git_archive_puts_the_added_object_under_bpf(tmp_path):
    """The workflow's `git archive --add-file` invocation, run for real on
    a scratch repository: the object lands at <prefix>/bpf/, next to the
    tracked tree."""
    repo = tmp_path / "repo"
    (repo / "bpf").mkdir(parents=True)
    (repo / "bpf" / "xdp_sni_filter.c").write_text("// source\n")
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    for cmd in (["init", "-q"], ["add", "."], ["commit", "-qm", "x"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env=env)
    (repo / "bpf" / "xdp_sni_filter.o").write_bytes(b"\x7fELF")
    tarball = tmp_path / "frfw-9.9.9.tar.gz"
    subprocess.run(["git", "-C", str(repo), "archive", "--format=tar.gz", "-o", str(tarball),
                    "--prefix=frfw-9.9.9/bpf/", "--add-file=bpf/xdp_sni_filter.o",
                    "--prefix=frfw-9.9.9/", "HEAD"], check=True)
    names = subprocess.run(["tar", "tzf", str(tarball)], check=True, capture_output=True, text=True).stdout.split()
    assert "frfw-9.9.9/bpf/xdp_sni_filter.o" in names
    assert "frfw-9.9.9/bpf/xdp_sni_filter.c" in names


# --- an update installs the release's program ---------------------------------------


def test_an_update_installs_the_releases_program(tmp_path):
    release = tmp_path / "frfw-0.3.0"
    (release / "bpf").mkdir(parents=True)
    (release / "bpf" / "xdp_sni_filter.o").write_bytes(b"new program")
    dest = tmp_path / "share" / "fr_os" / "bpf" / "xdp_sni_filter.o"
    update._install_xdp_object(release, dest)
    assert dest.read_bytes() == b"new program"
    assert stat.S_IMODE(dest.stat().st_mode) == 0o644
    assert not dest.with_name(dest.name + ".new").exists()

    # the next release replaces it, and the digest SEC-19 compares changes
    old_digest = xdp.object_digest(dest)
    (release / "bpf" / "xdp_sni_filter.o").write_bytes(b"newer program")
    update._install_xdp_object(release, dest)
    assert dest.read_bytes() == b"newer program" and xdp.object_digest(dest) != old_digest


def test_a_release_without_a_program_removes_the_previous_one(tmp_path):
    """Rolling back to a release built before P4-1: its code must not run
    a program built for a later one."""
    release = tmp_path / "frfw-0.2.0"
    release.mkdir()
    dest = tmp_path / "xdp_sni_filter.o"
    dest.write_bytes(b"a later release's program")
    update._install_xdp_object(release, dest)
    assert not dest.exists()
    update._install_xdp_object(release, dest)  # nothing there: still fine


def test_installing_a_release_installs_its_program(tmp_path, monkeypatch):
    """The real `_install_release_dir`, with pip and systemctl stood in:
    the program lands at frfw.paths.XDP_BPF_OBJ_PATH (a temporary path in
    tests, tests/conftest.py)."""
    ran = []
    monkeypatch.setattr(update, "_run", lambda argv: ran.append(argv))
    monkeypatch.setattr(update, "_stage_systemd_units", lambda d: None)
    release = tmp_path / "frfw-0.3.0"
    (release / "bpf").mkdir(parents=True)
    (release / "requirements.lock").write_text("")
    (release / "bpf" / "xdp_sni_filter.o").write_bytes(b"release program")
    update._install_release_dir(release)
    assert paths.XDP_BPF_OBJ_PATH.read_bytes() == b"release program"
    assert [argv[0] for argv in ran] == ["pip3", "pip3", "systemctl"]


def test_the_boot_test_reads_the_blocked_names_events(tmp_path):
    """What boot 3's event-file check matches: the logger's own JSON lines
    (frfw.xdp.format_event_json) for the blocked name only."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("qemu_boot_test", REPO_ROOT / "installer" / "qemu-boot-test.py")
    boot_test = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boot_test)

    events = tmp_path / "var" / "log" / "fr_os-sni" / "events.jsonl"
    events.parent.mkdir(parents=True)
    lines = [
        xdp.format_event_json(xdp.SniEvent(saddr="192.168.1.2", daddr="192.168.1.1", sport=40000, dport=443,
                                           hostname=name, action=action))
        for name, action in ((boot_test.XDP_BLOCKED_NAME, "drop"), (boot_test.XDP_ALLOWED_NAME, "pass"))
    ]
    events.write_text("\n".join(lines) + "\n")
    (found,) = boot_test.xdp_blocked_events(tmp_path)
    assert '"action": "drop"' in found
    assert boot_test.xdp_blocked_events(tmp_path / "nowhere") == []


@pytest.mark.skipif(os.geteuid() != 0 or shutil.which("setpriv") is None, reason="needs root and setpriv")
def test_an_unprivileged_reader_gets_an_xdp_error_not_a_crash(tmp_path):
    """The real failure, reproduced: an unprivileged process (the webUI's
    situation) asks for the counters under a root-only directory, as
    bpffs is on a router (mode 0700). Path.exists() raises PermissionError
    there; get_stats() turns it into the XdpError its callers handle."""
    pins = tmp_path / "bpf"
    (pins / "fr_os_xdp").mkdir(parents=True)
    pins.chmod(0o700)
    code = (
        "import sys\n"
        "from pathlib import Path\n"
        "from frfw import xdp\n"
        "print('module:', xdp.__file__)\n"
        f"xdp.PIN_STATS_PATH = Path({str(pins / 'fr_os_xdp' / 'stats')!r})\n"
        "try:\n"
        "    xdp.get_stats()\n"
        "except xdp.XdpError as exc:\n"
        "    print('XdpError:', exc)\n"
    )
    proc = subprocess.run(
        ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", sys.executable, "-c", code],
        capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}, cwd="/",
    )
    imported = proc.stdout.splitlines()[0] if proc.stdout else ""
    if not imported.startswith(f"module: {REPO_ROOT / 'src'}"):
        # `nobody` couldn't read this checkout and imported frfw from
        # somewhere else: that would test other code.
        pytest.skip(f"the unprivileged user can't import this checkout's frfw ({imported or proc.stderr[-200:]})")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines()[1].startswith("XdpError:") and "bpffs is root's" in proc.stdout
