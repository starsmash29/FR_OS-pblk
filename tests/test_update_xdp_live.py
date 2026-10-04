"""An update swaps the XDP program in the kernel (ROADMAP P4-1), end to end.

A router never compiles the program, so a release carries it compiled
and the updater installs it. This runs that path for real against the
kernel:

1. the router runs a program installed from an older build;
2. a release is built the way .github/workflows/build-installer.yml
   builds it -- `git archive` of this checkout plus the program compiled
   by scripts/build-xdp-object.sh (`--add-file`) -- and signed with a
   throwaway Ed25519 key made here (the real release key never comes
   near a test; trusted_keys() is pointed at the throwaway public key);
3. `frfw.update.apply_update` finds it in the release cache, verifies
   the signature and checksum, extracts it, and installs its program;
4. the apply that follows an update (the updater restarts fr-firewall)
   replaces the pinned program, and the interface runs the release's.

Stood in: `pip` (it would install into this test machine's Python),
`systemctl`/`systemd-run` and the unit staging (they would act on this
machine's systemd), and the readers' restart. Everything about the
program -- the tarball, the signature, the extraction, the install, the
kernel load and the attach -- is real.

Skipped on the same terms as tests/test_xdp_live.py, plus openssl and git.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from frfw import __version__, paths, release_signing, update, xdp
from frfw.config.schema import Config, Interface, NatConfig, XdpSniFilterConfig, Zone
from test_xdp_live import _skip_reason, _working_bpftool_dir

REPO_ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build-xdp-object.sh"
SOURCE = REPO_ROOT / "bpf" / "xdp_sni_filter.c"
RELEASE = "9.9.9"


def _extra_skip() -> str | None:
    for tool in ("openssl", "git"):
        if shutil.which(tool) is None:
            return f"{tool} not installed"
    return None


pytestmark = pytest.mark.skipif(
    _skip_reason() is not None or _extra_skip() is not None,
    reason=str(_skip_reason() or _extra_skip()),
)

DEV, PEER = "frupd0", "frupd1"


def _config() -> Config:
    return Config(
        version=1,
        hostname="r",
        interfaces={"lan": Interface(name="lan", device=DEV, zone="lan")},
        zones={"lan": Zone(name="lan")},
        rules=[],
        nat=NatConfig(),
        xdp_sni_filter=XdpSniFilterConfig(enabled=True, interfaces=["lan"], blocklist=["blocked.example"]),
    )


def _compile(source: Path, out: Path) -> Path:
    subprocess.run([str(BUILD_SCRIPT), str(source), str(out)], check=True, capture_output=True)
    return out


def _release(tmp_path: Path, releases_dir: Path, program: Path) -> Path:
    """Release RELEASE in the updater's cache, as the workflow makes it,
    signed with a throwaway key; returns the directory with its public
    half, for trusted_keys() to be pointed at."""
    cache = releases_dir / RELEASE
    cache.mkdir(parents=True)
    tarball = cache / release_signing.source_tarball_name(RELEASE)
    staged = tmp_path / "stage" / "bpf"
    staged.mkdir(parents=True)
    shutil.copy(program, staged / "xdp_sni_filter.o")
    # The workflow's own invocation (build-installer.yml, "Name the ISO,
    # package the source").
    subprocess.run(
        ["git", "-C", str(REPO_ROOT), "archive", "--format=tar.gz", "-o", str(tarball),
         f"--prefix=frfw-{RELEASE}/bpf/", f"--add-file={staged / 'xdp_sni_filter.o'}",
         f"--prefix=frfw-{RELEASE}/", "HEAD"],
        check=True, capture_output=True,
    )
    sums = cache / release_signing.SUMS_NAME
    sums.write_text(f"{release_signing.sha256_of(tarball)}  {tarball.name}\n")
    key = tmp_path / "throwaway.key"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)], check=True, capture_output=True)
    keys_dir = tmp_path / "trusted"
    keys_dir.mkdir()
    subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(keys_dir / "test-release.pem")],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(sums),
                    "-out", str(cache / release_signing.SIGNATURE_NAME)], check=True, capture_output=True)
    key.unlink()
    return keys_dir


@pytest.fixture()
def router(tmp_path, monkeypatch):
    """A veth port and an installed router's view of frfw.xdp: no source
    next to it, the program loaded from frfw.paths.XDP_BPF_OBJ_PATH."""
    tools = _working_bpftool_dir()
    if tools:
        monkeypatch.setenv("PATH", f"{tools}:{os.environ['PATH']}")
    subprocess.run(["ip", "link", "del", DEV], capture_output=True)
    subprocess.run(["ip", "link", "add", DEV, "type", "veth", "peer", "name", PEER], check=True)
    subprocess.run(["ip", "link", "set", DEV, "up"], check=True)
    subprocess.run(["ip", "link", "set", PEER, "up"], check=True)
    monkeypatch.setattr(xdp, "_checkout_source", lambda: None)
    installed = xdp.ensure_compiled
    monkeypatch.setattr(xdp, "ensure_compiled", lambda: installed(obj_path=paths.XDP_BPF_OBJ_PATH))
    monkeypatch.setattr(xdp, "restart_readers", lambda: [])
    try:
        yield tmp_path / "xdp_state.json"
    finally:
        live = xdp.live_attachment(DEV)
        if live is not None:
            xdp.detach(DEV, live[0])
        xdp.unload()
        subprocess.run(["ip", "link", "del", DEV], capture_output=True)


def test_an_update_puts_the_releases_program_in_the_kernel(router, tmp_path, monkeypatch):
    state_path = router

    # 1. The router runs an older build's program. (The same source with
    # its lines shifted: different debug info, so a different object and
    # digest, and a program that loads and behaves the same.)
    older_source = tmp_path / "older" / "xdp_sni_filter.c"
    older_source.parent.mkdir()
    older_source.write_text("// an older build\n" + SOURCE.read_text())
    shutil.copy(_compile(older_source, tmp_path / "older.o"), paths.XDP_BPF_OBJ_PATH)
    xdp.sync_sni_filter(_config(), state_path=state_path)
    old_id = xdp.pinned_prog_id()
    assert old_id is not None and xdp.live_attachment(DEV)[1] == old_id

    # 2. The release, built and signed as the workflow does.
    releases_dir = tmp_path / "releases"
    new_program = _compile(SOURCE, tmp_path / "release.o")
    keys_dir = _release(tmp_path, releases_dir, new_program)
    monkeypatch.setattr(release_signing, "TRUSTED_KEYS_DIR", keys_dir)

    # 3. The real updater, with pip and systemd stood in.
    ran: list[list[str]] = []
    monkeypatch.setattr(update, "_run", lambda argv: ran.append(argv))
    monkeypatch.setattr(update, "_stage_systemd_units", lambda release_dir: None)
    update.apply_update(RELEASE, state_path=tmp_path / "update_state.json", releases_dir=releases_dir)
    assert __version__ != RELEASE
    assert [argv[0] for argv in ran][:2] == ["pip3", "pip3"]
    assert paths.XDP_BPF_OBJ_PATH.read_bytes() == new_program.read_bytes()

    # 4. The apply that follows (fr-firewall's restart) swaps the program.
    xdp.sync_sni_filter(_config(), state_path=state_path)
    new_id = xdp.pinned_prog_id()
    assert new_id is not None and new_id != old_id, "the kernel still runs the older build's program"
    assert xdp.live_attachment(DEV)[1] == new_id
    assert xdp.build_lpm_key("blocked.example") in xdp._dump_lpm_keys(xdp.PIN_BLOCKLIST_PATH)
