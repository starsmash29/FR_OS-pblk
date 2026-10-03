"""The XDP filter's lifecycle against the real kernel (ROADMAP SEC-19).

`sync_sni_filter` runs for real here -- real bpftool loads, real pins in
bpffs, real attachments on a veth pair -- with only the object path and
the reader restart (a systemctl call) stood in. It pins down what the
unit tests in test_xdp.py can only assert about calls:

1. A pinned program that didn't come from the object being applied is
   replaced: the pinned program id changes, the interface moves to the
   new program, and the new blocklist map holds the blocklist.
2. An apply that fails part-way leaves every interface it did attach in
   the state file, so disabling the filter detaches them.

Skipped on the same terms as tests/test_xdp_live.py: root, clang, a
working bpftool, libbpf, bpffs, and no FR_OS program already pinned.
"""

from __future__ import annotations

import json
import os
import subprocess

import pytest

from frfw import xdp
from frfw.config.schema import Config, Interface, NatConfig, XdpSniFilterConfig, Zone
from test_xdp_live import _skip_reason, _working_bpftool_dir

pytestmark = pytest.mark.skipif(_skip_reason() is not None, reason=str(_skip_reason()))

DEV, PEER = "frl19a", "frl19b"
MISSING = "frl19zz"


def _config(*, enabled: bool, devices: list[str], blocklist: list[str]) -> Config:
    names = [f"if{n}" for n in range(len(devices))]
    return Config(
        version=1,
        hostname="r",
        interfaces={name: Interface(name=name, device=dev, zone="lan") for name, dev in zip(names, devices)},
        zones={"lan": Zone(name="lan")},
        rules=[],
        nat=NatConfig(),
        xdp_sni_filter=XdpSniFilterConfig(enabled=enabled, interfaces=names, blocklist=blocklist),
    )


@pytest.fixture()
def kernel(tmp_path, monkeypatch):
    tools = _working_bpftool_dir()
    if tools:
        monkeypatch.setenv("PATH", f"{tools}:{os.environ['PATH']}")
    subprocess.run(["ip", "link", "del", DEV], capture_output=True)
    subprocess.run(["ip", "link", "add", DEV, "type", "veth", "peer", "name", PEER], check=True)
    subprocess.run(["ip", "link", "set", DEV, "up"], check=True)
    subprocess.run(["ip", "link", "set", PEER, "up"], check=True)

    obj = xdp.ensure_compiled(obj_path=tmp_path / "xdp_sni_filter.o")
    monkeypatch.setattr(xdp, "ensure_compiled", lambda: obj)
    restarts: list[int] = []
    monkeypatch.setattr(xdp, "restart_readers", lambda: (restarts.append(1), [])[1])
    state_path = tmp_path / "xdp_state.json"
    try:
        yield {"state": state_path, "restarts": restarts, "obj": obj}
    finally:
        live = xdp.live_attachment(DEV)
        if live is not None:
            xdp.detach(DEV, live[0])
        xdp.unload()
        subprocess.run(["ip", "link", "del", DEV], capture_output=True)


def test_a_pinned_program_from_another_object_is_replaced_in_the_kernel(kernel):
    state_path, restarts = kernel["state"], kernel["restarts"]
    cfg = _config(enabled=True, devices=[DEV], blocklist=["blocked.example"])

    xdp.sync_sni_filter(cfg, state_path=state_path)
    first = xdp.pinned_prog_id()
    assert first is not None and xdp.live_attachment(DEV)[1] == first
    assert len(restarts) == 1  # a fresh load: readers move to the new maps

    # Unchanged object: the same program stays, nothing restarts.
    xdp.sync_sni_filter(cfg, state_path=state_path)
    assert xdp.pinned_prog_id() == first
    assert len(restarts) == 1

    # The pinned program now came from "another" object -- as after an
    # upgrade. Before SEC-19 load_and_pin kept it.
    state = json.loads(state_path.read_text())
    state["program"] = "0" * 64
    state_path.write_text(json.dumps(state))

    xdp.sync_sni_filter(cfg, state_path=state_path)
    second = xdp.pinned_prog_id()
    assert second is not None and second != first, "the old pinned program was kept"
    assert xdp.live_attachment(DEV)[1] == second, "the interface still runs the old program"
    assert xdp.build_lpm_key("blocked.example") in xdp._dump_lpm_keys(xdp.PIN_BLOCKLIST_PATH)
    assert not xdp._STAGING_DIR.exists()
    assert json.loads(state_path.read_text())["program"] == xdp.object_digest(kernel["obj"])
    assert len(restarts) == 2


def test_a_failed_apply_leaves_what_it_attached_recorded_and_disable_detaches_it(kernel):
    state_path = kernel["state"]

    with pytest.raises(xdp.XdpError):
        xdp.sync_sni_filter(_config(enabled=True, devices=[DEV, MISSING], blocklist=[]), state_path=state_path)
    assert xdp.live_attachment(DEV) is not None
    assert DEV in json.loads(state_path.read_text())["attached"]

    xdp.sync_sni_filter(_config(enabled=False, devices=[DEV], blocklist=[]), state_path=state_path)
    assert xdp.live_attachment(DEV) is None, "disable left an attachment it didn't know about"
    assert not xdp.is_loaded()
