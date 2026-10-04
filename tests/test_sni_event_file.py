"""ROADMAP SEC-4 (review v0.2.0 R10): the XDP SNI events reach their
readers through a file of the logger's own, not through the journal.

The webUI, fr-ai-ids and fr-appid used to read fr-xdp-sni-logger's
journal, which took the systemd-journal group -- every unit's log and
the kernel's. The logger now also writes each event to
paths.SNI_EVENTS_PATH (frfw.xdp.EventFile), which the readers follow
with `tail -F` (frfw.journal.follow_file_forever, the webUI's stream).
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time

import pytest

from frfw import xdp
from frfw.journal import follow_file_forever


def test_the_event_file_is_group_readable_only(tmp_path):
    path = tmp_path / "events.jsonl"
    old = os.umask(0)  # even under a permissive umask
    try:
        writer = xdp.EventFile(path)
    finally:
        os.umask(old)
    writer.write_line('{"sni": "a.example"}')
    writer.close()
    assert path.stat().st_mode & 0o777 == 0o640
    assert path.read_text() == '{"sni": "a.example"}\n'


def test_the_event_file_appends_and_empties_itself_at_its_cap(tmp_path):
    path = tmp_path / "events.jsonl"
    writer = xdp.EventFile(path, max_bytes=100)
    lines = [json.dumps({"n": n, "pad": "x" * 20}) for n in range(6)]
    for line in lines:
        writer.write_line(line)
    writer.close()
    kept = path.read_text().splitlines()
    assert path.stat().st_size <= 100
    # Whole lines only, the newest last: the file started over, it was
    # never cut mid-line.
    assert kept and kept == lines[-len(kept):]
    assert all(json.loads(line) for line in kept)


def test_an_existing_file_keeps_its_lines_until_the_cap(tmp_path):
    """A restarted logger appends; it doesn't wipe the readers' history."""
    path = tmp_path / "events.jsonl"
    first = xdp.EventFile(path)
    first.write_line("one")
    first.close()
    second = xdp.EventFile(path)
    second.write_line("two")
    second.close()
    assert path.read_text() == "one\ntwo\n"


def test_follow_file_forever_follows_through_a_missing_file_and_a_truncation(tmp_path):
    """The sensor daemons' reader, with the real `tail -F`: it waits for
    a file that isn't there yet, reads only lines written after it
    started, and carries on after the writer empties the file."""
    path = tmp_path / "events.jsonl"
    seen: list[str] = []
    threading.Thread(target=follow_file_forever, args=(path, seen.append),
                     kwargs={"program": "test"}, daemon=True).start()
    try:
        time.sleep(0.5)
        writer = xdp.EventFile(path, max_bytes=60)
        deadline = time.monotonic() + 10
        n = 0
        while time.monotonic() < deadline and not {"line-0", "line-9"} <= set(seen):
            writer.write_line(f"line-{n}" if n < 10 else "filler")
            n += 1
            time.sleep(0.2)
        writer.close()
        assert "line-0" in seen and "line-9" in seen, seen
    finally:
        subprocess.run(["pkill", "-f", f"tail -n 0 -F -- {path}"], check=False)


def _boot_test():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "installer" / "qemu-boot-test.py"
    spec = importlib.util.spec_from_file_location("qemu_boot_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to chown")
@pytest.mark.parametrize("file_mode, dir_mode, group, ok", [
    (0o640, 0o750, 1234, True),
    (0o644, 0o750, 1234, False),   # world-readable
    (0o660, 0o750, 1234, False),   # the readers' group could write it
    (0o640, 0o755, 1234, False),
    (0o640, 0o750, 0, False),      # not the readers' group
])
def test_the_boot_tests_event_file_check(tmp_path, file_mode, dir_mode, group, ok):
    boot_test = _boot_test()
    upper = tmp_path / "rw"
    (upper / "etc").mkdir(parents=True)
    (upper / "etc" / "group").write_text("root:x:0:\nfr_os-feeds:x:1234:\n")
    directory = upper / "var" / "log" / "fr_os-sni"
    directory.mkdir(parents=True)
    events = directory / "events.jsonl"
    events.write_text("")
    for path, mode in ((events, file_mode), (directory, dir_mode)):
        os.chown(path, 0, group)
        os.chmod(path, mode)
    results = []
    boot_test.check_sni_event_file(lambda passed, label: results.append(passed), upper)
    assert results == [ok]
