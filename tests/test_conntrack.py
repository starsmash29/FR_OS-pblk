"""Tests for frfw.conntrack. Unit tests parse hand-written conntrack
lines (the exact three formats -- TCP with a state field, UDP without
one, and ICMP with no ports at all -- confirmed against the real kernel
source's ct_seq_show() field layout); a real integration test (root
only) confirms the actual permission model this module's docstring
documents by hand: /proc/net/nf_conntrack is unreadable without root."""

from __future__ import annotations

import os

import pytest

from frfw import conntrack

requires_root = pytest.mark.skipif(os.geteuid() != 0, reason="permission test requires root")


def test_parses_a_real_tcp_line():
    line = (
        "ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=93.184.216.34 "
        "sport=54321 dport=443 src=93.184.216.34 dst=10.0.0.5 sport=443 dport=54321 "
        "[ASSURED] mark=0 use=1"
    )
    flow = conntrack._parse_line(line)
    assert flow == conntrack.ConntrackFlow(
        proto="tcp", src="10.0.0.5", sport=54321, dst="93.184.216.34", dport=443
    )


def test_parses_a_real_udp_line_with_no_state_field():
    line = (
        "ipv4     2 udp      17 29 src=10.0.0.5 dst=8.8.8.8 sport=51000 dport=53 "
        "[UNREPLIED] src=8.8.8.8 dst=10.0.0.5 sport=53 dport=51000 mark=0 use=1"
    )
    flow = conntrack._parse_line(line)
    assert flow == conntrack.ConntrackFlow(
        proto="udp", src="10.0.0.5", sport=51000, dst="8.8.8.8", dport=53
    )


def test_ignores_icmp_lines_with_no_ports():
    line = (
        "ipv4     2 icmp     1 29 src=10.0.0.5 dst=1.1.1.1 type=8 code=0 id=123 "
        "src=1.1.1.1 dst=10.0.0.5 type=0 code=0 id=123 mark=0 use=1"
    )
    assert conntrack._parse_line(line) is None


def test_ignores_short_or_malformed_lines():
    assert conntrack._parse_line("") is None
    assert conntrack._parse_line("garbage") is None
    assert conntrack._parse_line("ipv4 2 tcp 6 431999 ESTABLISHED src=only") is None


def test_read_snapshot_returns_empty_list_when_file_missing(tmp_path):
    assert conntrack.read_snapshot(tmp_path / "does-not-exist") == []


def test_read_snapshot_parses_multiple_lines(tmp_path):
    path = tmp_path / "nf_conntrack"
    path.write_text(
        "ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=1.1.1.1 "
        "sport=1 dport=443 src=1.1.1.1 dst=10.0.0.5 sport=443 dport=1 [ASSURED]\n"
        "ipv4     2 udp      17 29 src=10.0.0.6 dst=8.8.8.8 sport=2 dport=53 "
        "[UNREPLIED] src=8.8.8.8 dst=10.0.0.6 sport=53 dport=2\n"
    )
    flows = conntrack.read_snapshot(path)
    assert len(flows) == 2
    assert {f.src for f in flows} == {"10.0.0.5", "10.0.0.6"}


def test_read_snapshot_raises_conntrack_error_on_permission_denied(tmp_path, monkeypatch):
    path = tmp_path / "nf_conntrack"
    path.write_text("irrelevant")

    def deny(self):
        raise PermissionError("denied")

    monkeypatch.setattr(type(path), "read_text", deny, raising=False)
    with pytest.raises(conntrack.ConntrackError):
        conntrack.read_snapshot(path)


@requires_root
def test_real_proc_net_nf_conntrack_is_root_only():
    """Confirms, for real, the permission model frfw.conntrack's own
    docstring documents by hand: an unprivileged process cannot read
    /proc/net/nf_conntrack, which is exactly why frfw.helper.server's
    "conntrack_sample" command exists instead of the unprivileged
    fr-ai-ids daemon reading it directly."""
    import subprocess

    if not conntrack.CONNTRACK_PATH.is_file():
        pytest.skip("this kernel/sandbox has no /proc/net/nf_conntrack at all")

    proc = subprocess.run(
        ["runuser", "-u", "nobody", "--", "cat", str(conntrack.CONNTRACK_PATH)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "permission denied" in proc.stderr.lower()
