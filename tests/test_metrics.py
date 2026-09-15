"""Tests for frfw.metrics: the Prometheus text-exposition-format
renderer, and each metric family's data-gathering logic.

Filesystem-backed sources (/proc, /sys) are faked via monkeypatched
module-level path constants pointed at files under tmp_path -- the same
convention frfw.nft.builder/frfw.ids_quarantine's own tests use for
monkeypatching module constants, and frfw.netdetect's tests use for a
fake sysfs tree. A couple of tests deliberately run against the real
system paths (no monkeypatching) to confirm this actually works against
a genuine kernel, not just a fake tree shaped like one.
"""

from __future__ import annotations

import re

import pytest

from frfw import metrics as metrics_mod
from frfw.config import parse_config
from frfw.metrics import MetricFamily, generate_metrics_text, render


# --- Prometheus text exposition format rendering ----------------------------


def test_render_gauge_with_no_labels():
    fam = MetricFamily("fros_test_gauge", "A test gauge.", "gauge")
    fam.add(42)
    text = render([fam])
    assert text == (
        "# HELP fros_test_gauge A test gauge.\n"
        "# TYPE fros_test_gauge gauge\n"
        "fros_test_gauge 42\n"
    )


def test_render_counter_with_labels():
    fam = MetricFamily("fros_test_counter", "A test counter.", "counter")
    fam.add(10, device="eth0", direction="rx")
    fam.add(20, device="eth0", direction="tx")
    text = render([fam])
    lines = text.splitlines()
    assert lines[0] == "# HELP fros_test_counter A test counter."
    assert lines[1] == "# TYPE fros_test_counter counter"
    assert lines[2] == 'fros_test_counter{device="eth0",direction="rx"} 10'
    assert lines[3] == 'fros_test_counter{device="eth0",direction="tx"} 20'


def test_render_family_with_no_samples_still_emits_help_and_type():
    fam = MetricFamily("fros_test_empty", "Nothing to report yet.", "gauge")
    text = render([fam])
    assert text == "# HELP fros_test_empty Nothing to report yet.\n# TYPE fros_test_empty gauge\n"


def test_render_multiple_families_in_order():
    fam1 = MetricFamily("fros_a", "A.", "gauge")
    fam1.add(1)
    fam2 = MetricFamily("fros_b", "B.", "counter")
    fam2.add(2)
    text = render([fam1, fam2])
    assert text.index("fros_a") < text.index("fros_b")


def test_render_escapes_backslash_quote_and_newline_in_label_values():
    fam = MetricFamily("fros_test", "Test.", "gauge")
    fam.add(1, model='He said "hi"\\there\nfriend')
    text = render([fam])
    assert 'model="He said \\"hi\\"\\\\there\\nfriend"' in text


def test_render_float_value_is_a_valid_float_literal():
    fam = MetricFamily("fros_ratio", "A ratio.", "gauge")
    fam.add(0.4567)
    text = render([fam])
    value_line = [l for l in text.splitlines() if l.startswith("fros_ratio ")][0]
    value = value_line.split()[-1]
    assert float(value) == pytest.approx(0.4567)


#: Structural check every metric line (a sample line, not HELP/TYPE) must
#: satisfy: `name{label="value",...} number` or `name number`.
_SAMPLE_LINE_RE = re.compile(
    r'^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[a-zA-Z_][a-zA-Z0-9_]*="[^"]*"(,[a-zA-Z_][a-zA-Z0-9_]*="[^"]*")*\})? '
    r"[-+]?[0-9]+(\.[0-9]+)?$"
)


def test_full_output_matches_prometheus_exposition_format_structurally(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    text = generate_metrics_text(config, _StubHelper(), adblock_hosts_path=None)

    lines = text.splitlines()
    assert text.endswith("\n")
    seen_help_for: set[str] = set()
    seen_type_for: set[str] = set()
    for line in lines:
        if line.startswith("# HELP "):
            name = line.split()[2]
            seen_help_for.add(name)
            continue
        if line.startswith("# TYPE "):
            _, _, name, type_ = line.split()
            assert type_ in ("counter", "gauge")
            seen_type_for.add(name)
            continue
        assert _SAMPLE_LINE_RE.match(line), f"not a valid Prometheus sample line: {line!r}"
        name = line.split("{")[0].split()[0]
        assert name in seen_help_for, f"sample for {name!r} has no preceding # HELP"
        assert name in seen_type_for, f"sample for {name!r} has no preceding # TYPE"


class _StubHelper:
    def ztna_sessions_status(self):
        return {"ok": True, "count": 0}

    def bruteforce_status(self):
        return {"ok": True, "count": 0}

    def ids_quarantine_status(self):
        return {"ok": True, "count": 0}

    def hw_ram_info(self):
        return {"ok": True, "modules": []}


# --- fros_interface_bytes_total ---------------------------------------------


def _write_iface_stats(sys_net_dir, device, rx, tx):
    stats_dir = sys_net_dir / device / "statistics"
    stats_dir.mkdir(parents=True)
    (stats_dir / "rx_bytes").write_text(f"{rx}\n")
    (stats_dir / "tx_bytes").write_text(f"{tx}\n")


def test_interface_bytes_reads_real_sysfs_style_files(minimal_config_dict, tmp_path, monkeypatch):
    sys_net = tmp_path / "class_net"
    _write_iface_stats(sys_net, "eth0", 111, 222)
    _write_iface_stats(sys_net, "eth1", 333, 444)
    monkeypatch.setattr(metrics_mod, "_SYS_NET_DIR", sys_net)

    config = parse_config(minimal_config_dict)  # interfaces eth0 (wan), eth1 (lan)
    fam = metrics_mod._read_interface_bytes_family(config)

    values = {(s.labels["device"], s.labels["direction"]): s.value for s in fam.samples}
    assert values == {
        ("eth0", "rx"): 111, ("eth0", "tx"): 222,
        ("eth1", "rx"): 333, ("eth1", "tx"): 444,
    }


def test_interface_bytes_skips_device_with_missing_stats(minimal_config_dict, tmp_path, monkeypatch):
    sys_net = tmp_path / "class_net"
    _write_iface_stats(sys_net, "eth0", 111, 222)
    # eth1 has no statistics directory at all.
    monkeypatch.setattr(metrics_mod, "_SYS_NET_DIR", sys_net)

    config = parse_config(minimal_config_dict)
    fam = metrics_mod._read_interface_bytes_family(config)
    devices = {s.labels["device"] for s in fam.samples}
    assert devices == {"eth0"}


def test_interface_bytes_reads_real_loopback_from_the_real_system():
    """No monkeypatching -- confirms this actually works against a real
    kernel's /sys/class/net, not just a fake tree shaped like one."""
    config = parse_config(
        {
            "version": 1, "hostname": "t", "zones": {"wan": {}},
            "interfaces": {"wan": {"device": "lo", "zone": "wan"}}, "rules": [], "nat": {},
        }
    )
    fam = metrics_mod._read_interface_bytes_family(config)
    assert len(fam.samples) == 2
    assert all(isinstance(s.value, int) and s.value >= 0 for s in fam.samples)


# --- fros_xdp_status / fros_xdp_blocked_connections_total -------------------


def test_xdp_status_empty_when_disabled(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    fam = metrics_mod._read_xdp_status_family(config)
    assert fam.samples == []


def test_xdp_status_reports_native_and_generic_modes(minimal_config_dict, monkeypatch):
    from frfw import xdp as xdp_mod

    minimal_config_dict["xdp_sni_filter"] = {"enabled": True, "interfaces": ["wan", "lan"]}
    config = parse_config(minimal_config_dict)
    monkeypatch.setattr(xdp_mod, "get_attached", lambda: {"eth0": "xdpdrv", "eth1": "xdpgeneric"})

    fam = metrics_mod._read_xdp_status_family(config)
    values = {s.labels["device"]: s.value for s in fam.samples}
    assert values == {"eth0": 1, "eth1": 2}


def test_xdp_status_reports_zero_for_configured_but_not_attached(minimal_config_dict, monkeypatch):
    from frfw import xdp as xdp_mod

    minimal_config_dict["xdp_sni_filter"] = {"enabled": True, "interfaces": ["wan"]}
    config = parse_config(minimal_config_dict)
    monkeypatch.setattr(xdp_mod, "get_attached", lambda: {})

    fam = metrics_mod._read_xdp_status_family(config)
    assert fam.samples[0].value == 0


def test_xdp_blocked_connections_reads_drop_match_stat(monkeypatch):
    from frfw import xdp as xdp_mod

    monkeypatch.setattr(xdp_mod, "get_stats", lambda: {"drop_match": 7, "pass_no_sni": 3})
    fam = metrics_mod._read_xdp_blocked_family()
    assert fam.samples == [metrics_mod._Sample(value=7, labels={})]


# --- fros_adblock_total_domains ---------------------------------------------


def test_adblock_family_reports_zero_for_missing_hosts_file(tmp_path):
    fam = metrics_mod._read_adblock_family(tmp_path / "does-not-exist.hosts")
    assert fam.samples[0].value == 0


def test_adblock_family_counts_real_hosts_file(tmp_path):
    hosts_path = tmp_path / "adblock.hosts"
    hosts_path.write_text("0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.com\n")
    fam = metrics_mod._read_adblock_family(hosts_path)
    assert fam.samples[0].value == 2


# --- helper-backed status gauges (ztna/bruteforce/ai_ids) -------------------


class _CountHelper:
    def __init__(self, **counts):
        self._counts = counts

    def ztna_sessions_status(self):
        return {"ok": True, "count": self._counts.get("ztna", 0)}

    def bruteforce_status(self):
        return {"ok": True, "count": self._counts.get("bruteforce", 0)}

    def ids_quarantine_status(self):
        return {"ok": True, "count": self._counts.get("ai_ids", 0)}


def test_ztna_bruteforce_ai_ids_families_report_helper_counts():
    helper = _CountHelper(ztna=2, bruteforce=1, ai_ids=3)
    assert metrics_mod._read_ztna_family(helper).samples[0].value == 2
    assert metrics_mod._read_bruteforce_family(helper).samples[0].value == 1
    assert metrics_mod._read_ai_ids_family(helper).samples[0].value == 3


class _FailingHelper:
    def ztna_sessions_status(self):
        return {"ok": False, "message": "nft not found"}


def test_ztna_family_reports_nothing_when_helper_reports_failure():
    fam = metrics_mod._read_ztna_family(_FailingHelper())
    assert fam.samples == []


# --- CPU metrics -------------------------------------------------------------


def test_cpu_model_parses_real_proc_cpuinfo_field(tmp_path, monkeypatch):
    cpuinfo = tmp_path / "cpuinfo"
    cpuinfo.write_text("processor\t: 0\nmodel name\t: Intel(R) Xeon(R) Fake CPU\ncpu MHz\t\t: 2799.998\n")
    monkeypatch.setattr(metrics_mod, "_PROC_CPUINFO_PATH", cpuinfo)
    assert metrics_mod._read_cpu_model() == "Intel(R) Xeon(R) Fake CPU"


def test_cpu_mhz_prefers_cpufreq_sysfs_when_present(tmp_path, monkeypatch):
    cpufreq = tmp_path / "scaling_cur_freq"
    cpufreq.write_text("2400000\n")  # kHz
    monkeypatch.setattr(metrics_mod, "_CPUFREQ_CUR_PATH", cpufreq)
    assert metrics_mod._read_cpu_mhz() == 2400.0


def test_cpu_mhz_falls_back_to_cpuinfo_when_no_cpufreq(tmp_path, monkeypatch):
    monkeypatch.setattr(metrics_mod, "_CPUFREQ_CUR_PATH", tmp_path / "does-not-exist")
    cpuinfo = tmp_path / "cpuinfo"
    cpuinfo.write_text("model name\t: Fake CPU\ncpu MHz\t\t: 1234.5\n")
    monkeypatch.setattr(metrics_mod, "_PROC_CPUINFO_PATH", cpuinfo)
    assert metrics_mod._read_cpu_mhz() == 1234.5


def test_cpu_usage_ratio_computes_delta_between_two_samples(tmp_path, monkeypatch):
    stat_path = tmp_path / "stat"
    monkeypatch.setattr(metrics_mod, "_PROC_STAT_PATH", stat_path)

    samples = iter([
        "cpu  100 0 100 800 0 0 0 0 0 0\n",  # busy=200, total=1000
        "cpu  150 0 150 900 0 0 0 0 0 0\n",  # busy=300, total=1200
    ])

    def fake_read_text(self):
        return next(samples)

    monkeypatch.setattr(type(stat_path), "read_text", fake_read_text)
    # sample_interval=0.0 explicitly -- the module's own default constant
    # is baked into the function signature at def time, so monkeypatching
    # it afterward has no effect (a real gotcha this test deliberately
    # avoids rather than silently sleeping the module default for no
    # reason).
    ratio = metrics_mod._read_cpu_usage_ratio(sample_interval=0.0)
    # busy delta = 100, total delta = 200 -> 0.5
    assert ratio == pytest.approx(0.5)


def test_cpu_usage_ratio_real_system_is_between_zero_and_one():
    """No monkeypatching -- a real, hands-on double-sample against this
    sandbox's actual /proc/stat."""
    ratio = metrics_mod._read_cpu_usage_ratio(sample_interval=0.05)
    assert ratio is not None
    assert 0.0 <= ratio <= 1.0


def test_cpu_usage_ratio_none_when_proc_stat_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(metrics_mod, "_PROC_STAT_PATH", tmp_path / "does-not-exist")
    assert metrics_mod._read_cpu_usage_ratio() is None


# --- RAM metrics ---------------------------------------------------------------


def test_ram_totals_parses_real_meminfo_format(tmp_path, monkeypatch):
    meminfo = tmp_path / "meminfo"
    meminfo.write_text("MemTotal:       16482220 kB\nMemFree:        100 kB\nMemAvailable:   15878600 kB\n")
    monkeypatch.setattr(metrics_mod, "_PROC_MEMINFO_PATH", meminfo)

    used, total = metrics_mod._read_ram_totals()
    assert total == 16482220 * 1024
    assert used == (16482220 - 15878600) * 1024


def test_ram_totals_none_when_fields_missing(tmp_path, monkeypatch):
    meminfo = tmp_path / "meminfo"
    meminfo.write_text("SomeOtherField: 1 kB\n")
    monkeypatch.setattr(metrics_mod, "_PROC_MEMINFO_PATH", meminfo)
    assert metrics_mod._read_ram_totals() is None


def test_ram_families_include_info_gauge_from_helper():
    helper = _RamHelper(modules=[{"part_number": "ABC-123", "speed_mhz": 3200}])
    info_fam, usage_fam, total_fam = metrics_mod._read_ram_families(helper)
    assert info_fam.samples[0].labels == {"model": "ABC-123", "speed_mhz": "3200"}
    assert info_fam.samples[0].value == 1


def test_ram_families_empty_info_when_dmidecode_unavailable():
    helper = _RamHelper(modules=[])
    info_fam, _, _ = metrics_mod._read_ram_families(helper)
    assert info_fam.samples == []


class _RamHelper:
    def __init__(self, modules):
        self._modules = modules

    def hw_ram_info(self):
        return {"ok": True, "modules": self._modules}


def test_ram_usage_and_total_use_the_real_system_meminfo():
    """No monkeypatching -- real /proc/meminfo on this sandbox."""
    helper = _RamHelper(modules=[])
    _, usage_fam, total_fam = metrics_mod._read_ram_families(helper)
    assert usage_fam.samples[0].value > 0
    assert total_fam.samples[0].value > usage_fam.samples[0].value


# --- storage metrics -----------------------------------------------------------


def test_storage_mounts_filters_virtual_filesystems(tmp_path, monkeypatch):
    mounts = tmp_path / "mounts"
    mounts.write_text(
        "proc /proc proc rw 0 0\n"
        "tmpfs /dev/shm tmpfs rw 0 0\n"
        "/dev/sda1 / ext4 rw 0 0\n"
        "/dev/sdb1 /data ext4 rw 0 0\n"
    )
    monkeypatch.setattr(metrics_mod, "_PROC_MOUNTS_PATH", mounts)

    result = metrics_mod._read_storage_mounts()
    assert result == [("/", "/dev/sda1"), ("/data", "/dev/sdb1")]


def test_storage_mounts_deduplicates_repeated_mount_points(tmp_path, monkeypatch):
    mounts = tmp_path / "mounts"
    mounts.write_text("/dev/sda1 / ext4 rw 0 0\n/dev/sda1 / ext4 ro,remount 0 0\n")
    monkeypatch.setattr(metrics_mod, "_PROC_MOUNTS_PATH", mounts)

    result = metrics_mod._read_storage_mounts()
    assert result == [("/", "/dev/sda1")]


def test_storage_families_report_usage_via_statvfs(tmp_path, monkeypatch):
    mounts = tmp_path / "mounts"
    mounts.write_text(f"/dev/fake {tmp_path} ext4 rw 0 0\n")
    monkeypatch.setattr(metrics_mod, "_PROC_MOUNTS_PATH", mounts)

    info_fam, usage_fam, total_fam = metrics_mod._read_storage_families()
    assert info_fam.samples[0].labels == {"mount": str(tmp_path), "device_name": "/dev/fake"}
    assert usage_fam.samples[0].value >= 0
    assert total_fam.samples[0].value > 0


def test_storage_families_real_root_filesystem():
    """No monkeypatching -- confirms this actually works against the
    real system's /proc/mounts and a real os.statvfs call."""
    info_fam, usage_fam, total_fam = metrics_mod._read_storage_families()
    mounts = {s.labels["mount"] for s in info_fam.samples}
    assert "/" in mounts


# --- top-level orchestration / error isolation -----------------------------


def test_generate_metrics_text_with_none_config_skips_config_dependent_families():
    text = generate_metrics_text(None, _StubHelper(), adblock_hosts_path=None)
    assert "fros_interface_bytes_total" not in text
    assert "fros_xdp_status" not in text
    # Config-independent families are still present.
    assert "fros_hw_cpu_info" in text


def test_generate_metrics_text_survives_a_broken_helper(minimal_config_dict):
    class BrokenHelper:
        def ztna_sessions_status(self):
            raise RuntimeError("socket exploded")

        def bruteforce_status(self):
            return {"ok": True, "count": 0}

        def ids_quarantine_status(self):
            return {"ok": True, "count": 0}

        def hw_ram_info(self):
            return {"ok": True, "modules": []}

    config = parse_config(minimal_config_dict)
    text = generate_metrics_text(config, BrokenHelper(), adblock_hosts_path=None)

    # The broken family is silently skipped...
    assert "fros_ztna_active_sessions" not in text
    # ...but everything else still renders.
    assert "fros_bruteforce_banned_ips" in text
    assert "fros_hw_cpu_info" in text


def test_generate_metrics_text_survives_a_missing_adblock_path(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    # None is not a valid Path -- count_blocked_domains would raise
    # trying to use it; the per-family isolation must swallow that.
    text = generate_metrics_text(config, _StubHelper(), adblock_hosts_path=None)
    assert "fros_adblock_total_domains" not in text
    assert "fros_hw_cpu_info" in text  # unrelated families unaffected
