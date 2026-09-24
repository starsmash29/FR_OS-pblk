"""Tests for the IoT scanner's three passive inventory sources:
frfw.iot.oui (IEEE vendor registry), frfw.iot.arp (/proc/net/arp) and
frfw.iot.leases (Kea's memfile lease CSV)."""

from __future__ import annotations

from pathlib import Path

import pytest

from frfw.iot import arp, leases, oui

# --- OUI -------------------------------------------------------------------

_OUI_SAMPLE = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    "MA-L,240AC4,Espressif Inc.,\"Room 204, Building 2, Shanghai CN 200433 \"\n"
    'MA-L,50C7BF,"TP-LINK TECHNOLOGIES CO.,LTD.","Building 24, Shenzhen CN 518057 "\n'
    "MA-M,70B3D5123,Some Small Vendor,Somewhere\n"
)


@pytest.fixture
def oui_csv(tmp_path) -> Path:
    path = tmp_path / "oui.csv"
    path.write_text(_OUI_SAMPLE)
    return path


def test_load_vendor_db_reads_only_ma_l_and_handles_quoted_commas(oui_csv):
    db = oui.load_vendor_db(oui_csv)
    assert db == {"240AC4": "Espressif Inc.", "50C7BF": "TP-LINK TECHNOLOGIES CO.,LTD."}


def test_load_vendor_db_missing_file_is_empty(tmp_path):
    assert oui.load_vendor_db(tmp_path / "missing.csv") == {}


def test_vendor_for_matches_prefix_case_insensitively(oui_csv):
    db = oui.load_vendor_db(oui_csv)
    assert oui.vendor_for("24:0a:c4:11:22:33", db) == "Espressif Inc."
    assert oui.vendor_for("00:11:22:33:44:55", db) is None


def test_randomized_mac_never_gets_a_vendor(oui_csv):
    db = {"260AC4": "Should Not Match"}
    assert oui.is_locally_administered("26:0a:c4:11:22:33")
    assert oui.vendor_for("26:0a:c4:11:22:33", db) is None
    assert not oui.is_locally_administered("24:0a:c4:11:22:33")


@pytest.mark.parametrize(
    "raw,expected",
    [("AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"), (" aa:bb:cc:dd:ee:ff ", "aa:bb:cc:dd:ee:ff"), ("nope", None), (None, None)],
)
def test_normalize_mac(raw, expected):
    assert oui.normalize_mac(raw) == expected


def test_real_ieee_registry_if_installed():
    """Runs against Debian's real ieee-data file when present (installed
    in this sandbox to confirm the CSV format above is the real one)."""
    if not oui.OUI_CSV_PATH.exists():
        pytest.skip("ieee-data package not installed")
    db = oui.load_vendor_db()
    assert len(db) > 10000
    assert any("espressif" in v.lower() for v in db.values())


# --- ARP -------------------------------------------------------------------

_ARP_SAMPLE = """IP address       HW type     Flags       HW address            Mask     Device
10.0.0.20        0x1         0x2         24:0a:c4:11:22:33     *        eth1
10.0.0.21        0x1         0x0         00:00:00:00:00:00     *        eth1
10.0.0.22        0x1         0x6         AA:BB:CC:DD:EE:FF     *        eth2
garbage line
"""


def test_read_arp_table_skips_incomplete_entries(tmp_path):
    path = tmp_path / "arp"
    path.write_text(_ARP_SAMPLE)
    entries = arp.read_arp_table(path)
    assert entries == [
        arp.ArpEntry(ip="10.0.0.20", mac="24:0a:c4:11:22:33", device="eth1"),
        arp.ArpEntry(ip="10.0.0.22", mac="aa:bb:cc:dd:ee:ff", device="eth2"),
    ]


def test_read_arp_table_missing_file(tmp_path):
    assert arp.read_arp_table(tmp_path / "nope") == []


def test_real_proc_net_arp_is_readable_unprivileged():
    # World-readable, the reason the scanner needs no helper round trip
    # for it (confirmed by hand: -r--r--r-- root root).
    assert arp.ARP_PATH.stat().st_mode & 0o004
    assert isinstance(arp.read_arp_table(), list)


# --- Kea leases ------------------------------------------------------------

_HEADER = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n"


def test_read_leases_last_row_wins_and_filters_expired_and_states(tmp_path):
    now = 1_700_000_000
    path = tmp_path / "kea-leases4.csv"
    path.write_text(
        _HEADER
        + f"10.0.0.50,24:0a:c4:11:22:33,,3600,{now + 100},1,0,0,esp_112233,0,,0\n"
        + f"10.0.0.51,aa:bb:cc:dd:ee:01,,3600,{now - 5},1,0,0,old,0,,0\n"   # expired
        + f"10.0.0.52,aa:bb:cc:dd:ee:02,,3600,{now + 100},1,0,0,declined,1,,0\n"  # declined
        + f"10.0.0.53,aa:bb:cc:dd:ee:03,,3600,{now + 100},1,0,0,first,0,,0\n"
        + f"10.0.0.53,aa:bb:cc:dd:ee:03,,3600,{now - 1},1,0,0,first,2,,0\n"  # later: reclaimed
        + f"10.0.0.54,aa:bb:cc:dd:ee:04,,3600,{now + 100},1,0,0,renewed-old,0,,0\n"
        + f"10.0.0.54,AA:BB:CC:DD:EE:05,,3600,{now + 200},1,0,0,Printer&#x2cOffice,0,,0\n"
    )
    result = leases.read_leases(path, now=now)
    assert [(l.ip, l.mac, l.hostname) for l in result] == [
        ("10.0.0.50", "24:0a:c4:11:22:33", "esp_112233"),
        ("10.0.0.54", "aa:bb:cc:dd:ee:05", "Printer,Office"),
    ]


def test_read_leases_tolerates_older_kea_without_pool_id_column(tmp_path):
    now = 1_700_000_000
    path = tmp_path / "kea-leases4.csv"
    path.write_text(
        "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context\n"
        f"10.0.0.60,aa:bb:cc:dd:ee:06,,3600,{now + 10},1,0,0,host,0,\n"
    )
    assert [l.ip for l in leases.read_leases(path, now=now)] == ["10.0.0.60"]


def test_read_leases_missing_file_is_empty(tmp_path):
    assert leases.read_leases(tmp_path / "nope.csv") == []


def test_hostname_is_sanitized(tmp_path):
    now = 1_700_000_000
    path = tmp_path / "kea-leases4.csv"
    evil = "bad\x07host name" + "x" * 400
    path.write_text(_HEADER + f"10.0.0.70,aa:bb:cc:dd:ee:07,,3600,{now + 10},1,0,0,{evil},0,,0\n")
    (lease,) = leases.read_leases(path, now=now)
    assert len(lease.hostname) == 253
    assert lease.hostname.startswith("badhostname")  # control char and space dropped
