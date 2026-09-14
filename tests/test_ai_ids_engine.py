"""Tests for the mock frfw.ai_ids.AIIDSEngine.

These pin down behavior, not "correct" security detection -- there is no
such thing here, by design (see the module docstring). What matters is:
determinism (same MAC -> same mock stats every call), that excluded_macs
are actually excluded, and that lock/retrain state persists correctly.
"""

from __future__ import annotations

import pytest

from frfw.ai_ids import AIIDSEngine, train_isolation_forest
from frfw.config import parse_config


@pytest.fixture
def two_device_config(dhcp_config_dict):
    dhcp_config_dict["dhcp"]["lan"]["reservations"].append(
        {"mac": "11:22:33:44:55:66", "address": "10.0.0.51", "hostname": "laptop"}
    )
    return parse_config(dhcp_config_dict)


def test_list_devices_from_dhcp_reservations(two_device_config, tmp_path):
    engine = AIIDSEngine(two_device_config, tmp_path / "state.json")
    devices = engine.list_devices()

    assert {d.mac for d in devices} == {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}
    nas = next(d for d in devices if d.mac == "aa:bb:cc:dd:ee:ff")
    assert nas.hostname == "nas"
    assert nas.ip == "10.0.0.50"
    assert nas.locked is False
    assert 0 <= nas.learning_percent <= 100
    assert nas.risk_label
    assert nas.top_protocols
    assert nas.known_domains_count > 0


def test_mock_stats_are_deterministic_per_mac(two_device_config, tmp_path):
    engine = AIIDSEngine(two_device_config, tmp_path / "state.json")
    first = {d.mac: (d.risk_label, tuple(d.top_protocols), d.known_domains_count) for d in engine.list_devices()}
    second = {d.mac: (d.risk_label, tuple(d.top_protocols), d.known_domains_count) for d in engine.list_devices()}
    assert first == second


def test_excluded_macs_are_never_profiled(dhcp_config_dict, tmp_path):
    dhcp_config_dict["ai_ids"] = {"excluded_macs": ["aa:bb:cc:dd:ee:ff"]}
    config = parse_config(dhcp_config_dict)
    engine = AIIDSEngine(config, tmp_path / "state.json")

    assert engine.list_devices() == []
    assert engine.global_learning_progress() == 0.0


def test_global_learning_progress_is_average(two_device_config, tmp_path):
    engine = AIIDSEngine(two_device_config, tmp_path / "state.json")
    devices = engine.list_devices()
    expected = sum(d.learning_percent for d in devices) / len(devices)
    assert engine.global_learning_progress() == expected


def test_lock_profile_pins_learning_at_100(two_device_config, tmp_path):
    engine = AIIDSEngine(two_device_config, tmp_path / "state.json")
    engine.lock_profile("aa:bb:cc:dd:ee:ff")

    devices = {d.mac: d for d in engine.list_devices()}
    assert devices["aa:bb:cc:dd:ee:ff"].locked is True
    assert devices["aa:bb:cc:dd:ee:ff"].learning_percent == 100
    assert devices["11:22:33:44:55:66"].locked is False


def test_lock_profile_persists_across_engine_instances(two_device_config, tmp_path):
    state_path = tmp_path / "state.json"
    AIIDSEngine(two_device_config, state_path).lock_profile("aa:bb:cc:dd:ee:ff")

    reloaded = AIIDSEngine(two_device_config, state_path)
    devices = {d.mac: d for d in reloaded.list_devices()}
    assert devices["aa:bb:cc:dd:ee:ff"].locked is True


def test_lock_profile_unknown_mac_raises(two_device_config, tmp_path):
    engine = AIIDSEngine(two_device_config, tmp_path / "state.json")
    with pytest.raises(KeyError):
        engine.lock_profile("ff:ff:ff:ff:ff:ff")


def test_force_retrain_unlocks_and_resets_one_device(two_device_config, tmp_path):
    engine = AIIDSEngine(two_device_config, tmp_path / "state.json")
    engine.lock_profile("aa:bb:cc:dd:ee:ff")

    engine.force_retrain("aa:bb:cc:dd:ee:ff")

    devices = {d.mac: d for d in engine.list_devices()}
    assert devices["aa:bb:cc:dd:ee:ff"].locked is False
    assert devices["aa:bb:cc:dd:ee:ff"].learning_percent == 0


def test_force_retrain_all_resets_every_device(two_device_config, tmp_path):
    engine = AIIDSEngine(two_device_config, tmp_path / "state.json")
    engine.lock_profile("aa:bb:cc:dd:ee:ff")
    engine.lock_profile("11:22:33:44:55:66")

    engine.force_retrain(None)

    devices = engine.list_devices()
    assert all(not d.locked for d in devices)
    assert all(d.learning_percent == 0 for d in devices)


def test_force_retrain_unknown_mac_raises(two_device_config, tmp_path):
    engine = AIIDSEngine(two_device_config, tmp_path / "state.json")
    with pytest.raises(KeyError):
        engine.force_retrain("ff:ff:ff:ff:ff:ff")


def test_no_devices_gives_zero_global_progress(minimal_config_dict, tmp_path):
    config = parse_config(minimal_config_dict)  # no dhcp reservations at all
    engine = AIIDSEngine(config, tmp_path / "state.json")
    assert engine.list_devices() == []
    assert engine.global_learning_progress() == 0.0


def test_train_isolation_forest_is_an_explicit_stub():
    with pytest.raises(NotImplementedError):
        train_isolation_forest()
