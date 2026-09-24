"""Tests for frfw.iot.classify's point-based scoring."""

from __future__ import annotations

from frfw.iot.classify import (
    CATEGORY_GENERAL,
    CATEGORY_IOT,
    CATEGORY_UNKNOWN,
    Observation,
    classify,
)


def test_espressif_with_esphome_service_is_iot():
    result = classify(
        Observation(mac="24:0a:c4:11:22:33", vendor="Espressif Inc.", services=("_esphomelib._tcp",))
    )
    assert result.category == CATEGORY_IOT
    assert result.score == 6
    assert any("Espressif" in r for r in result.reasons)
    assert any("ESPHome" in r for r in result.reasons)


def test_strong_vendor_alone_reaches_threshold():
    assert classify(Observation(mac="24:0a:c4:11:22:33", vendor="Tuya Smart Inc.")).category == CATEGORY_IOT


def test_mixed_vendor_alone_stays_unknown():
    result = classify(Observation(mac="50:c7:bf:11:22:33", vendor="TP-LINK TECHNOLOGIES CO.,LTD."))
    assert result.category == CATEGORY_UNKNOWN
    assert result.score == 1


def test_mixed_vendor_plus_iot_hostname_is_iot():
    result = classify(Observation(mac="50:c7:bf:11:22:33", vendor="TP-LINK TECHNOLOGIES CO.,LTD.", hostname="HS110"))
    assert result.category == CATEGORY_IOT


def test_randomized_mac_with_computer_services_is_general():
    result = classify(
        Observation(mac="3a:11:22:33:44:55", hostname="Marias-MacBook", services=("_companion-link._tcp",))
    )
    assert result.category == CATEGORY_GENERAL
    assert result.score == -7


def test_homekit_accessory_with_no_vendor_is_iot():
    assert classify(Observation(mac="00:11:22:33:44:55", services=("_hap._tcp",))).category == CATEGORY_IOT


def test_no_signal_is_unknown_with_an_explanation():
    result = classify(Observation(mac="00:11:22:33:44:55"))
    assert result.category == CATEGORY_UNKNOWN
    assert result.score == 0
    assert result.reasons and "no identifying signal" in result.reasons[0]


def test_iot_and_computer_services_cancel_out():
    result = classify(Observation(mac="00:11:22:33:44:55", services=("_airplay._tcp", "_hap._tcp", "_ssh._tcp")))
    assert result.score == 0
    assert result.category == CATEGORY_UNKNOWN
