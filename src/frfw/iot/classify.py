"""Heuristic "is this an IoT device?" scoring.

No single signal is reliable on its own -- TP-Link makes both smart
plugs and laptop NICs, a Mac also advertises `_airplay._tcp` -- so each
signal adds or subtracts points and the verdict comes from the sum, with
every contributing reason kept so the webUI can show *why* a device was
classified the way it was. This is deliberately a transparent point
system, not a model: an admin has to be able to predict and override it
(iot.trusted_macs / iot.isolated_macs).

Signals (all passively or cheaply observable, none needs decryption):
- the IEEE OUI vendor of the MAC address (frfw.iot.oui);
- mDNS/DNS-SD service types the device advertises (frfw.iot.mdns);
- the DHCP hostname the device announced itself with (option 12);
- the locally-administered ("randomized") MAC bit, which phones and
  laptops use for privacy and embedded devices practically never do.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from frfw.iot.oui import is_locally_administered

CATEGORY_IOT = "iot"
CATEGORY_GENERAL = "general"
CATEGORY_UNKNOWN = "unknown"

IOT_THRESHOLD = 3
GENERAL_THRESHOLD = -2

#: Vendors whose registered OUIs are, in practice, almost only used on
#: embedded/IoT hardware. Matched as lowercase substrings of the IEEE
#: organization name (checked against the real registry: e.g.
#: "Espressif Inc.", "Tuya Smart Inc.", "Signify B.V.", "Nest Labs Inc.").
_STRONG_IOT_VENDORS = (
    "espressif", "tuya", "allterco", "itead", "signify", "philips lighting",
    "sonos", "roku", "ecobee", "wyze", "hikvision", "dahua", "ring llc",
    "nest labs", "arlo", "chamberlain", "lifx", "meross", "govee",
    "nanoleaf", "yeelight",
)

#: Vendors that ship lots of IoT gear *and* lots of phones/PCs/network
#: kit -- a weak hint only.
_MIXED_VENDORS = (
    "amazon technologies", "google", "xiaomi", "tp-link", "belkin", "raspberry pi",
)

_IOT_SERVICES = {
    "_hap._tcp": "HomeKit accessory",
    "_hap._udp": "HomeKit accessory (Thread)",
    "_homekit._tcp": "HomeKit",
    "_googlecast._tcp": "Google Cast device",
    "_hue._tcp": "Philips Hue bridge",
    "_sonos._tcp": "Sonos speaker",
    "_spotify-connect._tcp": "Spotify Connect speaker",
    "_matter._tcp": "Matter device",
    "_matterc._udp": "Matter commissionable device",
    "_esphomelib._tcp": "ESPHome firmware",
    "_shelly._tcp": "Shelly device",
    "_amzn-wplay._tcp": "Amazon Fire TV / Echo",
    "_ipp._tcp": "network printer",
    "_ipps._tcp": "network printer",
    "_printer._tcp": "network printer",
    "_pdl-datastream._tcp": "network printer",
    "_miio._udp": "Xiaomi Mi Home device",
    "_arduino._tcp": "Arduino board",
}

_GENERAL_SERVICES = {
    "_workstation._tcp": "workstation",
    "_smb._tcp": "file sharing (SMB)",
    "_afpovertcp._tcp": "file sharing (AFP)",
    "_ssh._tcp": "SSH server",
    "_sftp-ssh._tcp": "SFTP server",
    "_companion-link._tcp": "Apple phone/tablet/computer",
    "_rdlink._tcp": "Apple phone/tablet/computer",
}

_IOT_HOSTNAME_HINTS = (
    "esp_", "esp-", "espressif", "tasmota", "shelly", "sonoff", "tuya", "wled",
    "chromecast", "echo-", "kasa", "hs100", "hs103", "hs105", "hs110", "philips-hue",
    "sonos", "roku", "ring-", "nest-", "wyze", "ipcam", "camera", "doorbell",
    "thermostat", "smartplug", "smart-plug", "bulb", "yeelink", "miio", "printer",
)

_GENERAL_HOSTNAME_HINTS = (
    "desktop", "laptop", "macbook", "imac", "iphone", "ipad", "android-",
    "galaxy", "pixel", "thinkpad", "workstation", "-pc",
)


@dataclass(frozen=True)
class Observation:
    mac: str
    ip: str | None = None
    hostname: str = ""
    interface: str = ""
    vendor: str | None = None
    services: tuple[str, ...] = ()


@dataclass(frozen=True)
class Classification:
    category: str
    score: int
    reasons: tuple[str, ...] = field(default_factory=tuple)


def classify(obs: Observation) -> Classification:
    score = 0
    reasons: list[str] = []

    vendor_l = (obs.vendor or "").lower()
    if vendor_l:
        if any(v in vendor_l for v in _STRONG_IOT_VENDORS):
            score += 3
            reasons.append(f"+3 vendor '{obs.vendor}' ships mostly IoT hardware")
        elif any(v in vendor_l for v in _MIXED_VENDORS):
            score += 1
            reasons.append(f"+1 vendor '{obs.vendor}' ships IoT and general devices")

    iot_services = [s for s in obs.services if s in _IOT_SERVICES]
    if iot_services:
        score += 3
        names = ", ".join(sorted({_IOT_SERVICES[s] for s in iot_services}))
        reasons.append(f"+3 advertises IoT services via mDNS ({names})")
    general_services = [s for s in obs.services if s in _GENERAL_SERVICES]
    if general_services:
        score -= 3
        names = ", ".join(sorted({_GENERAL_SERVICES[s] for s in general_services}))
        reasons.append(f"-3 advertises computer services via mDNS ({names})")

    host_l = obs.hostname.lower()
    if host_l:
        if any(h in host_l for h in _IOT_HOSTNAME_HINTS):
            score += 2
            reasons.append(f"+2 DHCP hostname '{obs.hostname}' looks like an IoT device")
        elif any(h in host_l for h in _GENERAL_HOSTNAME_HINTS):
            score -= 2
            reasons.append(f"-2 DHCP hostname '{obs.hostname}' looks like a phone/computer")

    if is_locally_administered(obs.mac):
        score -= 2
        reasons.append("-2 randomized (locally administered) MAC, typical of phones/laptops")

    if score >= IOT_THRESHOLD:
        category = CATEGORY_IOT
    elif score <= GENERAL_THRESHOLD:
        category = CATEGORY_GENERAL
    else:
        category = CATEGORY_UNKNOWN
    if not reasons:
        reasons.append("no identifying signal (unknown vendor, no mDNS services, no hostname)")
    return Classification(category=category, score=score, reasons=tuple(reasons))
