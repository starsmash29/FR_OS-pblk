"""Security-lessons I1: every FR_OS service runs in a systemd sandbox.

The PAN-OS captive-portal zero-day ran as root on the firewall; every
listening service is attack surface. Each unit here is checked for the
sandbox it must have -- a new unit without one fails -- and, where
systemd-analyze can score unit files offline, for an exposure budget.
Whether the services still *work* inside their sandboxes is what the
QEMU boot test checks (installer/qemu-boot-test.py) and, for W^X, running
the whole suite under PR_SET_MDWE.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from frfw import paths

SYSTEMD = Path(__file__).resolve().parent.parent / "systemd"
SERVICES = sorted(p.name for p in SYSTEMD.glob("*.service"))


def service_section(name: str) -> dict[str, list[str]]:
    """[Service] of a unit: key -> every value it is given (systemd allows
    repeating a key)."""
    section, out = None, {}
    for raw in (SYSTEMD / name).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line
            continue
        if section == "[Service]":
            key, _, value = line.partition("=")
            out.setdefault(key, []).append(value)
    return out


def one(settings: dict, key: str) -> str | None:
    values = settings.get(key)
    return values[-1] if values else None


#: What every service has, however broad its job.
EVERYWHERE = {
    "NoNewPrivileges": {"yes"},
    "ProtectHome": {"yes", "read-only"},
    "ProtectKernelLogs": {"yes"},
    "ProtectClock": {"yes"},
    "RestrictNamespaces": {"yes"},
    "RestrictRealtime": {"yes"},
    "RestrictSUIDSGID": {"yes"},
    "LockPersonality": {"yes"},
    "SystemCallArchitectures": {"native"},
}

#: What every service has unless it is listed in BROAD below.
STRICT = {
    "PrivateDevices": {"yes"},
    "ProtectKernelModules": {"yes"},
    "ProtectControlGroups": {"yes"},
    "ProtectHostname": {"yes"},
    "MemoryDenyWriteExecute": {"yes"},
    "SystemCallErrorNumber": {"EPERM"},
}

#: The services whose job doesn't fit the strict sandbox, and why.
BROAD = {
    "fr-first-boot.service": "one-time machine setup: writes /etc, takes a NIC down, starts every unit",
    "fr-persistence-setup.service": "partitions and formats the boot medium: raw block devices and mount",
    "fr-kernel-prepare.service": "dpkg installs a kernel package: /boot, /usr/lib/modules, /etc, its maintainer "
                                 "scripts (ROADMAP SEC-14)",
}

#: ProtectSystem=strict (the whole file system read-only but the listed
#: paths) everywhere except:
PROTECT_SYSTEM = {
    "fr-accounts.service": "yes",  # useradd writes /etc/passwd, /etc/group, /etc/shadow
    "fr-update-helper.service": "full",  # pip writes wherever /usr/local's Python lives
    "fr-update-check.service": "full",  # installs a security release with auto_install_security (J3)
    "fr-first-boot.service": None,
    "fr-persistence-setup.service": None,
    "fr-kernel-prepare.service": None,
}

#: The services that run as root, and why. Everything else runs as its
#: own unprivileged account.
ROOT = {
    "fr-accounts.service": "creates the system accounts",
    "fr-adblock-dns.service": "dnsmasq binds :53, then drops to nobody itself",
    "fr-adblock-refresh.service": "writes root-owned /etc/fr_os files; no capability at all",
    "fr-apply-helper.service": "the privilege boundary: applies the network config",
    "fr-firewall.service": "applies the network config at boot",
    "fr-schedule-check.service": "re-applies the config when a rule schedule changes",
    "fr-first-boot.service": "one-time machine setup",
    "fr-persistence-setup.service": "partitions the boot medium",
    "fr-initial-password.service": "rewrites the root-only console notice",
    "fr-update-helper.service": "installs a verified release",
    "fr-update-check.service": "checks for releases; may install a verified security release (opt-in)",
    "fr-tls-fp.service": "opens a pinned BPF map, then drops to fr_os-sensor (frfw.privdrop)",
    "fr-xdp-sni-logger.service": "opens a pinned BPF map, then drops to fr_os-sensor (frfw.privdrop)",
    "fr-dns-log-trim.service": "empties dnsmasq's (nobody's) query log; CAP_DAC_OVERRIDE only, no network",
    "fr-kernel-confirm.service": "writes the boot environment on the persistence partition, reads the ruleset "
                                 "(ROADMAP SEC-14)",
    "fr-kernel-prepare.service": "installs Debian's kernel package with apt/dpkg (ROADMAP SEC-14)",
}

UNPRIVILEGED = {
    "fr-webui.service": paths.WEBUI_USER,
    "fr-ai-ids.service": paths.SENSOR_USER,
    "fr-appid.service": paths.SENSOR_USER,
    "fr-iot-scan.service": paths.SENSOR_USER,
}

#: Never in any service's capability bounding set.
NEVER = {"CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_SYS_BOOT", "CAP_SYS_RAWIO", "CAP_SYS_TIME", "CAP_MKNOD",
         "CAP_LINUX_IMMUTABLE", "CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE", "CAP_AUDIT_CONTROL", "CAP_SYSLOG",
         "CAP_SYS_TTY_CONFIG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND"}

#: `systemd-analyze security` exposure budget (0 best .. 10 worst) per unit.
EXPOSURE_BUDGET = {name: 2.5 for name in SERVICES}
EXPOSURE_BUDGET.update({
    "fr-apply-helper.service": 4.5,
    "fr-firewall.service": 4.5,
    "fr-schedule-check.service": 4.5,
    "fr-update-helper.service": 3.5,
    "fr-update-check.service": 3.5,
    "fr-first-boot.service": 7.5,
    "fr-persistence-setup.service": 8.0,
    "fr-kernel-prepare.service": 7.0,
})


def test_every_service_is_classified():
    assert set(SERVICES) == set(ROOT) | set(UNPRIVILEGED)
    assert not set(ROOT) & set(UNPRIVILEGED)
    assert set(BROAD) <= set(SERVICES) and set(PROTECT_SYSTEM) <= set(SERVICES)


@pytest.mark.parametrize("name", SERVICES)
def test_every_service_has_the_baseline(name):
    settings = service_section(name)
    for key, allowed in EVERYWHERE.items():
        assert one(settings, key) in allowed, f"{name}: {key}={one(settings, key)}"


@pytest.mark.parametrize("name", [n for n in SERVICES if n not in BROAD])
def test_every_other_service_has_the_strict_sandbox(name):
    settings = service_section(name)
    for key, allowed in STRICT.items():
        assert one(settings, key) in allowed, f"{name}: {key}={one(settings, key)}"
    # An explicit capability bounding set, a syscall filter, socket families.
    assert "CapabilityBoundingSet" in settings, name
    assert settings.get("SystemCallFilter"), name
    families = set(one(settings, "RestrictAddressFamilies").split())
    assert families <= {"AF_UNIX", "AF_NETLINK", "AF_INET", "AF_INET6"}, (name, families)


@pytest.mark.parametrize("name", SERVICES)
def test_the_file_system_is_read_only_but_what_it_writes(name):
    assert one(service_section(name), "ProtectSystem") == PROTECT_SYSTEM.get(name, "strict")


@pytest.mark.parametrize("name", SERVICES)
def test_no_service_can_gain_the_dangerous_capabilities(name):
    settings = service_section(name)
    if name in BROAD:
        return  # no bounding set: root with the full set, see BROAD
    caps = set(one(settings, "CapabilityBoundingSet").split())
    assert not caps & NEVER, (name, caps & NEVER)


@pytest.mark.parametrize("name,user", sorted(UNPRIVILEGED.items()))
def test_unprivileged_services_run_as_their_own_account(name, user):
    settings = service_section(name)
    assert one(settings, "User") == user and one(settings, "Group") == user
    # A syscall filter without the privileged calls, and no capability
    # but binding the webUI's :443.
    assert "~@privileged" in settings["SystemCallFilter"]
    assert set(one(settings, "CapabilityBoundingSet").split()) <= {"CAP_NET_BIND_SERVICE"}
    assert one(settings, "ProtectKernelTunables") == "yes"


def test_the_webui_writes_only_its_own_state():
    settings = service_section("fr-webui.service")
    assert one(settings, "ReadWritePaths") == str(paths.WEBUI_STATE_DIR)
    assert one(settings, "UMask") == "0077"
    assert set(one(settings, "RestrictAddressFamilies").split()) == {"AF_UNIX", "AF_INET", "AF_INET6"}


@pytest.mark.parametrize("name", ["fr-tls-fp.service", "fr-xdp-sni-logger.service"])
def test_bpf_readers_hold_only_what_opening_a_map_and_dropping_root_take(name):
    settings = service_section(name)
    assert set(one(settings, "CapabilityBoundingSet").split()) == {"CAP_BPF", "CAP_SETUID", "CAP_SETGID"}
    assert one(settings, "RestrictAddressFamilies") == "AF_UNIX"


def test_root_services_have_a_reason():
    for name in SERVICES:
        if "User" not in service_section(name):
            assert ROOT.get(name), f"{name} runs as root without a reason in ROOT"


def test_the_dns_filter_writes_no_pid_file():
    """/run is read-only in fr-adblock-dns's sandbox; dnsmasq writes
    /run/dnsmasq.pid even in the foreground unless told not to."""
    from frfw.adblock import dns_service

    assert "\npid-file=\n" in dns_service._DNSMASQ_CONF_TEMPLATE


def _offline_security_supported() -> bool:
    if not shutil.which("systemd-analyze"):
        return False
    proc = subprocess.run(["systemd-analyze", "security", "--offline=true", str(SYSTEMD / "fr-webui.service")],
                          capture_output=True, text=True)
    return "Overall exposure level" in proc.stdout


@pytest.mark.skipif(not _offline_security_supported(), reason="needs systemd-analyze security --offline (systemd >= 252)")
@pytest.mark.parametrize("name", SERVICES)
def test_exposure_score_is_within_budget(name):
    proc = subprocess.run(["systemd-analyze", "security", "--offline=true", "--no-pager", str(SYSTEMD / name)],
                          capture_output=True, text=True)
    match = re.search(r"Overall exposure level for \S+: ([0-9.]+)", proc.stdout)
    assert match, proc.stdout[-500:] + proc.stderr
    assert float(match.group(1)) <= EXPOSURE_BUDGET[name], f"{name}: {match.group(1)}"


@pytest.mark.parametrize("name", SERVICES)
def test_every_service_has_a_writable_temp_dir(name):
    """Found booting the image: with ProtectSystem=strict and no
    PrivateTmp, /tmp is read-only and the Kea config check in an apply
    ("No usable temporary directory") failed fr-firewall."""
    settings = service_section(name)
    if one(settings, "ProtectSystem") != "strict" or one(settings, "PrivateTmp") == "yes":
        return
    runtime = one(settings, "RuntimeDirectory")
    assert runtime, f"{name}: read-only /tmp and no RuntimeDirectory"
    assert f"TMPDIR=/run/{runtime}" in settings.get("Environment", []), name


@pytest.mark.parametrize("name", ["fr-firewall.service", "fr-apply-helper.service"])
def test_the_units_that_can_fall_back_or_alert_reach_the_audit_log(name):
    """ROADMAP SEC-5: when config.yaml fails at boot, fr-firewall raises a
    security alert in the root-owned audit log; it must be able to."""
    assert "-/var/log/fr_os" in one(service_section(name), "ReadWritePaths").split()


@pytest.mark.parametrize("name", ["fr-firewall.service", "fr-apply-helper.service", "fr-schedule-check.service"])
def test_the_units_that_apply_can_turn_routing_on(name):
    """An apply writes /proc/sys/net/ipv4/ip_forward (frfw.forwarding):
    ProtectKernelTunables would make that read-only."""
    assert one(service_section(name), "ProtectKernelTunables") != "yes"


#: The only units that may read the whole journal (the systemd-journal
#: group: every unit's log and the kernel's), and why (ROADMAP SEC-4,
#: review v0.2.0 R10). None: the XDP SNI events and the resolver's query
#: log have files of their own.
JOURNAL_READERS: dict[str, str] = {}


@pytest.mark.parametrize("name", SERVICES)
def test_only_the_listed_units_can_read_the_whole_journal(name):
    groups = set(" ".join(service_section(name).get("SupplementaryGroups", [])).split())
    assert ("systemd-journal" in groups) == (name in JOURNAL_READERS), name


def test_the_sni_event_file_is_written_by_its_logger_and_read_by_one_group():
    """The logger creates paths.SNI_EVENTS_PATH as root, in a directory
    systemd makes root:fr_os-feeds 0750, under a umask that leaves the
    file 0640: its readers (fr_os-webui and fr_os-sensor, both in
    fr_os-feeds) read it, none of them can write it (ROADMAP SEC-4, SEC-11)."""
    settings = service_section("fr-xdp-sni-logger.service")
    assert "User" not in settings  # root until it has opened the map and the file
    assert one(settings, "Group") == paths.FEEDS_GROUP
    assert Path("/var/log") / one(settings, "LogsDirectory") == paths.SNI_EVENTS_DIR
    assert one(settings, "LogsDirectoryMode") == "0750"
    assert one(settings, "UMask") == "0027"
    for reader in ("fr-ai-ids.service", "fr-appid.service", "fr-webui.service"):
        groups = one(service_section(reader), "SupplementaryGroups").split()
        assert groups == [paths.FEEDS_GROUP], reader
    assert one(service_section("fr-webui.service"), "Group") == paths.WEBUI_USER


def test_no_unit_but_the_webuis_has_the_webuis_group():
    """ROADMAP SEC-11: fr_os-webui reads config.yaml with its secrets, the
    audit log and the update state; a parser daemon must not."""
    for name in SERVICES:
        settings = service_section(name)
        groups = set(" ".join(settings.get("SupplementaryGroups", [])).split()) | set(settings.get("Group", []))
        assert (paths.WEBUI_USER in groups) == (name == "fr-webui.service"), name


def test_the_query_log_is_written_by_dnsmasq_and_read_by_one_group():
    """dnsmasq opens paths.DNS_QUERY_LOG_PATH as root under the unit's
    Group= and hands it to its own user (nobody:fr_os-feeds 0640, checked
    against real dnsmasq in tests/test_dns_filtering.py); the directory is
    root:fr_os-feeds 0750 (ROADMAP SEC-4, SEC-11)."""
    settings = service_section("fr-adblock-dns.service")
    assert one(settings, "Group") == paths.FEEDS_GROUP
    assert Path("/var/log") / one(settings, "LogsDirectory") == paths.DNS_QUERY_LOG_DIR
    assert one(settings, "LogsDirectoryMode") == "0750"


def test_the_query_log_trim_can_do_nothing_but_empty_that_file():
    settings = service_section("fr-dns-log-trim.service")
    assert one(settings, "CapabilityBoundingSet") == "CAP_DAC_OVERRIDE"
    assert one(settings, "ReadWritePaths") == f"-{paths.DNS_QUERY_LOG_DIR}"
    assert one(settings, "PrivateNetwork") == "yes"
    assert one(settings, "RestrictAddressFamilies") == "AF_UNIX"


def test_the_kernel_trial_writes_only_the_boot_environment_and_the_audit_log():
    """ROADMAP SEC-14: fr-kernel-confirm writes the GRUB environment block
    on the persistence partition's own root (outside the overlay) and a
    security alert; it reads the ruleset, and asks systemd -- never the
    kernel itself -- to reboot after a failed trial."""
    settings = service_section("fr-kernel-confirm.service")
    assert one(settings, "ReadWritePaths").split() == ["-/run/live/persistence", "-/var/log/fr_os"]
    assert one(settings, "CapabilityBoundingSet") == "CAP_NET_ADMIN"
    assert "@reboot" in one(settings, "SystemCallFilter")
    assert one(settings, "IPAddressDeny") == "any" and one(settings, "IPAddressAllow") == "localhost"
