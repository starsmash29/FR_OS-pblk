"""The security checklist (security-lessons K8): K1-K7 and friends in one
place, as a score and a list of what is still open.

Each check is worked out from what the router knows -- the accounts, the
saved config, the last update check, the rule check, the attack-surface
verdicts, the integrity check -- and links to the screen that fixes it.
A check whose facts aren't available (say, the apply-helper didn't
answer) is "unknown": it doesn't count for or against the score.
"""

from __future__ import annotations

from dataclasses import dataclass

from frfw.admin_account import RESERVED_USERNAMES

OK = "ok"
FAIL = "fail"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    state: str
    detail: str
    link: str
    lesson: str


@dataclass(frozen=True)
class Score:
    checks: list[Check]

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.state == OK)

    @property
    def known(self) -> int:
        return sum(1 for c in self.checks if c.state != UNKNOWN)

    @property
    def percent(self) -> int:
        return round(100 * self.passed / self.known) if self.known else 0

    @property
    def open(self) -> list[Check]:
        return [c for c in self.checks if c.state == FAIL]


def _check(id: str, title: str, ok: bool | None, good: str, bad: str, link: str, lesson: str) -> Check:
    state = UNKNOWN if ok is None else OK if ok else FAIL
    return Check(id, title, state, good if ok else bad if ok is not None else "not known right now", link, lesson)


def evaluate(*, config, accounts: dict, policy: dict, update_check: dict | None, integrity,
             lint_findings: list | None, surface_rows: list | None) -> Score:
    """`config`: the parsed config (None if it doesn't parse);
    `accounts`: username -> AdminAccount; `update_check`: the periodic
    check's cache for the running version (None: none yet); `integrity`:
    an IntegrityReport; `lint_findings`: rule-check findings;
    `surface_rows`: attack-surface rows (None: couldn't be listed)."""
    admins = [a for a in accounts.values() if a.is_admin]
    reserved = sorted(a.username for a in accounts.values() if a.username in RESERVED_USERNAMES)
    no_mfa = sorted(a.username for a in admins if not a.has_mfa)
    checks = [
        _check("default-user", "No default account names", not reserved,
               "no account is called admin, root or similar",
               f"account(s) with a default name: {', '.join(reserved)} -- attackers try those first",
               "/users", "K1/G1"),
        _check("mfa", "A second factor for every admin", not no_mfa and bool(admins),
               "every admin signs in with a second factor"
               + (" (required)" if policy.get("require_mfa_for_admins") else ""),
               f"admin(s) without a second factor: {', '.join(no_mfa)}", "/account/mfa", "G5"),
    ]
    if config is None:
        checks.append(Check("config", "A valid configuration", FAIL,
                            "the saved config doesn't parse, so the rest can't be checked", "/", "-"))
        return Score(checks)

    checks.append(_check("wan-management", "Management closed to the internet", not config.management.allow_wan,
                         "the webUI and SSH aren't reachable from the WAN"
                         + (" -- remote management goes through the VPN" if config.wireguard.enabled else ""),
                         "management.allow_wan is on: the webUI and SSH are open to the internet", "/system",
                         "F2/G4/K5"))
    if update_check is None:
        updates_ok = None
    else:
        updates_ok = not update_check.get("update_available")
    checks.append(_check("updates", "Up to date", updates_ok,
                         "no newer release than the one running",
                         f"FR_OS {(update_check or {}).get('latest_version')} is available"
                         + (" -- a security release" if (update_check or {}).get("security") else ""),
                         "/update", "G10/K3"))
    checks.append(_check("auto-security", "Security updates install themselves", config.update.auto_install_security,
                         "signed security releases are installed automatically",
                         "turn on automatic install of security releases", "/update", "J3"))
    if lint_findings is None:
        rules_ok = None
        bad_rules: list = []
    else:
        bad_rules = [f for f in lint_findings if f.kind in ("any-to-any", "open-from-internet", "shadowed")]
        rules_ok = not bad_rules
    checks.append(_check("rules", "No any-to-any, internet-wide or shadowed rules", rules_ok,
                         "the rule check finds none",
                         f"{len(bad_rules)} rule(s) to fix: {', '.join(sorted({f.rule for f in bad_rules}))}",
                         "/rules", "K2"))
    checks.append(_check("logging", "Firewall drops are logged", config.logging.drops,
                         "what the firewall drops is logged (rate-limited, kept 90 days)",
                         "logging.drops is off", "/", "K6"))
    segmented = config.iot.enabled or any(z in config.zones for z in ("iot", "guest"))
    checks.append(_check("segments", "Devices are segmented", segmented,
                         "IoT isolation or IoT/guest segments are on",
                         "every device shares one network: add IoT/guest segments", "/segments", "K4"))
    if surface_rows is None:
        unneeded = None
    else:
        stray = [r for r in surface_rows if r.unneeded]
        unneeded = not stray
    checks.append(_check("listening", "Nothing unneeded listens", unneeded,
                         "every reachable service is one the configuration needs",
                         "services nothing needs are listening: "
                         + ", ".join(f"{r.listener.proto}/{r.listener.port}" for r in (surface_rows or [])
                                     if r.unneeded), "/surface", "K7"))
    if integrity is None or not integrity.verifiable:
        integrity_ok = None
    else:
        integrity_ok = integrity.ok
    checks.append(_check("integrity", "FR_OS's own files are intact", integrity_ok,
                         "every installed file matches its recorded hash",
                         integrity.summary if integrity is not None else "", "/system", "G9"))
    return Score(checks)
