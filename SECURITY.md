# Security policy

FR_OS is a firewall: a vulnerability in it can open someone's network.
Please report one privately, and we'll fix it fast and say so openly.

## Reporting a vulnerability

**Don't open a public issue.** Use GitHub's private reporting instead:
the repository's **Security** tab → **Report a vulnerability**
(GitHub Security Advisories). Only the maintainers see the report.

Please include what you can: the FR_OS version (`firewall-cli --version`),
what is affected (webUI, a daemon, the ruleset, the image...), how to
reproduce it, and what an attacker gains. A proof of concept helps, but
isn't required.

We'll acknowledge the report within **3 days** and keep you posted. You
decide whether and how you're credited in the advisory.

## Supported versions

Only the latest release gets security fixes. FR_OS updates itself in
place (webUI → Update, or `firewall-cli update apply`), so staying on the
latest release is one click.

## How fast we fix (security-lessons J3)

Attackers weaponise published firewall bugs within days. Our targets,
from a confirmed report to a signed release:

| Severity | Examples | Fixed release within |
|---|---|---|
| Critical | remote code execution, authentication bypass, anything reachable from the WAN | **7 days** |
| High | privilege escalation on the box, a way around the firewall rules | 14 days |
| Medium / low | everything else | 30 days / next release |

Security releases are marked `[security]` in the release title (see
[docs/RELEASING.md](docs/RELEASING.md)). Every router checks for new
releases twice a day (`fr-update-check.timer`): a security release shows
a red banner on every webUI page, and an admin can let the router
install signed security releases by itself (Update screen →
"Install security updates automatically", `update.auto_install_security`).

Every release is signed (Ed25519, `SHA256SUMS.sig`); a router refuses an
update whose signature doesn't verify against the key it ships with.

## Scope

In scope: everything in this repository -- the webUI, the privileged
helpers, the daemons, the generated ruleset and configs, the installer
image and the update mechanism. Out of scope: vulnerabilities in Debian
packages FR_OS uses (report those to Debian), and attacks that need
physical access or root on the router already.
