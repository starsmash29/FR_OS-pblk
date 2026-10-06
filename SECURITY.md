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

## Operating system updates (review FR-003/C-02)

FR_OS runs on Debian 12 (bookworm), and Debian's security fixes reach a
router in two ways:

- **Every image** is built with `bookworm-security`, and the build fails
  if a security update is left uninstalled.
- **Every router** installs Debian security updates by itself, daily
  (`unattended-upgrades`, restricted to the security suite, without
  reboots), into its persistent root. That covers OpenSSL, OpenSSH,
  dnsmasq, Kea, nftables and the rest of userspace.

**The kernel** is handled apart. A live-booted FR_OS boots the kernel on
its boot medium, so the router fetches Debian's kernel fixes itself
(ROADMAP SEC-14): once a day it installs Debian's newer kernel from the
archive (signatures checked by apt) and builds its initrd, and the
dashboard says a kernel is ready to try. Trying it is the admin's:
"Try" on the Update screen reboots the router into it once, and the
router keeps it only if it comes up on it -- otherwise the image's own
kernel boots again by itself, with a security alert. The router never
reboots on its own for it. `update.kernel_updates: false` (or the switch
on the Update screen) turns the daily fetch off. A new FR_OS image still
carries the newest kernel too, and we publish one when a Debian kernel
security update matters for a router (remote reachable, netfilter,
network drivers).

## Scope

In scope: everything in this repository -- the webUI, the privileged
helpers, the daemons, the generated ruleset and configs, the installer
image and the update mechanism. Out of scope: vulnerabilities in Debian
packages FR_OS uses (report those to Debian), and attacks that need
physical access or root on the router already. Physical access to the
boot medium is full control: the stick isn't encrypted, so it can be
rewritten, and a second medium plugged in at boot can supply the
persistence layer or a staged kernel (review v0.2.1 #5). Check a stick
you suspect with `scripts/verify-medium.py` from another computer.
