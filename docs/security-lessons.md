# Security lessons from real-world firewall compromises

Other vendors' incidents, turned into concrete requirements for FR_OS. Each
lesson lists what went wrong there, the FR_OS measure, and where FR_OS stands
today (checked against `main` @ `0bec09c`). This file is separate from
[review-triage.md](review-triage.md), which covers FR_OS's own code review;
cross-references use its IDs (A1, B1, ...).

---

## F – MikroTik "MikroTrick" (2026, CVE-2026-67279 + CVE-2026-86060)

**What happened.** Two bugs chained into unauthenticated admin takeover over
SSH. A state-machine flaw in RouterOS's own SSH daemon let an attacker
trigger key re-exchange during authentication and reach the login step
without a `USERAUTH_SUCCESS`. The login program then took the username as an
unvalidated command-line argument: the username `-2` was parsed as an
option, and it read attacker-supplied credentials from the SSH channel.
Neither bug alone was enough; SSH reachable from the internet was the
precondition. Patched in RouterOS 6.49.21, 7.23.4 and 7.24.2.

| ID | Sev | FR_OS measure | Current state |
|---|---|---|---|
| F1 | high | **No argument injection.** Every call into `nft`, `ip`, `systemctl`, `bpftool`, `pip`, `journalctl` passes user- or config-derived values as argv: validate each against a strict allow-list (interface names, IPs, usernames, versions) *and* put `--` before positional values where the tool supports it. Fuzz tests with values that start with `-` or contain spaces, newlines, `;`, quotes | **Done** (`frfw.validate`): strict validators for interface names, IPv4 addresses, MACs, unit names/verbs, versions, `OWNER/NAME` repos, `/dev` nodes and host names, applied in the config loader (`device:`, `hostname`, `update.repo`) and again at the call sites; `--` before positional values for nft, systemctl, pip, sfdisk/partx/wipefs/mkfs/mount, useradd/usermod (`ip` and `blockdev` don't support it: the value follows `dev`, or is validated). Found and fixed on the way: validation regexes used `$`, which accepts a trailing newline (`"aa:bb:..:ff\n"` passed the MAC check and would have reached an `nft -f -` script) -- all use `\Z` now. Fuzz tests: `tests/test_argv_injection.py` |
| F2 | high | **Management plane never on the WAN by default.** Bind webUI and sshd to LAN/management addresses, not `0.0.0.0`; nft allows management only from LAN; WAN management is an explicit, warned opt-in, with WireGuard recommended instead | **Done** (`frfw.management`): the input chain drops :22/:443 from every non-management zone ahead of admin rules; the webUI binds loopback + the management zones' addresses; sshd gets a `ListenAddress` drop-in; `management.allow_wan` is the explicit opt-in, confirmed and warned on the System screen and in `apply`. The firewall fails closed (A2). WireGuard itself: ROADMAP phase 25 |
| F3 | medium | **sshd hardening drop-in:** keys only (`PasswordAuthentication no`), `PermitRootLogin no`, `AllowGroups`, `MaxAuthTries 3`, `LoginGraceTime 30`, `ListenAddress` = LAN | **Done** (`frfw.management`, `40-fr_os-management.conf`): `PasswordAuthentication no`, `AuthenticationMethods publickey`, `PermitRootLogin no`, `AllowGroups fr_os-ssh` (created empty: no SSH login until the admin adds a user with a key), `MaxAuthTries 3`, `LoginGraceTime 30`, `ListenAddress` = management addresses (F2). Sorts before distribution drop-ins so it wins; checked with the real `sshd -T` in tests |
| F4 | policy | **Never implement our own protocol or crypto** (SSH, TLS, auth). Use OpenSSH, OpenSSL/Python stdlib and WireGuard as shipped by Debian; write this into ARCHITECTURE.md | Holds today |
| F5 | high | **Privilege separation, so one bug is never root:** per-daemon users and `SO_PEERCRED` (A1), systemd sandboxing (D3) | See A1, D3 |

## G – Fortinet "FortiBleed" (June 2026, 74 000–86 000+ FortiGates)

**What happened.** Not one vulnerability but a credential campaign: mass
scanning of internet-exposed management interfaces (web GUI, SSH,
FortiCloud), login with **default or never-renamed admin accounts** and with
credentials leaked in earlier breaches, then **export of configuration
backups** and **offline cracking** of the admin hashes in them. Many devices
still held legacy salted SHA-256 hashes: the stronger PBKDF2 only applied
after an admin re-entered the password, and the old hash was kept in a
hidden `old-password` field. Attackers also harvested SSL-VPN credentials
passively from inside compromised boxes, created persistent VPN tunnels with
legitimate-looking names, and used the stolen credentials against AD, RADIUS
and internal systems. CISA and others recommended: remove management from
the internet, rotate all credentials, kill all sessions, enforce
phishing-resistant MFA, confirm PBKDF2 rehashing.

| ID | Sev | FR_OS measure | Current state |
|---|---|---|---|
| G1 | high | **No default credentials, ever.** Random admin password per install (never a shared default), shown once and then removed (A5); first-run account creation only with proof of physical presence (A3); let the first-run wizard set a non-`admin` username | **Done**: random password per install; the generated account is flagged, and its first sign-in can reach nothing but `/setup`, which requires an own username (not `admin`/`root`/...) and a new password -- the generated name and password stop working and leave the console (A5). No account can be created over the network (A3) |
| G2 | high | **Strong password hashing with automatic upgrade.** Move from PBKDF2-SHA256/200k to `hashlib.scrypt` (Python stdlib via OpenSSL, so no compiled dependency – the reason argon2 was avoided) or PBKDF2 ≥600k; rehash on the next successful login; **never keep the old hash** (no `old-password` field) | **Done** (`frfw.admin_account`): new hashes are `hashlib.scrypt` with OWASP's N=2^15, r=8, p=3 (32 MiB -- sized for a small router); a pre-G2 PBKDF2-200k hash still verifies (never below its floor) and is replaced in place on the next successful sign-in, for webUI accounts and ZTNA users alike -- no old-hash field anywhere; weaker stored parameters never verify (H1) |
| G3 | high | **Secrets never leak through backups or files.** `config.yaml` and `auth.json` stay 0640/0600 (A6); config export/backup (ROADMAP phase 29) either omits hashes and keys or encrypts them with a user passphrase; no API or webUI route returns hashes | Gap: A6 open; export not built yet – design it this way from the start |
| G4 | high | **Management off the internet by default** | **Done** -- same as F2 |
| G5 | high | **Phishing-resistant MFA for admins** (FIDO2/WebAuthn, TOTP fallback). Move ROADMAP phase 41 earlier than v0.5 | Gap: planned for v0.5 |
| G6 | medium | **Brute force and credential stuffing:** persistent (not in-memory) rate-limit counters, per-account and per-source lockout, and a check of new passwords against a local list of common/breached passwords | Partly: brute-force jail exists; counters are in-memory (BP12); length-only password policy (MiMo L5) |
| G7 | medium | **Kill all sessions.** Server-side session revocation; "log out everywhere" button; changing a password invalidates all its sessions | Gap: logout only deletes the cookie; a stolen cookie stays valid up to 12 h (MiMo L4) |
| G8 | medium | **VPN without reusable passwords:** WireGuard keys (ROADMAP phase 25) instead of password-based VPN; ZTNA with FIDO2 later. Passwords sniffed inside a compromised box are then worthless elsewhere | Planned (phase 25); ZTNA uses local passwords today |
| G9 | medium | **Detect persistence:** audit entry + alert for every new admin, ZTNA user, VPN peer/tunnel, and login from a new source; a system-integrity check (hash manifest of the installed image) on the dashboard; audit log not writable by the webUI (E6) | Gap |
| G10 | medium | **Fast, trustworthy patching:** signed updates (A4), `SECURITY.md` with private reporting, GitHub Security Advisories, a "security update available" banner | Gap |
| G11 | policy | **No vendor cloud login path** (the FortiCloud SSO bypass, CVE-2026-24858, was a side door). FR_OS stays 100% local; any future IdP/SSO (ROADMAP phase 46) is opt-in, off by default, and uses a maintained SAML/OIDC library | Holds today |

---

## H – Check Point "Marking your own homework" (June 2026, CVE-2026-50751)

**What happened.** Authentication bypass in Check Point's IKEv1 remote-access
VPN, exploited in the wild (ransomware affiliates) and added to CISA KEV.
During IKEv1 negotiation the client sends a vendor-ID payload whose flags the
gateway copied straight into the state that decides whether the phase-1
signature is verified. Setting one bit made the gateway skip the check, so a
forged certificate with random signature bytes was accepted. Precondition: the
deprecated IKEv1 protocol and legacy-client support left enabled for
compatibility.

| ID | Sev | FR_OS measure | Current state |
|---|---|---|---|
| H1 | high | **The client never chooses how strictly it is checked.** No request field, header, cookie, flag or negotiated option may lower authentication or verification strength. Every auth path fails closed, and has negative tests: forged, missing, replayed and downgraded credentials are rejected | **Done** for the paths that exist: `tests/webui/test_auth_negative.py` covers the webUI login and session (missing, forged, other-key, tampered, expired, replayed after a password change or account deletion; a viewer can't upgrade itself with any field, header or cookie; `X-Forwarded-For` doesn't dodge the brute-force guard), the ZTNA gate (wrong credentials; the connecting address is authorized, never a claimed one), the /metrics token (missing, wrong scheme, altered, broken configured digest fails closed) and both helper sockets (claims in a request about its sender are ignored; no request field can skip the release signature check). Fixed on the way: a stored hash could name any PBKDF2 iteration count (even 1) and still verify -- there is a floor now. Replay after logout: G7. Checklist item in ARCHITECTURE.md |
| H2 | high | **No legacy protocols, not even "for compatibility".** VPN = WireGuard only; if IPsec is ever added, strongSwan with IKEv2 only. No IKEv1, SSHv1, TLS < 1.2, SNMPv1/v2c, Telnet or FTP on the router. Set the webUI's minimum TLS version explicitly instead of relying on library defaults | **Done**: no IPsec, no legacy services; the webUI sets its TLS floor explicitly (`minimum_version = TLSv1_2`, `frfw.webui.server`), TLS 1.3-only with PQC on -- tested with real handshakes against the running webUI (TLS 1.0/1.1 refused). SSH: SHA-1/CBC/MD5 gone (H3) |
| H3 | medium | **No downgrade in negotiated crypto:** the sshd drop-in lists only strong key-exchange, cipher and MAC algorithms (extends F3 and the phase 8 PQC drop-in) | **Done** (`frfw.management`): the sshd drop-in lists only strong key exchange (sntrup761x25519, curve25519, DH group 16/18 with SHA-512; ML-KEM hybrid first via the PQC drop-in when PQC is on), ciphers (ChaCha20-Poly1305, AES-GCM, AES-CTR) and encrypt-then-MAC MACs. Tested with a real sshd and client: SHA-1/group1/group14/NIST-curve KEX, CBC/3DES ciphers and SHA-1/MD5/non-ETM MACs are refused. Also fixed: `frfw.pqc` asked `sshd -Q kex`, which doesn't exist, so the hybrid method was never offered |

## I – Palo Alto PAN-OS captive-portal zero-day (2026, CVE-2026-0300)

**What happened.** Pre-authentication buffer overflow in the User-ID
Authentication Portal (the captive portal service) gave unauthenticated
attackers root code execution on internet-exposed PA-Series and VM-Series
firewalls. Probing began on 9 April, a working exploit followed within a
week, the patch came on 13 May; attackers installed tunneling tools
(EarthWorm, ReverseSocks5). Over 5 800 exposed VM-Series devices were
tracked.

| ID | Sev | FR_OS measure | Current state |
|---|---|---|---|
| I1 | high | **Every listening service is attack surface.** Each service runs as its own unprivileged user in a systemd sandbox (`ProtectSystem=strict`, `NoNewPrivileges`, `CapabilityBoundingSet`, `RestrictAddressFamilies`, seccomp), binds only to the zones that need it, and is off unless used. Applies especially to the future captive portal (ROADMAP phase 45): guest VLAN only, never root, never on the WAN | Partly: see A1, D3. Captive portal not built yet – design it this way from the start |
| I2 | high | **Memory-safe code for anything that parses untrusted input.** Keep parsers in Python, or in eBPF where the verifier bounds memory access; any new native daemon in Rust or Go, not C | Holds today (Python + verifier-checked eBPF) |
| I3 | medium | **Attack-surface view:** a webUI screen listing every listening port per zone, with a warning for anything reachable from the WAN; an optional self-test that scans the WAN address from outside | Gap |

## J – AI-written exploit for a 2FA logic flaw (2026)

**What happened.** Google reported the first exploit it attributes to AI
authorship in the wild: a two-factor-authentication bypass through a
*semantic logic flaw* in an open-source web-based system administration
tool. The takeaway in the reporting: novel exploits get cheaper, and their
volume will follow model capability rather than attacker skill. FR_OS is
exactly this kind of target – an open-source, web-based admin tool.

| ID | Sev | FR_OS measure | Current state |
|---|---|---|---|
| J1 | high | **Test the auth flows as state machines, not just happy paths:** every login, first-run, session, MFA (when added), ZTNA and privilege-elevation flow gets tests for skipped steps, reordered requests, replayed tokens and parallel requests | Partly: good happy-path coverage; no systematic negative flow tests |
| J2 | medium | **Adversarial AI review before every release,** using `docs/review-prompt.md` with at least two different models, triaged like `review-triage.md` | Done once (2026-09-27); make it a release checklist step |
| J3 | medium | **Patch faster than attackers weaponise:** signed security releases (A4, G10), an opt-in automatic install of signed security updates, and a published patch-time target (for example 7 days for critical) | Gap |

## K – The most-exploited firewall misconfigurations

A 2026 industry list of the seven misconfigurations attackers exploit most:
weak/default passwords, overly permissive rules, unpatched firmware, poor
segmentation, misconfigured VPN, missing logging, and unnecessary open
services. FR_OS can prevent or flag most of them in the product itself,
instead of leaving them to the admin:

| ID | Sev | FR_OS measure | Current state |
|---|---|---|---|
| K1 | high | Default passwords → covered by G1, G2 | See G1 |
| K2 | medium | **Rule linter in the webUI:** warn on any→any allow rules, rules shadowed by earlier rules, rules with zero hits for 90 days (needs per-rule hit counters), and allow "temporary" rules with an expiry date that remove themselves | Gap (time-based rules exist since phase 17; expiry and linting do not) |
| K3 | medium | Unpatched firmware → update check with a security banner (G10, J3) | Partly: update check exists |
| K4 | medium | **Segmentation by default:** the first-run wizard offers LAN / IoT / guest zones; IoT isolation (phase 14) on by default for new devices | Partly |
| K5 | medium | VPN misconfiguration → WireGuard only, MFA for admins (G5, G8, H2) | Planned |
| K6 | medium | **Logging on by default:** firewall drops, admin logins and config changes logged out of the box, with a retention limit; SIEM forwarding in ROADMAP phase 34 | Partly: audit log exists |
| K7 | medium | Unnecessary services → I3 attack-surface view; nothing listening that isn't needed | See I1, I3 |
| K8 | medium | **Security score page** that pulls K1–K7 together: a hardening checklist on the dashboard (default user renamed, MFA on, no WAN management, updates current, no any→any rules, logging on) | Gap – good fit for the Stitch design language |

---

## Common thread

None of these incidents needed a clever exploit in the firewall's packet
path. Every one of them went through the **management and access plane**:
an admin interface, SSH, VPN or captive portal exposed to the internet,
reachable with default or stolen credentials, a legacy protocol kept "for
compatibility", or a service that trusted the client too much, and able to
hand out the secrets of the whole network once inside. For FR_OS that means the
management plane gets the same priority as the firewall engine itself:

1. not reachable from the WAN unless the admin explicitly says so (F2/G4),
2. no default or weak credentials, MFA available early (G1, G2, G5),
3. one bug never equals root (F5, A1),
4. secrets never leave the box in a crackable form (G3),
5. the client never decides how strictly it is checked, and no legacy
   protocol stays on for compatibility (H1, H2),
6. every exposed service is sandboxed and memory-safe (I1, I2),
7. secure configuration is the default, and weak configuration is flagged
   in the product (K2–K8),
8. compromise is visible (G9) and fixable fast (G10, J3).

## Suggested order

1. F2/G4 and G1 together with Batch A of review-triage.md (same code paths).
2. F1, F3, H1, H2, H3, G2, G3, G7.
3. J1 (auth flow tests) and G5 (MFA – pull ROADMAP phase 41 forward).
4. I1 sandboxing for every service, I3 attack-surface view.
5. G6, G8, G9, G10, J3, then the K2–K8 product features.
6. J2 as a standing release step.

## Sources

- The Hacker News – MikroTrick chain: https://thehackernews.com/2026/09/mikrotrick-chain-let-attackers-take.html
- CSA research note – FortiBleed and default credentials: https://labs.cloudsecurityalliance.org/research/csa-research-note-fortibleed-default-credentials-20260620-cs/
- SOCRadar – FortiBleed: https://socradar.io/blog/fortibleed-fortinet-firewalls-compromised/
- CISA alert, 2026-06-18: https://www.cisa.gov/news-events/alerts/2026/06/18/cisa-urges-hardening-fortinet-devices-after-reports-credential-exposure
- watchTowr Labs – Marking your own homework (CVE-2026-50751): https://labs.watchtowr.com/marking-your-own-homework-check-point-remote-access-vpn-ikev1-authentication-bypass-cve-2026-50751/
- Rapid7 – Check Point VPN zero-day exploited in the wild: https://www.rapid7.com/blog/post/etr-critical-check-point-vpn-zero-day-exploited-in-the-wild-cve-2026-50751/
- Check Point Blog – CVE-2026-50751 hotfix: https://blog.checkpoint.com/security/check-point-releases-important-hotfix-for-vulnerabilities-in-deprecated-ikev1-vpn-protocol/
- OpenVPN Blog – This Week in Cybersecurity (PAN-OS CVE-2026-0300, AI-written exploit): https://blog.openvpn.net/this-week-in-cybersecurity-275-million-canvas-records-a-palo-alto-firewall-zero-day-and-ai-writes-its-first-real-exploit
- Netwise – Top 7 firewall misconfigurations hackers exploit in 2026: https://netwisetech.ae/top-7-firewall-misconfigurations
- Ars Technica – Massive breach spills credentials for thousands of sensitive networks: https://arstechnica.com/security/2026/06/massive-breach-spills-credentials-for-thousands-of-sensitive-networks/
