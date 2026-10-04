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
| F2 | high | **Management plane never on the WAN by default.** Bind webUI and sshd to LAN/management addresses, not `0.0.0.0`; nft allows management only from LAN; WAN management is an explicit, warned opt-in, with WireGuard recommended instead | **Done** (`frfw.management`): the input chain drops :22/:443 from every non-management zone ahead of admin rules; the webUI binds loopback + the management zones' addresses; sshd gets a `ListenAddress` drop-in; `management.allow_wan` is the explicit opt-in, confirmed and warned on the System screen and in `apply`. The firewall fails closed (A2). WireGuard itself: G8 (done) |
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
| G3 | high | **Secrets never leak through backups or files.** `config.yaml` and `auth.json` stay 0640/0600 (A6); config export/backup (ROADMAP OPS-1) either omits hashes and keys or encrypts them with a user passphrase; no API or webUI route returns hashes | **Done** for what exists: `config.yaml` keeps 0640 (A6); `auth.json` is 0600 from creation; no page or API response contains a hash, salt, digest, the metrics token, the session key or the TLS private key (`tests/webui/test_no_secret_leaks.py` renders every GET route as admin, viewer and anonymous); `firewall-cli config-export` / `frfw.config.export.redacted()` -- what the backup feature (ROADMAP OPS-1) must use -- leaves out ZTNA hashes and the metrics digest. The network-parsing daemons no longer reach them: they read a copy of the config made by the same redaction (`/etc/fr_os/sensor-config.yaml`), and their account is in no group of the webUI's -- what they share with it has its own group, `fr_os-feeds` (ROADMAP SEC-11). Open: encrypted full backups: ROADMAP OPS-1 |
| G4 | high | **Management off the internet by default** | **Done** -- same as F2 |
| G5 | high | **Phishing-resistant MFA for admins** (FIDO2/WebAuthn, TOTP fallback). ROADMAP IDN-1 | **Done** (`frfw.webui.mfa`, `routes/mfa.py`): security keys / passkeys (WebAuthn via `py_webauthn`) and authenticator-app codes (TOTP via `pyotp`) for every account, enrolment and removal behind the current password; the password step gives only a 5-minute, single-use login ticket (5 wrong codes kill it and count toward the brute-force guard; 10 per account in 15 minutes lock its second step); TOTP codes are single-use, a key's counter must grow; admins can require MFA for admins (an admin without one is confined to enrolment); recovery by another admin or `firewall-cli mfa-reset`, both ending the sessions. Limit: browsers allow WebAuthn only on a host name, not an IP address -- opened by IP, TOTP is the factor. `tests/webui/test_mfa.py` drives WebAuthn end to end with a software authenticator (phishing origin, replay, cloned key, unknown key) |
| G6 | medium | **Brute force and credential stuffing:** persistent (not in-memory) rate-limit counters, per-account and per-source lockout, and a check of new passwords against a local list of common/breached passwords | **Done** (`frfw.webui.auth_rate_limiter`, `frfw.passwords`): the per-address jail (5 in 5 min -> an hour in the nft jail) and a new per-account lock (10 failures in 15 min from any number of addresses) are kept on disk (`login_guard.json`, 0600), so a webUI restart no longer resets them; an address the account signed in from in the last 90 days is never locked out (so an attacker can't lock the owner out), and unknown usernames lock the same way (no enumeration). Also for the ZTNA gate. Every way of setting a password (webUI accounts, first-run setup, resets, the CLI, ZTNA users) refuses the 10,000 most common passwords (local list, SecLists, MIT; also with trailing digits/punctuation stripped), repetitive ones and ones containing the username. `tests/webui/test_login_lockout.py` |
| G7 | medium | **Kill all sessions.** Server-side session revocation; "log out everywhere" button; changing a password invalidates all its sessions | **Done** (`frfw.webui.auth.SessionStore`): every cookie names a session id that must also be on the server (`sessions.json`, 0600, only SHA-256s of the ids); logout ends it there, a "Log out everywhere" button (also for viewers) ends all of the account's sessions, a password change ends every session (the browser that changed it gets a fresh one), an admin's reset and deleting the account end the user's sessions; a lost session list signs everyone out. Tests replay copied cookies after each of these |
| G8 | medium | **VPN without reusable passwords:** WireGuard keys (ROADMAP NET-4) instead of password-based VPN; ZTNA with FIDO2 later. Passwords sniffed inside a compromised box are then worthless elsewhere | **Done** (`frfw.wireguard`, VPN screen): remote access is WireGuard, with a key pair per device; the router keeps only public keys in config.yaml and its own private key root-only in `/etc/fr_os/wireguard` (a `private_key` in config.yaml is refused). A device's key pair can be made on the router and shown once (text + QR code, `no-store`, never stored or logged). The tunnel is a zone; its UDP port is the only thing opened. Turning the VPN on and every new device are security alerts (G9). Tested with a real tunnel between network namespaces through FR_OS's ruleset, and in the QEMU boot test on Debian's kernel module. Still open: ZTNA signs in with local passwords (FIDO2 later). `tests/test_wireguard.py`, `tests/webui/test_vpn_routes.py` |
| G9 | medium | **Detect persistence:** audit entry + alert for every new admin, ZTNA user, VPN peer/tunnel, and login from a new source; a system-integrity check (hash manifest of the installed image) on the dashboard; audit log not writable by the webUI (E6) | **Done** (`frfw.webui.audit`, `frfw.integrity`): the audit log is root's (`/var/log/fr_os/audit.log`, 0640 root:fr_os-webui) -- the webUI reads it and adds to it only through the apply-helper (`audit_append`, which sets the time and origin and caps what an entry may carry), so a compromised webUI can't rewrite or remove its tracks (E6). A new admin (added, or made admin), an admin's password reset by someone else, a new or changed ZTNA user, a sign-in from a new address, a second factor removed or reset, the admin-MFA requirement turned off and management opened to the WAN are **alerts**: on the dashboard (admins, until each has seen them) and marked in the audit log; changes made with `firewall-cli` on the console are alerts too. A software-integrity check compares every installed FR_OS file with the SHA-256 pip recorded (dashboard warning, System screen, `firewall-cli integrity`). Limits: a root attacker can rewrite the record as well (a manifest signed with the release key would close that (ROADMAP SEC-15)); VPN peers become alerts when WireGuard lands (G8). `tests/webui/test_security_alerts.py`; the QEMU boot test checks the log's owner, mode and that the webUI's entries arrive through the helper |
| G10 | medium | **Fast, trustworthy patching:** signed updates (A4), `SECURITY.md` with private reporting, GitHub Security Advisories, a "security update available" banner | **Done**: `SECURITY.md` asks for private reports through GitHub Security Advisories (acknowledged within 3 days) and publishes fix-time targets; a security release is marked `[security]` (docs/RELEASING.md). `fr-update-check.timer` checks twice a day (`firewall-cli update auto`) and caches the result; every webUI page shows a red "Security update available" banner for a security release and a quiet notice for an ordinary one. Updates stay signed (A4), and only go forward: an older signed release, which would bring back what has been fixed, is refused, and rollback to the version the router updated from is the one way back (ROADMAP SEC-12). The maintainer still has to turn on private vulnerability reporting in the repository settings. `tests/test_update_security.py`, `tests/webui/test_update_banner.py` |
| G11 | policy | **No vendor cloud login path** (the FortiCloud SSO bypass, CVE-2026-24858, was a side door). FR_OS stays 100% local; any future IdP/SSO (ROADMAP IDN-2) is opt-in, off by default, and uses a maintained SAML/OIDC library | Holds today |

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
| H1 | high | **The client never chooses how strictly it is checked.** No request field, header, cookie, flag or negotiated option may lower authentication or verification strength. Every auth path fails closed, and has negative tests: forged, missing, replayed and downgraded credentials are rejected | **Done** for the paths that exist: `tests/webui/test_auth_negative.py` covers the webUI login and session (missing, forged, other-key, tampered, expired, replayed after a password change or account deletion; a viewer can't upgrade itself with any field, header or cookie; `X-Forwarded-For` doesn't dodge the brute-force guard), the ZTNA gate (wrong credentials; the connecting address is authorized, never a claimed one), the /metrics token (missing, wrong scheme, altered, broken configured digest fails closed; and with no token configured /metrics is off, not public -- ROADMAP SEC-3) and both helper sockets (claims in a request about its sender are ignored; no request field can skip the release signature check). State-changing webUI routes need an explicit per-session CSRF token (hidden form field, `X-CSRF-Token` header or JSON body, bound by HMAC to the session id; review R15, `tests/webui/test_csrf.py`), and every HTTP response carries CSP (`script-src 'self'`, no inline script), `frame-ancestors 'none'` / `X-Frame-Options`, `Referrer-Policy` and `X-Content-Type-Options` headers. Also the SNI blocklist's own key (ROADMAP `SEC-17`): the kernel keys on the bytes the client sends, so a blocklisted name was reachable by changing its case or padding it with a trailing dot -- the client chose the spelling, not the operator. Both sides now canonicalize first (`extract_sni()` in `bpf/xdp_sni_filter.c`, `frfw.xdp.normalize_sni()`), pinned against each other by tests, and a name the filter provably cannot match (>= `MAX_SNI_LEN`) is refused at configuration time by name instead of installed silently. A ClientHello split across segments -- every browser's, with a post-quantum key share -- is followed in its next in-order segments, and a blocked name's flow is dropped from there on (ROADMAP SEC-17, `xdp_sni_split`); out-of-order segments and multi-record hellos still pass, counted as `pass_truncated`. Nor does the client choose the protocol: QUIC carries its ClientHello encrypted, so while the filter is on, UDP/443 from the filtered ports is rejected and the client falls back to TLS over TCP, where the name is checked (ROADMAP SEC-1). Fixed on the way: a stored hash could name any PBKDF2 iteration count (even 1) and still verify -- there is a floor now. Replay after logout: covered by G7. Checklist item in ARCHITECTURE.md |
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
| I1 | high | **Every listening service is attack surface.** Each service runs as its own unprivileged user in a systemd sandbox (`ProtectSystem=strict`, `NoNewPrivileges`, `CapabilityBoundingSet`, `RestrictAddressFamilies`, seccomp), binds only to the zones that need it, and is off unless used. Applies especially to the future captive portal (ROADMAP NET-8): guest VLAN only, never root, never on the WAN | **Done** for every service that exists (`systemd/*.service`, `tests/test_systemd_sandbox.py`): the webUI and the network-parsing daemons run as their own unprivileged accounts; the two BPF readers start as root with only CAP_BPF, open their map and drop to fr_os-sensor before reading it (`frfw.privdrop`); every unit has NoNewPrivileges, ProtectSystem=strict with only the paths it writes (except first boot, persistence setup, account creation and the updater, each justified in the test), PrivateTmp/PrivateDevices, protected kernel tunables/modules/logs/clock, no namespaces, W^X memory, a seccomp filter, restricted socket families and an explicit capability bounding set; `systemd-analyze security` went from 8.6-9.4 to 1.1-4.0 for everything but first boot and persistence setup. Off unless used: sshd is stopped and disabled while nobody can log in with a key; the DNS filter only runs when configured and binds the DHCP zones only. The QEMU boot test checks no service crashed or was killed in its sandbox and sshd never listened without keys. The webUI's own child processes are bounded: the live XDP log stream starts one `tail` of the logger's event file per session (no journal access since ROADMAP SEC-4) and at most `LOG_STREAM_LIMIT` of them per webUI process, and the child ends when the session's last tab disconnects, also on a quiet log: each tab checks for a disconnect at least every 15 s (ROADMAP SEC-13, review R19; `tests/webui/test_xdp_routes.py` proves it against a real uvicorn). Captive portal not built yet -- design it this way from the start |
| I2 | high | **Memory-safe code for anything that parses untrusted input.** Keep parsers in Python, or in eBPF where the verifier bounds memory access; any new native daemon in Rust or Go, not C | Holds today (Python + verifier-checked eBPF) |
| I3 | medium | **Attack-surface view:** a webUI screen listing every listening port per zone, with a warning for anything reachable from the WAN; an optional self-test that scans the WAN address from outside | **Done**, except the outside scan (`frfw.surface`, *System -> Attack surface*, `firewall-cli surface`): every listening socket (from `ss`, via the apply-helper) with, per zone, whether the input chain lets a new connection reach it and which rule decides -- evaluated from the config in the builder's order; anything reachable from an internet-facing zone is flagged at the top and makes the CLI exit 2. No built-in outside scanner (it needs a vantage point outside the network): the page gives the `nmap` command for the WAN address instead. Tests: `tests/test_surface.py`, `tests/webui/test_surface_screen.py` |

## J – AI-written exploit for a 2FA logic flaw (2026)

**What happened.** Google reported the first exploit it attributes to AI
authorship in the wild: a two-factor-authentication bypass through a
*semantic logic flaw* in an open-source web-based system administration
tool. The takeaway in the reporting: novel exploits get cheaper, and their
volume will follow model capability rather than attacker skill. FR_OS is
exactly this kind of target – an open-source, web-based admin tool.

| ID | Sev | FR_OS measure | Current state |
|---|---|---|---|
| J1 | high | **Test the auth flows as state machines, not just happy paths:** every login, first-run, session, MFA (when added), ZTNA and privilege-elevation flow gets tests for skipped steps, reordered requests, replayed tokens and parallel requests | **Done** (`tests/webui/test_auth_flows.py`): sign-in with a second factor is checked against a model after every step of all 258 sequences of up to 3 actions (password, wrong password, code, wrong code, replayed code, logout); first-run setup (can't be skipped, needs a session, replayed after completion, 4 parallel submissions), sessions (a logged-out cookie changes nothing; parallel password changes), MFA enrolment out of order (no options, wrong enrolment kind, answered twice, another account's enrolment, a replaced challenge), the ZTNA gate (status without sign-in, wrong then right, shared failure counter with /login, parallel sign-ins, disabled gate) and privilege changes (a demoted admin loses rights on the next request; a viewer can't raise itself). Found and fixed: account changes were an unlocked read-modify-write of `auth.json` -- parallel requests all "completed" first-run setup, lost accounts added at the same moment and crashed on a shared temp file; they now run under an `flock` on the state directory, also against `firewall-cli` in another process. Checklist item in ARCHITECTURE.md |
| J2 | medium | **Adversarial AI review before every release,** using `docs/review-prompt.md` with at least two different models, triaged like `review-triage.md` | Done: a release step (docs/RELEASING.md "Before tagging"); the record `docs/reviews/v<VERSION>.md` (format `docs/reviews/TEMPLATE.md`) is checked by `scripts/check_release_review.py` in the release workflow -- no record, fewer than two models, a stale commit or an open critical/high finding stops the release |
| J3 | medium | **Patch faster than attackers weaponise:** signed security releases (A4, G10), an opt-in automatic install of signed security updates, and a published patch-time target (for example 7 days for critical) | **Done**: `update.auto_install_security` (off by default, a switch on the Update screen) lets `fr-update-check.timer` install a security release within about 12 hours of its publication, through the same signature-checked `apply_update` as a manual update; success or failure is a dashboard alert, and a failure also shows on the Update screen. Ordinary releases are never installed by themselves. `SECURITY.md` publishes the targets: critical 7 days, high 14, others 30. `tests/test_update_auto_install.py`, `tests/webui/test_update_routes.py` |

## K – The most-exploited firewall misconfigurations

A 2026 industry list of the seven misconfigurations attackers exploit most:
weak/default passwords, overly permissive rules, unpatched firmware, poor
segmentation, misconfigured VPN, missing logging, and unnecessary open
services. FR_OS can prevent or flag most of them in the product itself,
instead of leaving them to the admin:

| ID | Sev | FR_OS measure | Current state |
|---|---|---|---|
| K1 | high | Default passwords → covered by G1, G2 | See G1 |
| K2 | medium | **Rule linter in the webUI:** warn on any→any allow rules, rules shadowed by earlier rules, rules with zero hits for 90 days (needs per-rule hit counters), and allow "temporary" rules with an expiry date that remove themselves | **Done** (`frfw.rule_lint`, `frfw.rule_hits`): the Rules screen, a warning when a rule is added, and `firewall-cli rule-check` report any→any and internet-wide accept rules, shadowed and redundant rules, rules unused for 90 days (every rule has an nft counter; the hourly timer records the last match) and expired rules. Temporary rules (`expires`) are stopped by the kernel itself at that second (`meta time`, tested in a network namespace) and left out of later rulesets; the entry is removed from config.yaml with one click (the router never rewrites the config on its own). `tests/test_rule_check.py`, `tests/webui/test_rule_check_screen.py` |
| K3 | medium | Unpatched firmware → update check with a security banner (G10, J3) | **Done** with G10 and J3: a periodic check, a red banner for security releases, and an opt-in automatic install |
| K4 | medium | **Segmentation by default:** the first-run wizard offers LAN / IoT / guest zones; IoT isolation (phase 14) on by default for new devices | **Done** (`frfw.segments`, Segments screen): right after first-run setup the admin is offered an IoT (VLAN 30) and a guest (VLAN 40) segment on the LAN port. Each has its own zone and DHCP and reaches the internet only; neither becomes a management zone, and IoT devices are inventoried and isolated. Interfaces can be VLANs, created by apply. New installs have IoT isolation on for the LAN (`auto_isolate`). `tests/test_segments.py`, `tests/webui/test_segments_screen.py`; the QEMU boot test brings both segments up on real VLANs |
| K5 | medium | VPN misconfiguration → WireGuard only, MFA for admins (G5, G8, H2) | **Done**: WireGuard (G8) is the only VPN; its zone is a management zone by default, so the webUI and SSH listen on the tunnel address and the firewall lets them through (with the VPN screen's rules), while the WAN stays closed. The System screen and the WAN warnings point to the VPN; admin MFA is G5. `tests/webui/test_vpn_management.py`; the QEMU boot test checks that the webUI listens on the tunnel address after the VPN is applied |
| K6 | medium | **Logging on by default:** firewall drops, admin logins and config changes logged out of the box, with a retention limit; SIEM forwarding in ROADMAP OPS-2 | **Done** (`logging.drops`, `frfw.firewall_log`): what the default-deny policy drops is logged, rate-limited, to the kernel log, and the latest drops are on the dashboard; sign-ins and changes are in the root-owned audit log (G9), which rotates at 1 MB; the journal is capped at 200 MB / 90 days. The QEMU boot test checks a real drop line in the journal. SIEM forwarding stays ROADMAP OPS-2. `tests/webui/test_logging_defaults.py` |
| K7 | medium | Unnecessary services → I3 attack-surface view; nothing listening that isn't needed | **Done** (`frfw.surface.needed_by`): every listening socket is matched against what the config turns on (webUI, SSH, DHCP client/server, DNS filter, IoT scan, WireGuard); anything reachable that nothing needs is flagged on the Attack surface page and by `firewall-cli surface` (exit 3). The QEMU boot test checks that a freshly set-up router has none. `tests/test_surface.py` |
| K8 | medium | **Security score page** that pulls K1–K7 together: a hardening checklist on the dashboard (default user renamed, MFA on, no WAN management, updates current, no any→any rules, logging on) | **Done** (`frfw.security_score`, Security score screen, dashboard card): default account names, MFA for every admin, no WAN management, up to date, automatic security updates, the rule check, drop logging, segmentation, nothing unneeded listening and software integrity -- each with its state and a link to the fix; unknown facts count neither way. `tests/webui/test_security_score.py`; the QEMU boot test loads the page on the real router |

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
3. J1 (auth flow tests) and G5 (MFA – ROADMAP IDN-1).
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
