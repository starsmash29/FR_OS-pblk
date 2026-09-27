# FR_OS security & correctness review

Independent review of the FR_OS repository at commit `076502e`. Scope follows
`docs/review-prompt.md`: webUI security, the privileged helpers, firewall
generation/rollback, the XDP/eBPF programs, installer/first boot/systemd, the
update mechanism, and code quality/tests. **No code was modified.**

Everything below was read out of the source, not the docs. Where I could not
confirm a suspicion from the source alone it is explicitly marked
**needs verification** rather than asserted.

## Summary table

| # | Sev | Area | Finding | Location |
|---|-----|------|---------|----------|
| 1 | high | helpers / privesc | Every unprivileged daemon shares the helper-socket identity; one JSON line to root | `systemd/fr-apply-helper.socket:9`, `systemd/fr-update-helper.socket:9`, `src/frfw/helper/server.py:63` |
| 2 | high | XDP/eBPF | SNI filter is a no-op on 802.1Q VLAN frames and on any port other than 443 | `bpf/xdp_sni_filter.c:826`, `bpf/xdp_sni_filter.c:843` |
| 3 | medium | secrets / perms | `save_config` silently downgrades `config.yaml` from `root:fr_os-webui 0640` to `0644` | `src/frfw/helper/server.py:299-303` |
| 4 | medium | webUI auth | No CSRF tokens and no security headers anywhere; `SameSite=Lax` is the only defense | `src/frfw/webui/deps.py:97`, `src/frfw/webui/app.py:94` |
| 5 | medium | update / supply chain | The `update.repo` the UI displays is not the repo the root installer uses | `src/frfw/webui/routes/update.py:35`, `src/frfw/helper/update_server.py:52` |
| 6 | medium | installer | Generated admin password written in plaintext to world-readable `/etc/issue`, never removed | `scripts/fr-first-boot.sh:71` |
| 7 | medium | webUI info leak | `/metrics` is unauthenticated by default and is an unauthenticated amplifier into the root helper | `src/frfw/webui/routes/metrics.py:50` |
| 8 | medium | webUI DoS | `/xdp/logs/stream` forks an unbounded `journalctl -f` per request, reachable by read-only accounts | `src/frfw/webui/routes/xdp.py:199` |
| 9 | low | XDP/eBPF | SNI blocklist is case- and trailing-dot-sensitive, so any client can bypass it | `bpf/xdp_sni_filter.c:945`, `src/frfw/xdp.py:356` |
| 10 | low | update / supply chain | Release tarballs are installed with no signature verification (documented, unmitigated) | `src/frfw/update.py:28` |
| 11 | low | webUI auth | Unauthenticated first-run account creation on a `0.0.0.0` listener | `src/frfw/webui/routes/auth.py:52`, `src/frfw/webui/server.py:51` |
| 12 | low | webUI auth | Brute-force counters are in-memory only; a restart resets the effective threshold | `src/frfw/webui/auth_rate_limiter.py:92` |
| 13 | low | secrets / perms | Session secret written non-exclusively to a fixed temp name; parent dir created 0755 | `src/frfw/webui/auth.py:36` |
| 14 | low | firewall rollback | Rollback restores only the ruleset, not the config file or other subsystems | `src/frfw/apply.py:104` |
| 15 | low | audit | ZTNA access grants are never audited; the audit log is writable by the identity it audits | `src/frfw/webui/routes/ztna.py:116`, `src/frfw/webui/audit.py:25` |

## Findings

### 1. high — One compromised unprivileged daemon is one JSON line away from root

**Where:** `systemd/fr-apply-helper.socket:7-9`, `systemd/fr-update-helper.socket:7-9`
(`SocketMode=0660`, `SocketGroup=fr_os-webui`); `src/frfw/helper/server.py:63-136`
and `src/frfw/helper/update_server.py:41-69`; five services run as that identity:
`systemd/fr-webui.service:9`, `systemd/fr-ai-ids.service:9`, `systemd/fr-appid.service:8`,
`systemd/fr-iot-scan.service:14`, plus `fr-tls-fp` which starts as root and
permanently drops to `fr_os-webui` (`src/frfw/tlsfp/daemon.py:49`).

**Description:** The helpers' only access control is socket file ownership, as
`src/frfw/helper/server.py:6-11` states outright. But the group that owns both
sockets is not "the webUI" — it is the shared identity of five separate services,
at least three of which parse attacker-controlled network data: `fr-ai-ids`
(conntrack + SNI/blocklist matching), `fr-appid` (per-flow classification) and
`fr-tls-fp` (userspace TLS ClientHello/JA3 parsing). Neither daemon inspects
`SO_PEERCRED`, so any of them can issue any command, including `save_config`,
`apply`, `ban_ip`, `authorize_ztna` and (over the second socket) `apply` for an
update, which `pip install`s a release as root.

**Scenario:** An out-of-bounds read or a stack overflow in the userspace TLS
fingerprint parser — the most complex untrusted-input parser in the project, fed
straight off the wire — hands the attacker the `fr_os-webui` identity. They then
send `{"cmd":"save_config","yaml":"…"}` to `/run/fr_os/apply.sock`, replacing the
router configuration wholesale (the YAML is re-validated, but only for
*validity* — a perfectly valid config with a wide-open `forward` policy passes),
and `{"cmd":"apply"}` to load it as root. Or they send
`{"cmd":"apply","version":"…"}` to `/run/fr_os/update.sock` for a root `pip
install`. The protocol docstring
(`src/frfw/helper/protocol.py:5-9`) argues the command set is narrow enough that
a peer cannot gain "arbitrary-file-read/write" — true, but writing the config
root applies and triggering a root `pip install` are both equivalent in effect.

**Fix:** Enforce peer credentials in both helpers: read `SO_PEERCRED` in the
request handler and reject any peer whose uid is not the specific service uid
expected for that command (and, for defence in depth, verify
`/proc/<pid>/exe`). Better still, give each client its own socket and group —
`fr-webui` needs write commands; `fr-ai-ids` needs only `quarantine_ip` +
`ids_quarantine_status`; `fr-iot-scan` only `iot_sync_isolation` +
`dhcp_leases`; `fr-appid` only `conntrack_sample`; `fr-tls-fp` needs nothing. The
current single-socket-for-everything design is what turns any parser bug into
root.

---

### 2. high — The XDP SNI filter silently does not inspect VLAN-tagged traffic or any port but 443

**Where:** `bpf/xdp_sni_filter.c:826` (`if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;`),
`bpf/xdp_sni_filter.c:843` (`if (tcp->dest != bpf_htons(443)) return XDP_PASS;`).

**Description:** The program examines only bare IPv4/TCP frames whose destination
port is 443. There is no 802.1Q/802.1ad tag peeling anywhere in the file (no
`ETH_P_8021Q` reference exists), and no configurable port set. This project
explicitly supports VLAN sub-interfaces — the config schema's own docstring uses
`eth1.30` as an example device — so a VLAN-carrying deployment is a first-class,
documented configuration here.

**Scenario:** An admin blocks a malware/advertising domain on the XDP screen,
confirms it shows as attached to the interface, and expects every LAN device to
be blocked. On a VLAN-tagged path (a guest network, a trunked uplink, an
802.1Q-aware bridge in front of the router) every frame arrives with ethertype
`0x8100`, hits line 826 and is passed unexamined — the blocklist has no effect
there at all. The same silent blindness applies to TLS on 8443/8080/4443, which
is routine for self-hosted services. Nothing in the status card, the stats
counters, or `ARCHITECTURE.md`'s limitations list tells the admin that the filter
does not cover those cases; the dashboard simply reports the program as attached
and working. **The stats make this actively misleading:** a fully-bypassed
filter reports `pass_no_match`/`pass_no_sni` rather than a distinguishable
"not applicable" state.

**Fix:** Peel up to two VLAN tags (`0x8100`, `0x88a8`) with proper bounds checks
on each header before the IP check, make the inspected destination ports
configurable (defaulting to 443), and surface "attached but not covering
VLAN-tagged traffic" in the webUI status card. If VLAN support is out of scope,
reject attaching the program to a VLAN device rather than silently passing.

---

### 3. medium — `save_config` downgrades the router config to world-readable on every save

**Where:** `src/frfw/helper/server.py:299-303`
(`_write_atomic`: `tmp_path.write_text(text)` then `tmp_path.replace(path)`).

**Description:** The helper writes the config via a fresh temp file created under
the daemon's umask (0644 for root) and `replace()`s it into place, so the
destination's existing mode and ownership are discarded. The installer sets this
file to `root:fr_os-webui 0640` explicitly (`scripts/install-system-integration.sh:58`
and `:63`, `scripts/fr-first-boot.sh:47-48`), and the CLI's own config writer
deliberately preserves it (`src/frfw/cli.py:483-488`: `os.chmod(tmp,
stat.st_mode & 0o7777)` + `os.chown`). `AdminStore._write` likewise chmods 0640
and chowns (`src/frfw/admin_account.py:159-166`). The helper is the outlier, and
it is the writer used by *every* webUI save — i.e. the normal path.

**Scenario:** An admin changes anything in the webUI. `/etc/fr_os/config.yaml`
becomes `root:root 0644` (and stays that way — the webUI can still read it, so
nothing visibly breaks, which is exactly why this survives testing). From then
on every local account can read the ZTNA users' PBKDF2 hashes (crackable
offline), the metrics bearer-token hash, the full DHCP/static addressing plan,
every firewall rule, and the internal network topology. On a router appliance
that is usually root plus the five `fr_os-webui` daemons, so the practical
audience is "any of the network-facing parsers" — the same population as finding 1.

**Fix:** In `_write_atomic`, copy the destination's mode and ownership onto the
temp file before replacing it (mirroring `cli.py:483-488`), or `os.chmod(tmp,
0o640)` + `os.chown(tmp, 0, <fr_os-webui gid>)` explicitly. Add a test asserting
the mode survives a `save_config` round trip.

---

### 4. medium — No CSRF tokens and no security headers; `SameSite=Lax` is the entire defense

**Where:** `src/frfw/webui/deps.py:97-125` (`require_login` performs no token
check), `src/frfw/webui/routes/auth.py:74-80` and
`src/frfw/webui/routes/accounts.py:157-163` (cookie set with `samesite="lax"`,
`httponly=True`, `secure=<derived from scheme>`); `src/frfw/webui/app.py:94-136`
(the only middleware in the app). A repository-wide search finds no
`X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`,
`X-Content-Type-Options` or `Referrer-Policy` anywhere, and no
`TrustedHostMiddleware`.

**Description:** Every mutating endpoint is a bare `<form method="post">` with no
anti-CSRF field, and the single defence is the `SameSite=Lax` cookie attribute.
That attribute *does* block classic cross-site POST CSRF in current
Chrome/Firefox/Safari, so this is not an exploitable-today vulnerability — it is
a single undeclared, undocumented, load-bearing browser default standing between
a remote site and every privileged action in the product: config writes + apply,
user/role management, update apply, ZTNA user management, IoT isolation.

**Scenario:** (a) The design breaks the first time a client does not implement
`SameSite` correctly — older embedded/IoT browsers, several HTTP client
libraries, or anything replaying a copied cookie jar — and then every admin
action is attacker-triggerable from any web page the admin visits. (b) With no
HSTS, a network attacker intercepting a first visit can strip or downgrade TLS
and read the session cookie outright; `secure=True` is set, but that only
prevents *transmission* over cleartext, not the cookie being *set* in the first
place. (c) With no CSP or `X-Frame-Options`, any HTML injection anywhere in the
UI becomes directly exploitable with no second layer — I found no injection
today (Jinja2 autoescaping is intact, see below), but the header that would
contain it does not exist.

**Fix:** Add a per-session CSRF token: emit it as a hidden field from `base.html`
and validate it inside `require_login` for every non-`GET/HEAD/OPTIONS` request
(keeping the central check is what makes it impossible to forget, which is the
stated design goal of that function). Add the security headers in the existing
`audit_changes` middleware, and add `TrustedHostMiddleware` since the listener is
`0.0.0.0` with no `Host` validation. Document the `SameSite` dependency in
`ARCHITECTURE.md` so it is a stated assumption rather than an implicit one.

---

### 5. medium — The update source shown in the UI is not the source the root installer uses

**Where:** `src/frfw/webui/routes/update.py:35-40` (`_resolve_repo` reads
`config.update.repo` and the value is displayed on the page at `:50-51`),
`src/frfw/helper/update_server.py:52` (`repo=server.repo`, fixed at daemon start
from `--repo`, default `DEFAULT_REPO`), `systemd/fr-update-helper.service:10`
(`ExecStart=firewall-update-helper` — no `--repo`), and
`src/frfw/config/schema.py:269-275` which documents `update.repo` as the
override for "a fork/community edition mirror".

**Description:** `update.repo` affects only the *check*. The privileged install
path reads its repo from the daemon's argv, and the shipped unit passes none, so
it always installs from the built-in `DEFAULT_REPO` regardless of the config.
The two halves of the same screen therefore disagree, and the screen shows the
config's value.

**Scenario:** An administrator running a community edition sets
`update.repo: their-org/FR_OS` specifically to pin installs to a mirror they
audit and trust. The Update screen dutifully reports that mirror's releases. They
click Apply, and the root helper downloads and `pip install`s the *upstream*
`starsmash29/FR_OS-pblk` tarball for that version number. A supply-chain control
an admin explicitly configured does nothing, and the UI actively asserts the
opposite of what happens.

**Fix:** Have the update-helper read `update.repo` from the config it can already
read (and fail closed if the two disagree), or remove the config option and show
the effective repo instead. Either way the page must display the source that
will actually be used, not the one that will be checked.

---

### 6. medium — The generated first-boot admin password is written in plaintext to world-readable `/etc/issue`

**Where:** `scripts/fr-first-boot.sh:64` (generation) and `:70-77` (the write);
`/etc/issue` gets mode 0644 root:root from the redirect + `mv`.

**Description:** The generated credential is placed in the console banner so the
admin can read it without logging in — a defensible decision for a headless
appliance, executed with the wrong mechanism. `/etc/issue` is world-readable by
convention, is not a secrets file, is captured in support bundles and console
transcripts, and (per the script's own message at `:73`) is never cleaned up. The
password is also never invalidated when the admin later changes it, so the file
keeps advertising a credential whose validity depends on whether the admin
remembered to rotate it.

**Scenario:** The router's disk image is backed up (a routine thing to do before
a firmware change), or a support engineer is asked to read the console, or any
local account runs `cat /etc/issue`. The initial admin password is disclosed to
all of them. If the admin never changed it — the script's message tells them to,
but nothing enforces it, and the webUI does not prompt — the credential is
current and the webUI is one login away.

**Fix:** Write the password to a `0600` root-owned file (e.g.
`/etc/fr_os/.initial-admin-credentials`) rather than `/etc/issue`, print only a
"run `sudo cat /etc/fr_os/.initial-admin-credentials`" line to the console, and
have the webUI delete that file on the first successful login (or force a
password change on first login).

---

### 7. medium — `/metrics` is unauthenticated by default and drives the root helper

**Where:** `src/frfw/webui/routes/metrics.py:50-86` (route with no
`require_login`; token check at `:61`), module docstring `:10-20` which
acknowledges the exposure, `src/frfw/helper/server.py:236-264`
(`conntrack_sample`, `bruteforce_status`, `ztna_sessions_status`, `hw_ram_info`
→ `dmidecode`).

**Description:** By default (`metrics.token_sha256` unset) the endpoint is open
to anyone who can reach the webUI port, and returns interface byte counters and
inventory, RAM part numbers and speeds, the IoT device inventory (MACs, IPs,
hostnames), the TLS-fingerprint database, ad-block category counts, the
live content of the ban/quarantine/ZTNA sets, and the configured hostname/zone
layout. Each scrape is a round trip to the **root** helper socket. The design is
deliberate and documented, and the shipped skeleton restricts 443 to the LAN, so
this is not remotely reachable out of the box — but "the LAN" on this product
includes guest networks and the IoT segment the product itself creates.

**Scenario:** Anyone on a guest/IoT VLAN that is permitted to reach the webUI
harvests the full device inventory (a map of every IoT device on the network, by
MAC and IP), the hardware BOM, and the current list of IPs the router considers
hostile or quarantined — useful for both reconnaissance and for knowing which
addresses are *not* being watched. With no rate limiting, the same caller can
also drive repeated root-privileged `dmidecode` invocations by polling the
endpoint.

**Fix:** Make the bearer token mandatory rather than opt-in (or serve `/metrics`
on a separate loopback/management-only listener), drop `hw_ram_info` from the
unauthenticated path, and add a per-source-IP rate limit. At minimum, split the
inventory/hardware series from the status series so the unauthenticated case
yields counters only.

---

### 8. medium — `/xdp/logs/stream` forks an unbounded long-lived subprocess per request, reachable by read-only accounts

**Where:** `src/frfw/webui/routes/xdp.py:52-58` (fixed `journalctl -f` argv —
no injection, correctly), `:192-207` (`_iter_journal_lines`),
`:209-238` (the route), protected only by `require_login` at `:210`.

**Description:** Each request spawns a `journalctl -f` that follows the journal
indefinitely, pinned to a worker thread in uvicorn's sync thread pool, and is
never bounded by a timeout, a concurrency cap, or a per-session stream limit.
`require_login` admits **viewer** accounts on `GET`, so the deliberately
read-only role can reach it. The `finally` block at `:204-206` calls
`proc.wait(timeout=5)` without catching `subprocess.TimeoutExpired`, so a
client that disconnects mid-stream can raise out of the generator.

**Scenario:** A viewer-level account (or a script replaying one viewer cookie)
opens the SSE stream a few dozen times. Each connection holds a thread from the
pool and a `journalctl` child process for as long as it stays open. Once the
thread pool is exhausted, the webUI stops serving *any* request — including
`/login` and `/metrics` — so a read-only account can deny the webUI to the
administrator. The dashboard's live log panel opens this stream automatically,
so even a well-behaved admin's browser tab refreshes contribute.

**Fix:** Cap concurrent streams globally (a `threading.Semaphore`, with a clear
error to excess clients), impose a maximum stream lifetime, require the admin
role for the route, and catch `subprocess.TimeoutExpired` in the cleanup path.

---

### 9. low — SNI blocklist matching is case- and trailing-dot-sensitive, so any client can bypass it

**Where:** `bpf/xdp_sni_filter.c:913` (`char sni[MAX_SNI_LEN] = {}`),
`:945-948` (`build_lpm_key` + `bpf_map_lookup_elem` — no case folding anywhere
in the data path), `src/frfw/xdp.py:356-365` (`sync_blocklist` builds keys from
the configured hostnames, which the loader lowercases at
`src/frfw/config/loader.py:647`).

**Description:** The lookup key is the byte-reversed SNI string; both sides are
compared exactly. The config side is normalised to lowercase, but the packet
side is not normalised at all, and a trailing dot in the client's SNI produces a
longer key that cannot match a shorter stored prefix.

**Scenario:** An admin blocks `evil.example`. The threat model for an SNI filter
is precisely a device the admin does not control — a compromised IoT device or
malware on the LAN — and such a device chooses its own TLS client. It sends
`server_name = Evil.Example` (or `evil.example.`). DNS is case-insensitive and
treats the FQDN root dot as equivalent, so the connection reaches the same
server, but the reversed LPM key differs and the lookup misses: the packet is
passed and counted as `pass_no_match`. The blocklist is bypassed by a
one-character change that costs the attacker nothing.

**Fix:** Lowercase ASCII `A`–`Z` into the SNI buffer in `extract_sni` (a short
unrolled loop is verifier-friendly, consistent with the rest of the file's
approach) and strip one trailing dot; or state plainly in `ARCHITECTURE.md` and
the webUI UI that the filter is a best-effort control that a determined local
device can evade.

---

### 10. low — Updates install unsigned tarballs as root

**Where:** `src/frfw/update.py:28-33` (the limitation is stated accurately in
the module docstring), `src/frfw/update.py:423-441` (`apply_update`),
`src/frfw/update.py:326-345` (`_fetch_release` → `_download_tarball` →
`_safe_extract`).

**Description:** HTTPS to GitHub is the only integrity boundary; anything that
can serve a different response — a compromised CDN edge, a misconfigured
corporate TLS interception appliance, a DNS/CA failure — becomes arbitrary root
code execution via `pip install` and the systemd unit rewrite in
`_stage_systemd_units`. The surrounding hygiene is genuinely good and worth
crediting: the version string is strictly validated with
`^v?(\d+)\.(\d+)\.(\d+)$` before use (`src/frfw/update.py:92`, `:441`), so
there is no path traversal through `/update/apply`'s free-text `version` form
field; `_safe_extract` (`:293`) refuses tar members that escape the destination;
and rollback is recorded in a state file before the switch. The gap is
authenticity, not path handling.

**Fix:** Verify a detached signature (cosign/minisign) or a signed checksum file
against a pinned public key before extracting, and refuse to install without it.
`version` should also be constrained to releases the check endpoint actually
listed.

---

### 11. low — Unauthenticated first-run account creation on a `0.0.0.0` listener

**Where:** `src/frfw/webui/routes/auth.py:52-65` (any `POST /login` when no
account file exists creates the admin, deliberately unrated — see the comment at
`:54-56`), `src/frfw/webui/server.py:51` (`--host 0.0.0.0`).

**Description:** "First requester becomes administrator" with no claim secret, no
console acknowledgement, and no time limit. The mitigation is entirely the
firewall default: the shipped skeleton allows 443 from the LAN only, so out of
the box this is safe.

**Scenario:** A fresh image is deployed and the firewall has not been applied
yet (first boot, or an operator disables `fr-firewall` while debugging), or an
admin later adds a WAN rule for the webUI for legitimate remote access. The
first HTTP client to reach port 443 owns the router, with no credential required
and nothing in the logs distinguishing it from a normal setup. The failure mode
is total compromise and the only barrier is a config default that nothing in the
code re-checks.

**Fix:** Require a one-time claim secret generated at install time and printed to
the console (the first-boot script already generates a credential, so the
mechanism exists) before `POST /login` may create the first account.

---

### 12. low — Brute-force counters are in-memory only, so a restart resets the effective threshold

**Where:** `src/frfw/webui/auth_rate_limiter.py:92-106` (the `_attempts` dict
lives for the process lifetime), `:48-53` (5 attempts / 5 min / 1 h ban).

**Description:** The kernel-level ban is durable (an nftables set element with a
timeout), but the *counter* that decides when to place it is process-local, so
`systemctl restart fr-webui`, a crash, or a deploy resets every IP's history. The
two login endpoints share one counter, which is correct, but the reset is not.

**Scenario:** An attacker who guesses 4 ZTNA passwords, waits for a restart (or
triggers one — the Update screen restarts the webUI on every successful apply,
`src/frfw/update.py:388`), and then continues, can sustain an unbounded
low-and-slow guessing rate against a ZTNA account, because the 5-in-5-minutes
threshold never accumulates. The `viewer`-role/admin `/login` endpoint is
protected the same way, and unlike a ZTNA password its target is a full admin
account.

**Fix:** Persist the counters (or, better, drop the in-memory threshold
entirely and let the kernel ban be the only control, so restarts cannot reduce
enforcement), and add per-account throttling in addition to per-IP.

---

### 13. low — Session secret is written non-exclusively; parent directory created 0755

**Where:** `src/frfw/webui/auth.py:36-45`.

**Description:** `_load_or_create_secret_key` writes to a fixed
`path.with_suffix(".tmp")` with no `O_EXCL` and no lock, then `replace()`s it.
Two concurrent starts can each generate a key; the loser's in-memory
`URLSafeTimedSerializer` keeps signing with a key that is no longer the file's
contents. `path.parent.mkdir(parents=True, exist_ok=True)` also uses the umask,
so the directory is 0755 unless `install-system-integration.sh:35`'s
`install -d -m 0750` already created it.

**Scenario:** Two `fr-webui` starts race (a manual start during debugging, a
socket/unit overlap, a provisioning step running concurrently). One process
issues cookies signed with a key that is no longer on disk; every one of its
sessions fails verification, producing an unreproducible "randomly logged out"
report that is very hard to diagnose from the symptom. The key file itself is
correctly `chmod 0o600`, and the secret is only read once at construction, so
this is an availability/diagnosability bug rather than a key-disclosure one.

**Fix:** `fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)` and
re-read the file if it already exists (handling `FileExistsError`); `chmod` the
directory to `0o700` after creating it.

---

### 14. low — Rollback restores only the ruleset, not the config or other subsystems

**Where:** `src/frfw/apply.py:104-115` (`rollback_last` reloads one `.nft`
backup), `src/frfw/provision.py:8-10` (the no-cross-subsystem-rollback
limitation is documented).

**Description:** The UI is honest about the scope (`dashboard.html:36-37` says
"Roll back to the previous **firewall ruleset**"), so this is not a
misrepresentation — but the recovery is incomplete in exactly the situation an
admin reaches for it. `config.yaml` still holds the bad edit, so any subsequent
apply — including the one `fr-firewall.service` performs at boot — reintroduces
it, and address/DHCP/dnsmasq/XDP effects from the bad apply remain in place.

**Scenario:** An admin applies a config that breaks DHCP or drops the LAN
address, then clicks Rollback. nftables reverts, the dashboard looks healthy,
and the router is still broken in the ways the ruleset doesn't control. Worse,
the config file — the actual source of the mistake — is untouched, so the
misconfiguration returns at the next boot, possibly long after anyone remembers
the incident.

**Fix:** Snapshot `config.yaml` alongside the ruleset backup and restore both on
rollback, or add a separate, clearly-labelled "revert configuration" action next
to the ruleset rollback, and mention in the rollback result message that the
config file was not reverted.

---

### 15. low — ZTNA access grants are never audited, and the audit log is writable by the identity it audits

**Where:** `src/frfw/webui/routes/ztna.py:116-121` (successful ZTNA login
grants network access and writes no audit entry; the file has no `audit.append`
call at all), `src/frfw/webui/audit.py:25-36` (appends to
`WEBUI_AUDIT_LOG_PATH`), `scripts/install-system-integration.sh:35` (that state
directory is created `0750` owned by `fr_os-webui:fr_os-webui`).

**Description:** `/login` records creations, failures and successes
(`routes/auth.py:65,68,72`), and the middleware records every non-GET request by
a logged-in account — but the public `/ztna/login` endpoint, which is the one
that decides who gets onto the network, is entirely absent from the audit trail.
Separately, the log lives in the state directory owned by `fr_os-webui`, i.e. by
the same shared identity that finding 1 is about, so any of the five daemons can
read *and rewrite* the record of who changed what.

**Scenario:** After an incident, there is no way to answer "who was authorized
onto the network, when" — the kernel set is empty once sessions expire, and no
log line was ever written. And an attacker who has already compromised one of
the `fr_os-webui` daemons can delete the evidence of the config changes they made
through the helper socket, since nothing about the log is root-owned or
append-only from the root side.

**Fix:** Write an audit entry on successful and failed ZTNA logins, and have the
root helper append audit records for privileged actions (`save_config`,
`apply`, `authorize_ztna`, `ban_ip`) into a root-owned file or straight to the
journal via `systemd-cat`, so the trail cannot be edited by the identity being
audited.

---

## Reviewed with no findings worth reporting

Recorded so the coverage is auditable, not as praise:

- **Command injection in webUI routes.** Every external command is a fixed argv
  list: `_JOURNALCTL_CMD` (`routes/xdp.py:52-58`), `openssl` (`webui/tls.py:71`),
  `nft`/`ip`/`bpftool`/`systemctl` (`frfw/xdp.py:278`, `:736`, `:743`; `frfw/svc.py:43`).
  No `shell=True`, no `os.system`, no string-built shell command anywhere in
  `src/frfw`.
- **Path traversal from webUI input.** No route takes a caller-supplied path.
  Writes are confined to state paths fixed at app construction
  (`app.py:74-92`); the helper never accepts a path from the socket
  (`helper/protocol.py:14-16` documents this and it holds —
  `helper/server.py:83-89` writes only `server.config_path`).
- **nftables ruleset injection via config.** Identifiers that reach nft syntax are
  regex-validated: zone/interface/rule names `^[a-z][a-z0-9_-]*$`, ZTNA usernames
  and hostnames similarly bounded (`src/frfw/config/loader.py:49-59`), MACs
  normalized, and comments have `"` replaced (`src/frfw/nft/builder.py:341`).
  `parse_config` runs in the webUI *and* again in the root helper before any write
  (`webui/actions.py:17-24`, `helper/server.py:87`).
- **Open/locked-out firewall on a bad config.** `nft -c -f -` gates every real
  apply (`frfw/apply.py:81`), the load is a single atomic `nft -f` transaction, and
  the previous ruleset is backed up first (`apply.py:88-89`). Runtime sets that
  `flush ruleset` would destroy are snapshotted and restored
  (`provision.py:107-165`). The `flush ruleset`-first design does mean frfw cannot
  coexist with hand-written nftables rules, which is documented in the builder's
  docstring and is a deliberate trade-off.
- **RBAC.** The role check is centralized in `require_login`
  (`deps.py:116-124`), which admits viewers only on safe methods plus
  `/logout` and `/account/password`; `require_admin` guards the account pages. The
  failure mode of forgetting it on a new route is closed by design
  (`tests/webui/test_rbac.py` walks every registered route), and I found no POST
  route reachable by a viewer.
- **XSS.** No `|safe`/`| safe` filter in any of the 20 templates; flash messages
  taken from query parameters (`responses.py:11`, `deps.py`) are rendered through
  plain `{{ error }}`, so Jinja2 autoescaping applies.
- **Password storage.** PBKDF2-HMAC-SHA256, 200,000 iterations, 16-byte random
  salt, `hmac.compare_digest` comparison, iteration count stored per-hash
  (`admin_account.py:59-77`); a nonexistent username still performs a hash to
  avoid a timing oracle (`admin_account.py:136-144`).
- **Session invalidation.** The cookie carries a session version derived from the
  password hash and the account is re-read on every request, so a role change,
  password change or deletion takes effect immediately
  (`auth.py:52-65`, `deps.py:109-114`).

### Testing gaps (code quality)

- No test asserts the **permissions** of `config.yaml` after a `save_config`
  round trip (finding 3) or of the audit log / session secret.
- No test covers the **first-run claim** path's security properties, and no test
  asserts that a viewer is refused by any non-allowlisted `GET` route that has a
  side effect (`/xdp/logs/stream` being the live example, finding 8).
- No test exercises the XDP program against **VLAN-tagged frames** or a
  **non-443 TLS port**; `tests/test_xdp_live.py` and `tests/test_xdp_sni_key.py`
  cover key construction and attach/detach, not the coverage gaps in finding 2.
- No test for **concurrency limits** on streaming endpoints, and none for the
  `SO_PEERCRED`-less helper socket beyond "the command name is known"
  (`tests/helper/`).

## Finding counts

| Severity | Count |
|----------|-------|
| critical | 0 |
| high | 2 |
| medium | 6 |
| low | 7 |
| **total** | **15** |
