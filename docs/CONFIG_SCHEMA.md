# Configuration schema (v1)

The `frfw` engine's input is a YAML file. This document describes the
fields of the `version: 1` schema. Validation is implemented by
`frfw.config.loader` (raises `ConfigError` on a bad field, naming the
specific field/value).

Full example: [`examples/config.yaml`](../examples/config.yaml).

## Name format

Interface, zone, rule, and port-forward names: identifiers starting
with a lowercase letter, containing lowercase letters/digits/`-`/`_`
(`^[a-z][a-z0-9_-]*$`).

## Top level

```yaml
version: 1          # required, only 1 is currently supported
hostname: fr-router  # required, non-empty string
timezone: Europe/Budapest  # optional, IANA zone rule schedules are written in; default: the system's
interfaces: {...}    # required, see below
zones: {...}         # required, see below
rules: [...]         # optional, default: []
nat: {...}           # optional, default: empty
dhcp: {...}          # optional, default: empty
ai_ids: {...}        # optional, default: empty (disabled)
adblocker: {...}     # optional, default: empty (disabled)
iot: {...}           # optional, default: empty (disabled)
app_control: {...}   # optional, default: empty (disabled)
tls_fingerprint: {...}  # optional, default: empty (disabled)
metrics: {...}       # optional, default: public /metrics, site name = hostname
```

## `interfaces`

Logical interface name → physical device + zone mapping.

```yaml
interfaces:
  wan:
    device: eth0        # required, must be unique (one device = one interface)
    zone: wan            # required, a zone name declared under zones
    address: 10.0.0.1/24  # optional, IPv4 address with CIDR prefix; applied by frfw.ifaddr
    description: "..."   # optional, free text
  iot:
    device: eth1.30
    zone: iot
    address: 192.168.30.1/24
    vlan: {parent: eth1, id: 30}  # optional: an 802.1Q VLAN, created by apply if missing
```

`address` is the router's own static IPv4 address on that interface --
applied via `ip addr replace` (`frfw.ifaddr`). Changed or removed, the
address the last apply set is removed from the device. Only required if the
zone should get a DHCP pool (see `dhcp` below); leave it unset on an
interface managed by a DHCP client (e.g. a typical WAN interface).

`vlan` (security-lessons K4) makes the interface an 802.1Q VLAN of
`parent` with the given `id` (1-4094). Apply creates it if missing and
brings both up. The Segments screen uses this for the IoT and guest
segments on the LAN port.

## `zones`

Logical groups that rules and NAT reference. Every zone declared here
must be used by at least one interface (and vice versa: every
interface's zone must be declared here) -- the loader checks
consistency in both directions.

```yaml
zones:
  wan:
    description: "..."   # optional
```

The zone name `self` is reserved: it cannot be declared under `zones`,
but can be used in rules as `to_zone: self` -- this means traffic
addressed to the router itself (nftables `input` chain), as opposed to
traffic forwarded between zones (`forward` chain).

## `rules`

A list of filtering rules, entering the generated ruleset in declaration
order (first match wins, as is usual in nftables).

```yaml
rules:
  - name: allow-ssh-from-lan-to-router  # required, unique
    action: accept        # required: accept | drop | reject
    from_zone: lan         # optional, absent = any zone
    to_zone: self           # optional, absent = any zone; "self" = the router itself
    proto: tcp               # optional, default: any; any|tcp|udp|icmp
    dst_port: 22               # optional, only with proto: tcp/udp; int or a "1000-2000" range string
    src_address: 10.0.0.0/24    # optional, IPv4 address/network
    dst_address: 10.0.0.5         # optional, IPv4 address/network
    src_mac: aa:bb:cc:dd:ee:ff     # optional, source MAC address (a device, whatever its IP)
    log: false                     # optional, default: false
    schedule:                      # optional, default: always
      days: [weekdays]             # mon..sun, weekdays, weekend, daily; default: daily
      start: "21:30"               # required with schedule, local "HH:MM"
      end: "06:30"                 # required with schedule, "HH:MM" or "24:00"
      cut_established: false       # optional; drop/reject only
    expires: "2026-10-01T18:00"    # optional: a temporary rule (security-lessons K2)
```

With `to_zone: self`, the rule goes into the `input` chain (no `oifname`
constraint, since the destination is the router itself); otherwise into
the `forward` chain.

### Temporary rules and the rule check (security-lessons K2)

`expires` is an ISO 8601 date and time; without an offset it is read in
the top-level `timezone`. The kernel itself stops matching the rule at
that second (`meta time`), with no reload needed, and rulesets built
later leave it out. The entry stays in config.yaml, marked expired, until
it is removed: the Rules screen has a button for that.

`firewall-cli rule-check` and the Rules screen check the rules for:
- any-to-any accept rules;
- accept rules open to all of a zone from the internet;
- rules shadowed or made redundant by an earlier rule;
- rules nothing has matched for 90 days;
- expired rules.

Every rule has an nft counter. `fr-schedule-check.timer` records hourly
when each rule last matched, in `/etc/fr_os/rule_hits.json`.

### Schedules (phase 17)

A rule with a `schedule` only matches during that window, in the
top-level `timezone` (see
[ARCHITECTURE.md](../ARCHITECTURE.md#time-based-rules-phase-17)).

- An `end` at or before `start` runs past midnight into the next day:
  `days: [fri], start: "22:00", end: "06:00"` covers Friday 22:00 to
  Saturday 06:00. `00:00`-`24:00` is a whole day; `start` and `end` may
  not be equal.
- Like every rule, a scheduled rule only sees *new* connections: one
  opened before the window keeps going. `cut_established: true` (drop and
  reject rules only) moves the rule ahead of the chain's established-
  connection accept, so those are cut too -- and such rules are evaluated
  before all ordinary rules.
- Rules are rendered for the zone's current UTC offset at `apply`;
  `fr-schedule-check.timer` re-applies within the hour after a
  daylight-saving change, but only if config.yaml is still the config
  that was last applied.

## `nat`

```yaml
nat:
  masquerade:
    - out_zone: wan          # required, the outbound zone traffic leaves through

  port_forwards:
    - name: forward-https-to-dmz-web  # required, unique
      in_zone: wan                     # required, inbound zone
      proto: tcp                        # required: tcp | udp
      dst_port: 443                      # required, 1-65535
      to_address: 10.0.2.10               # required, IPv4 address
      to_port: 443                         # optional, default: dst_port
```

## `dhcp`

A per-zone DHCPv4 pool, served by Kea (`frfw.kea`).

```yaml
dhcp:
  lan:
    range_start: 10.0.0.100      # required, IPv4 address, within the interface's subnet
    range_end: 10.0.0.200          # required, IPv4 address, not before range_start
    dns_servers: [1.1.1.1, 9.9.9.9]  # required, non-empty list of IPv4 addresses
    lease_time: 3600                   # optional, default: 3600 (seconds)
    reservations:                       # optional, default: []
      - mac: aa:bb:cc:dd:ee:ff             # required, aa:bb:cc:dd:ee:ff format
        address: 10.0.0.50                  # required, within the subnet
        hostname: nas                         # optional
```

Prerequisites for a zone to serve DHCP:

- The zone may have **exactly one** interface, and its `address` field
  must be set -- the pool's subnet and gateway (the Kea config's
  `routers` option) are derived from it.
- `range_start`/`range_end` and every reservation's address must be
  within the interface's subnet, and cannot coincide with the gateway
  (the interface's own) address.
- Reservation addresses/MACs must be unique within the zone; MACs are
  normalized to lowercase.

## `ai_ids`

Real-time, kernel-assisted anomaly detection and quarantine (phase 11,
see `frfw.ai_ids`) -- a separate `fr-ai-ids` systemd daemon scores each
source IP's connection-rate, destination-diversity, and XDP
SNI-blocklist-hit patterns against that IP's own recent baseline, and
asks the privileged apply-helper to quarantine a flagged IP in the
kernel (`frfw.ids_quarantine`) for `quarantine_duration_seconds`. See
[ARCHITECTURE.md](../ARCHITECTURE.md#real-time-kernel-assisted-ai-idsips-phase-11)
for the full design, including a from-first-principles explanation of
where the detection signal actually comes from.

```yaml
ai_ids:
  enabled: true                        # optional, default: false
  excluded_macs:                        # optional, default: []
    - aa:bb:cc:dd:ee:ff                   # aa:bb:cc:dd:ee:ff format, normalized to lowercase
  quarantine_duration_seconds: 7200       # optional, default: 7200 (2 hours), positive integer
```

`excluded_macs` is resolved against the current DHCP static reservations
(`dhcp.<zone>.reservations`) at daemon startup, into the set of IP
addresses that are never scored or quarantined (e.g. a backup server
that legitimately opens many connections). A MAC with no matching
reservation currently excludes nothing.

Note: `enabled`/`excluded_macs`/`quarantine_duration_seconds` are only
picked up when the `fr-ai-ids` daemon (re)starts -- like several other
subsystems in this project (e.g. the PQC hybrid TLS setting), saving
this section does not hot-reload the running daemon.

## `adblocker`

Local DNS-level blocking (phase 9, extended in phase 15; see
`frfw.adblock` and
[ARCHITECTURE.md](../ARCHITECTURE.md#categorized-dns-filtering-and-dns-threat-signals-phase-15)).
A dedicated dnsmasq instance (`fr-adblock-dns.service`) answers blocked
names with `0.0.0.0`. Lists are downloaded only by `firewall-cli
adblock-refresh` (daily timer, only while `enabled` is true) or the webUI's
"Refresh now", never by `apply`.

```yaml
adblocker:
  enabled: true                          # optional, default: false
  source_urls:                           # the base ad/tracker list, reported as category "ads"
    - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
  categories:                            # optional, default: {}; name -> list of URLs
    malware: [https://urlhaus.abuse.ch/downloads/hostfile/]
    phishing: [https://phishing.army/download/phishing_army_blocklist.txt]
  allowlist: [example.com]               # optional; these names and their subdomains are never blocked
  xdp_critical_limit: 0                  # optional, default: 0; see phase 9
  serve_lan: false                       # optional; announce the router as DNS server via DHCP
  force_dns: false                       # optional; requires serve_lan
  query_logging: false                   # optional; needed for the AI IDS's DNS signals
```

- `enabled: true` needs at least one of `source_urls` / `categories`.
- Lists may be hosts files (`0.0.0.0 name`, `127.0.0.1<TAB>name`) or plain
  one-domain-per-line lists. Category names follow the usual name format;
  `ads` is reserved for the base list. The webUI offers verified presets
  (`malware`, `phishing`, `doh-bypass`, `gambling`, `adult`, `social`,
  `fakenews`, see `frfw.adblock.categories`) -- each list's own license
  applies (Phishing Army, for example, is CC BY-NC 4.0: non-commercial).
- `allowlist` entries are removed from every list at refresh time and
  again on every `apply`; an entry taken *off* the allowlist returns at
  the next refresh. Firefox's DoH canary domain `use-application-dns.net`
  is always excluded from every list.
- `serve_lan` (needs at least one `dhcp` pool): Kea announces the router's
  own address as the DNS server in every pool, the pools' `dns_servers`
  become the resolver's upstreams (the router's own addresses are never
  used as an upstream), and the firewall accepts DNS from the DHCP zones.
- `force_dns`: every plain DNS query from the DHCP zones is redirected to
  the resolver, DNS-over-TLS/QUIC (port 853) is rejected, and Firefox's
  DoH canary answers NXDOMAIN so Firefox keeps using the system resolver.
  DoH to arbitrary servers on port 443 can't be stopped this way -- the
  `doh-bypass` category blocks the well-known DoH server names instead.
- `query_logging`: dnsmasq logs every query (`log-queries=extra`) to
  `/var/log/fr_os-dns/queries.log` (nobody:fr_os-webui 0640), where
  `fr-ai-ids` and `fr-appid` read it. This records which client looked up
  which name; the file is emptied once it is past 16 MiB (checked hourly
  by `fr-dns-log-trim.timer`). With it, dnsmasq's other messages go to
  that file too instead of the journal.

## `iot`

Light-weight IoT device discovery and isolation (phase 14, see
`frfw.iot` and
[ARCHITECTURE.md](../ARCHITECTURE.md#iot-device-discovery-and-isolation-phase-14)).
A periodic scan (`fr-iot-scan.timer`, every 10 minutes, or the webUI's
"Scan now") inventories the devices in `zones` from DHCP leases, the ARP
table and an mDNS service query, classifies each one, and keeps the
kernel's `iot_isolated` MAC set in sync with the decision.

```yaml
iot:
  enabled: true                   # optional, default: false
  zones: [lan]                    # required when enabled; zones to inventory -- never a nat.masquerade zone
  auto_isolate: false             # optional, default: false (discover and classify only)
  isolation_mode: internet_only   # optional, default: internet_only; internet_only | block
  trusted_macs:                   # optional, default: []; never isolated
    - aa:bb:cc:dd:ee:01
  isolated_macs:                  # optional, default: []; always isolated
    - aa:bb:cc:dd:ee:02
```

- `internet_only`: an isolated device can still reach the zone(s) a
  `nat.masquerade` entry points at (so at least one is required), but no
  other zone and no router service except DHCP and DNS.
- `block`: an isolated device gets DHCP and DNS from the router, nothing
  else.
- A MAC may not be both trusted and isolated; MACs are normalized to
  lowercase.
- mDNS discovery only runs on IoT-zone interfaces that have a static
  `address`; without one, DHCP leases and ARP entries are still used.
- Isolation is enforced by this router's firewall, so it covers traffic
  routed *through* it. Two devices on the same switch/Wi-Fi segment can
  still talk to each other directly -- use a dedicated zone (for example
  a VLAN interface such as `eth1.30`) for real layer-2 separation.
- Settings take effect on the next `apply` (the set and its rules are
  only in the ruleset while `enabled` is true); trust/isolate changes made
  from the webUI are re-applied immediately.

## `app_control`

Coarse application identification and blocking (phase 16, see
`frfw.appid` and
[ARCHITECTURE.md](../ARCHITECTURE.md#coarse-application-identification-phase-16)).
The `fr-appid` daemon attributes the names clients look up, and optionally
the TLS server names (SNI) they send, to the apps of a bundled 41-app
catalog (generated from v2fly/domain-list-community, MIT).

```yaml
app_control:
  enabled: true             # optional, default: false
  blocked_apps: [tiktok]    # optional, default: []; app ids from the catalog
  observe_sni: false        # optional, default: false; requires xdp_sni_filter.enabled
  block_via_xdp: false      # optional, default: false; requires xdp_sni_filter.enabled
```

- App ids are the catalog's (`netflix`, `youtube`, `tiktok`, `steam`,
  `zoom`, ... -- listed on the webUI's `/apps` screen); an unknown or
  repeated id is rejected.
- Observation sources: the resolver's query log (`adblocker.enabled` and
  `adblocker.query_logging`) and, with `observe_sni`, every SNI the XDP
  program sees (one line per TLS connection in the logger's event file,
  `/var/log/fr_os-sni/events.jsonl`). With neither, the
  daemon idles.
- `blocked_apps` are answered NXDOMAIN by the resolver for every catalog
  name of those apps and their subdomains, so blocking requires
  `adblocker.enabled` and `adblocker.serve_lan`; add `adblocker.force_dns`
  so clients can't just use another DNS server. The `adblocker.allowlist`
  does not apply to blocked apps.
- `block_via_xdp` also puts those names (the ones under 32 characters) on
  the XDP SNI blocklist at `apply`, which catches clients that resolved
  the name elsewhere (their own DNS-over-HTTPS).
- XDP only sees packets an interface *receives*: for `observe_sni` and
  `block_via_xdp` to see LAN clients, `xdp_sni_filter.interfaces` must be
  the LAN-side interfaces, not the WAN.
- While `xdp_sni_filter` is enabled, QUIC (HTTP/3, UDP/443) from its
  interfaces and the VLANs on them is rejected, so browsers there use TLS
  over TCP, whose name the filter sees (ROADMAP SEC-1). There is no key
  to turn this off: QUIC's name is encrypted, so allowing it would let
  any client get past the blocklist.
- These cross-section requirements are only checked while `enabled` is
  true. Changes take effect on the next `apply`; the daemon picks up
  config changes by itself.

## `tls_fingerprint`

TLS client fingerprinting without decryption (phase 19, see `frfw.tlsfp`
and
[ARCHITECTURE.md](../ARCHITECTURE.md#tls-client-fingerprinting-without-decryption-phase-19)).
The XDP program copies every ClientHello (and the rest of hellos that span
several TCP segments) to the `fr-tls-fp` daemon, which computes JA4 and
JA3 per device, keeps an inventory and reports new and blocklisted
fingerprints.

```yaml
tls_fingerprint:
  enabled: true                   # optional, default: false; requires xdp_sni_filter.enabled
  quarantine_on_match: false      # optional, default: false
  blocklist:                      # optional, default: []
    - fingerprint: t13d1516h2_8daaf6152771_e5627efa2ab1   # a JA4 fingerprint...
      label: "unexpected TLS client"                       # optional, at most 80 characters
    - ada70206e40642a3e4461f35503241d5                     # ...or a JA3 hash (plain string form)
```

- `xdp_sni_filter` must be enabled and attached to the LAN-side interfaces:
  that is where LAN clients' ClientHellos arrive.
- `quarantine_on_match` puts a device presenting a blocklisted fingerprint
  into the AI IDS quarantine set for `ai_ids.quarantine_duration_seconds`.
- Blocklist edits reach the running daemon within 30 seconds; `enabled`
  takes effect on the next `apply`.
- IPv4 TCP only: QUIC (HTTP/3) and IPv6 connections are not fingerprinted.

## `metrics`

Multi-site monitoring (phase 20, see
[ARCHITECTURE.md](../ARCHITECTURE.md#multi-site-read-only-monitoring-phase-20)).

```yaml
metrics:
  site: budapest-office     # optional; this router's name in fleet dashboards (fros_info's site_name); default: hostname
  token_sha256: 3f1a...     # optional; SHA-256 hex of the bearer token; /metrics is off without one
```

- Never write a token here by hand: `firewall-cli metrics-token
  --generate` (or System -> Multi-site monitoring in the webUI) creates
  one, prints it once and stores only its digest. `--disable` removes it.
- Without `token_sha256`, `GET /metrics` is off: it answers 404 and
  gathers nothing (ROADMAP SEC-3). With it, `GET /metrics` answers 401
  unless the request carries `Authorization: Bearer <token>` -- also
  while the rest of config.yaml fails validation.
- An authenticated scrape's output is reused for 15 seconds, so the
  kernel-side counts it reports can be up to that old; a config change
  shows at once.
- Takes effect immediately, no `apply` needed.
- Example scraper setup: `telemetry/prometheus-multisite.yml`; dashboards:
  `telemetry/grafana-fleet-dashboard.json` and the `Site` selector of
  `telemetry/grafana-dashboard.json`.

## `logging`

What the router logs out of the box (security-lessons K6).

```yaml
logging:
  drops: true            # default: log what the default-deny policy drops
  drops_per_minute: 10   # per chain; a flood can't fill the disk
```

The log lines (`fr_os/drop/input: ...`, `fr_os/drop/forward: ...`) go
to the kernel log. The journal keeps them within its limit (200 MB, 90
days; `/etc/systemd/journald.conf.d/fr_os.conf`), and the dashboard shows
the latest ones. Admin sign-ins and every change are always in the audit
log, which rotates at 1 MB.

## `wireguard`

The WireGuard VPN (security-lessons G8): remote access with keys instead
of passwords. The webUI's VPN screen writes this section.

```yaml
zones:
  vpn: {}                      # the tunnel's zone (it needs no 'interfaces' entry)
wireguard:
  enabled: true
  address: 10.99.0.1/24        # the router in the tunnel, with the tunnel's prefix
  listen_port: 51820           # UDP, opened on the input chain
  zone: vpn                    # default "vpn"; must not face the internet
  endpoint: vpn.example.net    # optional: what devices connect to (for their configuration)
  peers:
    - name: laptop
      public_key: 3Ld5...=     # the device's public key; its private key never is here
      address: 10.99.0.2       # the device in the tunnel (a /32 in the tunnel subnet)
```

- The tunnel interface is `wg0`. It belongs to `zone`, so rules decide
  what the VPN may reach, like any other zone (`from_zone: vpn`). The
  VPN screen adds `webui-from-vpn`, `ssh-from-vpn` and `vpn-to-lan` when
  it turns the VPN on, if they aren't there.
- The router's own private key is **not** in this file: it is generated
  on the first apply into `/etc/fr_os/wireguard/private.key` (0600
  root). A `private_key` here is refused.
- Refused: a tunnel subnet overlapping an interface's, a peer address
  outside the tunnel or used twice, the same public key twice, an
  internet-facing `zone`.
- The tunnel's zone is a management zone unless `management.zones` says
  otherwise: the webUI and SSH listen on the router's tunnel address, so
  remote management goes through the VPN instead of `allow_wan`
  (security-lessons K5).
- Needs the `wireguard` kernel module (Debian's kernel has it; the FR_OS
  image loads it at boot) and `wg` from wireguard-tools.

## `management`

Where the router can be managed from: the webUI (:443) and SSH (:22).
Security-lessons F2/G4 -- never from the internet unless you say so.

```yaml
management:
  zones: [lan]        # optional; default: every zone that isn't internet-facing
  allow_wan: false    # explicit opt-in to manage from the internet (not recommended)
  confirm_apply_seconds: 300   # optional; 0 = off, else 60-3600
```

- `confirm_apply_seconds` (ROADMAP SEC-26): an Apply from the webUI is
  held until it is confirmed from the webUI within this many seconds;
  otherwise the router goes back to the config applied before it, puts
  that config back in config.yaml and keeps the unconfirmed one for you
  to fix. The confirmation comes through the new rules and addresses, so
  an apply that cut you off is undone by itself. 0 turns it off.

- Internet-facing zones are the `nat.masquerade` `out_zone`s plus a zone
  called `wan`. Listing one in `zones` is refused unless `allow_wan: true`.
- The input chain drops :22/:443 from every non-management zone ahead of
  your own rules, so a rule that allows 443 from the WAN doesn't open the
  webUI; `allow_wan` is the only way.
- The webUI and sshd listen only on loopback and the static addresses of
  the management zones' interfaces (an sshd `ListenAddress` drop-in,
  `/etc/ssh/sshd_config.d/40-fr_os-management.conf`). With `allow_wan`
  they listen on every address; `apply` and the System screen warn.

## `update`

Where FR_OS looks for new releases, whether it may install security
releases by itself (security-lessons G10/J3), and whether it fetches
Debian's kernel fixes (ROADMAP SEC-14).

```yaml
update:
  repo: ""                       # optional; default: the upstream FR_OS repo
  auto_install_security: false   # opt-in: install signed security releases automatically
  kernel_updates: true           # fetch Debian's newer kernel, ready to try (default on)
```

- `repo`: `owner/name` of a GitHub repository publishing FR_OS releases
  (a fork or a mirror). Empty means the built-in default.
- `auto_install_security`: `fr-update-check.timer` (twice a day) installs
  a release marked as a security release (docs/RELEASING.md) as soon as it
  finds one -- only after its signature verifies, like any update -- and
  the dashboard shows an alert saying what was installed, or why the
  install failed. Ordinary releases are never installed by themselves.
  Off by default; the Update screen has a switch for it.
- `kernel_updates`: `fr-kernel-prepare.timer` (daily) asks apt which
  kernel Debian's `linux-image-amd64` points at and, when it is newer than
  every kernel on the router, installs it from the Debian archive (apt
  checks Debian's signatures) into the persistent root and builds its
  live-boot initrd. It is then *ready to try*: nothing is booted until an
  admin presses "Try it" on the Update screen, which reboots the router
  into a trial of it (frfw.kernel_boot: kept only if the router comes up
  on it). On by default, like Debian's userspace security updates, which
  use the same archive; the Update screen has a switch for it. A kernel
  that failed its trial is not prepared again.

## Known limitations

- Only IPv4 addresses/networks are supported in `src_address`/
  `dst_address`/`to_address`/`address` fields (IPv6 is planned, see
  [ROADMAP.md](../ROADMAP.md)).
- No hairpin/reflection NAT for port forwards (an internal client
  cannot reach its own WAN-side forwarded service via the public IP) --
  this can be added later if needed.
- An `apply` always replaces the entire nftables ruleset (`flush
  ruleset` + reload), it cannot be mixed with hand-written rules outside
  of frfw.
- DHCP can only be configured on a zone with exactly one interface;
  serving DHCP on a multi-interface zone (e.g. bridged LAN ports) is a
  future iteration.
- `frfw.ifaddr` only applies/updates addresses, it never removes ones
  that have been dropped from the config -- after removing an
  `address:` line, the old address stays on the machine until removed
  by hand or at the next reboot.
