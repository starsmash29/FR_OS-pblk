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
interfaces: {...}    # required, see below
zones: {...}         # required, see below
rules: [...]         # optional, default: []
nat: {...}           # optional, default: empty
dhcp: {...}          # optional, default: empty
ai_ids: {...}        # optional, default: empty (disabled)
adblocker: {...}     # optional, default: empty (disabled)
iot: {...}           # optional, default: empty (disabled)
app_control: {...}   # optional, default: empty (disabled)
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
```

`address` is the router's own static IPv4 address on that interface --
applied via `ip addr replace` (`frfw.ifaddr`). Only required if the
zone should get a DHCP pool (see `dhcp` below); leave it unset on an
interface managed by a DHCP client (e.g. a typical WAN interface).

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
    log: false                     # optional, default: false
```

With `to_zone: self`, the rule goes into the `input` chain (no `oifname`
constraint, since the destination is the router itself); otherwise into
the `forward` chain.

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
adblock-refresh` (daily timer) or the webUI's "Refresh now", never by
`apply`.

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
- `query_logging`: dnsmasq logs every query (`log-queries=extra`) to the
  system journal, where `fr-ai-ids` reads it. This records which client
  looked up which name, for as long as the journal keeps it.

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
  program sees (one journal line per TLS connection). With neither, the
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
- These cross-section requirements are only checked while `enabled` is
  true. Changes take effect on the next `apply`; the daemon picks up
  config changes by itself.

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
