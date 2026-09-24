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
iot: {...}           # optional, default: empty (disabled)
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
