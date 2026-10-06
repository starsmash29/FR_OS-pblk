# Stitch screens – FR_OS project

Inventory of every screen in the Google Stitch
**"FR_OS Brand Identity Exploration"** project
(`projects/16375246211377609752`), as of 2026-09-26. The project has **128
screens**: 116 application screens (pages, modals, reports) and 12 brand or
document elements (logos, DESIGN.md, text notes).

The screens were fetched with the Stitch MCP (`list_screens`); the fields,
tables and buttons come from the generated HTML of the screens (`<label>`,
`<th>`, `<button>`, placeholders). The UI texts are in their original English
form. The list holds the main elements, not every single button.

## Marks

| Mark | Meaning |
|---|---|
| ✅ **Exists** | FR_OS has the function (a webUI screen and/or config + CLI); the Stitch design essentially shows this. |
| 🟡 **Partly** | The core of the function exists, but the Stitch design shows a lot more (the "more" is the new part). |
| 🆕 **New** | FR_OS has no such function yet. |
| ➖ **n/a** | A brand or document element, not a function. |

The classification is based on the code on the `main` branch (`src/frfw`, the
webUI templates), phases 1–20 of the [ROADMAP.md](../ROADMAP.md) and the
[CONFIG_SCHEMA.md](CONFIG_SCHEMA.md). The ROADMAP's "Stitch screens for
features FR_OS doesn't have yet" section sums up the same marks briefly.

The Stitch designs show invented sample data and exaggerated "enterprise"
details in many places (e.g. `v4.18`, FIPS 140-3, 10G SFP+, DPDK). These are
design placeholders, not features of the existing product.

## Summary

| Area | Screens | ✅ | 🟡 | 🆕 | ➖ |
|---|---:|---:|---:|---:|---:|
| Overview and dashboard | 3 | 0 | 3 | 0 | 0 |
| Network – interfaces, firewall, NAT, DHCP | 11 | 0 | 6 | 5 | 0 |
| Network – routing, VPN, proxy, services | 19 | 0 | 0 | 19 | 0 |
| Network – traffic shaping (QoS) | 5 | 0 | 0 | 5 | 0 |
| Network – diagnostics | 5 | 0 | 0 | 5 | 0 |
| Protection | 8 | 3 | 4 | 1 | 0 |
| System – settings, accounts, updates | 9 | 0 | 6 | 3 | 0 |
| System – operations (backup, alerting, logging, HA) | 15 | 0 | 0 | 15 | 0 |
| System – temporary privilege elevation | 9 | 0 | 0 | 9 | 0 |
| System – hardware keystore (HSM) and disaster recovery | 23 | 0 | 0 | 23 | 0 |
| System – directory, RADIUS, 802.1X, PKI | 9 | 0 | 0 | 9 | 0 |
| Brand and documents | 12 | 0 | 0 | 0 | 12 |
| **Total** | **128** | **3** | **19** | **94** | **12** |

---

## 1. Overview and dashboard

### FR_OS Node Dashboard
`5066b77852e849b98e7a14555f62819c` · 🟡 **Partly**
- **Function:** the router's main overview page: live traffic, blocked threats, top traffic hosts, application categories, service states, resource load.
- **Main elements:** sections: *Real-Time Traffic Throughput*, *Top Blocked Threats*, *Top Bandwidth Hosts*, *Application Categories*, *Core Daemons & Protection Services*, *Hardware & System Resource Load*; mode switch (*Filtering / Passive / Bypass Mode*); time window (*Live 60s / 1h / 24h / 7d*); interface filter.
- **In FR_OS:** the dashboard exists (protection services with real state, system resources, interfaces, apply buttons). The live traffic graph, the top lists and the bypass mode are new.

### FR_OS Mobile Node Dashboard (390px)
`c82bb592a15c4c21af53625db0c7f0f1` · 🟡 **Partly**
- **Function:** the phone-sized (390 px) variant of the dashboard.
- **Main elements:** node card (uptime, CPU, RAM, temperature), WAN telemetry (down/up bandwidth, RTT, packet loss), IDS/threat summary, interface list; buttons: *Speedtest*, *Export Logs*, *Fail-Safe*; bottom navigation (*Dash / Traffic / Protect / Network / System*).
- **In FR_OS:** the webUI works on a phone too (off-canvas menu); the bottom tab navigation, the WAN telemetry and the speedtest are new.

### Read-Only Viewer Profile
`aa185544d7974c05a15de42db98c55b5` · 🟡 **Partly**
- **Function:** a read-only (auditor) view with live telemetry and the hit counts of the rules.
- **Main elements:** sections: *Dual-WAN Ingress / Egress Telemetry*, *L7 Payload Demux*, *Active Ingress/Egress Filter Rules*, *Kernel XDP / eBPF Live Diagnostic Trace*; table: ID, Action, Rule Name, Proto, Source, Destination, Hit Packets, Total Bytes; buttons: *Request Elevated Privileges*, *Export Audit Bundle (.JSON)*.
- **In FR_OS:** the `viewer` role exists (phase 18), and the viewer sees no edit cards. There is no separate auditor view, no rule hit counts and no privilege request.

---

## 2. Network – interfaces, firewall, NAT, DHCP

### Interfaces & VLAN Port Matrix
`30d719f88769487e93da0397c9ab4a57` · 🟡 **Partly**
- **Function:** physical ports, VLAN port assignment (tagged/untagged) and interface telemetry.
- **Tables:** *VLAN 802.1Q Port Assignment Matrix* (VID, VLAN Name, Gateway/Subnet, U/T per port, Zone, DHCP Scope); *Active Interfaces & Hardware PHY Telemetry* (Interface, Hardware/MAC, IP/MTU, Duplex/Speed, Throughput, Packets/Errors); *SFP+ Optical DDM Diagnostics*.
- **Buttons:** *Bonding / LACP*, *Cable & SFP Diag*, *Add Interface / VLAN*, *Batch Edit*, *Export Interface Metrics*.
- **In FR_OS:** the Interfaces screen exists (logical interface → device + zone, static address, NIC detection). The VLAN matrix, the PHY telemetry and the SFP diagnostics are new.

### Create & Provision VLAN Interface Modal
`d4a2cddb02584897836f80a4da2f1b72` · 🆕 **New**
- **Function:** create a new 802.1Q VLAN interface.
- **Fields:** VLAN Tag ID (2–4094), Interface Identifier (automatic name), Zone Alias, Security Zone, Parent Trunk Interface, 802.1p Priority, MTU (1500/9000/1450), Gateway IPv4/CIDR, IPv6 mode (Static/SLAAC/Track WAN/None).
- **Buttons:** *Copy Script*, *Test Carrier (Dry-Run)*, *Provision VLAN*.
- **In FR_OS:** an existing VLAN device (e.g. `eth1.30`) can be referenced as an interface, but creating and managing VLANs does not exist.

### Create & Provision LACP Link Aggregation Modal
`d26d94562604437b8cf67faad37a30eb` · 🆕 **New**
- **Function:** gather several ports into an LACP bond.
- **Fields:** Interface Name, Alias, Transmit Hash Policy, LACP Rate (Fast 1s / Slow 30s), addressing mode (Static / DHCP / VLAN Trunk), MTU (1500/9000/9216).
- **Buttons:** *Dry-Run LACP Partner*, *Create Bond & Commit Slaves*.

### Firewall & NAT Rule Manager
`4e793ebe284d4fe69dc70205bbf16b1a` · 🟡 **Partly**
- **Function:** firewall rules, port forwards, outbound NAT, aliases and schedules in one place.
- **Table:** #, Act, Verdict, Interface/Zone, Proto, Source, Port/Svc, Destination, Hits/Bandwidth, Description, Actions.
- **Buttons and tabs:** *Test Policy / Dry Run*, *Quick Port Forward*, *Add New Rule*; tabs: *Firewall Rules*, *Port Forwarding (DNAT)*, *Outbound NAT (SNAT)*, *Aliases & IP Lists*, *Schedules & Cron*; filters by zone pair.
- **In FR_OS:** the rules (Rules), the NAT (masquerade, port-forward) and the scheduled rules (phase 17) exist, on separate screens. The hit and bandwidth counters, the IP alias lists and the rule simulation are new.

### Create Firewall Filter Rule Modal
`4108830bbd4c42f5a4f1e91d63ece796` · 🟡 **Partly**
- **Function:** add a new filter rule.
- **Fields:** Rule Identifier, Priority (above/below), action (PASS / REJECT…), direction (Inbound/Outbound/Bidirectional), conntrack states (NEW/ESTABLISHED/RELATED/INVALID), Ingress Interface/VLAN, Source IP/CIDR and port, Strict MAC Guard, Egress Interface, Destination CIDR and port(s), Invert Match, protocol (TCP/UDP/ICMP/GRE/ANY), Log to SIEM.
- **Buttons:** *Add L7 Filter*, *Copy CLI*, *Dry-Run Simulation*, *Commit & Deploy*.
- **In FR_OS:** the Rules screen has rule creation (zones, protocol, addresses, port, action, schedule, MAC). Conntrack state matching, invert match, the L7 filter and the dry run are new.

### Create Port Forwarding & NAT Rule Modal
`128e75217c6843fc8d641f1ecbcd59f6` · 🟡 **Partly**
- **Function:** an inbound port-forward (DNAT) rule.
- **Fields:** Rule Identifier, L4 Protocol, Annotation, Inbound Interface, External WAN Port(s), Zero-Trust Ingress Policy, Source Whitelist/CIDR, Target LAN/DMZ Host IP (selectable from DHCP/ARP), Destination Port, L7 DPI, SIEM logging, ZTNA mTLS.
- **Buttons:** output format (*nftables / iptables-legacy / FR_OS JSON*), *Dry-Run Simulation*, *Commit NAT Rule & Apply*.
- **In FR_OS:** the port forward exists (name, inbound zone, tcp/udp, port, target address, target port). The source whitelist, ZTNA/mTLS and the L7 check are new.

### DHCP Leases & Client Inventory
`42a0fa1f54504a74b3978ce79875c38b` · 🟡 **Partly**
- **Function:** DHCP pools, active leases and a client inventory.
- **Table:** Client Hostname & OS, IP Address, MAC & OUI Vendor, Subnet/VLAN, Lease Type, Time Remaining, Traffic (24h), Status, Actions.
- **Buttons and tabs:** *Add Static Reservation*, *Flush Expired*, *DHCP Options*, *Export*; tabs: *Active Leases*, *Subnet Scope Pools*, *Static Reservations*, *DHCP Options (43/66)*, *Raw Kea Log*; per row *Send WOL*, *Reassign IP*, *Revoke Lease*.
- **In FR_OS:** the per-zone Kea DHCP pool and the reservations exist. The live lease list, the DHCP options, Wake-on-LAN and lease revocation are new.

### DHCP Static Lease Reservation & Client Pinning Modal
`8a147e96279040d0ab3bfa7c9420cfc2` · 🟡 **Partly**
- **Function:** a static DHCP reservation for a client.
- **Fields:** Hostname, MAC Address, DUID (DHCPv6), Device Profile, Subnet Scope, Reserved IPv4 (*Next Free*, *ARP Probe*), IPv6 suffix, Lease Policy (Infinite/Sticky), Default Gateway (Option 3), DNS (Option 6).
- **Buttons:** *Clone from Live Lease / ARP Table*, *Dry-Run Syntax Check*, *Commit Reservation*.
- **In FR_OS:** the reservation (MAC, IPv4, hostname) exists. DHCPv6, the option overrides and cloning from a lease are new.

### ARP & NDP Neighbor Discovery Table Modal
`5663f216e5564f2bb6cc35aab497b74b` · 🆕 **New**
- **Function:** browse and manage the kernel's neighbour table (ARP/NDP).
- **Table:** Type & State, IP / Reverse DNS, MAC, OUI Vendor, Interface, Last Confirmed, Trust/Flags, Actions; state filters (REACHABLE/STALE/PERMANENT/FAILED).
- **Buttons:** *Flush Stale*, *Raw CLI (ip neigh)*, *Export CSV*, *Add Static Pin*, *Scan (ARP Ping)*.
- **In FR_OS:** IoT discovery reads the ARP table internally, but there is no screen of its own.

### Client Deep-Dive Device Inspector Modal
`0f7506d5895c472d8f97390830880100` · 🆕 **New**
- **Function:** a detailed record sheet of one client: traffic, applications, isolation, DHCP/DNS.
- **Table:** Remote Destination, Resolved Hostname, Volume, Policy.
- **Fields (switches):** Block Internet Access, Enforce 2FA, Route via WireGuard, Full PCAP Mirroring.
- **Buttons and tabs:** *Overview*, *Active Flows & Conntrack*, *L7 Application*, *Security & Isolation*, *DHCP & DNS Pinning*; *Kill Conntrack*, *Quarantine Host*, *Send WoL*, *Save Policy Changes*.
- **In FR_OS:** pieces of the information are on other screens (IoT isolation, per-client application use); there is no unified client record sheet.

### Live Sessions Explorer
`b3e2ae64164741abbce32e85e6119a11` · 🆕 **New**
- **Function:** browse and manage live conntrack connections.
- **Table:** State/ID, Protocol/Dir, Source, Destination, L7 App/Fingerprint, Transfer Rate, Total Vol, TCP Win/Flags, Duration/TTL, Actions.
- **Buttons:** refresh (1s), *Dump PCAP*, *Kill Idle*, regex filter; views (Inbound / Outbound / East-West / Suspicious / High Bandwidth); per row *Session PCAP*, *Rate Limit*, *Drop & Ban*.
- **In FR_OS:** conntrack reading exists internally (AI IDS), but there is no connection browser screen.

---

## 3. Network – routing, VPN, proxy, services

### Policy-Based Routing (PBR) & Multi-WAN Manager
`77849a168e2a4799b3da7d9945ab3de7` · 🆕 **New**
- **Function:** manage several WAN connections and policy-based routing (`ip rule`).
- **Table:** Pref, Rule Name, Source Match, Destination/Port, DSCP/Mark, Target Table & Gateway, Hit Packets, State, Actions.
- **Fields (for testing):** Source IP/CIDR, Destination IP, Protocol & Port, DSCP.
- **Buttons:** *Test Route Probe*, *Flush Cache*, *New PBR Rule*, *Ping Targets Now*, routing table filters, *Dry-Run Check*, *Apply to Kernel*.

### Create Policy-Based Routing (PBR) Rule Modal
`4178c628997d48eea6408e195d0e11d9` · 🆕 **New**
- **Function:** a new PBR rule.
- **Fields:** Priority, Rule Name, Incoming Interface, Source Network and port, IP Protocol, Destination Network and port (templates: VoIP, Web, DNS), DSCP, Fwmark, Suppress Prefix Length; action: Lookup Table / Unreachable / Prohibit / Blackhole.
- **Buttons:** *Copy Script*, *Dry-Run Validation Test*, *Test Trajectory*, *Commit PBR Rule*.

### Multi-WAN Gateway Watchdog & Failover Settings Modal
`c0e9873a96a24ddb8b3d8650ff8cfca3` · 🆕 **New**
- **Function:** watch the WAN gateways and fail over automatically.
- **Sections:** *Monitored Uplink Gateways & Health Probes*, *Health Thresholds & Flap Damping*, *Failover Routing Policy & Switch Actions*.
- **Fields:** webhook alert (Slack/Discord/PagerDuty), kernel syslog event.
- **Buttons:** *Test Health Probe (Dry-Run)*, *Save & Activate Watchdog*.

### BGP Routing Table & Peering Explorer Modal
`791eba4348dc486f8dd4b82279c574e4` · 🆕 **New**
- **Function:** browse the BGP routing table.
- **Table:** Status & Flags, Prefix, Next Hop, Neighbor Peer, Metric/MED, LocalPref, AS-Path, Communities, Inspect.
- **Buttons:** *Export MRT / RIB*, *Raw BIRD CLI*, *Refresh Routes*, *Run Route Lookup*, *Clear Dampening*.

### BGP & OSPF Dynamic Peering Configuration Modal
`83bba943df5b4de2b1be3e14a1277913` · 🆕 **New**
- **Function:** set up a BGP or OSPF adjacency.
- **Fields:** Peer Alias, Description, Local ASN, Router ID, Source IP/Interface, Remote ASN, Neighbor IP, Multihop TTL, Update-Source, eBGP Multihop, Graceful Restart, TCP MD5 Key, Import/Export Route Policy.
- **Buttons:** *BGP Session / OSPFv2/v3*, *Test Handshake (TCP 179)*, *Deploy & Establish Peering*.

### VPN & WireGuard Tunnels
`da057ff604254c0dbbbb4c07b24772b2` · 🆕 **New**
- **Function:** manage WireGuard interfaces and peers, provision clients.
- **Table:** Peer Device, Tunnel IP, Public Key & PSK, Allowed Subnets, Endpoint, Handshake, Transfer, Actions.
- **Fields:** Device Tag, Tunnel Interface, Virtual IP, DNS Resolvers, Post-Quantum PSK, ZTNA ACL binding; new interface: Device Name, UDP Port, Subnet Pool.
- **Buttons:** *Provision Tunnel*, *Add Peer*, *Peer QR & .conf*, *Split / Full Tunnel*, *Generate QR*, *Download .conf*.

### WireGuard Add Peer & QR Provisioning Modal
`56e002a772734b5ca5ea67fd112b063d` · 🆕 **New**
- **Function:** add a new WireGuard client with a QR code.
- **Fields:** Device Name, Operator Identity, Target Interface, Client Public/Private Key, Post-Quantum PSK, Tunnel IP, DNS Resolvers, Routing Mode (Split/Full), ZTNA binding.
- **Buttons:** *Regenerate Keypair*, *Copy Raw*, *Download .conf*, *Activate Peer & Commit*.

### Reverse Proxy & Let's Encrypt
`1703ef12ed404993b39a43164fc37f03` · 🆕 **New**
- **Function:** reverse proxy with TLS termination and ACME certificates.
- **Table:** Domain, Status, Ingress/Proto, Backend Upstream, TLS Certificate, WAF Profile, Bandwidth (24h), Actions.
- **Buttons and tabs:** *Deploy & Reload*, *Force ACME Renewal*, *Add Host Proxy*; *Proxy Hosts*, *ACME Certificates*, *Upstream Pools*, *Security Headers & mTLS*, *Live Access Logs*.

### Add Ingress Proxy Host Modal
`afda2bffe6494ac1909f1e25b38aa63f` · 🆕 **New**
- **Function:** add a new proxy host.
- **Fields:** Domain Names, Scheme (HTTP/HTTPS/FastCGI/gRPC/TCP), Forward Host/IP, Forward Port, Path Prefix, WAF (OWASP CRS), Force HTTPS, HTTP/2 and HTTP/3, WebSocket, Strict mTLS.
- **Buttons:** tabs (*Routing*, *SSL/ACME*, *Security & WAF*, *Headers & Caching*), *Raw Caddy/HAProxy Preview*, *Test Upstream Reachability*, *Save & Hot-Reload*.

### mDNS Repeater & Multicast Router
`534f75c8f492469ba7f11b959d2e2e9b` · 🆕 **New**
- **Function:** forward mDNS/Bonjour between VLANs, IGMP proxy.
- **Table:** Status/Rule, Source Zone, Target Zone, Service Signature/Port, Direction & Mode, 24h Telemetry, Actions.
- **Buttons and tabs:** *Restart Avahi*, *Flush Mappings*, *PCAP Capture*, *Add Repeating Rule*; *Discovered Services*, *IGMP Proxy & IPTV*, *Service Whitelist/Blacklist*, *Live Multicast Snooper*.
- **In FR_OS:** only IoT discovery uses mDNS (reading); there is no forwarding.

### Add Repeating Rule Modal
`4e7535e55dfd4f848b7582814d6ba8c8` · 🆕 **New**
- **Function:** a new multicast forwarding rule between VLANs.
- **Fields:** Rule Alias, Service Template (AirPlay, Google Cast, Sonos, Matter, AirPrint, custom), Direction & Reflection Mode, Source Zone, Target Zones.
- **Buttons:** steps (*Service & Zones*, *Port & Filter*, *TTL & Security*, *Raw Avahi / nftables Preview*), *Dry-Run Discovery Test*, *Save & Reload*.

### Captive Portal & Guest Voucher Engine
`b8eff793556b434ca93cbbf544fcdfa1` · 🆕 **New**
- **Function:** guest network with a captive portal and vouchers.
- **Table:** Status & Expiration, Voucher Code, Client & MAC, VLAN & Interface, Data Transferred, Speed Profile, Actions.
- **Fields (voucher generator):** Batch Label, Access Profile (TTL), Concurrent Devices, Quantity.
- **Buttons:** *Preview Splash Page*, *Flush Expired Sessions*, *Export Active Leases (.csv)*, *Generate Vouchers*, *Revoke Selected*, *Generate & Print Voucher Slips*.

### Guest Splash Portal Preview & Live Customizer Modal
`2ca58096e8b848459820e44870ddd541` · 🆕 **New**
- **Function:** edit the guest sign-in page with a live preview.
- **Fields:** Voucher Serial, Organization Header, Welcome Banner, Accent Theme, Post-Auth Redirect; sections: *Authentication Policy*, *Walled Garden DNS Whitelist*, *Session & Bandwidth QoS*.
- **Buttons:** *Mobile 390px / Desktop 1024px*, authentication mode (*Voucher / SMS / 30m Trial*), *Simulate Client Auth*, *Save & Deploy Portal*.

### Guest Voucher Batch Print & Export Template (Thermal & PDF)
`fe467da61059461e898cb82edc294030` · 🆕 **New**
- **Function:** print voucher cards on a thermal printer or into a PDF.
- **Fields:** Output Target (Thermal 80/58 mm, A4/Letter, CSV/JSON), Roll Geometry, card content (Wi-Fi QR, URL, QoS/expiry, AUP), Auto-Cut, Print Range.
- **Buttons:** *Generate Batch*, *Printer Setup*, *Export PDF*, *Send to Thermal*, *Save Template*, *Print Test Slip*.

### Dynamic DNS (DDNS) Client & Multi-Provider Sync
`f018437319664402aa5d261bf0d107c0` · 🆕 **New**
- **Function:** a dynamic DNS client with several providers.
- **Table:** Status, Hostname, Provider, Bound Uplink, Resolved vs Target IP, Last Verified, Actions.
- **Fields:** Primary Address Source (how the public IP is detected).
- **Buttons:** *Force Refresh All*, *API Tokens Vault*, *Add DDNS Profile*, *Save Engine Preferences*, *Download Full Audit*.

### Create & Provision Dynamic DNS Profile Modal
`f78af2e1aa5f48a3b73824ec4c6b9991` · 🆕 **New**
- **Function:** a new DDNS profile.
- **Fields:** Provider (DuckDNS, RFC 2136 TSIG…), Hostname, record type (A/AAAA), credentials, IP source (Kernel Netlink / HTTP Reflector / STUN), interface binding.
- **Buttons:** *Auto-Detect*, *Dry-Run Handshake*, *Save & Provision Profile*.

### DNS Static Override & Host Record Modal
`2be5f38e9c2447dcbaf6c27bd786c221` · 🆕 **New**
- **Function:** add or override a local DNS record.
- **Fields:** FQDN, record type (A/AAAA/CNAME/TXT/PTR), Zone Scope, Description, IPv4 and IPv6 target, Auto PTR, mode (Local override / Conditional forward / Sinkhole), TTL.
- **Buttons:** *From DHCP*, *Next Free*, *ICMP Ping*, *Dry-Run (dig)*, *Commit Record & Reload*.

### Configure Encrypted DoH/DoT Upstream DNS Modal
`06e58bcf13cf4c5d80852a2ba0e0239b` · 🆕 **New**
- **Function:** set up an encrypted upstream DNS resolver.
- **Fields:** protocol (DoT/DoH/DoQ), Upstream IPv4/IPv6, TLS SNI, SPKI Pinning, multi-upstream mode (Fastest/Round-Robin/Priority).
- **Buttons:** *Dry-Run TLS Handshake*, *Commit Upstream & Reload*.
- **In FR_OS:** the DNS filter (adblock) can block the DoT/DoH bypass, but there is no encrypted upstream; the DHCP pools' DNS servers are plain IPv4 addresses.

### DNS Leak Test & Resolver Telemetry Diagnostics Modal
`4608c389ef0c492482a684e422de3568` · 🆕 **New**
- **Function:** test for DNS leaks and DNS hijacking.
- **Tests:** port 53 hijacking, DNS rebinding, IPv6 dual-stack leak, browser DoH canary.
- **Table:** Responder Node/IP, Protocol & Port, Latency, ASN & Operator, Tunnel Status.
- **Buttons:** *Run Deep Multi-Probe*, *Export PCAP / JSON*, *Re-Run Full Test Suite*.

---

## 4. Network – traffic shaping (QoS)

### Traffic Control & Smart Queue Management (CAKE SQM)
`c39e616f3d364f70934d031006c8ff00` · 🆕 **New**
- **Function:** CAKE-based queue management against bufferbloat.
- **Table:** Flow Source/Target, Priority Tier, Queue Depth, ECN Marks, Drops, Throughput.
- **Fields:** Link Layer Overhead (Ethernet/DOCSIS/ATM/Raw IP), DiffServ Classification, Host Fairness Mode, interface selector.
- **Buttons:** *Run Benchmark*, *Apply 95% Wire Calc*, *Reset Flow Counters*, *Simulate UDP Flooding*, *Save & Apply Qdisc*.

### FQ_CoDel Parameter Tuning & Kernel Configurator Modal
`4954338dd922420791ed323a31b790dd` · 🆕 **New**
- **Function:** tune the FQ_CoDel parameters.
- **Fields:** Quick Tuning Presets, FQ_CoDel Active, ECN Enabled, flow count (512–4096), Root/Ingress/Egress branch; *Queue Oscilloscope & AQM State* graph.
- **Buttons:** *Raw tc Preview*, *Reset to RFC Defaults*, *Dry-Run Check*, *Copy tc CLI*, *Apply & Commit to Kernel*.

### Hierarchical Token Bucket (HTB) Tree Editor Modal
`4b113b5a59b949f1a3ff6ad910dbf561` · 🆕 **New**
- **Function:** edit the HTB class tree.
- **Fields:** Class ID, Parent Handle, Description, Priority, Quantum, Burst, Cburst, Leaf Qdisc, Classification Rules.
- **Buttons:** templates (*1G/100M Fiber*, *500M Work+Game*), *Tree Graph / Tabular Matrix*, *+ Child*, priorities P0–P7, *Add Match*, *Dry-Run Test*, *Commit HTB Tree*.

### tc qdisc CLI & Raw Kernel Queue Inspector Modal
`ad7b71c06877498ba5169a438318289c` · 🆕 **New**
- **Function:** raw view of the kernel's qdisc tree and running `tc` commands.
- **Fields:** grep filter, interface selector, ready-made commands (`tc -s qdisc/class/filter show`).
- **Buttons:** *Live Refresh*, *Export Dump*, *Set Bandwidth*, *Toggle ACK-Filter*, *DiffServ Tin Preset*, *Reset Counters*, *Execute tc Command*, *Copy as Bash Script*.

### Bufferbloat Saturation Benchmark Diagnostics Modal
`4f7f391435db4d18ac1c9f6181210f1f` · 🆕 **New**
- **Function:** latency measurement under load (bufferbloat test).
- **Table:** Phase, Time Window, Active Flow Stress, Avg Latency, Min/Max, Added Bloat Delta, Loss/ECN, Status.
- **Fields:** Saturation Profile, Duration, Benchmark Node.
- **Buttons:** *Run Benchmark*, *Stop*, *Export RFC (.json)*, *Download .pcap*, *Commit CAKE Settings*.

---

## 5. Network – diagnostics

### Network Diagnostics & Path Analyzer
`684a655c0b6f464b9d714527a8364f43` · 🆕 **New**
- **Function:** a network diagnostics toolbox (ping, MTR, traceroute, TCP probe, DNS, iPerf3).
- **Table:** #, Host/ASN, IP, Loss %, Sent/Recv, Last, Avg, Best, Worst, StDev, Latency Profile.
- **Fields:** Target Host/IP, Outgoing Interface, Pings/Count, Interval.
- **Buttons:** tool selector (*ICMP Ping*, *MTR*, *Visual Traceroute*, *TCP SYN Probe*, *DNS Lookup Bench*, *iPerf3*), target templates, *Start Trace*, *Run Automated Health Audit*, *Export PCAP Trace*.

### MTR & Packet Loss / Jitter Telemetry Diagnostics Modal
`7ba99d04017541f8836f0b0776dec1bf` · 🆕 **New**
- **Function:** hop-by-hop packet loss and jitter measurement.
- **Table:** Hop, Host & IP, BGP/ASN, Loss %, Snt/Rcv, Last, Avg, Best, Wrst, StDev, RTT Dispersion.
- **Fields:** Egress Interface, Probe Payload, Packet Size, target.
- **Buttons:** *Restart Deep Trace*, *Copy MTR Report*, *Export CSV/JSON*, *Capture Extended PCAP*.

### iPerf3 & Bandwidth Speedtest Diagnostics Modal
`3190ef4181484a2199f591dd6f92c1c5` · 🆕 **New**
- **Function:** bandwidth measurement with iPerf3 (client and server mode).
- **Table:** ID, Interval, Transfer, Bandwidth, Retr, Cwnd.
- **Fields:** Target Host, Parallel Streams, Direction, Interface/Time.
- **Buttons:** *Client Mode / Server Daemon*, target templates, *Re-Run Benchmark*, *Export Report*.

### Live Packet Capture (PCAP & Wireshark Stream) Modal
`a8a0c8d9daf346d7ac018f2eab3fce6f` · 🆕 **New**
- **Function:** live packet capture on the router.
- **Table:** No., Time, Source, Destination, Proto, Length, Info.
- **Fields:** Interface Tap, Direction, Packet Slice/Ring, BPF filter (e.g. `host 10.0.0.1 and port 80`).
- **Buttons:** filter templates (DNS, TLS, VoIP, ICMP/ARP), *Stream Live (Wireshark Pipe)*, *Export .pcap*, *Download .pcapng*.

### IP Geo-Lookup & Packet Trajectory Simulator
`e921b78cf45a4994a3c6d5c2b30c1384` · 🆕 **New**
- **Function:** the geographic data of an IP, and what would happen to a packet coming from it (which rule would match).
- **Fields:** Target IPv4/IPv6/CIDR, Protocol, Port, inbound interface (WAN/LAN/WG).
- **Buttons:** sample addresses (Tor exit, Cloudflare, etc.), *Run Simulation*, *Copy Diagnostic JSON*, *Add Exception / Override Rule*.

---

## 6. Protection

### AI IDS/IPS
`36809da03a7d47f19e4761161aa6b950` · 🟡 **Partly**
- **Function:** intrusion detection and prevention: events, signatures, behaviour heuristics.
- **Table:** Time, Severity & MITRE, Signature/SID, Source, Destination, Proto & L7 App, Action Taken, Quick Actions.
- **Buttons and tabs:** *Add Custom Detection Rule*, *Update Threat Feeds*, *Tune Heuristic Thresholds*; *Active Detections*, *Signature Rulesets*, *AI Behavioral Heuristics*, *Suppression & Whitelist*, *Live Raw Alert Console*; per row *Perma-Drop*, *Isolate Dev*, *Suppress Signature*, *Download PCAP*.
- **In FR_OS:** the local, anomaly-based AI IDS/IPS exists (engine state, settings, quarantined hosts, recent events; phase 11). The Suricata signatures, the MITRE classification, the PCAP download and the whitelist handling are new.

### Applications & L7 DPI
`1b1e6bbc20674661be3a1fcd851b73c7` · 🟡 **Partly**
- **Function:** application detection and per-application control.
- **Table:** Application & Engine, Category, Risk Index, Active Clients, Bandwidth (24h), Applied Policy, Status, Actions.
- **Fields:** per-VLAN scope.
- **Buttons and tabs:** *Update Signatures*, *QoS Pools*, *Create Application Rule*; *Traffic Shaping & QoS Queues*, *Custom Signatures & Regex*, *Live Flow Stream*, *Category Breakdown*; policy: *Block / Throttle / Monitor / Unlimited*.
- **In FR_OS:** App-ID lite exists (~45 applications, 24-hour per-client use, blocking; phase 16). The risk index, the bandwidth cap, the custom signatures and the per-VLAN policy are new.

### ZTNA Gate
`e97f9268e8084722bdf8927301b2cbcf` · 🟡 **Partly**
- **Function:** zero-trust access: micro-access for identified users and devices.
- **Table:** Identity & Role, Device & Telemetry, ZTNA WG IP, Remote Endpoint, Micro-Access Scope, Posture State, Handshake, Actions.
- **Buttons and tabs:** *Add ZTNA Policy / Tunnel*, *Sync IdP (Keycloak)*, *Revoke Ephemeral Certs*; *Active Remote Tunnels*, *Micro-Perimeters*, *Posture Policies*, *Live Access Log*; per row *Revoke*, *+1h*, *Sever*, *Force Re-Authentication*.
- **In FR_OS:** ZTNA exists (sign-in gate, local accounts, protected rules, nftables set with a time limit; phase 7). The WireGuard-based tunnels, the device posture and the IdP sync are new.

### TLS Fingerprints & JA3/JA4 Inspector
`c95db0cad76c4fbd9521f8118e2604e1` · ✅ **Exists**
- **Function:** TLS ClientHello fingerprinting (JA3/JA4) without decryption.
- **Table:** Time, Severity, Client Endpoint, JA4 Fingerprint, Inferred Client Profile, Target SNI, Action State.
- **Buttons and tabs:** *Add Custom Fingerprint Rule*, *Sync Malicious JA4 DB*, *Flush Cache*; *Live Fingerprint Stream*, *Fingerprint Catalog*, *Anomalous & Rogue Clients*, *JA4 Rule Editor*; per row *Quarantine Client*, *Allowlist (1 Hour)*.
- **In FR_OS:** the TLS Fingerprints screen exists (events, devices and their fingerprints, alerting on new fingerprints, blocklist, quarantine; phase 19). The sync with an external malicious JA4 database and the temporary allowlist would be new.

### Ad-Block & TLS SNI Filter
`9dd6f77cef0244799ae861fdf0119126` · ✅ **Exists**
- **Function:** DNS-based ad and category filtering, and kernel-level TLS SNI filtering.
- **Table:** Feed Source, Engine, Assigned Enclaves, Rules, Last Sync, State, Action.
- **Fields (new feed):** Rule Type, Feed/Regex URL, Target Engine, VLAN scope.
- **Buttons and tabs:** *Add Blocklist / Regex*, *Flush DNS Cache*, *Force Sync All*; *Policy Matrix & Feeds*, *Live DNS & SNI Stream*, *Custom Whitelist / Blacklist*, *DoH / DoT Gateways*; *Bypass for 15 Minutes*, *Compile & Load into eBPF*.
- **In FR_OS:** Ad-Block & DNS Filtering (main list, categories, allowlist, LAN DNS, update; phases 9 and 15) and the XDP TLS SNI Filter (phase 4) exist. The regex rules, the per-VLAN feeds and the live query stream are new.

### Threat Intel & DNS Sinkhole
`7073a83855dc48419cab58dd213efd66` · 🟡 **Partly**
- **Function:** threat-intel feeds and a DNS sinkhole.
- **Table:** Time, Sev, Attack Class & Signature, Proto/Port, Attacker Source, Target Host, Engine Action, Payload.
- **Buttons and tabs:** *Update Feeds*, *Whitelist IP/FQDN*, *Add Blocklist / DoH Feed*; *Suricata IDS/IPS Stream*, *DNS Sinkhole & Blocklists*, *Threat Hunting & GeoIP*, *Quarantine & Signatures*; *Auto-Ban /24 Subnet*, *Configure Upstreams*, *View Extended Query Log*.
- **In FR_OS:** DNS blocking of the malware/phishing categories and the DNS threat indicators for the AI IDS exist (phase 15). The Suricata stream, the threat-intel IP feeds and the /24 auto-ban are new.

### IoT Devices & Isolation Sandbox
`2c1dced1f54446e4a128b39a07bc825e` · ✅ **Exists**
- **Function:** discovery and isolation of IoT devices.
- **Table:** State, Device/Identity, MAC & OUI Vendor, IP/VLAN, Fingerprint & Engine, Isolation Tier, WAN/LAN Flow, Threat Score, Quick Pinhole.
- **Fields:** Local-Only DNS Guard.
- **Buttons:** *Re-scan Fingerprints*, *Block All Cloud Telemetry*, *Register IoT Device*, device type filters (cameras, bridges, plugs, sensors), per row *Pinhole RTSP*, *Isolate Cam*, *Mute WAN*, *Apply Rules*.
- **In FR_OS:** the IoT Devices screen exists (inventory, explained IoT decision, scanning, MAC-based isolation in internet-only or full-block mode; phase 14). The pinhole exceptions and the threat score are new.

### Geo-IP Country Filter & Perimeter Policy Modal
`0e6cca2baa9a4f3a95be82d6d640c26f` · 🆕 **New**
- **Function:** country-based traffic filtering.
- **Sections:** *Policy Action & Directional Enforcement*, *Quick Presets & High-Risk Threat Packs* (EU, Tor, sanctions lists…), *Interactive Country Matrix*, *Exceptions & CIDR Overrides*, *nftables / eBPF CLI Preview*.
- **Fields:** country search (ISO 3166 / ASN), exception CIDRs.
- **Buttons:** continent filters, *Add Exemption*, *Copy Raw CLI*, *Dry-Run Simulation*, *Commit Geo-IP Policy*.

---

## 7. System – settings, accounts, updates

### System Settings
`e8a5f10273884751af47c2f056648e90` · 🟡 **Partly**
- **Function:** system-wide settings.
- **Sections:** *Node Identification & Domain*, *Time Synchronization (NTP / PTP)*, *Remote Logging & Telemetry Exporters*, *Upstream DNS & DoT/DoH*, *Hardware Cryptography & Offload*, *Dangerous Actions*.
- **Fields:** Hostname, Domain, Description & Location, Timezone, WebUI Port, Syslog Remote Host, Node Exporter Bind, eBPF Flow Metric Bind, OpenTelemetry Endpoint.
- **Buttons:** *Discard Draft*, *Export .yaml*, *Test DNS & NTP*, *Save & Apply*, *Reboot Node*, *Maintenance Mode*, *Factory Reset*.
- **In FR_OS:** the System screen exists (webUI TLS certificate, SSH/PQC, settings, storage and persistence, multi-site monitoring); the hostname and the timezone are in the config. NTP, syslog forwarding, OpenTelemetry, maintenance mode and factory reset are new.

### Telemetry, SNMP & Prometheus Metrics Exporter
`1d9f56ab0265466ab3b97911675c5349` · 🟡 **Partly**
- **Function:** export metrics to monitoring systems.
- **Sections:** *Prometheus Endpoint & TLS*, *SNMP v3 Engine & MIB Parameters*, *Live Metric Stream Inspector*.
- **Fields:** Scrape URI, Bearer Token, exporter modules (CPU, network, memory, XDP, IDS, QoS, WireGuard, NAT).
- **Buttons:** *Download MIB Files*, *Grafana JSON*, *Rotate Token*, *New Scrape Target*, *Add Poller User*, *Export Prometheus YAML*, *Apply Changes*.
- **In FR_OS:** the Prometheus `/metrics` (bearer token, verifiable TLS, `fros_info`, Grafana dashboards, multi-site example) exists (phases 12 and 20). SNMP, the per-module switch and the live metric view are new.

### Firmware & eBPF Bytecode Updates
`86520534d56b41a69bb32259db7e3e61` · 🟡 **Partly**
- **Function:** system updates, eBPF programs and boot partitions.
- **Tabs:** *Firmware & Kernel Updates*, *Live eBPF Programs & Hot-Patches*, *A/B Dual-Boot Partitions & Snapshots*, *Cryptographic Supply Chain & Signatures*, *Update History & Audit Trail*.
- **Buttons:** *Check for Updates Now*, *Upload Offline Package*, *Rollback to Slot B*, *Dry-Run*, *View Raw Git Diff*, *Commit Image & Schedule Reboot*, *Apply Hot-Reload*, *Create ZFS Snapshot*, *Clone Slot A to Emergency USB*.
- **In FR_OS:** the Update screen exists (version, update, single-slot rollback, last attempt; phase 6). The A/B partitions, the offline package, the signature check and the eBPF hot-patch are new.

### User Management & Access Control
`f4075e1b34e7468c9ad4fb08f285c43c` · 🟡 **Partly**
- **Function:** webUI accounts, roles, authentication methods and the audit log.
- **Table:** User & Identity, Assigned Role, Authentication Methods, Session State, Last Login, Actions.
- **Buttons and tabs:** *Invite / Add User*, *Configure SSO / OIDC*, *Rotate Root Secrets*; *Local Users & RBAC*, *Hardware Keys & WebAuthn*, *API Keys & Service Tokens*, *Single Sign-On*, *Live Auth Audit Log*; *Terminate All Remote Sessions*, *Suspend Account*.
- **In FR_OS:** the Users screen exists (accounts with the `admin` / `viewer` role, creation, audit log with the last 200 events; phase 18). The hardware keys, the API tokens, SSO and password ageing are new.

### Add New User & RBAC Provisioning Modal
`8f99ad5179d8411492d527f75b247dda` · 🟡 **Partly**
- **Function:** add a new user with detailed permissions.
- **Fields:** POSIX Username, Full Name, Email, UID Range, Initial Auth Method (WebAuthn invitation / one-time password / OIDC), SSH Public Key, fine-grained permissions (firewall commit, WireGuard, DHCP, conntrack, eBPF, key rotation), MFA Policy, Inactivity Timeout.
- **Buttons:** *Paste / Load .pub*, *Generate Invitation Link & Provision User*.
- **In FR_OS:** user creation (name, password, role) exists. The fine-grained permissions, the SSH key, the invitation link and MFA are new.

### Login & FIDO2 WebAuthn Authentication Gate
`5aaf570f6a194c658574d1fa5202d9ab` · 🟡 **Partly**
- **Function:** signing in to the webUI.
- **Fields:** Username, Master Password, TOTP code; touch of a FIDO2 key.
- **Buttons:** *FIDO2 Passkey* / *Password + 2FA*, *Verify & Launch Control Plane*; links: read-only sign-in, backup key, Rescue Shell, BIP-39 recovery key, rerun the OOBE.
- **In FR_OS:** password sign-in exists (admin account setup on first boot, brute-force protection). FIDO2/WebAuthn and TOTP are new.

### Out-of-Box First-Run Setup Wizard
`dfaabe8046d345bb9888df85a02df094` · 🆕 **New**
- **Function:** the first-boot wizard, the WAN step.
- **Sections:** *Physical Port Map*, *Primary WAN Uplink Configuration*.
- **Fields:** Interface Reassignment, WAN Protocol (DHCP / PPPoE / Static), Gateway Hostname, MAC Override, ISP VLAN tagging (VLAN ID, PCP), MTU, Upstream DNS Policy.
- **Buttons:** *Blink LED*, *Probe ISP Gateway Again*, *Save Draft & Exit to Rescue Shell*, *Validate & Continue*.
- **In FR_OS:** without a first-boot wizard, the router configures itself automatically (WAN = the port where a DHCP server answers, the other = LAN 10.73.1.1/24, out of the upstream's network; random admin password; ROADMAP SEC-8, NET-12). The wizard and PPPoE are new.

### First-Run Setup Wizard – Step 4: Root Security & FIDO2
`07646580372a46d5948db2fb86d8dcdb` · 🆕 **New**
- **Function:** step 4 of the wizard: admin account, SSH and hardware key.
- **Fields:** Operator Username, Master Password + confirmation, OpenSSH on/off, Management Port, Root Password Login, SSH Auth Policy, Authorized Hardware Public Key.
- **Buttons:** *Touch Security Key to Enroll*, *Add Key*, *Export Sealed Keys*, *Validate Security & Proceed*.

### First-Run Setup Wizard – Step 5: Policy Baseline & IPS
`8455c8882beb4e9790522a47a96422aa` · 🆕 **New**
- **Function:** step 5 of the wizard: picking a security baseline profile.
- **Elements:** baseline cards (*Strict Zero-Trust*, *Balanced Practitioner*, *Permissive Edge*), IPS mode (*Alert Only* / *Inline Drop*), automatic IoT quarantine.
- **Buttons:** *Dry-Run Simulation*, *Commit Baseline & Launch Control Plane*.

---

## 8. System – operations (backup, alerting, logging, HA)

### Configuration Backup & Git Rollback
`f0f5d78d06f1476086490805b05fe879` · 🆕 **New**
- **Function:** configuration snapshots with a git history, diff and restore.
- **Elements:** commit timeline, diff view (*Unified / Split View*), filters (*Manual / Firewall / Pre-flight / WireGuard*).
- **Buttons:** *Export Full Tarball*, *Import / Restore*, *Dry-Run Staging Test*, *Create Manual Snapshot*, *Rollback*, *Revert to…*, *Sync Now*, *Configure Sentinel Timeout*.
- **In FR_OS:** before an apply, the nftables ruleset goes into a timestamped backup, and the CLI can load the latest one back (`rollback`). The git history of the full configuration and the backup screen would be introduced by this design.

### Create Manual Snapshot Modal
`74a297773070403aab58c4cb4575c0a0` · 🆕 **New**
- **Function:** take a manual configuration snapshot.
- **Fields:** Commit Message, Tag, saved parts (firewall and NAT, routing, DNS and DHCP, sysctl), target (local git repo / encrypted S3).
- **Buttons:** *Dry-Run Diff*, *Commit & Push Snapshot*.

### Alert Rules & Incident Dispatcher
`dcdfece660144317be7c9dc67f79089f` · 🆕 **New**
- **Function:** alert rules and notification channels.
- **Table:** State, Severity, Rule & Target, Trigger Condition, Mitigation & Automated Action, Channels, Last Fired, Actions.
- **Buttons:** *Mute All (30m)*, *Test All Channels*, *Create Alert Rule*, *Add New Dispatch Channel*, channel tests (ping, email, syslog), severity filters, *Export JSON*.

### Create Alert Rule Modal
`bb0b6760c52e4f71a81ce3721843744e` · 🆕 **New**
- **Function:** a new alert rule.
- **Fields:** Rule Identifier, Subsystem, Severity (P0–P3), Metric Source, Operator, Threshold, Sustained For, Automated Defense, Kernel Action, Rollback; channels (Telegram, Slack, Discord, PagerDuty, SMTP, Wazuh/syslog).
- **Buttons:** *Visual Builder / PromQL*, *Simulate Evaluation*, *Compile & Deploy Rule*.

### Syslog & Remote SIEM Forwarder
`735922cf237c432f94b84c4cf8cd0f87` · 🆕 **New**
- **Function:** forward logs into remote syslog/SIEM systems.
- **Table:** Status, Pipeline Target, Protocol & Destination, Schema, Subsystems, Egress Rate/Drop, Actions.
- **Fields:** subsystem filters (XDP, IDS, NAT, WireGuard/ZTNA, kernel, RBAC), IP anonymisation (GDPR), payload removal, MAC hash, minimal severity (0–7).
- **Buttons:** *Buffer Flush*, *Test All Pipelines*, *Add Target Forwarder*, *Renew Cert*, *Export CSR*.

### Syslog & Remote SIEM Forwarder (5 Active Pipelines)
`1dac1b641ff7485386b76f55ec5a0038` · 🆕 **New**
- **Function:** a variant of the previous screen with five active pipelines, subsystem weights and buffer state.
- **Table:** Target Name, Protocol & Destination, Schema Format, Egress Rate, Latency/Drops, Transport Security, Status, Actions.
- **Fields:** PII Obfuscation (/24 mask), RFC 1918 noise dropping.
- **Buttons:** *View Tail*, *Add Target Forwarder*, *Test All Pipelines*, *Edit Global Routing AST*, *Spool Monitor*.

### Add Target Forwarder Modal
`d776735a6c7e4b889aaa9cf146f07b16` · 🆕 **New**
- **Function:** add a new log forwarder.
- **Fields:** Pipeline Name, Protocol, Destination URL/Host, Port, Framing Schema, Compression, Auth Mechanism, client certificate and key, CA Trust Anchor, SNI Override, HEC/API Token, subsystem filters, Minimum Severity, Max Queue Size, Retry Backoff.
- **Buttons:** *Test Endpoint & TLS Handshake*, *Save & Activate Forwarder*.

### Add Target Forwarder Modal (Test Handshake Verified)
`f778eb680f604924a710d78f129b974e` · 🆕 **New**
- **Function:** the state of the previous modal after a successful connection test (TLS handshake trace).
- **Buttons:** *Copy Raw Trace*, *Re-run Diagnostic Probe*, *Download PCAP Trace*, *Back to Configuration*, *Save & Activate Forwarder*.

### Live System Log & XDP Kernel Console
`3bedf762153b4c1487b06fa8fe5c9116` · 🆕 **New**
- **Function:** a live, combined system log console.
- **Fields:** grep filter.
- **Buttons and tabs:** source tabs (*XDP / eBPF*, *Firewall Log*, *IDS Alerts*, *Kernel & dmesg*, *DNS Resolver*, *WireGuard / Auth*), level filters (DROP/CRIT, WARN, PASS/INFO), *Pause*, *Export .log*, *Add Permanent eBPF Drop Rule*, *Geo-IP Trace*.

### Command Palette (Cmd+K) & Quick Action Engine
`d98dff5bac1c4792b3b16a35bd234ff1` · 🆕 **New**
- **Function:** a command palette callable from the keyboard: navigation, actions, entity search.
- **Fields:** command and search field.
- **Buttons:** modes (*All / Actions > / Navigation / / Entities #*), quick actions (*Inspect*, *Isolate*, *Edit Policy*).

### Command Palette Entity Deep Search (IP & MAC Inspector)
`2e0e941b4cfd4bfc8d7c993528591ba4` · 🆕 **New**
- **Function:** the command palette's entity search: all data of an IP or MAC address in one place.
- **Buttons:** *FIB Flows*, *DHCP Inventory*, *Packet Sniffer*, *Quarantine Host to Sandbox VLAN*, *Copy JSON Payload*.

### Emergency Rescue Shell & Fail-Safe Console
`cd01e7c741954fa5a132a5450c469bb0` · 🆕 **New**
- **Function:** an emergency console in the browser: command execution, recovery runbooks.
- **Sections:** *BIP-39 Root Key Attestation*, *Disaster Recovery Runbooks*, *Physical Bus & Transceiver Telemetry*.
- **Fields:** command line (e.g. `systemctl reset-failed`, `nft flush ruleset`).
- **Buttons:** *Core Dump*, *Reboot Hardened Kernel*, *Verify Root Signatures*, *Execute Rollback*, *Reset to Baseline*, *Raw Serial*, *Execute*.

### Post-Recovery Reboot & Invariant Re-Attestation
`ed93acf980154eba87bab0665b244693` · 🆕 **New**
- **Function:** reboot after a recovery and re-check of the system invariants.
- **Table:** Subsystem, Panic State, Recovered State.
- **Buttons:** *Pause Boot*, *Launch Now*, *Enter Control Plane*, *Download Cryptographic Recovery Bundle*.

### Incident Post-Mortem & Disaster Closeout Document
`ad1923b977fa4b20ae5137d5fba6efe2` · 🆕 **New**
- **Function:** the incident post-mortem.
- **Sections:** timeline, root cause analysis (RCA), mitigations, invariant checklist.
- **Table:** Offset, Stage, Subsystem, Event & Diagnostic Log, Verification.
- **Buttons:** *Export Attested PDF*, *Cryptographic Sig*, *Print Ledger Receipt*, *Archive to WORM Ledger*.

### Multi-Node Cluster & HA Failover Manager
`c67945311d94475092dbf7c5f34723d3` · 🆕 **New**
- **Function:** a high-availability (HA) cluster of several routers.
- **Table:** Virtual IP, Interface, VHID, Priority, Master Host, State.
- **Buttons:** *Join New Node*, *Initiate Graceful Switchover*, *Trigger Cluster Sync*, *Force Standby*, *Promote to Master*, *Add Virtual IP*, *Simulate WAN Loss*, *Test Split-Brain Fencing*, *HA Audit Report*.
- **In FR_OS:** phase 20 gives read-only monitoring of several routers under Prometheus/Grafana; there is no clustering and no failover.

---

## 9. System – temporary privilege elevation

One coherent flow: the viewer requests time-limited write access, uses it,
extends it or gives it back, and a signed audit report is produced at the end.
None of the steps exist in FR_OS (there the role is permanent: `admin` or
`viewer`).

### Request Elevated Privileges Modal
`04350c00e500403db14c404c92c765b1` · 🆕 **New**
- **Function:** request time-limited write access.
- **Fields:** Incident/Ticket Reference, Target Subsystem, Justification, recording the eBPF audit trace, notification on the audit channel; duration (30 minutes – 4 hours, custom); approval (*Admin Dispatcher / FIDO2 / TOTP*).
- **Buttons:** *Cancel & Keep Read-Only*, *Authenticate & Assert Privilege*.

### Active Operator View with Ephemeral TTL Countdown Banner
`2d277684fc73426f9ac2ac6556451b25` · 🆕 **New**
- **Function:** the work view of the elevated operator, with a countdown bar.
- **Sections:** *Target Subsystem Controls*, *Active Write-Enabled Rules*.
- **Fields:** Subnet Filter & Injection Scope (target CIDR).
- **Buttons:** *Extend Window*, *Revoke Elevation*, *Purge Stale UDP States*, *Flush BGP Route Cache*, *Simulate Drop*, *Bypass*.

### Extend Privilege Lease Window Modal
`b160b8a7a51a4293a3cb1386c0d29d52` · 🆕 **New**
- **Function:** extend the elevated privileges.
- **Fields:** Operational Justification (logged); duration (+15 minutes – +2 hours); re-authentication (FIDO2 / TOTP).
- **Buttons:** *Cancel & Maintain Current Expiry*, *Re-Authenticate & Extend*.

### Active Operator View Post-Extension (+30m Granted)
`e7197e95fe68401b8241d97557c7e9ca` · 🆕 **New**
- **Function:** the work view after a successful extension.
- **Table:** Rule #, Direction, Action/State, TTL Remaining, Mutate.
- **Buttons:** *Extend Window*, *Revoke Elevation*, *Purge UDP States*, *Flush BGP Cache*, *Export*.

### Privilege Lease Expired (TTL Expired)
`1ab067c1757e4404b02f7852a8a275de` · 🆕 **New**
- **Function:** the elevated privileges have expired; a new request can be started.
- **Fields:** Incident Reference, Requested Duration, MFA Authorizer, Elevation Scope Reason.
- **Buttons:** *Submit Request*, *Request New Elevation Window*, *Download Signed Audit Bundle*.

### Revoke Elevated Privileges Modal
`9ddb7b6999804d5fa58057c968dd134f` · 🆕 **New**
- **Function:** giving back the elevated privileges voluntarily.
- **Fields:** automatic download of the signed compliance package, sending an incident alert.
- **Buttons:** *Cancel & Continue Lease*, *Revoke Privileges & Seal Audit*.

### Cryptographic Audit Receipt & Compliance Report
`d0a30d30ad2c45ebace9b5488776925e` · 🆕 **New**
- **Function:** a signed summary of the changes made while the privileges were elevated.
- **Table:** Op/Subsystem, Mutation Payload, Pre → Post State, Status.
- **Buttons and tabs:** *Overview & Digest*, *State Mutations Diff*, *eBPF Syscall Trace*, *PCAP Ring Buffer*, *Operator Notes & Sign-off*; *Download Signed Bundle*, *Verify Signature*, *Print Certificate (PDF)*.

### PDF Compliance Certificate & Attestation Export
`fc497b2008b04402b58a873a68bc2141` · 🆕 **New**
- **Function:** the PDF certificate of the privilege lifecycle, page 1.
- **Table:** Verification Step, Target Boundary, Observed Delta, Audit Result.
- **Buttons:** *Fit Width / Fit Page*, *Print*, *Raw JSON Receipt*.

### PDF Compliance Certificate & Attestation Export (Sheet 2)
`5ab102c8f47d4b1fb84eec3a82586467` · 🆕 **New**
- **Function:** page 2 of the PDF certificate: kernel syscall trace and hash differences.
- **Table:** UTC Timestamp, Kernel Primitive, Parameters & Scope, Ret, Attestation Key.
- **Buttons:** *Raw Hex Export*, *Download Signed PDF*, *Verify Enclave Token*.

---

## 10. System – hardware keystore (HSM) and disaster recovery

One large, coherent design family: a TPM/HSM/YubiHSM keystore, key generation,
rotation and destruction, benchmark certificates, Shamir-style M-of-N key
sharing and restore. None of it exists in FR_OS. (The existing cryptographic
part is the hybrid post-quantum key exchange in webUI TLS and SSH, phase 8,
which is independent of this.)

### Hardware HSM & Cryptographic Keystore
`668eaa967c3d4b34b08e7273575727e9` · 🆕 **New**
- **Function:** the keystore's main page: crypto modules, key inventory, PCR registers.
- **Sections:** *Detected Cryptographic Modules & Token Slots* (TPM 2.0, YubiHSM 2, Intel QAT), *Key Inventory & Lifecycle*, *Platform Configuration Registers*.
- **Table:** Key Identifier & Usage, Hardware Slot, Algorithm, Public Fingerprint, Lifecycle/Rotation, State, Operations.
- **Buttons:** *Enroll Security Token*, *Rotate Ephemeral Root*, *Generate Asymmetric Keypair*, *Rescan PKCS#11 Bus*, *View PCR Bank*, *Manage Operator PIN*, *Export Public Keys*, *Benchmark Offload*; per row *Sign Test*, *Rotate*, *Rekey*, *Reseal*, *Backup*.

### Hardware HSM & Cryptographic Keystore (Post-Enrollment)
`6f230c98b6744bce89a6793b053a53f7` · 🆕 **New**
- **Function:** the keystore after a new token (YubiHSM 2 Edge) has been enrolled, with the audit flow.
- **Table:** Key Alias, Hardware Enclave, Algorithm, Fingerprint, Lifecycle/Expiry, State, Operations.
- **Buttons:** *Audit Attestation Key*, *Enroll Security Token*, *Audit PCRs*, *View Quorum*, *Trigger Attestation Quote*.

### Hardware HSM & Cryptographic Keystore (Key Generated)
`52c964623a9448c485110304c25428aa` · 🆕 **New**
- **Function:** the keystore after a new key pair has been generated.
- **Table:** as above (Key Identifier, Enclave, Algorithm, Fingerprint, Lifecycle, State, Operations).
- **Buttons:** *Attestation Receipt*, *Run Sign Test (ECDSA)*, *Enroll Token*, *Rotate Ephemeral Root*, *Generate Asymmetric Keypair*, *Audit Quorum*.

### Hardware HSM & Keystore (Ephemeral Root Rotation Active)
`e89bed2fc5f94a8ea30d4210a0cf8e1d` · 🆕 **New**
- **Function:** the keystore while a root key rotation is running, with the mesh propagation state.
- **Table:** Key Alias & Algorithm, Lifecycle State, Hardware Slot, Authorized Usage, Actions.
- **Buttons:** *Audit Receipt*, *Rollback v1*, *Force Zeroize*, *Refresh Ring*, *CAVP Pass*.

### Hardware HSM & Keystore (Post-Zeroization State)
`1f9e8f6ab15148318581cbe8938450fd` · 🆕 **New**
- **Function:** the keystore after a key has been destroyed (zeroization).
- **Sections:** *Zeroization Completed & Committed*, *Physical HSM & Slot Inventory*, *Mesh Convergence Matrix*.
- **Buttons:** *View Receipt*, *Export Attestation Proof*, *Certificate Chain*, *Provision New Ephemeral Key*.

### Hardware HSM & Keystore (Post-Recovery Restored State)
`98f89d5f7af04da4891d3a804658899d` · 🆕 **New**
- **Function:** the keystore after a disaster recovery.
- **Sections:** *Cryptographic Keystore Ledger*, *Hardware Attestation Record*.
- **Buttons:** *View Recovery Attestation*, *Rescan Enclaves*, *Export Shards*, *Sign Test*, *Rotate Standby*, *Download Cryptographic Proof (.sig)*.

### Enroll Security Token & HSM Device Modal
`3ec17182701b49a88117024aa8d20820` · 🆕 **New**
- **Function:** enroll a hardware token or an HSM.
- **Fields:** Token Alias, Security Domain, Slot Mapping, allowed algorithms (RSA-4096, ECDSA P-384, Ed25519; RSA-2048 forbidden), Admin SO PIN, Operator PIN.
- **Buttons:** *Re-scan Bus*, *Cancel & Release Slot*, *Confirm Enrollment & Seal Token*.

### Generate Asymmetric Keypair Modal
`eb5c6353e3c4442891ca3736622fd7c1` · 🆕 **New**
- **Function:** generate a key pair and bind it to a hardware enclave.
- **Fields:** Key Alias, key exchange mode (ECDH / KEM), QAT offload.
- **Buttons:** *Generate Keypair & Seal into Enclave*.

### Hardware HSM Sign Test & Cryptographic Benchmark Modal
`39bfd201622c43febbe2d48cd2b7ab56` · 🆕 **New**
- **Function:** an ECDSA P-384 signing test and a performance measurement on the HSM.
- **Buttons:** *Copy Hex*, *Download CAVP Vector*, *Export Signed Receipt*, *Rerun 60s Stress Test*.

### Hardware HSM Extended 60s Stress Test Modal
`65fddbef9f134975b1100355fd9751ea` · 🆕 **New**
- **Function:** the result of a 60-second HSM load test (crypto slot state, throughput).
- **Buttons:** *Download CAVP JSON*, *Export Signed PDF*, *Close & Retain Results*.

### Signed PDF Stress Test Certificate & Benchmark Attestation
`74c0408bdb264912acdd1dc786a29339` · 🆕 **New**
- **Function:** the signed PDF certificate of the load test, page 1.
- **Sections:** summary, hardware profile, PCR quote, signature, throughput graph, latency percentiles, CAVP checks.
- **Table:** Percentile, Response Time, Ring Queue Delay, Hardware Exec, FIPS Threshold, Status.
- **Buttons:** *Print*, *Raw Signature*, *Download PDF*, pager.

### Signed PDF Stress Test Certificate (Sheet 2: CAVP Trace & Raw Nonces)
`ebb3ab169f5e4399b49b5515f5be4913` · 🆕 **New**
- **Function:** page 2 of the certificate: CAVP trace, raw nonces, verifier tooling.
- **Sections:** *Attestation Verifier*, *Vector Verification Tooling*, *Worker Core Load Balance*.
- **Buttons:** *Print*, *Raw Signature*, *Download PDF*.

### Ephemeral Root Key Rotation Modal
`3de9cc5dea15424d8ffc756fb7119d71` · 🆕 **New**
- **Function:** start the rotation of the root key pair.
- **Fields:** Rotation Trigger, Grace Period (48 hours recommended), re-signing scopes (ZTNA, eBPF, WireGuard mesh).
- **Buttons:** *Abort & Retain Current Root*, *Simulate Mesh Re-Key (Dry-Run)*, *Authorize & Commit Key Rotation*.

### Ephemeral Root Key Rotation (Dry-Run Simulation Results)
`9a73f778eea94f45b3634ef184dce0a2` · 🆕 **New**
- **Function:** the result of the rotation simulation, per node.
- **Sections:** *Mesh Re-Keying & WireGuard Handoff*, *Node-by-Node Mesh Verification Matrix*.
- **Buttons:** *Re-run Simulation with Heavy Traffic*, *Back to Rotation Settings*, *Proceed & Commit Live Key Rotation*.

### Ephemeral Root Key Rotation Audit Receipt & Attestation
`1e631212810e4744bba0fffb6e63113c` · 🆕 **New**
- **Function:** the signed audit receipt of the closed rotation (hash chain).
- **Buttons:** *Audit JSON*, *Raw Sig*, *PDF Attestation*, *Keystore*, *Copy Root*.

### Force Zeroize v1 (Cryptographic Key Destruct Modal)
`3817bf853f3a4ee6af496702588ed601` · 🆕 **New**
- **Function:** destroy a key immediately and irreversibly.
- **Fields:** typing the alias of the key as a confirmation.
- **Buttons:** *Cancel & Keep Grace Window*, *Confirm & Zeroize Slot Immediately*.

### Zeroization Audit Attestation (REC-ZERO-0314-001)
`d72a7eeee3c94bca952b148f8e9b90e9` · 🆕 **New**
- **Function:** the audit receipt of the destruction.
- **Sections:** bit deletion, Merkle proof, hardware seals, cluster sync, CLI check.
- **Table:** Pass #, Bit Pattern, Cell Verification, Latency.
- **Buttons:** *Audit JSON*, *Raw Nonce Dump*, *Download Signed PDF*, *Verify PCR*, *Export Compliance Bundle*.

### Disaster Recovery Key Export (M-of-N Shamir Sharding Modal)
`51ddef044462435589c4095f9a4ad743` · 🆕 **New**
- **Function:** split a recovery key into M-of-N Shamir shares.
- **Sections:** threshold setting, custodian list (N = 5), packaging and KEM, mandatory passphrase, physical quorum check.
- **Buttons:** number of custodians (3 / 5 / 7), *Cancel Export*, *Execute Shamir Split & Export Shards*.

### Disaster Recovery Shard Handover Manifest & Escrow Receipts
`b4f8470df1884663a7a8446b9ff96ea0` · 🆕 **New**
- **Function:** the record of the handover of the key shares.
- **Table:** Shard #, Custodian, Escrow Medium, CRC-32 & SHA, Delivery & Integrity Seal, Custodian Actions.
- **Buttons:** *Download All*, *Print 5 Air-Gapped Keycards*, *Verify Token*, *Print Custodian Handover Sheets*, *Verify Escrow Quorum Offline*, *Close & Lock*.

### Disaster Recovery Key Recovery (M-of-N Reassembly Wizard)
`90393f9c2cc04666a35a1803040b9a32` · 🆕 **New**
- **Function:** restore the key from the shares.
- **Fields:** 33-word SLIP-0039 mnemonic; input mode (*Hardware Token / Air-Gap QR / Mnemonic Seed / PGP Blob*).
- **Buttons:** *Tap Hardware Token*, *Abort Recovery*, *Simulate Lagrange Math*.

### Disaster Recovery Key Recovery (Quorum Complete & Key Reconstructed)
`7e9e3a26982d4621b72347eb7b08f3e6` · 🆕 **New**
- **Function:** acknowledgement of a successful restore.
- **Buttons:** *Download Audit Receipt*, *View Attestation Cert*, *Finalize & Return to Keystore*.

### Recovery Audit Attestation (REC-RESTORE-0314-002)
`606c6822f22e4545826b8669e909e35c` · 🆕 **New**
- **Function:** the signed audit report of the recovery.
- **Table:** Index, Custodian, Hardware Authenticator, Vector Checksum, Timestamp, Enclave Signature Status, Commit State.
- **Buttons:** *Download Signed JSON*, *Export Signed PDF*, *Verify Seal with OpenSSL*, *Export Full Attestation Bundle*.

### Platform Integrity, TPM 2.0 & Secure Boot Attestation
`b0ab191841c54e2daa6890a41c38852a` · 🆕 **New**
- **Function:** check the integrity of the boot chain (TPM PCRs, Secure Boot).
- **Table:** Index, Measurement Scope, Current Hash, Golden Baseline, Status.
- **Buttons and tabs:** *Verify Platform PCRs*, *Export Quote & Sig*, *Re-seal Enclave Secrets*; *PCR Registers*, *Boot Event Log*, *Firmware Manifest*, *Kernel Lockdown*.
- **In FR_OS:** the ISO also boots on UEFI (phase 13), but there is no TPM measurement and no Secure Boot attestation.

---

## 11. System – directory, RADIUS, 802.1X, PKI

Central authentication (AD/LDAP), a built-in FreeRADIUS, 802.1X network
access and an own certificate authority. None of it exists in FR_OS (the
webUI and the ZTNA accounts are local).

### Centralized Directory & RADIUS Authentication Gate
`c0bda2944ffa4b17906009a97eecd63a` · 🆕 **New**
- **Function:** directory and RADIUS servers, NAS clients, group→VLAN rules.
- **Tables:** NAS clients (Name, IP/Subnet, Shared Secret, Capabilities, Req/min, Status); *Group-to-VLAN & RBAC Policy Matrix* (Directory Group, FR_OS Role, 802.1X VLAN, Bandwidth Profile, Session Lease, Actions).
- **Buttons:** *Test Connection*, *Flush Auth Cache*, *Sync Schema Now*, *Add Authentication Server*, *Test Bind*, *Force Sync*, *Add NAS Client*, *Add Group Rule*.

### Centralized Directory & RADIUS Authentication Gate (Updated NAS Matrix)
`7f7e314749864eaa973dabf1926311cc` · 🆕 **New**
- **Function:** the previous screen with an extended NAS matrix.
- **Table:** NAS Authenticator, Node Type/Protocol, IP/Subnet, Shared Secret, RFC 3576 CoA, RADIUS Dictionary, Engine Status, Quick Actions.
- **Buttons:** *Issue 802.1X Cert*, *Test AAA Auth*, *Sync Directories*, *Add Server*, *Add NAS Client*, *CoA Ping*, *Test Policy Simulator*, *Download clients.conf*.

### Add & Configure NAS Client Modal (RADIUS Clients Matrix)
`43a20099c56c4203aa01edfa2090bc0d` · 🆕 **New**
- **Function:** add a new RADIUS NAS client (switch, AP, VPN).
- **Fields:** Friendly Name, Short Identifier, Device Archetype, NAS IP/CIDR, Ingress Interface, Shared Secret, Auth Policy Profile, Auth/Acct/CoA UDP Port, CoA Secret, Vendor Dictionary, Fallback VLAN.
- **Buttons:** *Generate Strong Secret*, *Send Test Access-Request*, *Dry-Run Config Check*, *Save & Deploy NAS Client*.

### Add Authentication Server Modal
`27dfc47ab4484c5e8793d09672e8fd99` · 🆕 **New**
- **Function:** add an LDAP/AD directory server.
- **Fields:** Protocol, Server Alias, Hostname/IP, Port, TLS, Root CA, Bind DN, Bind Password, Base DN (*Auto-Detect*), User Search Filter, Group Membership Filter; bind mode (service account / anonymous).
- **Buttons:** *Re-Run Handshake Test*, *Save & Provision Identity Server*.

### Edit Group-to-VLAN Mapping Rule Modal
`79650ffbf43e4e2580e93e827dd4e3cb` · 🆕 **New**
- **Function:** map a directory group to a VLAN, a bandwidth profile and a role.
- **Fields:** Identity Provider, Match Protocol, Group DN, Target VLAN/Subnet, Fallback VLAN, CA Issuer, Health Attestation, RADIUS Filter-ID, Priority Tier, Downlink/Uplink Ceiling, Qdisc, Admin Role, Privilege Escalation, MFA Policy, ZTNA Endpoints, Egress Inspection, Session Lease.
- **Buttons:** *Browse LDAP Tree*, QoS profiles, *Dry-Run Simulation*, *Save & Deploy Rule to AAA Daemon*.

### 802.1X Policy & Dynamic VLAN Simulator Modal
`3727b5cdf12344079259d6998760f39b` · 🆕 **New**
- **Function:** simulate 802.1X authentication: which VLAN and policy a device would get.
- **Fields:** EAP Identity, EAP Method, Supplicant MAC, Compliance/TPM Posture, NAS Authenticator, Port/SSID, NAS Port-Type, Calling/Called-Station-Id.
- **Buttons:** sample devices (laptop, workstation, guest, IoT camera), *Run Policy Simulation*, *Export Simulation JSON*, *Simulate CoA Disconnect*.

### 802.1X EAP & PKI Certificate Manager
`6bcc72a4c6b54c48848d70cee2b878f5` · 🆕 **New**
- **Function:** an own certificate authority (CA) and 802.1X/EAP certificate management.
- **Sections:** *CA Hierarchy & Trust Anchor*, *SCEP / EST Automated Gateway*.
- **Table:** Common Name/SAN, Role/Type, Cryptographic Suite, Hardware Attestation, Validity, Serial & Fingerprint, Actions.
- **Buttons:** *Issue Cert / CSR*, *Renew FreeRADIUS*, *Publish CRL & OCSP*, *Create / Import CA*, *Export CA Bundle*.

### Issue Certificate & Sign CSR Modal
`0dbb53986ff94aaebefd8add883e0ee0` · 🆕 **New**
- **Function:** issue a certificate (sign a CSR, key pair + PKCS#12, or a SCEP/EST one-time secret).
- **Fields:** Signing CA, Hash Algorithm, Validity Period, Auto-renew (SCEP), PEM CSR (drag & drop).
- **Buttons:** *Load Demo CSR*, *Dry-Run ASN.1*, *Sign & Issue Certificate*.

### Certificate Post-Issuance & Export Modal
`eaf1bfe22e06414faa1ff80386ba8b28` · 🆕 **New**
- **Function:** download an issued certificate in different formats.
- **Table:** Common Name/SAN, Serial, Algorithm, Attestation, Binding, Expires, Status.
- **Buttons:** *Download .crt / fullchain.pem / .mobileconfig / Intune .xml*, *View Raw ASN.1*, *Copy PEM*, *Issue New Certificate*.

---

## 12. Brand and documents

Not functions, but brand and design material.

| Screen | ID | Content |
|---|---|---|
| FR_OS Brand Discovery & Exploration (6 Directions) | `389b12f3acc94b2697ba95f89db0ba5b` | Six brand directions visually: Precision, Flow, Boundary, Signal, Industrial, Open Technology. |
| FR_OS Brand Identity Exploration | `a1fe3ca5fc0948c9b8b644b925000e4b` | The same as a text document (in Hungarian): comparison matrix, principles, do-not list. |
| FR_OS Frost Precision Logo | `4ed82141405548c3ba77dc2a77f72b24` | Logo variant (512×512). |
| FR_OS Hex-Frost Security Logo | `929d5c506a274ee5b34e010f6b7b57fb` | Logo variant (512×512). |
| FR_OS Glacial Bastion Logo | `7185e872371f4e47bb71d44f8a4e314e` | Logo variant (512×512). |
| FR_OS Minimalist Logo with Wordmark | `6db27c830a194f8a8b937543a5ab9edf` | Logo with wordmark. |
| FR_OS Logo – V1 Pure Minimalist (No Subtitle) | `11e953d7f4c0443d929e4b97e9728f23` | Horizontal logo variant. |
| FR_OS Logo – V2 Modern Flow with Diamond Node | `85deb921d010491cb10a3c487c7f7eae` | Horizontal logo variant. |
| FR_OS Logo – V3 Hex Vault Perimeter & Pulse Dot | `44f1c7a9d84f4a9e983299869e0e9b59` | Horizontal logo variant. |
| DESIGN.md | `1441345348995393367` | The description of the webUI design system uploaded to Stitch (colours, typography). |
| FR_OS 2-Part Distribution Manifest | `07c2361fa4ec48c88b428df0eb4bcb95` | A text note about splitting the design package into two ZIP archives. |
| Extracted text from zenarmor.com (home dashboard) | `f65fb8325be4491e89f968fdf213c2e5` | Text taken as a reference from the Zenarmor dashboard documentation. |
