# Stitch képernyők – FR_OS projekt

A Google Stitch **„FR_OS Brand Identity Exploration”** projekt
(`projects/16375246211377609752`) összes képernyőjének leltára, 2026-09-26-i
állapot szerint. A projektben **128 képernyő** van: 116 alkalmazás-képernyő
(oldalak, modálok, jelentések) és 12 márka- vagy dokumentum-elem (logók,
DESIGN.md, szöveges jegyzetek).

A képernyők a Stitch MCP-vel lettek lekérve (`list_screens`); a mezők, táblák
és gombok a képernyők generált HTML-jéből származnak (`<label>`, `<th>`,
`<button>`, placeholder-ek). A UI-szövegek eredeti, angol formájukban
szerepelnek. A felsorolás a fő elemeket tartalmazza, nem minden egyes gombot.

## Jelölések

| Jel | Jelentés |
|---|---|
| ✅ **Létezik** | A funkció megvan az FR_OS-ben (webUI-képernyő és/vagy config + CLI); a Stitch-terv lényegében ezt mutatja. |
| 🟡 **Részben** | A funkció magja megvan, de a Stitch-terv jóval többet mutat (a „több” az új rész). |
| 🆕 **Új** | Ilyen funkció még nincs az FR_OS-ben. |
| ➖ **n/a** | Márka- vagy dokumentum-elem, nem funkció. |

A besorolás alapja a `main` ág kódja (`src/frfw`, a webUI-sablonok), a
[ROADMAP.md](../ROADMAP.md) 1–20. fázisa és a
[CONFIG_SCHEMA.md](CONFIG_SCHEMA.md). A ROADMAP „Stitch screens for features
FR_OS doesn't have yet” szakasza ugyanezeket a jelölteket foglalja össze
röviden.

A Stitch-tervek sok helyen kitalált mintaadatot és túlzó „enterprise”
részleteket mutatnak (pl. `v4.18`, FIPS 140-3, 10G SFP+, DPDK). Ezek terv-
elemek, nem a meglévő termék tulajdonságai.

## Összesítő

| Terület | Képernyő | ✅ | 🟡 | 🆕 | ➖ |
|---|---:|---:|---:|---:|---:|
| Áttekintés és dashboard | 3 | 0 | 3 | 0 | 0 |
| Hálózat – interfészek, tűzfal, NAT, DHCP | 11 | 0 | 6 | 5 | 0 |
| Hálózat – útválasztás, VPN, proxy, szolgáltatások | 19 | 0 | 0 | 19 | 0 |
| Hálózat – forgalomszabályozás (QoS) | 5 | 0 | 0 | 5 | 0 |
| Hálózat – diagnosztika | 5 | 0 | 0 | 5 | 0 |
| Védelem | 8 | 3 | 4 | 1 | 0 |
| Rendszer – beállítások, fiókok, frissítés | 9 | 0 | 6 | 3 | 0 |
| Rendszer – üzemeltetés (mentés, riasztás, napló, HA) | 15 | 0 | 0 | 15 | 0 |
| Rendszer – ideiglenes jogosultság-emelés | 9 | 0 | 0 | 9 | 0 |
| Rendszer – hardveres kulcstár (HSM) és katasztrófa-helyreállítás | 23 | 0 | 0 | 23 | 0 |
| Rendszer – címtár, RADIUS, 802.1X, PKI | 9 | 0 | 0 | 9 | 0 |
| Márka és dokumentumok | 12 | 0 | 0 | 0 | 12 |
| **Összesen** | **128** | **3** | **19** | **94** | **12** |

---

## 1. Áttekintés és dashboard

### FR_OS Node Dashboard
`5066b77852e849b98e7a14555f62819c` · 🟡 **Részben**
- **Funkció:** a router fő áttekintő oldala: élő forgalom, blokkolt fenyegetések, top forgalmazó hosztok, alkalmazás-kategóriák, szolgáltatások állapota, erőforrás-terhelés.
- **Fő elemek:** szekciók: *Real-Time Traffic Throughput*, *Top Blocked Threats*, *Top Bandwidth Hosts*, *Application Categories*, *Core Daemons & Protection Services*, *Hardware & System Resource Load*; üzemmód-kapcsoló (*Filtering / Passive / Bypass Mode*); időablak (*Live 60s / 1h / 24h / 7d*); interfész-szűrő.
- **FR_OS-ben:** a dashboard létezik (védelmi szolgáltatások valós állapottal, rendszer-erőforrások, interfészek, apply-gombok). Az élő forgalmi grafikon, a top-listák és a bypass üzemmód újak.

### FR_OS Mobile Node Dashboard (390px)
`c82bb592a15c4c21af53625db0c7f0f1` · 🟡 **Részben**
- **Funkció:** a dashboard telefonos (390 px) változata.
- **Fő elemek:** node-kártya (uptime, CPU, RAM, hőmérséklet), WAN-telemetria (le/fel sávszélesség, RTT, csomagvesztés), IDS/fenyegetés-összesítő, interfészlista; gombok: *Speedtest*, *Export Logs*, *Fail-Safe*; alsó navigáció (*Dash / Traffic / Protect / Network / System*).
- **FR_OS-ben:** a webUI telefonon is működik (off-canvas menü); az alsó tab-navigáció, a WAN-telemetria és a speedtest újak.

### Read-Only Viewer Profile
`aa185544d7974c05a15de42db98c55b5` · 🟡 **Részben**
- **Funkció:** csak olvasó (auditor) nézet élő telemetriával és a szabályok találati számaival.
- **Fő elemek:** szekciók: *Dual-WAN Ingress / Egress Telemetry*, *L7 Payload Demux*, *Active Ingress/Egress Filter Rules*, *Kernel XDP / eBPF Live Diagnostic Trace*; tábla: ID, Action, Rule Name, Proto, Source, Destination, Hit Packets, Total Bytes; gombok: *Request Elevated Privileges*, *Export Audit Bundle (.JSON)*.
- **FR_OS-ben:** a `viewer` szerepkör létezik (18. fázis), és a viewer nem lát szerkesztő kártyákat. Külön auditor-nézet, szabály-találatszámok és jogosultság-kérés nincs.

---

## 2. Hálózat – interfészek, tűzfal, NAT, DHCP

### Interfaces & VLAN Port Matrix
`30d719f88769487e93da0397c9ab4a57` · 🟡 **Részben**
- **Funkció:** fizikai portok, VLAN-port hozzárendelés (tagged/untagged) és interfész-telemetria.
- **Táblák:** *VLAN 802.1Q Port Assignment Matrix* (VID, VLAN Name, Gateway/Subnet, portonként U/T, Zone, DHCP Scope); *Active Interfaces & Hardware PHY Telemetry* (Interface, Hardware/MAC, IP/MTU, Duplex/Speed, Throughput, Packets/Errors); *SFP+ Optical DDM Diagnostics*.
- **Gombok:** *Bonding / LACP*, *Cable & SFP Diag*, *Add Interface / VLAN*, *Batch Edit*, *Export Interface Metrics*.
- **FR_OS-ben:** az Interfaces képernyő létezik (logikai interfész → eszköz + zóna, statikus cím, hálókártya-felismerés). A VLAN-mátrix, a PHY-telemetria és az SFP-diagnosztika újak.

### Create & Provision VLAN Interface Modal
`d4a2cddb02584897836f80a4da2f1b72` · 🆕 **Új**
- **Funkció:** új 802.1Q VLAN-interfész létrehozása.
- **Mezők:** VLAN Tag ID (2–4094), Interface Identifier (automatikus név), Zone Alias, Security Zone, Parent Trunk Interface, 802.1p Priority, MTU (1500/9000/1450), Gateway IPv4/CIDR, IPv6 mód (Static/SLAAC/Track WAN/None).
- **Gombok:** *Copy Script*, *Test Carrier (Dry-Run)*, *Provision VLAN*.
- **FR_OS-ben:** egy meglévő VLAN-eszköz (pl. `eth1.30`) hivatkozható interfészként, de VLAN létrehozása és kezelése nincs.

### Create & Provision LACP Link Aggregation Modal
`d26d94562604437b8cf67faad37a30eb` · 🆕 **Új**
- **Funkció:** több port összefogása LACP-bondba.
- **Mezők:** Interface Name, Alias, Transmit Hash Policy, LACP Rate (Fast 1s / Slow 30s), címzési mód (Static / DHCP / VLAN Trunk), MTU (1500/9000/9216).
- **Gombok:** *Dry-Run LACP Partner*, *Create Bond & Commit Slaves*.

### Firewall & NAT Rule Manager
`4e793ebe284d4fe69dc70205bbf16b1a` · 🟡 **Részben**
- **Funkció:** tűzfalszabályok, port-forwardok, kimenő NAT, aliasok és ütemezések egy helyen.
- **Tábla:** #, Act, Verdict, Interface/Zone, Proto, Source, Port/Svc, Destination, Hits/Bandwidth, Description, Actions.
- **Gombok és fülek:** *Test Policy / Dry Run*, *Quick Port Forward*, *Add New Rule*; fülek: *Firewall Rules*, *Port Forwarding (DNAT)*, *Outbound NAT (SNAT)*, *Aliases & IP Lists*, *Schedules & Cron*; szűrők zónapár szerint.
- **FR_OS-ben:** a szabályok (Rules), a NAT (masquerade, port-forward) és az időzített szabályok (17. fázis) megvannak, külön képernyőkön. A találat- és sávszélesség-számlálók, az IP-alias listák és a szabály-szimuláció újak.

### Create Firewall Filter Rule Modal
`4108830bbd4c42f5a4f1e91d63ece796` · 🟡 **Részben**
- **Funkció:** új szűrőszabály felvétele.
- **Mezők:** Rule Identifier, Priority (above/below), akció (PASS / REJECT…), irány (Inbound/Outbound/Bidirectional), conntrack-állapotok (NEW/ESTABLISHED/RELATED/INVALID), Ingress Interface/VLAN, Source IP/CIDR és port, Strict MAC Guard, Egress Interface, Destination CIDR és port(ok), Invert Match, protokoll (TCP/UDP/ICMP/GRE/ANY), Log to SIEM.
- **Gombok:** *Add L7 Filter*, *Copy CLI*, *Dry-Run Simulation*, *Commit & Deploy*.
- **FR_OS-ben:** a Rules képernyőn van szabályfelvétel (zónák, protokoll, címek, port, akció, ütemezés, MAC). A conntrack-állapot szűrés, az invert match, az L7-szűrő és a dry-run újak.

### Create Port Forwarding & NAT Rule Modal
`128e75217c6843fc8d641f1ecbcd59f6` · 🟡 **Részben**
- **Funkció:** bejövő port-forward (DNAT) szabály.
- **Mezők:** Rule Identifier, L4 Protocol, Annotation, Inbound Interface, External WAN Port(s), Zero-Trust Ingress Policy, Source Whitelist/CIDR, Target LAN/DMZ Host IP (DHCP/ARP-ból választható), Destination Port, L7 DPI, SIEM-naplózás, ZTNA mTLS.
- **Gombok:** kimeneti formátum (*nftables / iptables-legacy / FR_OS JSON*), *Dry-Run Simulation*, *Commit NAT Rule & Apply*.
- **FR_OS-ben:** a port-forward megvan (név, bejövő zóna, tcp/udp, port, célcím, célport). A forrás-whitelist, a ZTNA/mTLS és az L7-ellenőrzés újak.

### DHCP Leases & Client Inventory
`42a0fa1f54504a74b3978ce79875c38b` · 🟡 **Részben**
- **Funkció:** DHCP-tartományok, aktív lease-ek és kliensleltár.
- **Tábla:** Client Hostname & OS, IP Address, MAC & OUI Vendor, Subnet/VLAN, Lease Type, Time Remaining, Traffic (24h), Status, Actions.
- **Gombok és fülek:** *Add Static Reservation*, *Flush Expired*, *DHCP Options*, *Export*; fülek: *Active Leases*, *Subnet Scope Pools*, *Static Reservations*, *DHCP Options (43/66)*, *Raw Kea Log*; soronként *Send WOL*, *Reassign IP*, *Revoke Lease*.
- **FR_OS-ben:** zónánkénti Kea DHCP-pool és foglalások megvannak. Az élő lease-lista, a DHCP-opciók, a Wake-on-LAN és a lease-visszavonás újak.

### DHCP Static Lease Reservation & Client Pinning Modal
`8a147e96279040d0ab3bfa7c9420cfc2` · 🟡 **Részben**
- **Funkció:** statikus DHCP-foglalás egy klienshez.
- **Mezők:** Hostname, MAC Address, DUID (DHCPv6), Device Profile, Subnet Scope, Reserved IPv4 (*Next Free*, *ARP Probe*), IPv6 suffix, Lease Policy (Infinite/Sticky), Default Gateway (Option 3), DNS (Option 6).
- **Gombok:** *Clone from Live Lease / ARP Table*, *Dry-Run Syntax Check*, *Commit Reservation*.
- **FR_OS-ben:** a foglalás (MAC, IPv4, hostname) megvan. A DHCPv6, az opciók felülírása és a lease-ből klónozás újak.

### ARP & NDP Neighbor Discovery Table Modal
`5663f216e5564f2bb6cc35aab497b74b` · 🆕 **Új**
- **Funkció:** a kernel szomszédtáblájának (ARP/NDP) böngészése és kezelése.
- **Tábla:** Type & State, IP / Reverse DNS, MAC, OUI Vendor, Interface, Last Confirmed, Trust/Flags, Actions; állapotszűrők (REACHABLE/STALE/PERMANENT/FAILED).
- **Gombok:** *Flush Stale*, *Raw CLI (ip neigh)*, *Export CSV*, *Add Static Pin*, *Scan (ARP Ping)*.
- **FR_OS-ben:** az IoT-felderítés belül olvassa az ARP-táblát, de önálló képernyő nincs.

### Client Deep-Dive Device Inspector Modal
`0f7506d5895c472d8f97390830880100` · 🆕 **Új**
- **Funkció:** egy kliens részletes adatlapja: forgalmak, alkalmazások, izoláció, DHCP/DNS.
- **Tábla:** Remote Destination, Resolved Hostname, Volume, Policy.
- **Mezők (kapcsolók):** Block Internet Access, Enforce 2FA, Route via WireGuard, Full PCAP Mirroring.
- **Gombok és fülek:** *Overview*, *Active Flows & Conntrack*, *L7 Application*, *Security & Isolation*, *DHCP & DNS Pinning*; *Kill Conntrack*, *Quarantine Host*, *Send WoL*, *Save Policy Changes*.
- **FR_OS-ben:** részinformációk más képernyőkön vannak (IoT-izoláció, alkalmazáshasználat kliensenként), egységes kliens-adatlap nincs.

### Live Sessions Explorer
`b3e2ae64164741abbce32e85e6119a11` · 🆕 **Új**
- **Funkció:** élő conntrack-kapcsolatok böngészése és kezelése.
- **Tábla:** State/ID, Protocol/Dir, Source, Destination, L7 App/Fingerprint, Transfer Rate, Total Vol, TCP Win/Flags, Duration/TTL, Actions.
- **Gombok:** frissítés (1s), *Dump PCAP*, *Kill Idle*, regex-szűrő; nézetek (Inbound / Outbound / East-West / Suspicious / High Bandwidth); soronként *Session PCAP*, *Rate Limit*, *Drop & Ban*.
- **FR_OS-ben:** a conntrack-olvasás belül megvan (AI IDS), de kapcsolat-böngésző képernyő nincs.

---

## 3. Hálózat – útválasztás, VPN, proxy, szolgáltatások

### Policy-Based Routing (PBR) & Multi-WAN Manager
`77849a168e2a4799b3da7d9945ab3de7` · 🆕 **Új**
- **Funkció:** több WAN-kapcsolat és szabályalapú útválasztás (`ip rule`) kezelése.
- **Tábla:** Pref, Rule Name, Source Match, Destination/Port, DSCP/Mark, Target Table & Gateway, Hit Packets, State, Actions.
- **Mezők (tesztelő):** Source IP/CIDR, Destination IP, Protocol & Port, DSCP.
- **Gombok:** *Test Route Probe*, *Flush Cache*, *New PBR Rule*, *Ping Targets Now*, routing-tábla szűrők, *Dry-Run Check*, *Apply to Kernel*.

### Create Policy-Based Routing (PBR) Rule Modal
`4178c628997d48eea6408e195d0e11d9` · 🆕 **Új**
- **Funkció:** új PBR-szabály.
- **Mezők:** Priority, Rule Name, Incoming Interface, Source Network és port, IP Protocol, Destination Network és port (sablonok: VoIP, Web, DNS), DSCP, Fwmark, Suppress Prefix Length; akció: Lookup Table / Unreachable / Prohibit / Blackhole.
- **Gombok:** *Copy Script*, *Dry-Run Validation Test*, *Test Trajectory*, *Commit PBR Rule*.

### Multi-WAN Gateway Watchdog & Failover Settings Modal
`c0e9873a96a24ddb8b3d8650ff8cfca3` · 🆕 **Új**
- **Funkció:** WAN-átjárók figyelése és automatikus átállás.
- **Szekciók:** *Monitored Uplink Gateways & Health Probes*, *Health Thresholds & Flap Damping*, *Failover Routing Policy & Switch Actions*.
- **Mezők:** Webhook-riasztás (Slack/Discord/PagerDuty), kernel syslog esemény.
- **Gombok:** *Test Health Probe (Dry-Run)*, *Save & Activate Watchdog*.

### BGP Routing Table & Peering Explorer Modal
`791eba4348dc486f8dd4b82279c574e4` · 🆕 **Új**
- **Funkció:** a BGP-útvonaltábla böngészése.
- **Tábla:** Status & Flags, Prefix, Next Hop, Neighbor Peer, Metric/MED, LocalPref, AS-Path, Communities, Inspect.
- **Gombok:** *Export MRT / RIB*, *Raw BIRD CLI*, *Refresh Routes*, *Run Route Lookup*, *Clear Dampening*.

### BGP & OSPF Dynamic Peering Configuration Modal
`83bba943df5b4de2b1be3e14a1277913` · 🆕 **Új**
- **Funkció:** BGP- vagy OSPF-szomszédság beállítása.
- **Mezők:** Peer Alias, Description, Local ASN, Router ID, Source IP/Interface, Remote ASN, Neighbor IP, Multihop TTL, Update-Source, eBGP Multihop, Graceful Restart, TCP MD5 Key, Import/Export Route Policy.
- **Gombok:** *BGP Session / OSPFv2/v3*, *Test Handshake (TCP 179)*, *Deploy & Establish Peering*.

### VPN & WireGuard Tunnels
`da057ff604254c0dbbbb4c07b24772b2` · 🆕 **Új**
- **Funkció:** WireGuard-interfészek és peerek kezelése, kliens-provisioning.
- **Tábla:** Peer Device, Tunnel IP, Public Key & PSK, Allowed Subnets, Endpoint, Handshake, Transfer, Actions.
- **Mezők:** Device Tag, Tunnel Interface, Virtual IP, DNS Resolvers, Post-Quantum PSK, ZTNA ACL kötés; új interfész: Device Name, UDP Port, Subnet Pool.
- **Gombok:** *Provision Tunnel*, *Add Peer*, *Peer QR & .conf*, *Split / Full Tunnel*, *Generate QR*, *Download .conf*.

### WireGuard Add Peer & QR Provisioning Modal
`56e002a772734b5ca5ea67fd112b063d` · 🆕 **Új**
- **Funkció:** új WireGuard-kliens felvétele QR-kóddal.
- **Mezők:** Device Name, Operator Identity, Target Interface, Client Public/Private Key, Post-Quantum PSK, Tunnel IP, DNS Resolvers, Routing Mode (Split/Full), ZTNA-kötés.
- **Gombok:** *Regenerate Keypair*, *Copy Raw*, *Download .conf*, *Activate Peer & Commit*.

### Reverse Proxy & Let's Encrypt
`1703ef12ed404993b39a43164fc37f03` · 🆕 **Új**
- **Funkció:** reverse proxy TLS-terminálással és ACME-tanúsítványokkal.
- **Tábla:** Domain, Status, Ingress/Proto, Backend Upstream, TLS Certificate, WAF Profile, Bandwidth (24h), Actions.
- **Gombok és fülek:** *Deploy & Reload*, *Force ACME Renewal*, *Add Host Proxy*; *Proxy Hosts*, *ACME Certificates*, *Upstream Pools*, *Security Headers & mTLS*, *Live Access Logs*.

### Add Ingress Proxy Host Modal
`afda2bffe6494ac1909f1e25b38aa63f` · 🆕 **Új**
- **Funkció:** új proxy-host felvétele.
- **Mezők:** Domain Names, Scheme (HTTP/HTTPS/FastCGI/gRPC/TCP), Forward Host/IP, Forward Port, Path Prefix, WAF (OWASP CRS), Force HTTPS, HTTP/2 és HTTP/3, WebSocket, Strict mTLS.
- **Gombok:** fülek (*Routing*, *SSL/ACME*, *Security & WAF*, *Headers & Caching*), *Raw Caddy/HAProxy Preview*, *Test Upstream Reachability*, *Save & Hot-Reload*.

### mDNS Repeater & Multicast Router
`534f75c8f492469ba7f11b959d2e2e9b` · 🆕 **Új**
- **Funkció:** mDNS/Bonjour-továbbítás VLAN-ok között, IGMP-proxy.
- **Tábla:** Status/Rule, Source Zone, Target Zone, Service Signature/Port, Direction & Mode, 24h Telemetry, Actions.
- **Gombok és fülek:** *Restart Avahi*, *Flush Mappings*, *PCAP Capture*, *Add Repeating Rule*; *Discovered Services*, *IGMP Proxy & IPTV*, *Service Whitelist/Blacklist*, *Live Multicast Snooper*.
- **FR_OS-ben:** az mDNS-t csak az IoT-felderítés használja (olvasásra), továbbítás nincs.

### Add Repeating Rule Modal
`4e7535e55dfd4f848b7582814d6ba8c8` · 🆕 **Új**
- **Funkció:** új VLAN-ok közötti multicast-továbbítási szabály.
- **Mezők:** Rule Alias, Service Template (AirPlay, Google Cast, Sonos, Matter, AirPrint, egyéni), Direction & Reflection Mode, Source Zone, Target Zones.
- **Gombok:** lépések (*Service & Zones*, *Port & Filter*, *TTL & Security*, *Raw Avahi / nftables Preview*), *Dry-Run Discovery Test*, *Save & Reload*.

### Captive Portal & Guest Voucher Engine
`b8eff793556b434ca93cbbf544fcdfa1` · 🆕 **Új**
- **Funkció:** vendéghálózat captive portállal és voucherekkel.
- **Tábla:** Status & Expiration, Voucher Code, Client & MAC, VLAN & Interface, Data Transferred, Speed Profile, Actions.
- **Mezők (voucher-generátor):** Batch Label, Access Profile (TTL), Concurrent Devices, Quantity.
- **Gombok:** *Preview Splash Page*, *Flush Expired Sessions*, *Export Active Leases (.csv)*, *Generate Vouchers*, *Revoke Selected*, *Generate & Print Voucher Slips*.

### Guest Splash Portal Preview & Live Customizer Modal
`2ca58096e8b848459820e44870ddd541` · 🆕 **Új**
- **Funkció:** a vendég bejelentkező oldal szerkesztése élő előnézettel.
- **Mezők:** Voucher Serial, Organization Header, Welcome Banner, Accent Theme, Post-Auth Redirect; szekciók: *Authentication Policy*, *Walled Garden DNS Whitelist*, *Session & Bandwidth QoS*.
- **Gombok:** *Mobile 390px / Desktop 1024px*, hitelesítési mód (*Voucher / SMS / 30m Trial*), *Simulate Client Auth*, *Save & Deploy Portal*.

### Guest Voucher Batch Print & Export Template (Thermal & PDF)
`fe467da61059461e898cb82edc294030` · 🆕 **Új**
- **Funkció:** vouchercédulák nyomtatása hőnyomtatóra vagy PDF-be.
- **Mezők:** Output Target (Thermal 80/58 mm, A4/Letter, CSV/JSON), Roll Geometry, cédula tartalma (Wi-Fi QR, URL, QoS/lejárat, AUP), Auto-Cut, Print Range.
- **Gombok:** *Generate Batch*, *Printer Setup*, *Export PDF*, *Send to Thermal*, *Save Template*, *Print Test Slip*.

### Dynamic DNS (DDNS) Client & Multi-Provider Sync
`f018437319664402aa5d261bf0d107c0` · 🆕 **Új**
- **Funkció:** dinamikus DNS-kliens több szolgáltatóval.
- **Tábla:** Status, Hostname, Provider, Bound Uplink, Resolved vs Target IP, Last Verified, Actions.
- **Mezők:** Primary Address Source (a publikus IP felismerésének módja).
- **Gombok:** *Force Refresh All*, *API Tokens Vault*, *Add DDNS Profile*, *Save Engine Preferences*, *Download Full Audit*.

### Create & Provision Dynamic DNS Profile Modal
`f78af2e1aa5f48a3b73824ec4c6b9991` · 🆕 **Új**
- **Funkció:** új DDNS-profil.
- **Mezők:** Provider (DuckDNS, RFC 2136 TSIG…), Hostname, rekordtípus (A/AAAA), hitelesítő adatok, IP-forrás (Kernel Netlink / HTTP Reflector / STUN), interfész-kötés.
- **Gombok:** *Auto-Detect*, *Dry-Run Handshake*, *Save & Provision Profile*.

### DNS Static Override & Host Record Modal
`2be5f38e9c2447dcbaf6c27bd786c221` · 🆕 **Új**
- **Funkció:** helyi DNS-rekord felvétele vagy felülírása.
- **Mezők:** FQDN, rekordtípus (A/AAAA/CNAME/TXT/PTR), Zone Scope, Description, IPv4 és IPv6 cél, Auto PTR, mód (Local override / Conditional forward / Sinkhole), TTL.
- **Gombok:** *From DHCP*, *Next Free*, *ICMP Ping*, *Dry-Run (dig)*, *Commit Record & Reload*.

### Configure Encrypted DoH/DoT Upstream DNS Modal
`06e58bcf13cf4c5d80852a2ba0e0239b` · 🆕 **Új**
- **Funkció:** titkosított upstream DNS-feloldó beállítása.
- **Mezők:** protokoll (DoT/DoH/DoQ), Upstream IPv4/IPv6, TLS SNI, SPKI Pinning, Multi-Upstream mód (Fastest/Round-Robin/Priority).
- **Gombok:** *Dry-Run TLS Handshake*, *Commit Upstream & Reload*.
- **FR_OS-ben:** a DNS-szűrő (adblock) blokkolni tudja a DoT/DoH megkerülést, de titkosított upstream nincs; a DHCP-pool DNS-szerverei sima IPv4-címek.

### DNS Leak Test & Resolver Telemetry Diagnostics Modal
`4608c389ef0c492482a684e422de3568` · 🆕 **Új**
- **Funkció:** DNS-szivárgás és -eltérítés tesztelése.
- **Tesztek:** Port 53 hijacking, DNS rebinding, IPv6 dual-stack leak, böngésző DoH canary.
- **Tábla:** Responder Node/IP, Protocol & Port, Latency, ASN & Operator, Tunnel Status.
- **Gombok:** *Run Deep Multi-Probe*, *Export PCAP / JSON*, *Re-Run Full Test Suite*.

---

## 4. Hálózat – forgalomszabályozás (QoS)

### Traffic Control & Smart Queue Management (CAKE SQM)
`c39e616f3d364f70934d031006c8ff00` · 🆕 **Új**
- **Funkció:** CAKE-alapú sorkezelés a bufferbloat ellen.
- **Tábla:** Flow Source/Target, Priority Tier, Queue Depth, ECN Marks, Drops, Throughput.
- **Mezők:** Link Layer Overhead (Ethernet/DOCSIS/ATM/Raw IP), DiffServ Classification, Host Fairness Mode, interfészválasztó.
- **Gombok:** *Run Benchmark*, *Apply 95% Wire Calc*, *Reset Flow Counters*, *Simulate UDP Flooding*, *Save & Apply Qdisc*.

### FQ_CoDel Parameter Tuning & Kernel Configurator Modal
`4954338dd922420791ed323a31b790dd` · 🆕 **Új**
- **Funkció:** FQ_CoDel paraméterek hangolása.
- **Mezők:** Quick Tuning Presets, FQ_CoDel Active, ECN Enabled, flows-szám (512–4096), Root/Ingress/Egress ág; *Queue Oscilloscope & AQM State* grafikon.
- **Gombok:** *Raw tc Preview*, *Reset to RFC Defaults*, *Dry-Run Check*, *Copy tc CLI*, *Apply & Commit to Kernel*.

### Hierarchical Token Bucket (HTB) Tree Editor Modal
`4b113b5a59b949f1a3ff6ad910dbf561` · 🆕 **Új**
- **Funkció:** HTB-osztályfa szerkesztése.
- **Mezők:** Class ID, Parent Handle, Description, Priority, Quantum, Burst, Cburst, Leaf Qdisc, Classification Rules.
- **Gombok:** sablonok (*1G/100M Fiber*, *500M Work+Game*), *Tree Graph / Tabular Matrix*, *+ Child*, prioritás P0–P7, *Add Match*, *Dry-Run Test*, *Commit HTB Tree*.

### tc qdisc CLI & Raw Kernel Queue Inspector Modal
`ad7b71c06877498ba5169a438318289c` · 🆕 **Új**
- **Funkció:** a kernel qdisc-fájának nyers megtekintése és `tc` parancsok futtatása.
- **Mezők:** grep-szűrő, interfészválasztó, előre megírt parancsok (`tc -s qdisc/class/filter show`).
- **Gombok:** *Live Refresh*, *Export Dump*, *Set Bandwidth*, *Toggle ACK-Filter*, *DiffServ Tin Preset*, *Reset Counters*, *Execute tc Command*, *Copy as Bash Script*.

### Bufferbloat Saturation Benchmark Diagnostics Modal
`4f7f391435db4d18ac1c9f6181210f1f` · 🆕 **Új**
- **Funkció:** késleltetésmérés terhelés alatt (bufferbloat-teszt).
- **Tábla:** Phase, Time Window, Active Flow Stress, Avg Latency, Min/Max, Added Bloat Delta, Loss/ECN, Status.
- **Mezők:** Saturation Profile, Duration, Benchmark Node.
- **Gombok:** *Run Benchmark*, *Stop*, *Export RFC (.json)*, *Download .pcap*, *Commit CAKE Settings*.

---

## 5. Hálózat – diagnosztika

### Network Diagnostics & Path Analyzer
`684a655c0b6f464b9d714527a8364f43` · 🆕 **Új**
- **Funkció:** hálózati diagnosztikai eszköztár (ping, MTR, traceroute, TCP-probe, DNS, iPerf3).
- **Tábla:** #, Host/ASN, IP, Loss %, Sent/Recv, Last, Avg, Best, Worst, StDev, Latency Profile.
- **Mezők:** Target Host/IP, Outgoing Interface, Pings/Count, Interval.
- **Gombok:** eszközválasztó (*ICMP Ping*, *MTR*, *Visual Traceroute*, *TCP SYN Probe*, *DNS Lookup Bench*, *iPerf3*), célpont-sablonok, *Start Trace*, *Run Automated Health Audit*, *Export PCAP Trace*.

### MTR & Packet Loss / Jitter Telemetry Diagnostics Modal
`7ba99d04017541f8836f0b0776dec1bf` · 🆕 **Új**
- **Funkció:** hopról hopra csomagvesztés- és jitter-mérés.
- **Tábla:** Hop, Host & IP, BGP/ASN, Loss %, Snt/Rcv, Last, Avg, Best, Wrst, StDev, RTT Dispersion.
- **Mezők:** Egress Interface, Probe Payload, Packet Size, célpont.
- **Gombok:** *Restart Deep Trace*, *Copy MTR Report*, *Export CSV/JSON*, *Capture Extended PCAP*.

### iPerf3 & Bandwidth Speedtest Diagnostics Modal
`3190ef4181484a2199f591dd6f92c1c5` · 🆕 **Új**
- **Funkció:** sávszélesség-mérés iPerf3-mal (kliens és szerver módban).
- **Tábla:** ID, Interval, Transfer, Bandwidth, Retr, Cwnd.
- **Mezők:** Target Host, Parallel Streams, Direction, Interface/Time.
- **Gombok:** *Client Mode / Server Daemon*, célpont-sablonok, *Re-Run Benchmark*, *Export Report*.

### Live Packet Capture (PCAP & Wireshark Stream) Modal
`a8a0c8d9daf346d7ac018f2eab3fce6f` · 🆕 **Új**
- **Funkció:** élő csomagelkapás a routeren.
- **Tábla:** No., Time, Source, Destination, Proto, Length, Info.
- **Mezők:** Interface Tap, Direction, Packet Slice/Ring, BPF-szűrő (pl. `host 10.0.0.1 and port 80`).
- **Gombok:** szűrősablonok (DNS, TLS, VoIP, ICMP/ARP), *Stream Live (Wireshark Pipe)*, *Export .pcap*, *Download .pcapng*.

### IP Geo-Lookup & Packet Trajectory Simulator
`e921b78cf45a4994a3c6d5c2b30c1384` · 🆕 **Új**
- **Funkció:** egy IP földrajzi adatai, és mi történne egy tőle érkező csomaggal (melyik szabály találna).
- **Mezők:** Target IPv4/IPv6/CIDR, Protocol, Port, bejövő interfész (WAN/LAN/WG).
- **Gombok:** mintacímek (Tor exit, Cloudflare, stb.), *Run Simulation*, *Copy Diagnostic JSON*, *Add Exception / Override Rule*.

---

## 6. Védelem

### AI IDS/IPS
`36809da03a7d47f19e4761161aa6b950` · 🟡 **Részben**
- **Funkció:** behatolásérzékelés és -megelőzés: észlelések, szignatúrák, viselkedés-heurisztika.
- **Tábla:** Time, Severity & MITRE, Signature/SID, Source, Destination, Proto & L7 App, Action Taken, Quick Actions.
- **Gombok és fülek:** *Add Custom Detection Rule*, *Update Threat Feeds*, *Tune Heuristic Thresholds*; *Active Detections*, *Signature Rulesets*, *AI Behavioral Heuristics*, *Suppression & Whitelist*, *Live Raw Alert Console*; soronként *Perma-Drop*, *Isolate Dev*, *Suppress Signature*, *Download PCAP*.
- **FR_OS-ben:** a helyi, anomália-alapú AI IDS/IPS megvan (motorállapot, beállítások, karanténban lévő hosztok, friss események; 11. fázis). A Suricata-szignatúrák, a MITRE-besorolás, a PCAP-letöltés és a whitelist-kezelés újak.

### Applications & L7 DPI
`1b1e6bbc20674661be3a1fcd851b73c7` · 🟡 **Részben**
- **Funkció:** alkalmazásfelismerés és alkalmazásonkénti szabályozás.
- **Tábla:** Application & Engine, Category, Risk Index, Active Clients, Bandwidth (24h), Applied Policy, Status, Actions.
- **Mezők:** VLAN-onkénti hatókör.
- **Gombok és fülek:** *Update Signatures*, *QoS Pools*, *Create Application Rule*; *Traffic Shaping & QoS Queues*, *Custom Signatures & Regex*, *Live Flow Stream*, *Category Breakdown*; policy: *Block / Throttle / Monitor / Unlimited*.
- **FR_OS-ben:** az App-ID lite megvan (~45 alkalmazás, kliensenkénti 24 órás használat, blokkolás; 16. fázis). A kockázati index, a sávszélesség-korlátozás, az egyéni szignatúrák és a VLAN-onkénti policy újak.

### ZTNA Gate
`e97f9268e8084722bdf8927301b2cbcf` · 🟡 **Részben**
- **Funkció:** zero-trust hozzáférés: azonosított felhasználók és eszközök mikro-hozzáférése.
- **Tábla:** Identity & Role, Device & Telemetry, ZTNA WG IP, Remote Endpoint, Micro-Access Scope, Posture State, Handshake, Actions.
- **Gombok és fülek:** *Add ZTNA Policy / Tunnel*, *Sync IdP (Keycloak)*, *Revoke Ephemeral Certs*; *Active Remote Tunnels*, *Micro-Perimeters*, *Posture Policies*, *Live Access Log*; soronként *Revoke*, *+1h*, *Sever*, *Force Re-Authentication*.
- **FR_OS-ben:** a ZTNA megvan (bejelentkezési kapu, helyi fiókok, védett szabályok, nftables-halmaz időkorláttal; 7. fázis). A WireGuard-alapú tunnelek, az eszköz-posture és az IdP-szinkron újak.

### TLS Fingerprints & JA3/JA4 Inspector
`c95db0cad76c4fbd9521f8118e2604e1` · ✅ **Létezik**
- **Funkció:** TLS ClientHello ujjlenyomatozás (JA3/JA4) visszafejtés nélkül.
- **Tábla:** Time, Severity, Client Endpoint, JA4 Fingerprint, Inferred Client Profile, Target SNI, Action State.
- **Gombok és fülek:** *Add Custom Fingerprint Rule*, *Sync Malicious JA4 DB*, *Flush Cache*; *Live Fingerprint Stream*, *Fingerprint Catalog*, *Anomalous & Rogue Clients*, *JA4 Rule Editor*; soronként *Quarantine Client*, *Allowlist (1 Hour)*.
- **FR_OS-ben:** a TLS Fingerprints képernyő megvan (események, eszközök és ujjlenyomataik, új ujjlenyomatok jelzése, blocklist, karantén; 19. fázis). Új lenne a külső rosszindulatú-JA4-adatbázis szinkronja és az ideiglenes allowlist.

### Ad-Block & TLS SNI Filter
`9dd6f77cef0244799ae861fdf0119126` · ✅ **Létezik**
- **Funkció:** DNS-alapú reklám- és kategóriaszűrés, valamint kernelszintű TLS SNI-szűrés.
- **Tábla:** Feed Source, Engine, Assigned Enclaves, Rules, Last Sync, State, Action.
- **Mezők (új feed):** Rule Type, Feed/Regex URL, Target Engine, VLAN-hatókör.
- **Gombok és fülek:** *Add Blocklist / Regex*, *Flush DNS Cache*, *Force Sync All*; *Policy Matrix & Feeds*, *Live DNS & SNI Stream*, *Custom Whitelist / Blacklist*, *DoH / DoT Gateways*; *Bypass for 15 Minutes*, *Compile & Load into eBPF*.
- **FR_OS-ben:** az Ad-Block & DNS Filtering (alaplista, kategóriák, allowlist, LAN DNS, frissítés; 9. és 15. fázis) és az XDP TLS SNI Filter (4. fázis) megvan. A regex-szabályok, a VLAN-onkénti feedek és az élő lekérdezés-folyam újak.

### Threat Intel & DNS Sinkhole
`7073a83855dc48419cab58dd213efd66` · 🟡 **Részben**
- **Funkció:** fenyegetés-hírszerzési feedek és DNS-sinkhole.
- **Tábla:** Time, Sev, Attack Class & Signature, Proto/Port, Attacker Source, Target Host, Engine Action, Payload.
- **Gombok és fülek:** *Update Feeds*, *Whitelist IP/FQDN*, *Add Blocklist / DoH Feed*; *Suricata IDS/IPS Stream*, *DNS Sinkhole & Blocklists*, *Threat Hunting & GeoIP*, *Quarantine & Signatures*; *Auto-Ban /24 Subnet*, *Configure Upstreams*, *View Extended Query Log*.
- **FR_OS-ben:** a malware/phishing kategóriák DNS-blokkolása és a DNS-fenyegetésjelek az AI IDS felé megvannak (15. fázis). A Suricata-folyam, a threat-intel IP-feedek és a /24 auto-ban újak.

### IoT Devices & Isolation Sandbox
`2c1dced1f54446e4a128b39a07bc825e` · ✅ **Létezik**
- **Funkció:** IoT-eszközök felderítése és elkülönítése.
- **Tábla:** State, Device/Identity, MAC & OUI Vendor, IP/VLAN, Fingerprint & Engine, Isolation Tier, WAN/LAN Flow, Threat Score, Quick Pinhole.
- **Mezők:** Local-Only DNS Guard.
- **Gombok:** *Re-scan Fingerprints*, *Block All Cloud Telemetry*, *Register IoT Device*, eszköztípus-szűrők (kamerák, bridge-ek, konnektorok, szenzorok), soronként *Pinhole RTSP*, *Isolate Cam*, *Mute WAN*, *Apply Rules*.
- **FR_OS-ben:** az IoT Devices képernyő megvan (leltár, magyarázott IoT-döntés, szkennelés, MAC-alapú izoláció internet-only vagy teljes tiltás módban; 14. fázis). A pinhole-kivételek és a threat score újak.

### Geo-IP Country Filter & Perimeter Policy Modal
`0e6cca2baa9a4f3a95be82d6d640c26f` · 🆕 **Új**
- **Funkció:** országalapú forgalomszűrés.
- **Szekciók:** *Policy Action & Directional Enforcement*, *Quick Presets & High-Risk Threat Packs* (EU, Tor, szankciós listák…), *Interactive Country Matrix*, *Exceptions & CIDR Overrides*, *nftables / eBPF CLI Preview*.
- **Mezők:** országkereső (ISO 3166 / ASN), kivétel-CIDR-ek.
- **Gombok:** kontinens-szűrők, *Add Exemption*, *Copy Raw CLI*, *Dry-Run Simulation*, *Commit Geo-IP Policy*.

---

## 7. Rendszer – beállítások, fiókok, frissítés

### System Settings
`e8a5f10273884751af47c2f056648e90` · 🟡 **Részben**
- **Funkció:** rendszerszintű beállítások.
- **Szekciók:** *Node Identification & Domain*, *Time Synchronization (NTP / PTP)*, *Remote Logging & Telemetry Exporters*, *Upstream DNS & DoT/DoH*, *Hardware Cryptography & Offload*, *Dangerous Actions*.
- **Mezők:** Hostname, Domain, Description & Location, Timezone, WebUI Port, Syslog Remote Host, Node Exporter Bind, eBPF Flow Metric Bind, OpenTelemetry Endpoint.
- **Gombok:** *Discard Draft*, *Export .yaml*, *Test DNS & NTP*, *Save & Apply*, *Reboot Node*, *Maintenance Mode*, *Factory Reset*.
- **FR_OS-ben:** a System képernyő megvan (webUI TLS-tanúsítvány, SSH/PQC, beállítások, tárolás és perzisztencia, multi-site monitoring); a hostname és az időzóna a configban van. Az NTP, a syslog-továbbítás, az OpenTelemetry, a karbantartási mód és a gyári visszaállítás újak.

### Telemetry, SNMP & Prometheus Metrics Exporter
`1d9f56ab0265466ab3b97911675c5349` · 🟡 **Részben**
- **Funkció:** metrikák exportálása monitorozó rendszerek felé.
- **Szekciók:** *Prometheus Endpoint & TLS*, *SNMP v3 Engine & MIB Parameters*, *Live Metric Stream Inspector*.
- **Mezők:** Scrape URI, Bearer Token, exporter-modulok (CPU, hálózat, memória, XDP, IDS, QoS, WireGuard, NAT).
- **Gombok:** *Download MIB Files*, *Grafana JSON*, *Rotate Token*, *New Scrape Target*, *Add Poller User*, *Export Prometheus YAML*, *Apply Changes*.
- **FR_OS-ben:** a Prometheus `/metrics` (bearer token, verifikálható TLS, `fros_info`, Grafana-dashboardok, multi-site példa) megvan (12. és 20. fázis). Az SNMP, a modulonkénti ki/bekapcsolás és az élő metrika-nézet újak.

### Firmware & eBPF Bytecode Updates
`86520534d56b41a69bb32259db7e3e61` · 🟡 **Részben**
- **Funkció:** rendszerfrissítés, eBPF-programok és boot-partíciók kezelése.
- **Fülek:** *Firmware & Kernel Updates*, *Live eBPF Programs & Hot-Patches*, *A/B Dual-Boot Partitions & Snapshots*, *Cryptographic Supply Chain & Signatures*, *Update History & Audit Trail*.
- **Gombok:** *Check for Updates Now*, *Upload Offline Package*, *Rollback to Slot B*, *Dry-Run*, *View Raw Git Diff*, *Commit Image & Schedule Reboot*, *Apply Hot-Reload*, *Create ZFS Snapshot*, *Clone Slot A to Emergency USB*.
- **FR_OS-ben:** az Update képernyő megvan (verzió, frissítés, egyszintű rollback, utolsó kísérlet; 6. fázis). Az A/B partíciók, az offline csomag, az aláírás-ellenőrzés és az eBPF hot-patch újak.

### User Management & Access Control
`f4075e1b34e7468c9ad4fb08f285c43c` · 🟡 **Részben**
- **Funkció:** webUI-fiókok, szerepkörök, hitelesítési módok és auditnapló.
- **Tábla:** User & Identity, Assigned Role, Authentication Methods, Session State, Last Login, Actions.
- **Gombok és fülek:** *Invite / Add User*, *Configure SSO / OIDC*, *Rotate Root Secrets*; *Local Users & RBAC*, *Hardware Keys & WebAuthn*, *API Keys & Service Tokens*, *Single Sign-On*, *Live Auth Audit Log*; *Terminate All Remote Sessions*, *Suspend Account*.
- **FR_OS-ben:** a Users képernyő megvan (fiókok `admin` / `viewer` szerepkörrel, felvétel, auditnapló az utolsó 200 eseménnyel; 18. fázis). A hardverkulcsok, az API-tokenek, az SSO és a jelszóöregítés újak.

### Add New User & RBAC Provisioning Modal
`8f99ad5179d8411492d527f75b247dda` · 🟡 **Részben**
- **Funkció:** új felhasználó felvétele részletes jogosultságokkal.
- **Mezők:** POSIX Username, Full Name, Email, UID Range, Initial Auth Method (WebAuthn meghívó / egyszeri jelszó / OIDC), SSH Public Key, finom jogosultságok (tűzfal-commit, WireGuard, DHCP, conntrack, eBPF, kulcsrotáció), MFA Policy, Inactivity Timeout.
- **Gombok:** *Paste / Load .pub*, *Generate Invitation Link & Provision User*.
- **FR_OS-ben:** a felhasználófelvétel (név, jelszó, szerepkör) megvan. A finom jogosultságok, az SSH-kulcs, a meghívó-link és az MFA újak.

### Login & FIDO2 WebAuthn Authentication Gate
`5aaf570f6a194c658574d1fa5202d9ab` · 🟡 **Részben**
- **Funkció:** bejelentkezés a webUI-ba.
- **Mezők:** Username, Master Password, TOTP-kód; FIDO2-kulcs érintése.
- **Gombok:** *FIDO2 Passkey* / *Password + 2FA*, *Verify & Launch Control Plane*; linkek: read-only belépés, tartalékkulcs, Rescue Shell, BIP-39 vészkulcs, OOBE újrafuttatása.
- **FR_OS-ben:** a jelszavas belépés megvan (első indításkor admin-fiók beállítással, brute-force védelemmel). A FIDO2/WebAuthn és a TOTP újak.

### Out-of-Box First-Run Setup Wizard
`dfaabe8046d345bb9888df85a02df094` · 🆕 **Új**
- **Funkció:** első indítási varázsló, WAN-lépés.
- **Szekciók:** *Physical Port Map*, *Primary WAN Uplink Configuration*.
- **Mezők:** Interface Reassignment, WAN Protocol (DHCP / PPPoE / Static), Gateway Hostname, MAC Override, ISP VLAN-tagging (VLAN ID, PCP), MTU, Upstream DNS Policy.
- **Gombok:** *Blink LED*, *Probe ISP Gateway Again*, *Save Draft & Exit to Rescue Shell*, *Validate & Continue*.
- **FR_OS-ben:** az első indítás varázsló nélkül, automatikusan állítja be a routert (első NIC = WAN DHCP, második = LAN 192.168.1.1/24, véletlen admin-jelszó). A varázsló és a PPPoE újak.

### First-Run Setup Wizard – Step 4: Root Security & FIDO2
`07646580372a46d5948db2fb86d8dcdb` · 🆕 **Új**
- **Funkció:** a varázsló 4. lépése: admin-fiók, SSH és hardverkulcs.
- **Mezők:** Operator Username, Master Password + megerősítés, OpenSSH ki/be, Management Port, Root Password Login, SSH Auth Policy, Authorized Hardware Public Key.
- **Gombok:** *Touch Security Key to Enroll*, *Add Key*, *Export Sealed Keys*, *Validate Security & Proceed*.

### First-Run Setup Wizard – Step 5: Policy Baseline & IPS
`8455c8882beb4e9790522a47a96422aa` · 🆕 **Új**
- **Funkció:** a varázsló 5. lépése: biztonsági alapprofil kiválasztása.
- **Elemek:** baseline-kártyák (*Strict Zero-Trust*, *Balanced Practitioner*, *Permissive Edge*), IPS-mód (*Alert Only* / *Inline Drop*), automatikus IoT-karantén.
- **Gombok:** *Dry-Run Simulation*, *Commit Baseline & Launch Control Plane*.

---

## 8. Rendszer – üzemeltetés (mentés, riasztás, napló, HA)

### Configuration Backup & Git Rollback
`f0f5d78d06f1476086490805b05fe879` · 🆕 **Új**
- **Funkció:** konfiguráció-pillanatképek git-történettel, diff és visszaállítás.
- **Elemek:** commit-idővonal, diff-nézet (*Unified / Split View*), szűrők (*Manual / Firewall / Pre-flight / WireGuard*).
- **Gombok:** *Export Full Tarball*, *Import / Restore*, *Dry-Run Staging Test*, *Create Manual Snapshot*, *Rollback*, *Revert to…*, *Sync Now*, *Configure Sentinel Timeout*.
- **FR_OS-ben:** apply előtt az nftables-szabálykészlet időbélyeges mentésbe kerül, és a CLI vissza tudja tölteni a legutóbbit (`rollback`). A teljes konfiguráció git-történetét és a mentés-képernyőt ez a terv vezetné be.

### Create Manual Snapshot Modal
`74a297773070403aab58c4cb4575c0a0` · 🆕 **Új**
- **Funkció:** kézi konfiguráció-pillanatkép készítése.
- **Mezők:** Commit Message, Tag, mentett részek (tűzfal és NAT, routing, DNS és DHCP, sysctl), cél (helyi git-repó / titkosított S3).
- **Gombok:** *Dry-Run Diff*, *Commit & Push Snapshot*.

### Alert Rules & Incident Dispatcher
`dcdfece660144317be7c9dc67f79089f` · 🆕 **Új**
- **Funkció:** riasztási szabályok és értesítési csatornák.
- **Tábla:** State, Severity, Rule & Target, Trigger Condition, Mitigation & Automated Action, Channels, Last Fired, Actions.
- **Gombok:** *Mute All (30m)*, *Test All Channels*, *Create Alert Rule*, *Add New Dispatch Channel*, csatornatesztek (ping, email, syslog), súlyosság-szűrők, *Export JSON*.

### Create Alert Rule Modal
`bb0b6760c52e4f71a81ce3721843744e` · 🆕 **Új**
- **Funkció:** új riasztási szabály.
- **Mezők:** Rule Identifier, Subsystem, Severity (P0–P3), Metric Source, Operator, Threshold, Sustained For, Automated Defense, Kernel Action, Rollback; csatornák (Telegram, Slack, Discord, PagerDuty, SMTP, Wazuh/syslog).
- **Gombok:** *Visual Builder / PromQL*, *Simulate Evaluation*, *Compile & Deploy Rule*.

### Syslog & Remote SIEM Forwarder
`735922cf237c432f94b84c4cf8cd0f87` · 🆕 **Új**
- **Funkció:** naplók továbbítása távoli syslog/SIEM-rendszerekbe.
- **Tábla:** Status, Pipeline Target, Protocol & Destination, Schema, Subsystems, Egress Rate/Drop, Actions.
- **Mezők:** alrendszer-szűrők (XDP, IDS, NAT, WireGuard/ZTNA, kernel, RBAC), IP-anonimizálás (GDPR), payload-eltávolítás, MAC-hash, minimális súlyosság (0–7).
- **Gombok:** *Buffer Flush*, *Test All Pipelines*, *Add Target Forwarder*, *Renew Cert*, *Export CSR*.

### Syslog & Remote SIEM Forwarder (5 Active Pipelines)
`1dac1b641ff7485386b76f55ec5a0038` · 🆕 **Új**
- **Funkció:** az előző képernyő változata öt aktív pipeline-nal, alrendszer-súlyokkal és pufferállapottal.
- **Tábla:** Target Name, Protocol & Destination, Schema Format, Egress Rate, Latency/Drops, Transport Security, Status, Actions.
- **Mezők:** PII Obfuscation (/24 maszk), RFC 1918 zaj eldobása.
- **Gombok:** *View Tail*, *Add Target Forwarder*, *Test All Pipelines*, *Edit Global Routing AST*, *Spool Monitor*.

### Add Target Forwarder Modal
`d776735a6c7e4b889aaa9cf146f07b16` · 🆕 **Új**
- **Funkció:** új napló-továbbító felvétele.
- **Mezők:** Pipeline Name, Protocol, Destination URL/Host, Port, Framing Schema, Compression, Auth Mechanism, kliens-tanúsítvány és -kulcs, CA Trust Anchor, SNI Override, HEC/API Token, alrendszer-szűrők, Minimum Severity, Max Queue Size, Retry Backoff.
- **Gombok:** *Test Endpoint & TLS Handshake*, *Save & Activate Forwarder*.

### Add Target Forwarder Modal (Test Handshake Verified)
`f778eb680f604924a710d78f129b974e` · 🆕 **Új**
- **Funkció:** az előző modál sikeres kapcsolatteszt utáni állapota (TLS-handshake nyomkövetés).
- **Gombok:** *Copy Raw Trace*, *Re-run Diagnostic Probe*, *Download PCAP Trace*, *Back to Configuration*, *Save & Activate Forwarder*.

### Live System Log & XDP Kernel Console
`3bedf762153b4c1487b06fa8fe5c9116` · 🆕 **Új**
- **Funkció:** élő, összevont rendszernapló-konzol.
- **Mezők:** grep-szűrő.
- **Gombok és fülek:** forrás-fülek (*XDP / eBPF*, *Firewall Log*, *IDS Alerts*, *Kernel & dmesg*, *DNS Resolver*, *WireGuard / Auth*), szintszűrők (DROP/CRIT, WARN, PASS/INFO), *Pause*, *Export .log*, *Add Permanent eBPF Drop Rule*, *Geo-IP Trace*.

### Command Palette (Cmd+K) & Quick Action Engine
`d98dff5bac1c4792b3b16a35bd234ff1` · 🆕 **Új**
- **Funkció:** billentyűzetről hívható parancspaletta: navigáció, műveletek, entitás-keresés.
- **Mezők:** parancs- és keresőmező.
- **Gombok:** módok (*All / Actions > / Navigation / / Entities #*), gyorsműveletek (*Inspect*, *Isolate*, *Edit Policy*).

### Command Palette Entity Deep Search (IP & MAC Inspector)
`2e0e941b4cfd4bfc8d7c993528591ba4` · 🆕 **Új**
- **Funkció:** a parancspaletta entitás-keresése: egy IP- vagy MAC-cím összes adata egy helyen.
- **Gombok:** *FIB Flows*, *DHCP Inventory*, *Packet Sniffer*, *Quarantine Host to Sandbox VLAN*, *Copy JSON Payload*.

### Emergency Rescue Shell & Fail-Safe Console
`cd01e7c741954fa5a132a5450c469bb0` · 🆕 **Új**
- **Funkció:** vészhelyzeti konzol böngészőből: parancsfuttatás, helyreállítási runbookok.
- **Szekciók:** *BIP-39 Root Key Attestation*, *Disaster Recovery Runbooks*, *Physical Bus & Transceiver Telemetry*.
- **Mezők:** parancssor (pl. `systemctl reset-failed`, `nft flush ruleset`).
- **Gombok:** *Core Dump*, *Reboot Hardened Kernel*, *Verify Root Signatures*, *Execute Rollback*, *Reset to Baseline*, *Raw Serial*, *Execute*.

### Post-Recovery Reboot & Invariant Re-Attestation
`ed93acf980154eba87bab0665b244693` · 🆕 **Új**
- **Funkció:** helyreállítás utáni újraindítás és a rendszerinvariánsok újraellenőrzése.
- **Tábla:** Subsystem, Panic State, Recovered State.
- **Gombok:** *Pause Boot*, *Launch Now*, *Enter Control Plane*, *Download Cryptographic Recovery Bundle*.

### Incident Post-Mortem & Disaster Closeout Document
`ad1923b977fa4b20ae5137d5fba6efe2` · 🆕 **Új**
- **Funkció:** incidens-utólagos jelentés (post-mortem).
- **Szekciók:** idővonal, gyökérok-elemzés (RCA), mitigációk, invariáns-ellenőrzőlista.
- **Tábla:** Offset, Stage, Subsystem, Event & Diagnostic Log, Verification.
- **Gombok:** *Export Attested PDF*, *Cryptographic Sig*, *Print Ledger Receipt*, *Archive to WORM Ledger*.

### Multi-Node Cluster & HA Failover Manager
`c67945311d94475092dbf7c5f34723d3` · 🆕 **Új**
- **Funkció:** több routerből álló magas rendelkezésre állású (HA) fürt.
- **Tábla:** Virtual IP, Interface, VHID, Priority, Master Host, State.
- **Gombok:** *Join New Node*, *Initiate Graceful Switchover*, *Trigger Cluster Sync*, *Force Standby*, *Promote to Master*, *Add Virtual IP*, *Simulate WAN Loss*, *Test Split-Brain Fencing*, *HA Audit Report*.
- **FR_OS-ben:** a 20. fázis több router csak olvasó monitorozását adja Prometheus/Grafana alatt; fürtözés és failover nincs.

---

## 9. Rendszer – ideiglenes jogosultság-emelés

Egy összefüggő folyamat: a viewer időkorlátos írási jogot kér, használja,
meghosszabbítja vagy visszaadja, a végén aláírt audit-jelentés készül.
Egyik lépése sincs meg az FR_OS-ben (a szerepkör ott állandó: `admin` vagy
`viewer`).

### Request Elevated Privileges Modal
`04350c00e500403db14c404c92c765b1` · 🆕 **Új**
- **Funkció:** időkorlátos írási jog kérése.
- **Mezők:** Incident/Ticket Reference, Target Subsystem, Justification, eBPF audit-trace rögzítése, értesítés az audit-csatornára; időtartam (30 perc – 4 óra, egyéni); jóváhagyás (*Admin Dispatcher / FIDO2 / TOTP*).
- **Gombok:** *Cancel & Keep Read-Only*, *Authenticate & Assert Privilege*.

### Active Operator View with Ephemeral TTL Countdown Banner
`2d277684fc73426f9ac2ac6556451b25` · 🆕 **Új**
- **Funkció:** emelt jogú munkanézet visszaszámláló sávval.
- **Szekciók:** *Target Subsystem Controls*, *Active Write-Enabled Rules*.
- **Mezők:** Subnet Filter & Injection Scope (cél-CIDR).
- **Gombok:** *Extend Window*, *Revoke Elevation*, *Purge Stale UDP States*, *Flush BGP Route Cache*, *Simulate Drop*, *Bypass*.

### Extend Privilege Lease Window Modal
`b160b8a7a51a4293a3cb1386c0d29d52` · 🆕 **Új**
- **Funkció:** az emelt jog meghosszabbítása.
- **Mezők:** Operational Justification (naplózott); időtartam (+15 perc – +2 óra); újrahitelesítés (FIDO2 / TOTP).
- **Gombok:** *Cancel & Maintain Current Expiry*, *Re-Authenticate & Extend*.

### Active Operator View Post-Extension (+30m Granted)
`e7197e95fe68401b8241d97557c7e9ca` · 🆕 **Új**
- **Funkció:** a munkanézet sikeres meghosszabbítás után.
- **Tábla:** Rule #, Direction, Action/State, TTL Remaining, Mutate.
- **Gombok:** *Extend Window*, *Revoke Elevation*, *Purge UDP States*, *Flush BGP Cache*, *Export*.

### Privilege Lease Expired (TTL Expired)
`1ab067c1757e4404b02f7852a8a275de` · 🆕 **Új**
- **Funkció:** lejárt emelt jog; új kérés indítható.
- **Mezők:** Incident Reference, Requested Duration, MFA Authorizer, Elevation Scope Reason.
- **Gombok:** *Submit Request*, *Request New Elevation Window*, *Download Signed Audit Bundle*.

### Revoke Elevated Privileges Modal
`9ddb7b6999804d5fa58057c968dd134f` · 🆕 **Új**
- **Funkció:** az emelt jog önkéntes visszaadása.
- **Mezők:** aláírt compliance-csomag automatikus letöltése, incidens-riasztás küldése.
- **Gombok:** *Cancel & Continue Lease*, *Revoke Privileges & Seal Audit*.

### Cryptographic Audit Receipt & Compliance Report
`d0a30d30ad2c45ebace9b5488776925e` · 🆕 **Új**
- **Funkció:** a jogosultság-emelés alatti változtatások aláírt összesítője.
- **Tábla:** Op/Subsystem, Mutation Payload, Pre → Post State, Status.
- **Gombok és fülek:** *Overview & Digest*, *State Mutations Diff*, *eBPF Syscall Trace*, *PCAP Ring Buffer*, *Operator Notes & Sign-off*; *Download Signed Bundle*, *Verify Signature*, *Print Certificate (PDF)*.

### PDF Compliance Certificate & Attestation Export
`fc497b2008b04402b58a873a68bc2141` · 🆕 **Új**
- **Funkció:** a jogosultság-életciklus PDF-tanúsítványa, 1. oldal.
- **Tábla:** Verification Step, Target Boundary, Observed Delta, Audit Result.
- **Gombok:** *Fit Width / Fit Page*, *Print*, *Raw JSON Receipt*.

### PDF Compliance Certificate & Attestation Export (Sheet 2)
`5ab102c8f47d4b1fb84eec3a82586467` · 🆕 **Új**
- **Funkció:** a PDF-tanúsítvány 2. oldala: kernel-syscall nyomkövetés és hash-különbségek.
- **Tábla:** UTC Timestamp, Kernel Primitive, Parameters & Scope, Ret, Attestation Key.
- **Gombok:** *Raw Hex Export*, *Download Signed PDF*, *Verify Enclave Token*.

---

## 10. Rendszer – hardveres kulcstár (HSM) és katasztrófa-helyreállítás

Egy nagy, összefüggő tervcsalád: TPM/HSM/YubiHSM kulcstár, kulcsgenerálás,
-rotáció és -megsemmisítés, benchmark-tanúsítványok, Shamir-féle M-of-N
kulcsmegosztás és -visszaállítás. Egyik része sincs meg az FR_OS-ben. (A
meglévő kriptográfiai rész a hibrid post-kvantum kulcscsere a webUI TLS-ben és
az SSH-ban, 8. fázis, ami ettől független.)

### Hardware HSM & Cryptographic Keystore
`668eaa967c3d4b34b08e7273575727e9` · 🆕 **Új**
- **Funkció:** a kulcstár fő oldala: kriptomodulok, kulcsleltár, PCR-regiszterek.
- **Szekciók:** *Detected Cryptographic Modules & Token Slots* (TPM 2.0, YubiHSM 2, Intel QAT), *Key Inventory & Lifecycle*, *Platform Configuration Registers*.
- **Tábla:** Key Identifier & Usage, Hardware Slot, Algorithm, Public Fingerprint, Lifecycle/Rotation, State, Operations.
- **Gombok:** *Enroll Security Token*, *Rotate Ephemeral Root*, *Generate Asymmetric Keypair*, *Rescan PKCS#11 Bus*, *View PCR Bank*, *Manage Operator PIN*, *Export Public Keys*, *Benchmark Offload*; soronként *Sign Test*, *Rotate*, *Rekey*, *Reseal*, *Backup*.

### Hardware HSM & Cryptographic Keystore (Post-Enrollment)
`6f230c98b6744bce89a6793b053a53f7` · 🆕 **Új**
- **Funkció:** a kulcstár új token (YubiHSM 2 Edge) felvétele után, audit-folyammal.
- **Tábla:** Key Alias, Hardware Enclave, Algorithm, Fingerprint, Lifecycle/Expiry, State, Operations.
- **Gombok:** *Audit Attestation Key*, *Enroll Security Token*, *Audit PCRs*, *View Quorum*, *Trigger Attestation Quote*.

### Hardware HSM & Cryptographic Keystore (Key Generated)
`52c964623a9448c485110304c25428aa` · 🆕 **Új**
- **Funkció:** a kulcstár új kulcspár generálása után.
- **Tábla:** mint fent (Key Identifier, Enclave, Algorithm, Fingerprint, Lifecycle, State, Operations).
- **Gombok:** *Attestation Receipt*, *Run Sign Test (ECDSA)*, *Enroll Token*, *Rotate Ephemeral Root*, *Generate Asymmetric Keypair*, *Audit Quorum*.

### Hardware HSM & Keystore (Ephemeral Root Rotation Active)
`e89bed2fc5f94a8ea30d4210a0cf8e1d` · 🆕 **Új**
- **Funkció:** a kulcstár futó root-kulcs-rotáció közben, mesh-propagációs állapottal.
- **Tábla:** Key Alias & Algorithm, Lifecycle State, Hardware Slot, Authorized Usage, Actions.
- **Gombok:** *Audit Receipt*, *Rollback v1*, *Force Zeroize*, *Refresh Ring*, *CAVP Pass*.

### Hardware HSM & Keystore (Post-Zeroization State)
`1f9e8f6ab15148318581cbe8938450fd` · 🆕 **Új**
- **Funkció:** a kulcstár egy kulcs megsemmisítése (zeroization) után.
- **Szekciók:** *Zeroization Completed & Committed*, *Physical HSM & Slot Inventory*, *Mesh Convergence Matrix*.
- **Gombok:** *View Receipt*, *Export Attestation Proof*, *Certificate Chain*, *Provision New Ephemeral Key*.

### Hardware HSM & Keystore (Post-Recovery Restored State)
`98f89d5f7af04da4891d3a804658899d` · 🆕 **Új**
- **Funkció:** a kulcstár katasztrófa-helyreállítás után.
- **Szekciók:** *Cryptographic Keystore Ledger*, *Hardware Attestation Record*.
- **Gombok:** *View Recovery Attestation*, *Rescan Enclaves*, *Export Shards*, *Sign Test*, *Rotate Standby*, *Download Cryptographic Proof (.sig)*.

### Enroll Security Token & HSM Device Modal
`3ec17182701b49a88117024aa8d20820` · 🆕 **Új**
- **Funkció:** hardveres token vagy HSM felvétele.
- **Mezők:** Token Alias, Security Domain, Slot Mapping, engedélyezett algoritmusok (RSA-4096, ECDSA P-384, Ed25519; RSA-2048 tiltva), Admin SO PIN, Operator PIN.
- **Gombok:** *Re-scan Bus*, *Cancel & Release Slot*, *Confirm Enrollment & Seal Token*.

### Generate Asymmetric Keypair Modal
`eb5c6353e3c4442891ca3736622fd7c1` · 🆕 **Új**
- **Funkció:** kulcspár generálása és kötése egy hardveres enklávéhoz.
- **Mezők:** Key Alias, kulcscsere-mód (ECDH / KEM), QAT offload.
- **Gombok:** *Generate Keypair & Seal into Enclave*.

### Hardware HSM Sign Test & Cryptographic Benchmark Modal
`39bfd201622c43febbe2d48cd2b7ab56` · 🆕 **Új**
- **Funkció:** ECDSA P-384 aláírásteszt és teljesítménymérés a HSM-en.
- **Gombok:** *Copy Hex*, *Download CAVP Vector*, *Export Signed Receipt*, *Rerun 60s Stress Test*.

### Hardware HSM Extended 60s Stress Test Modal
`65fddbef9f134975b1100355fd9751ea` · 🆕 **Új**
- **Funkció:** 60 másodperces HSM-terhelésteszt eredménye (kriptoslotok állapota, áteresztés).
- **Gombok:** *Download CAVP JSON*, *Export Signed PDF*, *Close & Retain Results*.

### Signed PDF Stress Test Certificate & Benchmark Attestation
`74c0408bdb264912acdd1dc786a29339` · 🆕 **Új**
- **Funkció:** a terhelésteszt aláírt PDF-tanúsítványa, 1. oldal.
- **Szekciók:** összefoglaló, hardverprofil, PCR-idézet, aláírás, átviteli grafikon, késleltetés-percentilisek, CAVP-ellenőrzések.
- **Tábla:** Percentile, Response Time, Ring Queue Delay, Hardware Exec, FIPS Threshold, Status.
- **Gombok:** *Print*, *Raw Signature*, *Download PDF*, lapozó.

### Signed PDF Stress Test Certificate (Sheet 2: CAVP Trace & Raw Nonces)
`ebb3ab169f5e4399b49b5515f5be4913` · 🆕 **Új**
- **Funkció:** a tanúsítvány 2. oldala: CAVP-nyomkövetés, nyers nonce-ok, ellenőrző eszközök.
- **Szekciók:** *Attestation Verifier*, *Vector Verification Tooling*, *Worker Core Load Balance*.
- **Gombok:** *Print*, *Raw Signature*, *Download PDF*.

### Ephemeral Root Key Rotation Modal
`3de9cc5dea15424d8ffc756fb7119d71` · 🆕 **Új**
- **Funkció:** a root-kulcspár rotációjának indítása.
- **Mezők:** Rotation Trigger, Grace Period (ajánlott 48 óra), újra-aláírási hatókörök (ZTNA, eBPF, WireGuard mesh).
- **Gombok:** *Abort & Retain Current Root*, *Simulate Mesh Re-Key (Dry-Run)*, *Authorize & Commit Key Rotation*.

### Ephemeral Root Key Rotation (Dry-Run Simulation Results)
`9a73f778eea94f45b3634ef184dce0a2` · 🆕 **Új**
- **Funkció:** a rotáció szimulációjának eredménye node-onként.
- **Szekciók:** *Mesh Re-Keying & WireGuard Handoff*, *Node-by-Node Mesh Verification Matrix*.
- **Gombok:** *Re-run Simulation with Heavy Traffic*, *Back to Rotation Settings*, *Proceed & Commit Live Key Rotation*.

### Ephemeral Root Key Rotation Audit Receipt & Attestation
`1e631212810e4744bba0fffb6e63113c` · 🆕 **Új**
- **Funkció:** a lezárt rotáció aláírt audit-nyugtája (hash-lánc).
- **Gombok:** *Audit JSON*, *Raw Sig*, *PDF Attestation*, *Keystore*, *Copy Root*.

### Force Zeroize v1 (Cryptographic Key Destruct Modal)
`3817bf853f3a4ee6af496702588ed601` · 🆕 **Új**
- **Funkció:** egy kulcs azonnali, visszafordíthatatlan megsemmisítése.
- **Mezők:** a kulcs aliasának begépelése megerősítésként.
- **Gombok:** *Cancel & Keep Grace Window*, *Confirm & Zeroize Slot Immediately*.

### Zeroization Audit Attestation (REC-ZERO-0314-001)
`d72a7eeee3c94bca952b148f8e9b90e9` · 🆕 **Új**
- **Funkció:** a megsemmisítés auditnyugtája.
- **Szekciók:** bit-törlés, Merkle-bizonyíték, hardveres pecsétek, klaszter-szinkron, CLI-ellenőrzés.
- **Tábla:** Pass #, Bit Pattern, Cell Verification, Latency.
- **Gombok:** *Audit JSON*, *Raw Nonce Dump*, *Download Signed PDF*, *Verify PCR*, *Export Compliance Bundle*.

### Disaster Recovery Key Export (M-of-N Shamir Sharding Modal)
`51ddef044462435589c4095f9a4ad743` · 🆕 **Új**
- **Funkció:** vészhelyreállító kulcs szétosztása M-of-N Shamir-részekre.
- **Szekciók:** küszöb-beállítás, letéteményes-lista (N = 5), csomagolás és KEM, kötelező jelmondat, fizikai kvórum-ellenőrzés.
- **Gombok:** letéteményesek száma (3 / 5 / 7), *Cancel Export*, *Execute Shamir Split & Export Shards*.

### Disaster Recovery Shard Handover Manifest & Escrow Receipts
`b4f8470df1884663a7a8446b9ff96ea0` · 🆕 **Új**
- **Funkció:** a kulcsrészek átadásának nyilvántartása.
- **Tábla:** Shard #, Custodian, Escrow Medium, CRC-32 & SHA, Delivery & Integrity Seal, Custodian Actions.
- **Gombok:** *Download All*, *Print 5 Air-Gapped Keycards*, *Verify Token*, *Print Custodian Handover Sheets*, *Verify Escrow Quorum Offline*, *Close & Lock*.

### Disaster Recovery Key Recovery (M-of-N Reassembly Wizard)
`90393f9c2cc04666a35a1803040b9a32` · 🆕 **Új**
- **Funkció:** a kulcs visszaállítása a részekből.
- **Mezők:** 33 szavas SLIP-0039 mnemonic; bemeneti mód (*Hardware Token / Air-Gap QR / Mnemonic Seed / PGP Blob*).
- **Gombok:** *Tap Hardware Token*, *Abort Recovery*, *Simulate Lagrange Math*.

### Disaster Recovery Key Recovery (Quorum Complete & Key Reconstructed)
`7e9e3a26982d4621b72347eb7b08f3e6` · 🆕 **Új**
- **Funkció:** sikeres visszaállítás visszaigazolása.
- **Gombok:** *Download Audit Receipt*, *View Attestation Cert*, *Finalize & Return to Keystore*.

### Recovery Audit Attestation (REC-RESTORE-0314-002)
`606c6822f22e4545826b8669e909e35c` · 🆕 **Új**
- **Funkció:** a helyreállítás aláírt auditjelentése.
- **Tábla:** Index, Custodian, Hardware Authenticator, Vector Checksum, Timestamp, Enclave Signature Status, Commit State.
- **Gombok:** *Download Signed JSON*, *Export Signed PDF*, *Verify Seal with OpenSSL*, *Export Full Attestation Bundle*.

### Platform Integrity, TPM 2.0 & Secure Boot Attestation
`b0ab191841c54e2daa6890a41c38852a` · 🆕 **Új**
- **Funkció:** a boot-lánc integritásának ellenőrzése (TPM PCR-ek, Secure Boot).
- **Tábla:** Index, Measurement Scope, Current Hash, Golden Baseline, Status.
- **Gombok és fülek:** *Verify Platform PCRs*, *Export Quote & Sig*, *Re-seal Enclave Secrets*; *PCR Registers*, *Boot Event Log*, *Firmware Manifest*, *Kernel Lockdown*.
- **FR_OS-ben:** az ISO UEFI-n is bootol (13. fázis), de TPM-mérés és Secure Boot attesztáció nincs.

---

## 11. Rendszer – címtár, RADIUS, 802.1X, PKI

Központi azonosítás (AD/LDAP), beépített FreeRADIUS, 802.1X hálózati
hozzáférés és saját tanúsítványkiadó. Egyik része sincs meg az FR_OS-ben (a
webUI- és a ZTNA-fiókok helyiek).

### Centralized Directory & RADIUS Authentication Gate
`c0bda2944ffa4b17906009a97eecd63a` · 🆕 **Új**
- **Funkció:** címtár- és RADIUS-kiszolgálók, NAS-kliensek, csoport→VLAN szabályok.
- **Táblák:** NAS-kliensek (Name, IP/Subnet, Shared Secret, Capabilities, Req/min, Status); *Group-to-VLAN & RBAC Policy Matrix* (Directory Group, FR_OS Role, 802.1X VLAN, Bandwidth Profile, Session Lease, Actions).
- **Gombok:** *Test Connection*, *Flush Auth Cache*, *Sync Schema Now*, *Add Authentication Server*, *Test Bind*, *Force Sync*, *Add NAS Client*, *Add Group Rule*.

### Centralized Directory & RADIUS Authentication Gate (Updated NAS Matrix)
`7f7e314749864eaa973dabf1926311cc` · 🆕 **Új**
- **Funkció:** az előző képernyő bővített NAS-mátrixszal.
- **Tábla:** NAS Authenticator, Node Type/Protocol, IP/Subnet, Shared Secret, RFC 3576 CoA, RADIUS Dictionary, Engine Status, Quick Actions.
- **Gombok:** *Issue 802.1X Cert*, *Test AAA Auth*, *Sync Directories*, *Add Server*, *Add NAS Client*, *CoA Ping*, *Test Policy Simulator*, *Download clients.conf*.

### Add & Configure NAS Client Modal (RADIUS Clients Matrix)
`43a20099c56c4203aa01edfa2090bc0d` · 🆕 **Új**
- **Funkció:** új RADIUS NAS-kliens (switch, AP, VPN) felvétele.
- **Mezők:** Friendly Name, Short Identifier, Device Archetype, NAS IP/CIDR, Ingress Interface, Shared Secret, Auth Policy Profile, Auth/Acct/CoA UDP Port, CoA Secret, Vendor Dictionary, Fallback VLAN.
- **Gombok:** *Generate Strong Secret*, *Send Test Access-Request*, *Dry-Run Config Check*, *Save & Deploy NAS Client*.

### Add Authentication Server Modal
`27dfc47ab4484c5e8793d09672e8fd99` · 🆕 **Új**
- **Funkció:** LDAP/AD címtárszerver felvétele.
- **Mezők:** Protocol, Server Alias, Hostname/IP, Port, TLS, Root CA, Bind DN, Bind Password, Base DN (*Auto-Detect*), User Search Filter, Group Membership Filter; bind-mód (szolgáltatásfiók / anonim).
- **Gombok:** *Re-Run Handshake Test*, *Save & Provision Identity Server*.

### Edit Group-to-VLAN Mapping Rule Modal
`79650ffbf43e4e2580e93e827dd4e3cb` · 🆕 **Új**
- **Funkció:** címtárcsoport leképezése VLAN-ra, sávszélesség-profilra és szerepkörre.
- **Mezők:** Identity Provider, Match Protocol, Group DN, Target VLAN/Subnet, Fallback VLAN, CA Issuer, Health Attestation, RADIUS Filter-ID, Priority Tier, Downlink/Uplink Ceiling, Qdisc, Admin Role, Privilege Escalation, MFA Policy, ZTNA Endpoints, Egress Inspection, Session Lease.
- **Gombok:** *Browse LDAP Tree*, QoS-profilok, *Dry-Run Simulation*, *Save & Deploy Rule to AAA Daemon*.

### 802.1X Policy & Dynamic VLAN Simulator Modal
`3727b5cdf12344079259d6998760f39b` · 🆕 **Új**
- **Funkció:** 802.1X hitelesítés szimulálása: melyik VLAN-t és policyt kapna egy eszköz.
- **Mezők:** EAP Identity, EAP Method, Supplicant MAC, Compliance/TPM Posture, NAS Authenticator, Port/SSID, NAS Port-Type, Calling/Called-Station-Id.
- **Gombok:** mintaeszközök (laptop, munkaállomás, vendég, IoT-kamera), *Run Policy Simulation*, *Export Simulation JSON*, *Simulate CoA Disconnect*.

### 802.1X EAP & PKI Certificate Manager
`6bcc72a4c6b54c48848d70cee2b878f5` · 🆕 **Új**
- **Funkció:** saját tanúsítványkiadó (CA) és 802.1X/EAP-tanúsítványok kezelése.
- **Szekciók:** *CA Hierarchy & Trust Anchor*, *SCEP / EST Automated Gateway*.
- **Tábla:** Common Name/SAN, Role/Type, Cryptographic Suite, Hardware Attestation, Validity, Serial & Fingerprint, Actions.
- **Gombok:** *Issue Cert / CSR*, *Renew FreeRADIUS*, *Publish CRL & OCSP*, *Create / Import CA*, *Export CA Bundle*.

### Issue Certificate & Sign CSR Modal
`0dbb53986ff94aaebefd8add883e0ee0` · 🆕 **Új**
- **Funkció:** tanúsítvány kiadása (CSR aláírása, kulcspár+PKCS#12, vagy SCEP/EST egyszeri titok).
- **Mezők:** Signing CA, Hash Algorithm, Validity Period, Auto-renew (SCEP), PEM CSR (drag & drop).
- **Gombok:** *Load Demo CSR*, *Dry-Run ASN.1*, *Sign & Issue Certificate*.

### Certificate Post-Issuance & Export Modal
`eaf1bfe22e06414faa1ff80386ba8b28` · 🆕 **Új**
- **Funkció:** kiadott tanúsítvány letöltése különféle formátumokban.
- **Tábla:** Common Name/SAN, Serial, Algorithm, Attestation, Binding, Expires, Status.
- **Gombok:** *Download .crt / fullchain.pem / .mobileconfig / Intune .xml*, *View Raw ASN.1*, *Copy PEM*, *Issue New Certificate*.

---

## 12. Márka és dokumentumok

Nem funkciók, hanem arculati és tervezési anyagok.

| Képernyő | ID | Tartalom |
|---|---|---|
| FR_OS Brand Discovery & Exploration (6 Directions) | `389b12f3acc94b2697ba95f89db0ba5b` | Hat arculati irány vizuálisan: Precision, Flow, Boundary, Signal, Industrial, Open Technology. |
| FR_OS Brand Identity Exploration | `a1fe3ca5fc0948c9b8b644b925000e4b` | Ugyanez szöveges dokumentumként (magyarul): összehasonlító mátrix, alapelv, tiltólista. |
| FR_OS Frost Precision Logo | `4ed82141405548c3ba77dc2a77f72b24` | Logóváltozat (512×512). |
| FR_OS Hex-Frost Security Logo | `929d5c506a274ee5b34e010f6b7b57fb` | Logóváltozat (512×512). |
| FR_OS Glacial Bastion Logo | `7185e872371f4e47bb71d44f8a4e314e` | Logóváltozat (512×512). |
| FR_OS Minimalist Logo with Wordmark | `6db27c830a194f8a8b937543a5ab9edf` | Logó felirattal. |
| FR_OS Logo – V1 Pure Minimalist (No Subtitle) | `11e953d7f4c0443d929e4b97e9728f23` | Vízszintes logóváltozat. |
| FR_OS Logo – V2 Modern Flow with Diamond Node | `85deb921d010491cb10a3c487c7f7eae` | Vízszintes logóváltozat. |
| FR_OS Logo – V3 Hex Vault Perimeter & Pulse Dot | `44f1c7a9d84f4a9e983299869e0e9b59` | Vízszintes logóváltozat. |
| DESIGN.md | `1441345348995393367` | A webUI design-rendszerének Stitch-be feltöltött leírása (színek, tipográfia). |
| FR_OS 2-Part Distribution Manifest | `07c2361fa4ec48c88b428df0eb4bcb95` | Szöveges jegyzet a tervcsomag két ZIP-archívumra bontásáról. |
| Extracted text from zenarmor.com (home dashboard) | `f65fb8325be4491e89f968fdf213c2e5` | Referenciaként beemelt szöveg a Zenarmor dashboard-dokumentációjából. |
