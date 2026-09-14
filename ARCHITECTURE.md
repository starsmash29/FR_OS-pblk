# Architektúra

Ez a dokumentum rögzíti a projekt alapvető architekturális döntéseit. A cél egy
egyedi, Linux-alapú firewall/router operációs rendszer, homelab használatra,
hosszabb távon GitHub community edition potenciállal.

## Miért nem pfSense/OPNsense (FreeBSD)?

- **NIC-kompatibilitás**: Linux driver-ökoszisztémája jóval szélesebb, mint a
  FreeBSD-é — nem csak Intel, hanem Realtek, Aquantia, olcsóbb/használt
  Mellanox kártyák is natívan támogatottak.
- **Nagy sebességű útvonal**: 10GbE/40GbE line-rate stateful tűzfalazáshoz a
  Linux XDP/eBPF (és szükség esetén DPDK) ökoszisztémája érettebb és jobban
  hangolható, mint a FreeBSD equivalensei.

## Rétegek és választott technológiák

| Réteg | Választás | Indoklás |
|---|---|---|
| Alap OS | Debian minimal (netinst) | Stabil, jól dokumentált, hosszú támogatási ciklus, minimális alap image |
| Csomagszűrés | nftables | A modern Linux natív tűzfal-alrendszere, leváltja az iptables-t, jó Python-integráció (`nft -f`, JSON API) |
| Gyors útvonal (10G+) | XDP/eBPF, később DPDK opció | Kernel-stack megkerülése nagy csomagsebességnél; DPDK csak ha az XDP nem elég (extra komplexitás, userspace driver) |
| Menedzsment UI | Python/FastAPI backend + egyszerű frontend | Gyors fejlesztés, jó async I/O, könnyen tesztelhető; a frontend kezdetben szerver-renderelt/minimál JS, nem SPA-keretrendszer-függő |
| Konfig-tárolás | YAML (forrás igazság) + SQLite (futásidejű állapot/session) | YAML git-barát, diff-elhető, kézzel is szerkeszthető vészhelyzetben; SQLite a nem-verziózandó futásidejű adatokhoz (pl. DHCP lease-ek) |
| Telepítés | Debian preseed / live-build + first-boot script | Automatikus, felhasználói beavatkozás nélküli telepítés, pfSense-szerű élmény |

## Rendszerfelépítés (nagy vonalakban)

```
                    ┌─────────────────────────┐
                    │        WebUI (UI)        │
                    │   FastAPI + frontend      │
                    │   nem root, unix socket    │
                    │   API-n át kommunikál      │
                    └────────────┬─────────────┘
                                 │ privileged helper / unix socket
                    ┌────────────▼─────────────┐
                    │      frfw config engine   │
                    │  (Python csomag: frfw)     │
                    │  - config séma + validáció │
                    │  - nftables ruleset gen.   │
                    │  - apply / rollback logika │
                    └────────────┬─────────────┘
                                 │ nft -f / nft -c
                    ┌────────────▼─────────────┐
                    │        nftables            │
                    │   (kernel packet filter)   │
                    └───────────────────────────┘
```

A `frfw` Python csomag a rendszer szíve: ez tartalmazza a konfigurációs sémát,
a validációs logikát és az nftables ruleset-generátort. Ezt fázistól függetlenül
használja majd a CLI (1. fázis), a systemd service (2. fázis) és a webUI
(3. fázis) is — egyetlen forrás a "config → tűzfalszabályok" fordításhoz,
hogy ne legyen inkonzisztencia a CLI-vel kézzel beállított és a webUI-n
keresztül beállított rendszer között.

## Konfigurációs modell

A konfiguráció alapfogalmai (részletes séma: [`docs/CONFIG_SCHEMA.md`](docs/CONFIG_SCHEMA.md)):

- **interfaces**: fizikai/logikai hálózati interfészek, mindegyik egy zónához
  rendelve (pl. `wan` eszköz → `wan` zóna).
- **zones**: logikai csoportok (wan/lan/opt mintára), amikhez szabályok
  hivatkoznak — nem kell minden szabályban interfészt felsorolni.
- **rules**: forgalomszűrési szabályok zóna-pár (from_zone → to_zone),
  protokoll, port, cím alapján, `accept`/`drop`/`reject` akcióval.
- **nat**: masquerade (kimenő NAT) és port-forward (bejövő DNAT) szabályok.

A séma szándékosan egyszerű és lapos — a cél, hogy a webUI (3. fázis) közvetlenül
erre tudjon szerkesztő felületet építeni, YAML kézi szerkesztése nélkül is.

## nftables ruleset felépítés

A generált ruleset egy `inet fr_os` táblát tartalmaz `input`/`forward`/`output`
lánccal (alapértelmezett drop policy, explicit accept a loopback-re és az
established/related forgalomra), valamint egy `ip fr_os_nat` táblát
`prerouting`/`postrouting` lánccal a DNAT/masquerade szabályokhoz.
Minden generált szabály tartalmaz egy megjegyzést (`comment`) a forrás YAML
szabály nevével, hogy a `nft list ruleset` kimenete visszakövethető legyen a
konfigurációra.

## Biztonsági modell (előretekintés a 2. fázisra)

A webUI nem futhat rootként. A tervezett megoldás: a webUI egy Unix socketen
keresztül küld kérést egy minimális jogosultságú, root alatt futó "apply
helper" systemd service-nek, ami kizárólag a `frfw` config-apply műveletet
tudja elvégezni — nem általános parancsvégrehajtást. Ez a döntés a 2. fázisban
kerül részletezésre és implementálásra.

## Nem lezárt döntések

Az alábbi pontok fázis közben, konkrét hardver/környezet ismeretében dőlnek el
— itt csak jelezzük, hogy tudatosan nyitva hagytuk őket:

- Konkrét XDP program és eBPF loader könyvtár (pl. saját libbpf-alapú kód vs.
  meglévő projekt) — 4. fázis.
- DPDK bevonásának szükségessége — csak akkor, ha XDP/eBPF nem elég a célzott
  hardveren mért teljesítményhez.
- Konkrét NIC driver lista/tesztmátrix — a ténylegesen elérhető homelab
  hardver alapján bővül.
