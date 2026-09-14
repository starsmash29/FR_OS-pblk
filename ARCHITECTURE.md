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

## Rendszerintegráció (2. fázis)

Kanonikus elérési utak (`frfw.paths`):

| Mi | Hol |
|---|---|
| Konfiguráció | `/etc/fr_os/config.yaml` |
| Ruleset-backupok | `/etc/fr_os/backups/ruleset-<timestamp>.nft` (alapból 10 megőrizve) |
| Apply-helper socket | `/run/fr_os/apply.sock` |

systemd unit-ok (`systemd/`):

- `fr-firewall.service` — boot-kor alkalmazza a kanonikus configot, a
  Debian `nftables.service`-ét követő ordering-gel (korai boot,
  `network-pre.target` előtt, hogy a szabályok a hálózat felállása előtt
  már érvényben legyenek).
- `fr-apply-helper.socket` + `fr-apply-helper.service` — a privilegizált
  apply-helper, socket-activation-nel (ld. Biztonsági modell lent).
- `fr-webui.service` — placeholder a 3. fázisig, egy üzenetet kiíró
  bináris a tényleges FastAPI app helyén, hogy a service-függőségek
  (`fr-apply-helper.socket`) már most tesztelhetők legyenek.

`scripts/install-system-integration.sh` végzi a rendszerbe-illesztést egy
friss gépen: `/etc/fr_os` létrehozása, alap config telepítése (ha még
nincs), `fr_os-webui` csoport létrehozása, systemd unit-ok telepítése.

## Biztonsági modell

A webUI nem futhat rootként. A 2. fázisban implementált megoldás: a webUI egy
Unix socketen (`/run/fr_os/apply.sock`, `frfw.helper`) keresztül küld kérést
egy root alatt futó "apply-helper" systemd service-nek
(`fr-apply-helper.service`, socket-activation-nel indítva
`fr-apply-helper.socket` által). A socket-fájl csoport-tulajdonosa egy
dedikált `fr_os-webui` csoport (`SocketGroup=` a `.socket` unit-ban) — ez a
hozzáférés-vezérlés, nem a protokoll maga.

A protokoll szándékosan minimális: egyetlen JSON-objektum soronként, három
parancs (`ping`/`apply`/`rollback`), egyik sem fogad el a hívótól kapott
fájlútvonalat — a helper mindig a saját maga indításakor kapott kanonikus
config- és backup-útvonalat használja (alapból `frfw.paths.CONFIG_PATH` /
`BACKUP_DIR`). Ez azt jelenti, hogy a webUI kompromittálódása esetén sem
válik a helper általános root-szintű fájlolvasási/-írási vagy
parancsvégrehajtási primitívvé — kizárólag a tűzfal-konfiguráció
alkalmazására/visszaállítására korlátozott.

Lásd még: [`frfw/helper/`](src/frfw/helper/) (szerver + kliens),
[`systemd/fr-apply-helper.socket`](systemd/fr-apply-helper.socket).

## Nem lezárt döntések

Az alábbi pontok fázis közben, konkrét hardver/környezet ismeretében dőlnek el
— itt csak jelezzük, hogy tudatosan nyitva hagytuk őket:

- Konkrét XDP program és eBPF loader könyvtár (pl. saját libbpf-alapú kód vs.
  meglévő projekt) — 4. fázis.
- DPDK bevonásának szükségessége — csak akkor, ha XDP/eBPF nem elég a célzott
  hardveren mért teljesítményhez.
- Konkrét NIC driver lista/tesztmátrix — a ténylegesen elérhető homelab
  hardver alapján bővül.
