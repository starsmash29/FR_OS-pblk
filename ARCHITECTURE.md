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
| Menedzsment UI | Python/FastAPI backend + egyszerű frontend | Gyors fejlesztés, jó async I/O, könnyen tesztelhető; a frontend szerver-renderelt Jinja2 + minimál CSS, nem SPA-keretrendszer-függő |
| Konfig-tárolás | YAML (forrás igazság) + SQLite (futásidejű állapot/session) | YAML git-barát, diff-elhető, kézzel is szerkeszthető vészhelyzetben; SQLite a nem-verziózandó futásidejű adatokhoz (pl. DHCP lease-ek — bár ezeket ma maga a Kea kezeli saját memfile lease-adatbázisában, nem frfw) |
| DHCP szerver | Kea DHCPv4 | ISC hivatalos isc-dhcp-server-utódja, aktívan fejlesztett, JSON-config (egyszerű Python-oldali generálás), beépített `-t` szintaxis-tesztelő (`kea-dhcp4 -t`, az `nft -c`-hez hasonló szerepben) |
| Telepítés | Debian preseed / live-build + first-boot script | Automatikus, felhasználói beavatkozás nélküli telepítés, pfSense-szerű élmény |

## Rendszerfelépítés (nagy vonalakban)

```
                    ┌─────────────────────────┐
                    │        WebUI (UI)         │
                    │  FastAPI + Jinja2 frontend │
                    │  unprivileged fr_os-webui   │
                    │  user, HTTPS (:443)          │
                    └────────────┬─────────────┘
                        │                 │
       közvetlen fájlolvasás    │  save_config / apply / rollback
       (/etc/fr_os/config.yaml, │  (unix socket, csak ezek a
        csoport-jogosultsággal) │   műveletek)
                        │        ┌────────▼─────────────┐
                        │        │  apply-helper (root)   │
                        │        │  frfw.helper.server      │
                        │        └────────┬─────────────┘
                        │                 │
                    ┌───▼─────────────────▼─────┐
                    │      frfw config engine     │
                    │  (Python csomag: frfw)       │
                    │  - config séma + validáció    │
                    │  - nftables ruleset gen.        │
                    │  - interfész-cím alkalmazás       │
                    │  - Kea DHCP config gen.             │
                    │  - apply / rollback logika            │
                    └────┬───────────────┬───────────┘
                         │ ip addr       │ nft -f / -c    │ kea-dhcp4 -t +
                         │               │                │ systemctl restart
                    ┌────▼───┐      ┌────▼─────┐    ┌─────▼──────────┐
                    │ kernel  │      │ nftables  │    │ kea-dhcp4-server │
                    │ netlink │      │ (csomag-  │    │ (DHCP szerver)    │
                    │ (címek) │      │  szűrés)  │    └──────────────────┘
                    └─────────┘      └───────────┘
```

A `frfw` Python csomag a rendszer szíve: ez tartalmazza a konfigurációs sémát,
a validációs logikát, az nftables ruleset-generátort, az interfész-cím és a
Kea DHCP config generátorokat. Ezt fázistól függetlenül használja a CLI
(1. fázis), a systemd service (2. fázis) és a webUI (3. fázis) is — egyetlen
forrás a "config → rendszerállapot" fordításhoz (`frfw.provision.apply_all`),
hogy ne legyen inkonzisztencia a CLI-vel kézzel beállított és a webUI-n
keresztül beállított rendszer között.

## Konfigurációs modell

A konfiguráció alapfogalmai (részletes séma: [`docs/CONFIG_SCHEMA.md`](docs/CONFIG_SCHEMA.md)):

- **interfaces**: fizikai/logikai hálózati interfészek, mindegyik egy zónához
  rendelve (pl. `wan` eszköz → `wan` zóna), opcionális statikus IPv4 címmel
  (`address: 10.0.0.1/24`) — ezt a `frfw.ifaddr` alkalmazza `ip addr`-on
  keresztül, és ez adja a DHCP pool alhálózatát/gateway-ét is.
- **zones**: logikai csoportok (wan/lan/opt mintára), amikhez szabályok
  hivatkoznak — nem kell minden szabályban interfészt felsorolni.
- **rules**: forgalomszűrési szabályok zóna-pár (from_zone → to_zone),
  protokoll, port, cím alapján, `accept`/`drop`/`reject` akcióval.
- **nat**: masquerade (kimenő NAT) és port-forward (bejövő DNAT) szabályok.
- **dhcp**: zónánkénti DHCPv4 pool (cím-tartomány, DNS-szerverek,
  lease-idő, statikus foglalások) — csak olyan zónára állítható be, aminek
  pontosan egy, statikus címmel rendelkező interfésze van (ld. lent).

A séma szándékosan egyszerű és lapos — a webUI közvetlenül erre épít
szerkesztő felületet (dict-szintű YAML-szerkesztés + újra-validálás mentés
előtt, ld. `frfw.webui.config_store`), kézi YAML-szerkesztés nélkül is.

## nftables ruleset felépítés

A generált ruleset egy `inet fr_os` táblát tartalmaz `input`/`forward`/`output`
lánccal (alapértelmezett drop policy, explicit accept a loopback-re és az
established/related forgalomra), valamint egy `ip fr_os_nat` táblát
`prerouting`/`postrouting` lánccal a DNAT/masquerade szabályokhoz.
Minden generált szabály tartalmaz egy megjegyzést (`comment`) a forrás YAML
szabály nevével, hogy a `nft list ruleset` kimenete visszakövethető legyen a
konfigurációra.

## DHCP (Kea) config generálás

A `dhcp` szekcióból a `frfw.kea` modul egy Kea `Dhcp4` JSON configot épít
(`interfaces-config` a releváns eszközökre korlátozva, `subnet4` tömb
pool-okkal, `routers`/`domain-name-servers` option-adattal, és
`reservations` a statikus foglalásokhoz). A generált fájlt a `kea-dhcp4 -t`
paranccsal ellenőrizzük (ugyanaz a szerep, mint az `nft -c`-nek), mielőtt
tényleges alkalmazásra kerülne — ez a valós `kea-dhcp4` bináris, nem egy
saját JSON-séma-ellenőrző, tehát a Kea saját szemantikai szabályait
(pl. hogy a felsorolt interfészeknek léteznie kell a gépen) is kikényszeríti.

Alkalmazáskor a `frfw.kea.apply_dhcp_config` felülírja
`/etc/kea/kea-dhcp4.conf`-ot és újraindítja a `kea-dhcp4-server` systemd
service-t — ugyanaz a "generált fájl, sosem kézzel szerkesztett" elv, mint
az nftables ruleset-nél.

## Rendszerintegráció

Kanonikus elérési utak (`frfw.paths`):

| Mi | Hol |
|---|---|
| Konfiguráció | `/etc/fr_os/config.yaml` (root:fr_os-webui, 0640 — a webUI csak olvassa) |
| Ruleset-backupok | `/etc/fr_os/backups/ruleset-<timestamp>.nft` (alapból 10 megőrizve, root-only) |
| WebUI saját állapota | `/etc/fr_os/webui/` (TLS kulcspár, admin fiók, session-secret — fr_os-webui tulajdonában, ld. lent) |
| Apply-helper socket | `/run/fr_os/apply.sock` |

systemd unit-ok (`systemd/`):

- `fr-firewall.service` — boot-kor alkalmazza a kanonikus configot, a
  Debian `nftables.service`-ét követő ordering-gel (korai boot,
  `network-pre.target` előtt, hogy a szabályok a hálózat felállása előtt
  már érvényben legyenek).
- `fr-apply-helper.socket` + `fr-apply-helper.service` — a privilegizált
  apply-helper, socket-activation-nel (ld. Biztonsági modell lent).
- `fr-webui.service` — a tényleges FastAPI app (`fr-webui` bináris),
  unprivileged `fr_os-webui` userként fut. A 443-as (root alatti) portra
  kötéshez nem root kell, hanem `AmbientCapabilities=CAP_NET_BIND_SERVICE`
  + `NoNewPrivileges=yes` — ugyanaz a minta, amit a Kea saját
  (`kea-dhcp4-server.service`) unit-ja is használ `_kea` userrel.

`scripts/install-system-integration.sh` végzi a rendszerbe-illesztést egy
friss gépen: `/etc/fr_os` létrehozása, alap config telepítése (ha még
nincs), `fr_os-webui` rendszerfelhasználó és -csoport létrehozása,
`config.yaml` csoport-olvashatóvá tétele, `/etc/fr_os/webui` létrehozása
`fr_os-webui` tulajdonban, systemd unit-ok telepítése. Az admin jelszót
külön, interaktívan kell beállítani (`firewall-cli set-admin-password`) —
ezt a telepítő szándékosan nem automatizálja.

## Biztonsági modell

A webUI nem futhat rootként — `fr_os-webui` rendszerfelhasználóként fut,
`AmbientCapabilities=CAP_NET_BIND_SERVICE`-vel a 443-as porthoz (ld. fent).
Minden root-szintű műveletet (nftables betöltés, interfész-cím
alkalmazása, Kea config írása+újraindítása) egy Unix socketen
(`/run/fr_os/apply.sock`, `frfw.helper`) keresztül kér a webUI egy root
alatt futó "apply-helper" systemd service-től (`fr-apply-helper.service`,
socket-activation-nel indítva `fr-apply-helper.socket` által). A
socket-fájl csoport-tulajdonosa egy dedikált `fr_os-webui` csoport
(`SocketGroup=` a `.socket` unit-ban) — ez a hozzáférés-vezérlés, nem a
protokoll maga.

A protokoll szándékosan minimális: egyetlen JSON-objektum soronként, négy
parancs:

- `ping` — health-check
- `apply` (`dry_run` opcióval) — a kanonikus configot alkalmazza
  (`frfw.provision.apply_all`: címek → nftables → DHCP)
- `rollback` — visszaáll a legutóbbi ruleset-backupra
- `save_config` — kap egy YAML szöveget, `frfw.config.parse_config`-gal
  validálja, és csak sikeres validáció esetén írja felül vele a
  kanonikus configot (atomikusan, tmp-fájl + rename)

Egyik parancs sem fogad el a hívótól kapott *fájlútvonalat* — a helper
mindig a saját maga indításakor kapott kanonikus config-/backup-/Kea-config
útvonalat használja (alapból `frfw.paths.CONFIG_PATH` / `BACKUP_DIR` /
`frfw.kea.KEA_CONFIG_PATH`). Ez azt jelenti, hogy a webUI kompromittálódása
esetén sem válik a helper általános root-szintű fájlolvasási/-írási vagy
parancsvégrehajtási primitívvé — kizárólag a tűzfal-/DHCP-konfiguráció
mentésére/alkalmazására/visszaállítására korlátozott, és minden bejövő YAML
teljes séma-validáción megy át, mielőtt bármi lemezre kerülne.

A `config.yaml` *olvasása* nem megy a helperen keresztül (a webUI a saját
felhasználói jogosultságával, csoport-olvasási joggal éri el közvetlenül —
ez nem biztonságkritikus művelet), csak az *írása* — ez az egyetlen
kivétel a "minden root-műveletet a helper végez" szabály alól, mert olvasás
önmagában nem tud rendszerállapotot módosítani.

Lásd még: [`frfw/helper/`](src/frfw/helper/) (szerver + kliens),
[`systemd/fr-apply-helper.socket`](systemd/fr-apply-helper.socket),
[`systemd/fr-webui.service`](systemd/fr-webui.service).

## Nem lezárt döntések

Az alábbi pontok fázis közben, konkrét hardver/környezet ismeretében dőlnek el
— itt csak jelezzük, hogy tudatosan nyitva hagytuk őket:

- Konkrét XDP program és eBPF loader könyvtár (pl. saját libbpf-alapú kód vs.
  meglévő projekt) — 4. fázis.
- DPDK bevonásának szükségessége — csak akkor, ha XDP/eBPF nem elég a célzott
  hardveren mért teljesítményhez.
- Konkrét NIC driver lista/tesztmátrix — a ténylegesen elérhető homelab
  hardver alapján bővül.
