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

## AI IDS/IPS (mock)

> ⚠ A `frfw.ai_ids` modul **jelenleg teljes egészében kitalált adatot
> szolgáltat**. Nincs valós csomag-/forgalomelemzés a Phase 4 (XDP/eBPF)
> előtt — a modul azért készült el most, hogy a config-séma, a webUI és
> az ütemezett-újratanítás infrastruktúra (CLI parancs + systemd timer)
> már összeálljon és tesztelhető legyen, mire a valós adatgyűjtés
> megérkezik. Minden képernyő/API-válasz, ami ezt az adatot mutatja,
> kötelezően jelöli a mock jelleget (ld. `ai_ids.html` figyelmeztető
> sávja) — ez sosem kezelhető valós biztonsági jelzésként.

Az "ismert eszközök" listája a `dhcp.<zone>.reservations` statikus
foglalásokból jön (a legközelebbi dolog egy "ismert eszköz" fogalomhoz
valós forgalomfigyelés nélkül). Minden eszközhöz egy MAC-cím alapján
determinisztikus (nem újra-random) mock profil generálódik — kockázati
címke, "top protokollok", ismert domainek száma —, valamint egy
`/etc/fr_os/webui/ai_ids_state.json` fájlban perzisztált, valódi
állapotot hordozó rész: a szimulált tanulási % (a `retrain_started_at`
óta eltelt idő / `learning_days` alapján) és a "locked" flag.

**Biztonsági modell — szándékos eltérés a többi képernyőtől**: a "Force
Retrain" és "Lock Profile" műveletek *nem* mennek a `frfw.helper`
privilegizált démonon keresztül. A helper kizárólag root-jogosultságot
igénylő műveletekre való (nft, `ip addr`, Kea újraindítás); az AI IDS
motor sosem nyúl a kernelhez vagy rendszerszolgáltatáshoz, tisztán
userspace JSON-állapotot módosít a webUI saját (unprivileged, már írható)
könyvtárában — ezt a root démonba tenni feleslegesen bővítené a
támadási felületét. Az `ai_ids` *config-szekció* (enabled/learning_days/
retrain_time/excluded_macs) mentése viszont a megszokott módon a helper
`save_config` parancsán megy át, mint minden más YAML-módosítás.

Jövőbeli integrációs pont: `frfw.ai_ids.train_isolation_forest` egy
explicit `NotImplementedError`-t dobó stub a scikit-learn
`IsolationForest`-hez — a `scikit-learn` szándékosan nem függősége sem a
core csomagnak, sem a `webui` extra-nak, amíg ez nincs ténylegesen
megvalósítva.

A napi újratanítási óra ütemezését (`ai_ids.retrain_time`, alapból
`03:30`) a `systemd/fr-ai-ids-retrain.timer` + `.service` pár végzi,
`fr_os-webui` userként (ugyanaz, mint a webUI, mert ugyanazt az
állapot-fájlt írja). A timer jelenleg egy statikus `OnCalendar=*-*-*
03:30:00`-t használ, ami **nem követi automatikusan** egy egyedi
`retrain_time` config-értéket — ennek szinkronizálása egy jövőbeli
finomítás (nyitott kérdés, ld. ROADMAP.md).

## XDP/eBPF gyors útvonal (tervezés)

**Státusz: döntés + technikai előkészítés kész, tényleges eBPF-kód még
nem íródott** — a felhasználóval egyeztetve, mivel az implementáció
valós 10G/40GbE teszthardvert igényel ahhoz, hogy a ROADMAP.md
elfogadási kritériuma (mért teljesítményjavulás) egyáltalán
értelmezhető legyen. Ez a szakasz a döntést és a konkrét tervet rögzíti,
hogy a tényleges kódolás ne nulláról induljon, amikor lesz mire mérni.

### Hatókör-döntés: fast-drop blocklist, nem "nftables újraírva eBPF-ben"

Egy teljes, stateful, zóna-alapú tűzfal újraírása eBPF-ben (connection
tracking, minden protokoll, minden akció, amit az 1. fázis `frfw.nft`
motorja már tud) önmagában akkora projekt lenne, mint az eddigi 1-3.
fázis együttvéve — és a kernel saját nftables/conntrack alrendszerét
próbálná feleslegesen kiváltani, amit valójában jól optimalizáltak.

Ehelyett a döntés: egy **XDP fast-drop blocklist**, ami a legkorábbi
lehetséges ponton (a hálózati driver recv-hook-jában, még a kernel
hálózati stackje és így az nftables előtt) eldobja az ismert rossz
forrás-IP-kről érkező csomagokat, egy BPF hash map alapján. Ez
*kiegészíti*, nem helyettesíti a meglévő nftables-motort — pontosan
úgy, ahogy a valós DDoS-védelmi rendszerek (pl. Cloudflare L4Drop,
Facebook/Meta Katran) használják az XDP-t: nem általános tűzfalként,
hanem egy szűk, nagyon gyors előszűrőként a lassabb, teljes-funkciójú
útvonal előtt.

### Technikai megvalósíthatóság — ellenőrizve (nem 10G hardveren, de valósan)

A fejlesztői sandboxban (nem célhardver, generic/SKB XDP mód egy veth
párra) végigment a teljes build→load→map-frissítés pipeline:

1. **Fordítás**: `clang -O2 -g -target bpf -I<arch include dir> -c
   xdp_fastdrop.c -o xdp_fastdrop.o`. A `-g` (debug info) szükséges,
   mert a modern, BTF-alapú `SEC(".maps")` map-deklarációs szintaxis
   BTF-et igényel a betöltéshez — enélkül `libbpf: BTF is required, but
   is missing`-gal elhasal.
2. **Betöltés/csatolás**: `ip link set dev <iface> {xdpgeneric|xdpdrv}
   obj xdp_fastdrop.o sec xdp` — ugyanaz a "shell ki a rendszer saját
   eszközéhez" minta, mint `frfw.nft`/`frfw.kea`/`frfw.ifaddr`-nál,
   nincs szükség egyedi Python libbpf-bindinghoz. `xdpgeneric` (SKB
   mód) bármilyen NIC-en működik driver-támogatás nélkül — ez a
   biztonságos alapértelmezett, összhangban a "széles NIC-kompatibilitás"
   céllal. `xdpdrv` (natív mód) valós teljesítménynövekedéshez kell, de
   csak XDP-t támogató driverrel rendelkező NIC-eken érhető el.
3. **Map perzisztencia/frissítés**: egy `__uint(pinning,
   LIBBPF_PIN_BY_NAME);` annotációval ellátott BPF map betöltéskor
   automatikusan pinnelődik `/sys/fs/bpf/tc/globals/<map neve>` alá
   (iproute2 beépített libbpf-je kezeli ezt, nincs szükség külön
   `bpftool`-lal történő pinnelésre). Ez a pinnelt map aztán élőben,
   újratöltés nélkül frissíthető: `bpftool map update/delete pinned
   /sys/fs/bpf/tc/globals/blocklist_map key ... value ...` — ez adja a
   gyors "blokkolj/engedj fel egy IP-t" primitívet.
4. **Ismert buktató, amire figyelni kell célrendszeren**: Debian
   csomagolásban a `bpftool` a futó kernelhez illesztett csomagból jön
   (`linux-perf`/kernel-specifikus), tehát ált. konzisztens — de ha egy
   `bpftool` becsomagolt wrapper-szkript "nem található a kernelhez"
   hibát ad (ahogy ebben a sandboxban is, ahol a csomagolt kernel-verzió
   string nem egyezett a fordítási célverzióval), a tényleges bináris
   ilyenkor is elérhető `/usr/lib/linux-tools-<verzió>/bpftool` alatt —
   érdemes a `frfw.xdp`-be egy ilyen fallback-keresést beépíteni.

### Tervezett architektúra (implementáció előtt)

- **Config-séma**: egy `fast_path` szekció (`enabled`, `mode: generic |
  driver`, `zones: [wan]` — mely zónák interfészeire csatolódjon a
  program —, `blocklist: [ip, ...]`). Egyetlen, megosztott blocklist
  minden fast-path-szal ellátott interfészen (nem zónánként külön map),
  mivel egy támadó IP-t minden interfészen blokkolni akarunk.
- **`frfw.xdp` modul**: `compile_program()` (clang hívás),
  `attach()`/`detach()` (`ip link set` hívás), `sync_blocklist()`
  (bpftool map update/delete a config és a jelenlegi map-tartalom
  diffje alapján). Ugyanaz a "generál → validál → alkalmaz" minta, mint
  `frfw.nft`/`frfw.kea`-nál.
- **`frfw.provision.apply_all`**: negyedik lépésként hívná
  `frfw.xdp.apply_fast_path(config, dry_run=...)`, cím → nftables →
  DHCP → XDP sorrendben — így sem a CLI-nek, sem a webUI-nak nem kell
  külön tudnia az XDP-ről, ugyanúgy, ahogy a DHCP bevezetése sem
  igényelt hívó-oldali változást a már meglévő lépéseken kívül.
- **WebUI**: egy "Fast Path" képernyő (be/ki kapcsolás, mód választás,
  blocklist szerkesztés) — a NAT/DHCP képernyők mintájára, a meglévő
  `try_save`/`save_config` infrastruktúrát újrahasználva.
- **Új rendszerfüggőségek**, amik csak akkor kellenek, ha valaki
  bekapcsolja a fast path-t: `clang`, `llvm` (fordításhoz), `libbpf-dev`
  + a kernel fejlécei (BPF header-ökhöz), `bpftool` (map-kezeléshez).
  Ezek nem kerülnek be az alap `frfw` függőségek közé — külön extra-ként
  (`pip install frfw[xdp]`-hez hasonlóan, illetve a Debian
  csomagszinten egy opcionális csomagcsoportként) tervezett.

### Miért nem íródott meg most a tényleges kód

A `xdpgeneric` (SKB) mód bármilyen gépen tesztelhető lenne funkcionálisan
(ahogy fent be is bizonyosodott) — de a ROADMAP.md fázis-4
elfogadási kritériuma kifejezetten *mért teljesítményjavulást* kér XDP
be/ki állapot között, ami csak akkor értelmezhető, ha van mihez
viszonyítani: valós 10G/40GbE forgalom, és ideális esetben natív
(`xdpdrv`) módot támogató NIC. Kód nélkül, találgatott
teljesítményszámokkal dokumentálni a fázist megtévesztő lenne — ehelyett
a döntés és a pontos terv áll készen, hogy a tényleges implementáció (a
fenti tervezet alapján) gyorsan végigmehessen, mihelyt lesz
teszthardver.

## Automatikus installer (fázis 5)

Cél: USB-ről bootolva, terminálmunka nélkül működő FR_OS rendszer. A
választott megközelítés live-build-alapú hibrid live ISO (a három
felmerült opció -- Debian preseed installer, live-build hibrid image,
előre elkészített dd-elhető appliance image -- közül a live-build
hibrid image lett kiválasztva, a nehezebb, de rugalmasabb út).

### Build pipeline

`installer/live-build/` a live-build konfigurációs fa (`auto/config`,
`config/package-lists/`, `config/hooks/`, `config/bootloaders/`).
`installer/build-live-image.sh` orkesztrálja: beszinkronizálja a repo
forrását a chroot `includes.chroot/opt/frfw-src`-be (hogy a chroot hook
onnan pip-telepíthesse a frfw-t), majd `lb clean && lb config && lb
build`. `.github/workflows/build-installer.yml` `workflow_dispatch`-csal
CI-ból is indítható.

A chroot hook (`config/hooks/0100-install-frfw.hook.chroot`) a
build **chroot** stádiumában fut le -- tehát a squashfs image részévé
válik minden, amit csinál: telepíti a frfw csomagot (`pip install
frfw[webui]`), lemásolja a systemd unitokat és a scripteket, majd
engedélyezi a `fr-first-boot.service`-t (ez az egyetlen unit, amit a
build maga engedélyez -- a többit a first-boot script kapcsolja be,
lásd lent).

### First boot

`scripts/fr-first-boot.sh` + `systemd/fr-first-boot.service` (oneshot,
`ConditionPathExists=!/etc/fr_os/.first-boot-done`) -- ez fut le
pontosan egyszer, valódi (nem live-demo) telepítés/boot után:

1. Admin jelszó generálása (`firewall-cli set-admin-password
   --generate` -- nem-interaktív, kriptográfiailag véletlen jelszó,
   `secrets` modullal)
2. Hálózati interfészek automatikus detekciója
3. Az összes `fr-*.service`/`.timer` egység engedélyezése és indítása
4. Marker fájl létrehozása, hogy újrafutás ne történjen

Ez a lépés valósítja meg a "terminálmunka nélkül" kritériumot: minden,
ami *image-be süthető* (csomagok, kód, unit fájlok), már a build
időben megtörtént; ami *gépspecifikus* (melyik NIC melyik, jelszó, TLS
kulcsok), az itt, első bootkor generálódik.

### Ellenőrzés -- valós, végponttól-végpontig futtatott build

A `installer/build-live-image.sh` pipeline ténylegesen lefutott ebben a
sandboxban, és egy valódi, bootolható hibrid ISO-t adott (`file`
szerint "ISO 9660 CD-ROM filesystem data (DOS/MBR boot sector),
bootable", ~327 MB). A squashfs-t kicsomagolva és ellenőrizve:

- `frfw` pip-pel telepítve (`dist-packages/frfw`,
  `frfw-0.1.0.dist-info`), `firewall-cli` a helyén
- mind a 7 `fr-*.service`/`.timer` egység a helyén
  (`fr-firewall`, `fr-apply-helper.socket/.service`, `fr-webui`,
  `fr-ai-ids-retrain.service/.timer`, `fr-first-boot`)
- `fr-first-boot.service` engedélyezve
  (`/etc/systemd/system/multi-user.target.wants/`-ban szimlinkelve)
- az ideiglenes `/opt/frfw-src` forráskönyvtár helyesen eltávolítva a
  hook végén (nem marad a végleges image-ben)

Ez a build/squashfs szintű, statikus ellenőrzés -- a tényleges USB-ről
bootolás és a first-boot script valós lefutása friss VM-en/gépen még
nincs kipróbálva (lásd ROADMAP.md fázis 5 nyitott pontjai).

### Ennek az egy live-build snapshotnak a limitációi

A build host ebben a sandboxban egy nagyon régi, Ubuntu-patch-elt
live-build csomagot futtat (`3.0~a57`, 2012-es belső theme fájlokkal),
nem Debian saját, aktuális live-build csomagját. Több, forráskód-szinten
ellenőrzött inkompatibilitást kellett emiatt megkerülni -- mindegyik
részletesen dokumentálva közvetlenül `installer/live-build/auto/config`
fejlécében és `installer/live-build/config/bootloaders/README.md`-ben:

- Ubuntu-specifikus mirror/kulcs/kernel-csomagnév alapértelmezések
  (`--mode debian` explicit mirror/keyring/linux-flavour felülírásokkal)
- `--debian-installer false`: a beépített "telepítsd lemezre" varázsló
  egy nem létező csomaglistát (`lilo`, `linux-image-2.6-amd64`)
  próbálna telepíteni minden nem-Ubuntu módban, felülírás nélkül --
  emiatt a jelenlegi ISO egy teljes, működő **live** rendszer, nem egy
  klasszikus "másold lemezre" telepítő varázsló
- hiányzó `rsvg` bináris (a splash grafika renderelése emiatt el lett
  hagyva -- egyszerű háttérszín helyettesíti)
- hiányzó `bootlogo` cpio archívum (üres, érvényes archívum pótolja)
- `isohybrid` rossz csomagnévről (`syslinux` a helyes `syslinux-utils`
  helyett) történő keresése a chroot-ban
- a chroot hook-ok helye: ez a snapshot csak `config/hooks/*.chroot`-ot
  néz, a newer live-build `config/hooks/live/` almappa-konvencióját nem
  ismeri (csendben, hibaüzenet nélkül kihagyja onnan a hook-okat --
  ez volt a legalattomosabb hiba: az első teljes build sikeresen
  lefutott, de a frfw egyáltalán nem került bele az image-be)

Egy friss (Debian saját, aktuális) live-build csomaggal ezek közül több
valószínűleg magától sem jelentkezne -- minden egyes pont mellett ott a
konkrét megjegyzés, hogy mit érdemes elsőként visszaállítani/kipróbálni
ott.

## Rendszerintegráció

Kanonikus elérési utak (`frfw.paths`):

| Mi | Hol |
|---|---|
| Konfiguráció | `/etc/fr_os/config.yaml` (root:fr_os-webui, 0640 — a webUI csak olvassa) |
| Ruleset-backupok | `/etc/fr_os/backups/ruleset-<timestamp>.nft` (alapból 10 megőrizve, root-only) |
| WebUI saját állapota | `/etc/fr_os/webui/` (TLS kulcspár, admin fiók, session-secret, AI IDS mock-állapot — fr_os-webui tulajdonában, ld. lent) |
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
- `fr-ai-ids-retrain.timer` + `.service` — naponta (alapból 03:30-kor)
  lefuttatja `firewall-cli ai-ids-retrain`-t `fr_os-webui` userként (root
  nélkül, ld. AI IDS/IPS szekció fent).

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
