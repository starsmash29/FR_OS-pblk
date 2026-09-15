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
> szolgáltat**. A fázis 4 XDP/eBPF munkája (ld. lent) egy konkrét,
> célzott funkciót valósít meg -- TLS SNI szűrés --, nem egy általános
> forgalom-elemző csövet, amit az AI IDS felhasználhatna; így ennek a
> mock motornak valós adatforrása továbbra sincs. A modul azért készült
> el már most, hogy a config-séma, a webUI és az ütemezett-újratanítás
> infrastruktúra (CLI parancs + systemd timer) már összeálljon és
> tesztelhető legyen, mire egy tényleges adatgyűjtő útvonal megérkezik.
> Minden képernyő/API-válasz, ami ezt az adatot mutatja, kötelezően
> jelöli a mock jelleget (ld. `ai_ids.html` figyelmeztető sávja) — ez
> sosem kezelhető valós biztonsági jelzésként.

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

## XDP/eBPF gyors útvonal: kernel-szintű TLS SNI szűrő (fázis 4)

**Státusz: megírva, valóban lefordítva, a BPF verifier által ténylegesen
elfogadva, és egy kézzel összeállított, valós TLS 1.3 ClientHello-val
végponttól-végpontig letesztelve ebben a sandboxban** (`ip link ...
xdpgeneric` alatt `lo`-ra csatolva; ld. lent a pontos mit-és-hogyan-t).
Ez a fejezet felváltja a korábbi, tisztán tervezési szintű "fast-drop
IP blocklist" leírást: a tényleges, felhasználóval egyeztetett hatókör
végül nem egy generikus forrás-IP-blocklist lett, hanem egy **kernel-
térben futó TLS ClientHello parser, ami a SNI (Server Name Indication)
mező alapján dob csomagot** — lásd a pontos indoklást és a scope
különbséget lejjebb.

### Hatókör: SNI-alapú TLS szűrés, nem generikus IP fast-drop

Az eredetileg itt tervezett "IP forrás-cím blocklist" helyett a
tényleges implementáció egy jóval specifikusabb, de gyakorlatiasabb
funkciót valósít meg: **443-as portra menő TCP forgalomban megkeresi a
TLS ClientHello-t, kiolvassa belőle a domain nevet (SNI), és ez alapján
dobja el vagy engedi át a csomagot** — mielőtt a kernel hálózati stackje
vagy az nftables egyáltalán látná. Ez pontosan a Cloudflare/Meta-féle
"szűk, gyors előszűrő a teljes-funkciójú útvonal előtt" minta, csak a
konkrét blokkolási kritérium domain név, nem IP-cím -- ami a gyakorlati
"blokkolj hirdetés-/követő-domaineket" használati esetre jóval
közvetlenebbül illik, mint egy nyers IP-lista.

### A kernel-oldali program: `bpf/xdp_sni_filter.c`

A fájl saját fejléc-kommentje (három, külön kiemelt "IMPORTANT" szakasz)
dokumentálja a valódi, tudatos korlátokat -- ezek nem hiányosságok,
hanem dokumentált tervezési döntések:

1. **Nincs TCP-stream reassembly.** A program *statikusan, csomagonként*
   dolgozik: csak azt a ClientHello-t látja meg, ami *egyetlen* TCP
   szegmensbe belefér (a payload byte 0-án kezdődik egy TLS handshake
   record header-rel, 0x16). Egy több szegmensre töredezett ClientHello
   (nagy `key_share`/`supported_groups` lista, vagy Chrome tudatos
   ClientHello-paddingje) láthatatlan marad, és fail-open módon átmegy.
   Ez tudatos, dokumentált kompromisszum ("soha ne blokkolj olyat, amit
   nem látunk teljesen"), nem hiba.
2. **Nincs Encrypted Client Hello (ECH) támogatás.** ECH esetén a valódi
   SNI titkosítva van; ez bármilyen cleartext-SNI-szűrő elkerülhetetlen,
   nem erre az implementációra specifikus korlátja.
3. **Nincs hamisított TCP RST.** `XDP_DROP` a válasz találat esetén,
   nem egy szintetizált, in-window RST -- az utóbbi a peer
   szekvenciaszámának követését, checksum újraszámítást és
   `XDP_TX`-szel való visszainjektálást igényelne; valós, de
   lényegesen komplexebb, és nem szükséges a "blokkold a kapcsolatot"
   célhoz.
4. Csak IPv4 -- konzisztensen a projekt többi részével (`frfw.nft`, Kea
   DHCP is IPv4-only ma).

A tényleges kernel-térbeli parser (TLS record → handshake → ClientHello
mezők → extensions lista → server_name extension → SNI byte-ok
kiolvasása) egy `BPF_MAP_TYPE_LPM_TRIE`-ben keres, amibe a blokkolt
domainek `reverse("." + hostname)` alakban kerülnek be -- ez teszi
lehetővé, hogy egy "example.com"-ra szóló bejegyzés helyesen blokkolja a
"www.example.com"-ot is, de *ne* blokkoljon egy csak karakter-szinten
hasonló, de nem al-domain nevet (pl. "notexample.com") -- a fájl saját
"LPM trie key construction" kommentje ezt kézzel kiszámolt példákkal is
végigviszi. Találat esetén `XDP_DROP`, és egy async
`BPF_MAP_TYPE_RINGBUF` eseménybe kerül a forrás/cél IP:port + a
megtalált SNI -- ez a userspace-nek szóló log, teljesen leválasztva a
tényleges drop-döntéstől (a userspace olvasása/nem-olvasása sosem
befolyásolja, hogy egy csomag eldobásra kerül-e).

### A BPF verifier: a tényleges nehézség nem a TLS-parsing volt

A csomagformátum-parsing logika (record/handshake/extension mezők
bejárása, hossz-ellenőrzések) viszonylag egyenes vonalú volt. Amire
jóval több idő ment: **a kernel BPF verifier-ének rávezetése arra, hogy
ez a logika ténylegesen bizonyíthatóan biztonságos** -- egy sor, önmagában
is tanulságos, ismétlődő minta formájában jelentkező korlátozás, amiket
`bpf/xdp_sni_filter.c` minden egyes előfordulási helyén részletesen
dokumentál (nem itt, hogy ne kerüljön két, egymástól eltávolodni képes
másolat ugyanarról a dologról):

- A verifier pointer-tartomány-bizonyítása egy adott regiszterhez
  kötött, nem magához a mutatott memóriacímhez -- egy már bizonyítottan
  biztonságos pointer *újratöltése* egy stack slot-ból, vagy átadása egy
  BPF-to-BPF hívás argumentumaként, elveszítheti ezt a bizonyítást, még
  ha a ténylegesen mutatott cím nem is változott.
- Egy ternary (`cond ? olvasás : 0`) nem akadályozza meg LLVM-et abban,
  hogy mindkét ágat kiértékelje, ha a "biztonságos-e" feltétel egy
  *korábbi*, különálló ellenőrzésből származó, elmentett logikai érték
  -- a tényleges memória-hozzáférést védő ellenőrzésnek *ugyanabban* az
  `if`-ben kell lennie, mint magának az olvasásnak.
- Az 512 bájtos BPF stack-korlát (kernel-oldali, nem hangolható) direkt
  befolyásolta a `MAX_SNI_LEN` értékét (128→64→32-re csökkent), és
  megkövetelt egy explicit "barrel shifter" technikát egy változó
  hosszúságú string-eltolás implementálásához, mert egy futásidejű
  indexszel közvetlenül indexelt kis stack-tömb sem fordítási időben
  (clang), sem verifier-szinten nem bizonyítható be biztonságosnak.
- Egy csomag-pointer verifier által *nyomon követett* felső korlátja
  *összeadódhat* egy unrolled ciklus iterációin keresztül, még akkor
  is, ha a tényleges futásidejű érték jóval kisebb korlát alatt marad
  -- ez, nem pedig regiszter-nyomás, volt a végső ok, amiért a kiterjesztés-
  bejáró ciklus nem verifikálódott, amíg át nem lett alakítva egy
  minden iterációban egy rögzített bázisponttól újraszámolt (nem
  iteratívan összeadott) pointerre.

### Valós ellenőrzés (nem csak review, tényleges futtatás)

1. `clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c
   xdp_sni_filter.c -o xdp_sni_filter.o` -- tisztán fordul.
2. `ip link set dev lo xdpgeneric obj xdp_sni_filter.o sec xdp` -- a
   kernel verifier ténylegesen elfogadja és betölti (nem csak
   szintaktikailag helyes C kód, hanem bizonyítottan memória-biztonságos
   BPF bytecode).
3. Python `struct` modullal kézzel összeállított, valós TLS 1.3
   ClientHello byte-sorozat (SNI extension-nel), valódi TCP socketen
   `127.0.0.1:443`-ra küldve, míg a program `lo`-ra van csatolva: egy
   blokklistás SNI esetén a kapcsolat a szó szoros értelmében sosem
   kapja meg az adatot (minden retranszmisszió is eldobásra kerül --
   `STAT_DROP_MATCH` számláló nő minden próbálkozásnál), egy nem-
   blokkolt SNI esetén a payload hiánytalanul megérkezik a szerverhez.
4. A ring buffer esemény (forrás/cél IP:port + SNI) helyesen
   dekódolódik userspace oldalon egy közvetlen `ctypes` `libbpf`
   binding-gal (ld. lent).

### Userspace orchestrator: `frfw.xdp`

A kernel-oldali programhoz tartozó Python réteg ugyanazt a "shell ki a
rendszer saját eszközéhez" mintát követi, mint `frfw.nft`/`frfw.kea`/
`frfw.ifaddr` -- `ip` és `bpftool`, nem egy nehezebb library (bcc,
teljes libbpf-python binding). Az egyetlen kivétel a ring buffer
olvasása, amihez nincs értelmes CLI primitíva: ehhez egy közvetlen,
kis `ctypes` binding köti be `libbpf`-nek pontosan három függvényét
(`ring_buffer__new`/`__poll`/`__free`) -- ez a program egyetlen olyan
pontja, ami valódi library-hívásra épül bcc helyett, és tisztán
olvasás-oldali (sosem befolyásolhatja a drop-döntést).

- **Fordítás** (`ensure_compiled`): ha a célon nincs előre lefordított
  `.o`, és van elérhető `bpf/xdp_sni_filter.c` forrás (dev checkout,
  vagy egy telepített release megőrzött forrásfája `RELEASES_DIR`
  alatt), lefordítja clang-gal. Egy éles image-nek nincs szüksége
  C-fordítóra -- a live-build pipeline-nak kellene előre lefordított
  `.o`-t szállítania (ez még nincs bekötve, ld. Nyitott pontok).
- **Betöltés + pinning** (`load_and_pin`): a programot és MINDEN
  map-jét egyszer tölti be és pinneli `/sys/fs/bpf/fr_os_xdp` alá
  (`bpftool prog loadall ... pinmaps ...`) -- ez teszi lehetővé, hogy
  több interfészhez csatolva (pl. WAN + egy vendég-WiFi uplink) mind
  *ugyanazt* a blocklist/stats/events map-ot lássa, nem külön-külön
  másolatot map-onként interfészenként.
- **Csatolás** (`attach`): előbb natív (`xdpdrv`) módot próbál (valós
  driver-szintű sebesség támogatott NIC-eken), sikertelenség esetén
  generic (`xdpgeneric`) módra esik vissza -- ez a fallback-lánc, amit
  a projekt eredeti terve is előírt, és amit ez a sandbox saját `lo`
  interfésze is ténylegesen kikényszerít (a loopback sosem támogat
  natív módot).
- **Blocklist szinkron** (`sync_blocklist`): a pinnelt LPM trie
  tartalmát a config kívánt állapotához igazítja (hozzáad/eltávolít),
  anélkül hogy minden `apply`-nál törölné és újraépítené.
- **`frfw.provision.apply_all`**: negyedik (utolsó) lépésként hívja
  `frfw.xdp.sync_sni_filter`-t, cím → nftables → DHCP → XDP sorrendben
  -- sem a CLI-nek, sem a webUI-nak nem kell külön tudnia az XDP-ről.
- **`fr-xdp-sni-logger` daemon** (`frfw.xdp.run_event_logger`,
  `systemd/fr-xdp-sni-logger.service`): a ring buffert olvassa
  folyamatosan, blokkoló `ring_buffer__poll`-lal (nem busy-waiting --
  tétlen állapotban gyakorlatilag nulla CPU-t használ), és minden
  találatot naplóz journald-on keresztül.

### Nyitott pontok

- **WebUI képernyő** a blocklist szerkesztéséhez és élő
  napló/statisztika megjelenítéséhez -- még nincs implementálva (a
  `frfw.xdp.get_stats()`/`get_attached()` a szükséges backend-adatot
  már szolgáltatja, csak a képernyő maga hiányzik).
- **Live-build integráció**: a `.o` fájl előre-fordítása és image-be
  csomagolása a build pipeline részeként, hogy éles image-en ne
  kelljen `clang`-ra támaszkodni induláskor.
- **Valós 10G/40GbE teljesítménymérés**: ez a sandbox nem alkalmas
  ilyen mérésre (nincs megfelelő NIC/forgalom-generátor) -- a program
  helyessége (a fenti értelemben) igazolt, a natív módú, nagy
  csomagsebességű teljesítmény-előny viszont csak megfelelő
  teszthardveren mérhető, ahogy azt ennek a szakasznak a korábbi
  változata is jelezte.

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

## Frissítési mechanizmus (fázis 6)

`frfw.update` két, élesen elválasztott félre bomlik, ugyanazt a
jogosultsági mintát követve, mint a projekt többi része:

**Ellenőrzés** (`check_latest`, `list_releases`) egy jogosultság nélküli,
read-only HTTPS GET a konfigurált (vagy alapértelmezett,
`frfw.update.DEFAULT_REPO`) GitHub repó Releases API-ja ellen. Nincs
perzisztált "utoljára ellenőrizve" állapot -- minden webUI oldalbetöltés
frissen lekérdezi, ugyanaz a minta, mint az AI IDS képernyő élőben
számolt progress bar-ja. Egy repó, aminek még nincs release-e (mint
ennek a projektnek jelenleg, 0.1.0-nál) nem hiba, hanem "nincs elérhető
frissítés" -- a GitHub API-ja ilyenkor egyszerű 404-et ad, amit a modul
explicit lekezel.

**Alkalmazás** (`apply_update`, `rollback_update`) valódi root
jogosultságot igényel: letölt és kicsomagol egy release tarball-t
(`https://github.com/<repo>/archive/refs/tags/<tag>.tar.gz`), `pip
install`-olja, frissíti a systemd unit fájlokat, majd újraindítja az
érintett service-eket. Ez a fél kizárólag a privilegizált
`fr-update-helper` daemonból (lásd lent) vagy közvetlenül egy SSH-n
keresztül root-ként futtatott `firewall-cli update apply/rollback`
paranccsal hívható -- a webUI folyamat maga sosem futtatja közvetlenül.

### Külön daemon, nem a meglévő apply-helper bővítve

A tűzfal-config apply-helpere (`frfw.helper.server`, fázis 2) tudatosan
minimális: "csak `CONFIG_PATH`/`BACKUP_DIR`-hoz nyúl, nincs általános
parancsvégrehajtás" (lásd `frfw.helper.protocol` docstringjét). A
csomagtelepítés, systemd unit átírás és service-restart ennél sokkal
szélesebb jogosultsági felület -- ezt ráépíteni az apply-helperre
indokolatlanul kiszélesítené AZ Ő attack surface-ét is. Ezért egy külön,
saját socketes daemon (`fr-update-helper`, `frfw.helper.update_server` +
`update_protocol` + `update_client`), ami szerkezetében szinte
teljesen ugyanaz (systemd socket activation, egy-JSON-objektum-soronként
protokoll, `StreamRequestHandler` connectionönként), de fizikailag
független unit/socket/kód -- egy változtatás az egyikben sosem érintheti
véletlenül a másikat.

### A webUI önmagát frissíti -- a race, amit ez okoz, és a megoldása

Az update a webUI *saját* service-ét (`fr-webui.service`) is
újraindítja, hogy az új kód ténylegesen érvénybe lépjen -- de ez pont az
a folyamat, ami a frissítést kérő HTTP kérést kiszolgálja. Ha
szinkronban, azonnal újraindítanánk, a böngésző sosem kapná meg a
válasz oldalt (a kapcsolat megszakadna, mielőtt bármi visszaérne).
Megoldás: `fr-apply-helper.service`/`fr-firewall.service` szinkronban,
azonnal újraindul; `fr-webui.service` újraindítása
`systemd-run --on-active=3s`-sal néhány másodperccel later-re van
ütemezve, decouple-olva ettől a kéréstől -- így a "sikeres frissítés"
oldal még megjelenik, mielőtt a webUI tényleg újraindulna. Hasonló okból
maga a `fr-update-helper.service` sem indul újra saját magát az update
része -- az megölné a folyamatot, mielőtt a választ visszaküldhetné a
hívónak; ez egy dokumentált, tudatos korlátozás (a daemon saját kódja
csak a következő természetes újraindításkor, pl. reboot-nál, frissül).

### Rollback

Egy szintig megy vissza: `apply_update` az update ELŐTTI verziót
`previous_version`-ként elmenti a perzisztált állapotba
(`paths.UPDATE_STATE_PATH`, `root:fr_os-webui`, 0640 -- ugyanaz a minta,
mint `config.yaml`-nál: csak a privilegizált oldal írja, a webUI csak
olvassa), MIELŐTT vált; `rollback_update` ezt telepíti vissza és törli
-- egy rollback-et visszagörgetni már nem lehet. Ha a korábbi verzió
kicsomagolt forrása még megvan `RELEASES_DIR` (`/opt/fr_os/releases`)
alatt (egy sikeres update sosem törli a régi verziók könyvtárát), a
rollback újra letöltés nélkül, hálózat nélkül is működik -- pont akkor
számít, ha maga a hibás update törte el a hálózatot is.

Hiba esetén (letöltés, kicsomagolás, pip install vagy service-restart
bármelyike) a próbálkozás és a hibaüzenet bekerül az állapotfájl
`last_update` mezőjébe, és a hívás `UpdateError`-t dob -- sem a CLI, sem
a webUI oldal nem marad néma egy sikertelen frissítésnél.

### Ismert korlátozás: nincs kriptográfiai aláírás-ellenőrzés

A letöltött release tarball-on nincs semmilyen kriptográfiai
aláírás-ellenőrzés a HTTPS-kapcsolat GitHub-hoz felett -- ugyanaz a
bizalmi modell, mint egy sima `git clone`/`pip install`-é egy nem
rögzített indexből. Release-aláírás (`cosign` vagy egy GPG-aláírt
checksum fájl) ésszerű következő lépés, mihelyt vannak valós, taggelt
release-ek amiket alá lehet írni.

### Ellenőrzés

A teljes mechanizmust (verzió parse/összehasonlítás, check_latest/
list_releases minden HTTP-ági a GitHub API valós, élő hívásával a
projekt jelenleg üres repója ellen -- helyesen "nincs kiadás" 404-et ad
vissza --, teljes apply/rollback folyamat sikeres és hibás ággal,
path-traversal védelem a tarball-kicsomagoláson, az update-helper socket
protokollja, webUI útvonalak) egységtesztek fedik (lásd
`tests/test_update*.py`, `tests/webui/test_update_routes.py`). Ami NEM
lett kipróbálva: egy valós, régebbi verzióról egy tényleges, publikált
GitHub release-re történő frissítés végponttól-végpontig egy élő
VM-en -- ehhez a repónak előbb kell legalább egy valódi tagged
release-e legyen (lásd ROADMAP.md fázis 6).

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

- ~~Konkrét XDP program és eBPF loader könyvtár~~ -- eldőlt: saját
  `bpf/xdp_sni_filter.c` (nem egy meglévő projekt átvétele) + `ip`/
  `bpftool` CLI-alapú `frfw.xdp` orchestrator (nem bcc), ld. fenti
  "XDP/eBPF gyors útvonal" szakaszt.
- DPDK bevonásának szükségessége — csak akkor, ha XDP/eBPF nem elég a célzott
  hardveren mért teljesítményhez; ez a kérdés a valós teljesítménymérésig
  (ld. fenti "Nyitott pontok") továbbra is nyitott.
- Konkrét NIC driver lista/tesztmátrix — a ténylegesen elérhető homelab
  hardver alapján bővül.
