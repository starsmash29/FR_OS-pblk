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
  találatot egy-egy JSON sorként naplóz journald-on keresztül
  (`frfw.xdp.format_event_json`) -- ez teszi lehetővé, hogy a webUI
  strukturált adatként, nem szöveg-parse-olással dolgozza fel ugyanazt
  a sort.

### WebUI képernyő (`/xdp`)

Ugyanaz a "szerkeszd a nyers YAML dict-et, validálj, mentsd a
privilegizált helperen keresztül" minta, mint minden más képernyőn
(`frfw.webui.actions.try_save`) — az `enabled`/`interfaces`/`blocklist`
mentése sosem csatolja/oldja le közvetlenül a tényleges XDP programot,
az csak a következő `apply`-nál történik meg (CLI vagy a dashboard
"Apply" gombja), pontosan úgy, mint egy nftables ruleset vagy Kea
config-változtatásnál. A státusz-kártya ezért tudatosan *két* különböző
állapotot különböztet meg: "Disabled" (a funkció ki van kapcsolva) és
"Not attached yet -- run Apply" (be van kapcsolva a configban, de a
kernel-oldali program még nincs betöltve/csatolva) — mindkettő piros
badge-dzsel, de eltérő szöveggel, hogy egy admin lássa a különbséget
"kikapcsolva" és "bekapcsolva, de még nem alkalmazva" között.

Az élő napló (`GET /xdp/logs/stream`, Server-Sent Events) NEM a kernel
ring buffer-t olvassa közvetlenül -- az ahhoz pinnelt map root-only
(ld. `RingBufferReader` docstringje), a webUI process pedig tudatosan
nem root-ként fut (`systemd/fr-webui.service`). Ehelyett a már
`fr-xdp-sni-logger` által journald-ba írt, már dekódolt JSON sorokat
tail-eli (`journalctl -u fr-xdp-sni-logger.service -f -o cat`) —
`fr-webui.service` egy `SupplementaryGroups=systemd-journal` sort kapott
ehhez, ami a szokásos, minimális jogosultságú módja annak, hogy egy nem
root process olvashassa a journal-t root nélkül. A frontend oldalon egy
natív `EventSource` (nem WebSocket, nem library) csatlakozik erre a
végpontra, és minden bejövő JSON sort a "terminál" konténer aljára
fűz, automatikus görgetéssel és egy max. 300 soros korláttal (hogy a DOM
ne nőjön korlátlanul egy nyitva hagyott lapon) — sima vanilla JS, SPA
keretrendszer nélkül, a projekt többi képernyőjével konzisztens módon.

### Nyitott pontok

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
| ZTNA session-állapot (csak megjelenítési célra, ld. lent) | `/etc/fr_os/ztna_state.json` |

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

## Identitás-alapú Zero Trust hálózati hozzáférés (ZTNA, fázis 7)

Cél: egy homelab-barát, 100% lokális (nincs Okta/Azure AD/felhő-függőség)
identitás-alapú belépési kapu, ami a LAN-t vagy egy kijelölt "Production
Server Zone"-t csak sikeres bejelentkezés után enged elérni -- úgy, hogy
az adatsík (a tényleges forgalom szűrése) továbbra is 100%-ban
kernel-térben (nftables) fut, 40 Gbps-es sebességig sem lassítva le
semmit egy userspace proxy-n (Envoy/Squid) átvezetéssel. A vezérlősík (a
bejelentkezés) és az adatsík (a csomagszűrés) szigorúan külön van
választva -- ez a szakasz mindkettőt tárgyalja.

### Séma és a `require_ztna` jelölés újrahasznosítása

`frfw.config.schema.ZtnaConfig` (`enabled`, `session_ttl_seconds`,
`users: list[ZtnaUser]`) egy önálló, felhasználónevet és jelszó-hash-t
tároló felhasználó-listát ad a confighoz -- külön a webUI admin fiókjától
(`frfw.admin_account`), mert ez egy más célközönség (végfelhasználók, nem
a rendszergazda). Ahelyett, hogy egy új "védett zóna" fogalmat vezettünk
volna be, a meglévő `Rule` dataclass kapott egy `require_ztna: bool`
mezőt -- egy szabály így a from_zone/to_zone/proto/port/cím-illesztés
mellett *opcionálisan* megköveteli, hogy a forrás-IP a ZTNA-halmazban
legyen, ami ugyanazt a motort használja fel, nem egy párhuzamos
absztrakciót. A jelszavak tárolása PBKDF2-HMAC-SHA256 hash (a
`frfw.admin_account`-tal megegyező, 200k iterációs sémával) -- ez
*hashelés*, nem visszafejthető titkosítás, ami tárolt jelszavakhoz a
helyes megközelítés.

### Adatsík: nftables named set kernel-natív timeout-tal

`frfw.nft.builder` egy `authenticated_ztna_users` nevű, `flags
dynamic,timeout` halmazt renderel (csak ha `ztna.enabled`), és minden
`require_ztna: true` szabályhoz hozzáfűzi az `ip saddr
@authenticated_ztna_users` illesztést. A halmazba kerülő elemek saját,
egyedi timeout-tal kapnak felvételt (`add element ... { <ip> timeout
<n>s }`) -- ez azt jelenti, hogy a lejárt IP-ket a **kernel** dobja ki
saját maga, nulla cron jobbal vagy userspace háttérfolyamattal. Ezt
valós teszttel is megerősítettük: egy 5 másodperces timeout-tal felvett
elem 6 másodpercen belül eltűnt a halmazból, futó kód nélkül (ld.
`tests/test_ztna.py`).

### Vezérlősík: bejelentkezés a privilegizált helperen keresztül

A webUI nem futhat rootként, tehát nem módosíthatja közvetlenül a kernel
nftables-állapotát -- ez a projekt már meglévő privilégium-szeparációját
követi (ld. Biztonsági modell fent). `GET/POST /ztna/login`
(`frfw.webui.routes.ztna`) a `ZtnaConfig.users`-ben tárolt hash ellen
ellenőriz (időzítés-biztos módon -- ismeretlen felhasználónévre is
lefut a hash-számítás, hogy a válaszidőből ne legyen felhasználónév
kitalálható), majd sikeres belépéskor a klienskérés forrás-IP-jét egy új
`authorize_ztna` unix-socket paranccsal (`frfw.helper.protocol/server/
client`) küldi el a root alatt futó `fr-apply-helper`-nek, ami felveszi
az IP-t a kernel halmazba a configban beállított TTL-lel.

Fontos, közvetlen teszttel megerősített felismerés: még a *csak-olvasó*
`nft list` is root-ot/`CAP_NET_ADMIN`-t igényel (`runuser -u nobody --
nft list ruleset` → "Operation not permitted"). Emiatt a `GET
/ztna/status` (a felhasználó hátralévő session-idejét mutató publikus
oldal) sem olvashatja közvetlenül a kernel-állapotot -- ez is egy új
`ztna_status` helper-parancson keresztül megy, ugyanúgy, mint az
`authorize_ztna`. Nincs külön böngésző-oldali session-cookie: az
egyetlen tekintélyforrás az, hogy a forrás-IP *éppen most* benne
van-e a kernel halmazban, amit minden `/ztna/status` hívás élőben
lekérdez a helperen keresztül -- szándékosan nincs egy második,
elcsúszni képes állapot-forrás a böngészőben.

A megjelenítés-célú `/etc/fr_os/ztna_state.json` (ip → {username,
authorized_at}) *nem* tekintélyforrás, csak arra kell, hogy a `/ztna`
admin-képernyő emberi nevet tudjon mutatni egy IP mellett -- a tényleges
engedélyezést mindig a kernel halmaz dönti el.

### A `flush ruleset` probléma és a snapshot/restore megoldás

`frfw.nft.builder.build_ruleset()` minden alkalmazáskor egy hatókör
nélküli `flush ruleset`-tel kezd, ami minden apply-nál törli a *teljes*
kernel nftables-állapotot (az összes táblát/családot) -- ez egy
bejelentkezett ZTNA session-t egy teljesen független config-módosítás
(pl. egy DHCP-beállítás mentése) mellékhatásaként is kijelentkeztetne.
Ezt `frfw.provision.apply_all` oldja meg: az nftables-alkalmazási lépést
`frfw.ztna.snapshot_before_reload()` / `restore_after_reload()`
zárójelezi (csak ha `ztna.enabled` és nem dry-run) -- a snapshot a
`flush` előtt lekéri az aktuálisan élő elemeket a *hátralévő*
TTL-ükkel együtt, a restore pedig az új ruleset betöltése után
visszaírja őket, így egy admin-oldali config-mentés nem null-ázza le
véletlenül egy másik felhasználó aktív munkamenetét. Ezt egy valós,
nem mockolt integrációs teszt is lefedi (`test_ztna.py`): egy valós nft
halmazt flush-el, majd megerősíti, hogy a restore helyes hátralévő
TTL-lel hozza vissza a session-öket.

### Nyitott pontok

- **Nincs rate-limiting/lockout** a `/ztna/login`-on -- ez konzisztens
  a meglévő admin `/login` route-tal (az sem véd brute-force ellen), de
  egyik sem jobb ennél; ha ez éles környezetben szempont, mindkettőt
  együtt érdemes megoldani (pl. `fail2ban` a naplók alapján, ami már
  most is a projekt naplózási modelljéhez illeszkedne).
- A `/xdp` webUI képernyő (ld. fázis 4) valószínűleg ugyanazzal a
  problémával küzd, amit itt tudatosan elkerültünk: ha bármelyik route
  közvetlenül `nft`/`bpftool` hívást tesz a nem-root webUI processzből,
  az vagy hibázik jogosultság hiányában, vagy (rosszabb esetben) a
  webUI-t futtató service kapott ehhez felesleges jogosultságot. Ez itt
  nem lett javítva -- külön ellenőrzést/fázist igényelne.

## Hibrid poszt-kvantum kulcscsere a menedzsment-rétegen (fázis 8)

Cél: a webUI saját HTTPS-je és (ha telepítve van) a host sshd-je hibrid
(klasszikus + poszt-kvantum) kulcscserét ajánljon fel -- `X25519MLKEM768`
TLS 1.3-ban, `mlkem768x25519-sha256` SSH-ban --, régebbi kliensre/hostra
észrevétlenül visszaesve klasszikusra, homelab-hardveren futtatható,
külön kripto-gyorsítót nem igénylő módon. **Ez a szakasz szokatlanul sok
"nem működik úgy, ahogy elsőre tűnik" felismerést dokumentál** -- pontosan
azért, mert ez a projekt eddigi legfrissebb, legkevésbé kiforrott
technológiai rétege, és a hibás feltételezések itt drágák (egy rossz
`KexAlgorithms` sort sshd egyszerűen nem indul el vele).

### Két kemény verzió-küszöb, mindkettő ténylegesen ellenőrizve

- **TLS**: az `X25519MLKEM768` csoportot az OpenSSL csak **3.5.0**-tól
  (2025-04) ismeri. A legtöbb jelenleg csomagolt Debian -- ezen belül
  ennek a projektnek a saját installer-image-e is (ld. "Automatikus
  installer" fázis) -- ennél régebbi OpenSSL-t linkel, és ez Python-kódból
  nem kerülhető meg: a `ssl` modul azt az libssl.so-t csomagolja be, amivel
  az interpretert fordították, egy pip-csomag pedig nem tud megosztott
  rendszerkönyvtárat frissíteni. `frfw.pqc.openssl_supports_hybrid_tls()`
  ezt a fejlesztői sandboxban ténylegesen tesztelt, valós verzióellenőrzés
  (ez a sandbox OpenSSL 3.0.13-at futtat -- a hiány-ág tehát nem
  feltételezés, hanem közvetlenül megfigyelt eredmény).
- **SSH**: az `mlkem768x25519-sha256` kulcscsere-módszert az OpenSSH csak
  **9.9**-től (2024-09) ismeri. Egy régebbi sshd nemcsak hogy nem ismeri
  fel, hanem -- ez a lényeg -- egy ismeretlen algoritmusnév a
  `KexAlgorithms`-ban **el sem indítja** a démont, nem csendben kihagyja.
  `frfw.pqc.sync_ssh_kex` ezért minden hívásnál frissen lekérdezi a
  telepített sshd tényleges, befordított listáját (`sshd -Q kex`), és a
  generált drop-in-t `sshd -t`-vel validálja, mielőtt alkalmazottnak
  tekintené -- sikertelen validáció esetén visszaállítja az előző
  tartalmat (vagy törli a fájlt, ha korábban nem is létezett), nem hagy
  sshd számára feldolgozhatatlan configot a lemezen.

### A várt (és felkínált) API nem létezik: `SSLContext` nem tud csoport-listát

A kérés eredetileg a Python `ssl.SSLContext`-en keresztüli, kódból
történő csoport-preferencia beállítást irányozta elő. Ez -- ellenőrzött,
nem feltételezett tény -- **nem lehetséges** a CPython stdlib-bel:
`SSLContext.set_ecdh_curve()` úgy néz ki, mintha ezt tudná, de nem erről
van szó. Közvetlen teszttel megerősítve (ld. `tests/test_pqc.py`):

```python
ctx.set_ecdh_curve("X25519")           # egyetlen név: működik
ctx.set_ecdh_curve("X25519:P-256")     # kettő, kettősponttal: ValueError
```

Mindkét név önmagában érvényes TLS 1.3 csoportnév, a kettősponttal
összefűzött lista mégis elutasításra kerül -- ez azt jelzi, hogy ez a
függvény egyetlen klasszikus EC-görbét (`OBJ_sn2nid`-stílusú keresés)
tud beállítani, sosem prioritási listát, és egy hibrid PQC-csoportnév
eleve nincs is ebben a klasszikus görbenév-táblában, függetlenül attól,
hogy a mögöttes OpenSSL egyébként támogatja-e. A dokumentált, ténylegesen
működő mechanizmus egy TLS 1.3 csoport-*lista* beállítására az OpenSSL
saját config-fájljának `[system_default_sect]` `Groups=` direktívája --
ugyanaz a mechanizmus, amit Debian/Fedora már ma is használ
rendszerszintű `CipherString`-alapú kripto-politika-alapértékekhez (ld.
`man 5 config`). Mivel az OpenSSL ezt a fájlt csak egyszer, a folyamat
indulásakor olvassa be, a beállítás módosítása mindig `fr-webui`
újraindítását igényli ahhoz, hogy érvénybe lépjen -- ugyanaz a "változás
alkalmazáshoz/újraindításhoz kötött" valóság, amivel a projekt minden
más alrendszere is együtt él (ld. pl. a frissítési mechanizmus saját,
hasonló újraindítás-üzenetét).

Ezt a mechanizmust `frfw.pqc.write_openssl_pqc_conf` generálja
(`/etc/fr_os/webui_pqc_openssl.cnf`), amire `fr-webui.service`
feltétel nélkül `OPENSSL_CONF=`-fal mutat (ld. az unit fájlt) -- ez a
fájl mindig létezik és mindig érvényes (klasszikus csoportokkal, ha a
hibrid mód ki van kapcsolva), így ez a környezeti változó sosem törik el
semmit, és kizárólag ezt az egy folyamatot érinti, sosem a rendszerszintű
`/etc/ssl/openssl.cnf`-et. A kérésben szereplő, ténylegesen támogatott
`ssl.SSLContext`-beállítás (`minimum_version`/`maximum_version` TLS
1.3-ra rögzítve) külön, `frfw.pqc.tls_ssl_context_factory`-ként valósult
meg, uvicorn saját `ssl_context_factory=` bővítési pontján keresztül
bekötve (`frfw.webui.server`) -- ezt valós `uvicorn.Config(...).load()`
hívással, valódi generált tanúsítvánnyal is leteszteltük, nem csak
elszigetelt unit teszttel.

### SSH: `sshd_config.d` drop-in, sosem a fő fájl

`frfw.pqc.sync_ssh_kex` egy `/etc/ssh/sshd_config.d/50-fr_os-pqc-kex.conf`
drop-in-t ír/töröl (Debian saját, alapból bekapcsolt `Include
/etc/ssh/sshd_config.d/*.conf` mechanizmusát kihasználva, ld. a
generált fájl saját fejlécét) -- sosem nyúl közvetlenül
`/etc/ssh/sshd_config`-hoz. A futó démont *reload*-olja, sosem
restart-olja: a reload új kapcsolatokhoz olvassa be újra a configot
anélkül, hogy bármelyik már élő SSH-munkamenetet (akár azt is, amin
keresztül az admin épp ezt a változtatást alkalmazza) megszakítaná.

### Vezérlősík: config-jelölés, sosem közvetlen beavatkozás

`config.pqc.enabled` (`frfw.config.schema.PqcConfig`) ugyanazt a
"szerkeszd a nyers YAML dict-et, validálj, mentsd a privilegizált
helperen keresztül" mintát követi, mint minden más képernyő -- a
beállítás mentése sosem módosítja közvetlenül a TLS-t vagy sshd-t, az
csak a következő `apply`-nál történik meg
(`frfw.provision.apply_all` 6. lépéseként: `frfw.pqc.sync_tls_pqc_conf`
+ `sync_ssh_kex`), pontosan úgy, mint egy nftables-szabály vagy XDP
blocklist-változtatás.

### Státusz-képernyő (`/system`) és a "quantum-safe" jelzés valódi hatóköre

A `GET /system` (admin) és a dashboard kis jelvénye
(`frfw.pqc.PqcStatus.quantum_safe`) két, szándékosan külön tartott
fogalmat kombinál: *host-képesség* (támogatja-e az adott gép telepített
OpenSSL/OpenSSH build-je ezt egyáltalán -- gépfüggő tény, független a
configtól) és *alkalmazott állapot* (mit mond a legutóbb generált
fájl/drop-in ténylegesen -- ez elmaradhat egy még nem alkalmazott
config-módosítástól, ugyanaz a "config vs. alkalmazott állapot
elcsúszhat, amíg nem futtatsz apply-t" minta, ami az XDP képernyőn is
megvan). A "quantum-safe" jelzés **nem** állítja, hogy az épp nyitva
lévő böngésző-/SSH-kapcsolat ténylegesen a hibrid csoportot használja --
ennek ellenőrzéséhez az adott TLS/SSH-session tárgyalt csoportjának
introspekciója kellene, amit sem a Python `ssl` modulja, sem ez a modul
nem tesz meg. A képesség-ellenőrzés maga (`ssl.OPENSSL_VERSION_INFO`,
`sshd -Q kex`) nem igényel jogosultságot, ezért -- a ZTNA kapu
kernel-állapot-olvasásaitól eltérően -- közvetlenül a nem-privilegizált
webUI-folyamatban fut, nem a helperen keresztül.

### Ellenőrzés hatóköre -- őszintén kimondva

Ez a modul úgy készült és lett tesztelve, hogy **nincs hozzáférés valós
OpenSSL 3.5+ vagy OpenSSH 9.9+ build-hez** (ez a fejlesztői sandbox
OpenSSL 3.0.13-at futtat, sshd egyáltalán nincs telepítve). Minden
képesség-ellenőrzést közvetlenül, éles binárison/interpreteren
ellenőriztünk *a hiány helyes felismerésére* (a sandbox OpenSSL-je
helyesen "nem támogatott"-ként azonosítja magát, az sshd hiánya
helyesen "nincs telepítve"-ként), és a `set_ecdh_curve` korlátozás
ténylegesen, élesben lett igazolva. A pozitív ág -- "a hibrid csoport
ténylegesen, végponttól-végpontig letárgyalásra kerül egy valós
kliens/sshd ellen" -- viszont *specifikáció szerint implementáltnak*,
nem pedig ugyanúgy függetlenül ellenőrzöttnek tekintendő, mint ahogy azt
a projekt más, kernel-közeli alrendszereinél (nftables, XDP, ZTNA) ez a
dokumentum eddig mindenhol állíthatta.

### Nyitott pontok

- **Valós OpenSSL 3.5+/OpenSSH 9.9+ ellen sosem tesztelve** (ld. fent) --
  amint elérhető ilyen build (pl. Debian trixie/13 vagy újabb), érdemes
  egy valós hibrid handshake-et Wireshark/`openssl s_client -groups`
  szintjén is megerősíteni.
- **A live-build installer alapképe** (ld. "Automatikus installer" fázis)
  jelenleg egy régi, Ubuntu-patch-elt snapshot-ot használ, aminek
  OpenSSL/OpenSSH verziója szinte biztosan a küszöb alatt van -- ez a
  funkció ezen az image-en ma csak a "TLS 1.3-only, klasszikus
  csoportok" ágon fut, ami önmagában is valódi hardening, csak nem a
  kért PQC-hibrid.
- **Nincs automatikus `fr-webui` újraindítás** a TLS-oldali beállítás
  alkalmazásakor -- ez tudatos döntés (ld. fent, "változás
  alkalmazáshoz/újraindításhoz kötött"), nem hiányzó funkció, de
  admin-oldali kézi lépést igényel.

## Helyi DNS/XDP hirdetésblokkoló (fázis 9)

Cél: hosts-formátumú blokklisták (alapból a StevenBlack "unified" lista)
letöltése, deduplikálása, és a kapott domain-halmaz kiszolgálása egy
100% lokális DNS-rezolverből -- nagy volumenű (tízezres nagyságrendű)
listáknál userspace hash-tábla/szöveges fájl, nem kernel-memória --, egy
opcionális, kis "kritikus" részhalmazzal a már meglévő 4. fázis XDP LPM
trie-jában. **Fontos, előre tisztázandó pontosítás**: ezt a fázist a
kérés úgy fogalmazta meg, mintha a projektnek már lenne saját DNS-
rezolvere ("reload the DNS resolver") -- ellenőrizve: **nem volt**
(a DHCP-t végző Kea sosem végzett DNS-feloldást, ld. `frfw.kea` saját
docstringjét, ami kifejezetten "nem dnsmasq"-ot mond). Ez a fázis
vezeti be az első DNS-rezolvert a projektbe, nem egy meglévőt bővít.

### Miért dnsmasq, és miért egy saját, dedikált példány

A "lightweight, legacy x86 hardveren is fusson" megkötés dnsmasq-ra
mutat unbound helyett (lényegesen kisebb erőforrás-igény, natív
hosts-fájl-alapú blokkolás `addn-hosts=`-szal -- pontosan a kért
"host-file" mechanizmus). A `frfw.adblock.dns_service` modul viszont
tudatosan **nem** a Debian-csomag alapértelmezett `dnsmasq.service`/
`dnsmasq.conf`-ját bővíti drop-in-nel: a `/etc/dnsmasq.d/` könyvtár
csak akkor töltődik be automatikusan, ha a `conf-dir=` sor ki van
kommentezve az `/etc/dnsmasq.conf`-ban, ami friss telepítésen nem
garantált, és a gép egyébként is futtathat rendszer-dnsmasq-ot valami
mástól függetlenül. Ehelyett egy teljes, önálló konfigurációt generál
(`frfw.paths.ADBLOCK_DNSMASQ_CONF_PATH`) és egy saját, dedikált
systemd unitot vezérel (`fr-adblock-dns.service`) -- pontosan ugyanaz a
"egy teljes generált config, egy dedikált service" minta, amit a Kea
DHCP-motor is használ (`frfw.kea.KEA_CONFIG_PATH`/`KEA_SERVICE_NAME`).

### Letöltés sosem `apply`-on belül

A blokklisták több megabájtosak és több tízezer sorosak lehetnek; ezeket
minden `firewall-cli apply`-nál (ami egy admin-munkamenet közben akár
sokszor lefuthat) újra letölteni pazarló és lassú lenne. A letöltés+
parse+dedup ezért egy külön, explicit művelet: `firewall-cli
adblock-refresh` (napi `fr-adblock-refresh.timer`-rel meghívva, ld.
lent) vagy a webUI "Refresh now" gombja (ami az apply-helper egy új,
`refresh_adblock` socket-parancsán megy át -- a letöltés maga nem
igényel jogosultságot, de a végleges írás `/etc/fr_os` alá és ez a
teljes művelet a webUI processzből sosem futhat közvetlenül, ld. lent).
`frfw.provision.apply_all` ezzel szemben csak azt egyezteti, hogy a
dnsmasq-példány fut-e (vagy áll-e) a confignak megfelelően, és a már
korábban letöltött listát szolgálja ki -- sosem nyúl a hálózathoz.

### Letöltés: `urllib.request`, nem új függőség

A projekt egyetlen meglévő "tölts le valamit az internetről" precedense
(`frfw.update._fetch_json`) a stdlib `urllib.request`-et használja,
explicit `timeout` paraméterrel, retry nélkül, egyetlen "seam"
függvényen keresztül -- sem `requests`, sem `httpx` nem szerepel futásidejű
függőségként ebben a projektben (a `pyproject.toml` `dev` extra-jában
lévő `httpx` kizárólag a FastAPI `TestClient` belső szállítója, nem
alkalmazáskód). `frfw.adblock` ugyanezt a mintát követi
(`_fetch_url`), és a kért "aszinkron/non-blocking" viselkedést egy
stdlib `concurrent.futures.ThreadPoolExecutor`-ral éri el (I/O-kötött
feladat, nem CPU-kötött, a GIL nem számít) -- valódi `asyncio`/`aiohttp`
helyett, ami új függőség lenne ezen a projekten sosem indokolt módon.

### A meglévő XDP LPM trie újrahasznosítása, nem egy második térkép

A kérés "kritikus részhalmaz" ötletét szó szerint, a meglévő
`frfw.xdp.sync_blocklist`/`XdpSniFilterConfig.blocklist` mechanizmus
újrahasznosításával valósítottuk meg -- **nem** egy második BPF map
bevezetésével. `frfw.provision.apply_all` az XDP-lépés előtt, memórián
belül (a `config.yaml`-ba sosem visszaírva)
`dataclasses.replace`-szel egyesíti a `xdp_sni_filter.blocklist`-et a
már letöltött ad-block lista első `adblocker.xdp_critical_limit`
(alapból 0, azaz kikapcsolva) domainjével -- pontosan úgy, ahogy egy
ZTNA-engedélyezett IP sem kerül be a tűzfalszabályok fájljába.
`xdp_critical_limit == 0` esetén ez a lépés nem nyúl az XDP-hez
egyáltalán -- a hirdetésblokkoló bekapcsolása sosem kapcsolja be
csendben az XDP-t is.

### Vezérlősík: config-jelölés, sosem közvetlen beavatkozás

`config.adblocker` ugyanazt a "szerkeszd a nyers YAML dict-et, validálj,
mentsd a privilegizált helperen keresztül" mintát követi, mint minden
más képernyő. Az élő domain-számláló (`GET /adblock`) és a resolver
fut/nem-fut jelvény közvetlenül, jogosultság nélkül a webUI processzben
számolódik: egy hosts-formátumú fájl sorainak megszámolása és egy
`systemctl is-active` lekérdezés egyaránt nem igényel root-ot vagy
`CAP_NET_ADMIN`-t (ellentétben a ZTNA kapu kernel-állapot-olvasásával),
így itt nincs szükség a helperen történő round trip-re.

### Valós, kézzel megerősített ellenőrzés

A tényleges blokkolási mechanizmust (nem csak a `dnsmasq --test`
szintaxis-ellenőrzést, ami magában a tesztsorozatban is fut) kézzel,
élesben megerősítettük: egy valós dnsmasq-példányt indítottunk a
generált configgal egy próba-porton, és `dig`-gel lekérdezve a
blokklistán szereplő domain `0.0.0.0`-ra oldódott fel, míg egy nem
listázott domain esetén dnsmasq továbbította a lekérdezést felfelé (nem
az addn-hosts-ból szolgálta ki) -- pontosan a várt viselkedés. Ez a
konkrét élő-lekérdezéses forgatókönyv **nem** automatizált tesztként
került be: ismételten reprodukálható sima shell-ből és sima `python3
-c`-ből (ugyanazzal a `subprocess.Popen`-hívással), de nem a projekt
saját pytest-folyamatán belülről ebben a sandboxban -- a dnsmasq
gyermekfolyamat a helyes portra bind-el (`ss -ulnp`-vel megerősítve),
mégsem válaszol egy teljesen külön shellből érkező lekérdezésre, ami
kizárja, hogy ez az frfw-kód hibája lenne. Ez egy folyamat-/hálózati
névtér-jellegű sajátossága ennek a CI-sandboxnak a pytest alatti
gyermekfolyamat-indításnak, nem egy állandóan skippelt vagy flaky tesztet
érdemlő hiba -- ld. `tests/test_adblock_dns_service.py` saját, részletes
kommentjét.

### Nyitott pontok

- **A DHCP kliensek DNS-szervere nincs automatikusan erre a
  rezolverre állítva.** `DhcpPool.dns_servers` változatlanul azt
  szolgáltatja, amit az admin explicit módon beállított -- a Kea
  DHCP-konfiguráció automatikus átírása a router saját LAN-címére mint
  DNS-szerverre külön, nem triviális integrációs lépés lenne (érintené
  minden meglévő DHCP-pool viselkedését), amit ez a fázis tudatosan nem
  végzett el csendes mellékhatásként.
- **Nincs valós hibrid handshake-szintű Wireshark-elemzés** a letöltési
  folyamatról (a HTTPS-kapcsolat GitHub/StevenBlack felé az egyetlen
  bizalmi határ, ugyanaz a korlátozás, mint a frissítési mechanizmusnál).
- **Élő dnsmasq-lekérdezéses automatizált teszt hiánya** (ld. fent) --
  ha egy jövőbeli CI-környezetben ez a sandbox-sajátosság nem áll fenn,
  érdemes újra megpróbálni automatizálni.

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
