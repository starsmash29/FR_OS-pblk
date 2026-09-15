# Roadmap

Fázisonkénti fejlesztési terv. Minden fázis végén a rendszernek működő,
tesztelhető állapotban kell lennie egy sima Debian VM-en, mielőtt a következő
fázis elkezdődik. Az architektúra döntéseket lásd: [ARCHITECTURE.md](ARCHITECTURE.md).

## 1. fázis – Firewall-motor magja — **kész**

- [x] `ARCHITECTURE.md` / `ROADMAP.md`
- [x] YAML konfig-séma tervezése (interfészek, zónák, szabályok, NAT)
- [x] `frfw` Python csomag: séma + validáció (`frfw.config`)
- [x] nftables ruleset-generátor (`frfw.nft`)
- [x] `firewall-cli` (`validate` / `render` / `apply`)
- [x] Egységtesztek, valós `nft -c` szintaxis-ellenőrzéssel
- [x] Példa homelab konfiguráció (`examples/config.yaml`)

**Elfogadási kritérium**: `firewall-cli apply examples/config.yaml` egy sima
Debian VM-en (nftables telepítve) hibamentesen legenerálja és betölti a
ruleset-et, `nft list ruleset` a várt szabályokat mutatja.

## 2. fázis – Rendszerintegráció — **kész**

- [x] systemd unit a firewall-motorhoz (boot-kori automatikus config-apply):
      `systemd/fr-firewall.service`, a Debian `nftables.service`
      mintáját követve (korai boot, `Before=network-pre.target`)
- [x] systemd unit a webUI-hoz: `systemd/fr-webui.service`, egyelőre egy
      placeholder binárisra mutat (`fr-webui-placeholder`), a tényleges
      FastAPI app a 3. fázisban kerül be *(3. fázisban lecserélve a
      valódi `fr-webui` binárisra, ld. lent)*
- [x] Hálózati interfészek automatikus felismerése -- a tervezettől
      eltérően nem az `ip link` parancs kimenetét parse-oljuk, hanem
      közvetlenül a `/sys/class/net/` sysfs fát olvassuk
      (`frfw.netdetect`): ugyanazt az információt adja, függőségmentes,
      és sokkal egyszerűbb tesztelni (fake sysfs fa egy tmp könyvtárban).
      `firewall-cli detect-interfaces` listázza a talált NIC-eket,
      `firewall-cli assign-interfaces --wan ... --lan ... [--opt zone:dev]`
      pedig ebből generál egy minimális, érvényes konfigurációt
      (pfSense-szerű "melyik NIC micsoda" telepítési lépés,
      nem-interaktív/szkriptelhető formában)
- [x] Konfig-perzisztencia: `/etc/fr_os/config.yaml` kanonikus hely
      (`frfw.paths`), a CLI minden parancsa erre defaultol; minden valós
      (nem dry-run) `apply` előtt a futó ruleset-et időbélyegzett backupba
      menti (`/etc/fr_os/backups/`, alapból 10 megőrzött verzió),
      `firewall-cli rollback [--list]` a legutóbbira áll vissza
- [x] Root-jogosultság elválasztás: `frfw.helper` -- root alatt futó
      "apply-helper" démon (`firewall-helper` / `fr-apply-helper.service`)
      egy Unix socketen (`fr-apply-helper.socket`, socket-activation,
      csoport-alapú hozzáférés-vezérléssel) fogad egy minimális
      JSON-protokollt (`ping`/`apply`/`rollback`); a végpont sosem fogad
      el hívótól kapott fájlútvonalat, mindig a kanonikus configot/backup
      könyvtárat használja -- így a jövőbeli unprivileged webUI sem
      kaphat általános fájlolvasási/-írási vagy parancsvégrehajtási
      képességet a root démonon keresztül

**Elfogadási kritérium**: friss Debian VM-en `scripts/install-system-integration.sh`
lefuttatása után `systemctl enable --now fr-firewall` a rendszer boot-kor
automatikusan alkalmazza az utoljára mentett konfigurációt (`/etc/fr_os/config.yaml`);
interfész-felismerés és -hozzárendelés parancssorból lefuttatható
(`firewall-cli detect-interfaces`, `firewall-cli assign-interfaces`); rossz
config alkalmazása után `firewall-cli rollback` visszaállítja az előzőt.

## 3. fázis – WebUI — **kész**

- [x] FastAPI backend a `frfw` motor fölött (`frfw.webui`) -- a webUI a
      configot dict-szinten szerkeszti (`frfw.webui.config_store`), majd
      minden mentés előtt a teljes dokumentumot újra lefuttatja
      `frfw.config.parse_config`-on: nincs "a webUI szerint érvényes"
      külön fogalom, csak "a `frfw` séma szerint érvényes"
- [x] Alapképernyők (szerver-renderelt Jinja2 + egyszerű CSS, SPA-keretrendszer
      nélkül, ahogy az ARCHITECTURE.md eltervezte): dashboard/státusz,
      interfészek (a felismert NIC-ekkel együtt), szabályok, NAT
      (masquerade + port-forward), DHCP
- [x] **DHCP hozzáadva a konfig-sémához és a motorhoz is** (nem csak a
      webUI-hoz) -- ez menet közben derült ki szükségesnek: a `dhcp`
      backend kiválasztása (Kea, a felhasználóval egyeztetve) új
      séma-szekciót (`interfaces[].address`, `dhcp.<zone>`), egy Kea
      JSON-generátort (`frfw.kea`, valós `kea-dhcp4 -t` szintaxis-ellenőrzéssel)
      és egy interfész-cím-alkalmazó modult (`frfw.ifaddr`, `ip addr`
      alapú) igényelt; ezeket egy közös `frfw.provision.apply_all`
      fogja össze cím→tűzfal→DHCP sorrendben, amit a CLI és a webUI is
      egyaránt használ
- [x] Admin bejelentkezés: egyetlen helyi admin fiók
      (`frfw.admin_account`, PBKDF2-HMAC-SHA256 -- szándékosan nem
      bcrypt/argon2, hogy ne legyen fordított C-kiterjesztés függőség),
      aláírt session-cookie (`itsdangerous`); `firewall-cli
      set-admin-password` állítja be/vissza CLI-ből
- [x] HTTPS alapból: önaláírt tanúsítvány generálása első induláskor
      (`frfw.webui.tls`, `openssl` meghívásával); a webUI unprivileged
      `fr_os-webui` userként fut, 443-as portra kötéshez
      `AmbientCapabilities=CAP_NET_BIND_SERVICE` (ugyanez a minta, amit a
      Kea saját systemd unit-ja is használ)
- [x] Config mentés/visszaállítás: a mentés a privilegizált apply-helperen
      át történik (`save_config` parancs, ld. lent) -- **git-alapú
      verziózás nem készült el** (a `ROADMAP.md` eredetileg "esetleg"-ként
      jelölte); helyette az nftables ruleset-szintű backup/rollback
      (2. fázis) marad az egyetlen "vissza az előzőre" mechanizmus.
      Config-szintű (nem csak ruleset-szintű) verziózás nyitott kérdés
      egy következő iterációra.
- [x] Root-jogosultság-elválasztás kiegészítve: `frfw.helper` új
      `save_config` parancsa (JSON-protokoll, ld. 2. fázis) validál és ír
      egy YAML configot -- a webUI így sosem ír közvetlenül
      `/etc/fr_os/config.yaml`-ba, csak a helperen keresztül

**Elfogadási kritérium**: böngészőből elérhető felületen létrehozható egy
teljes WAN/LAN szabálykészlet + NAT, mentés után a `frfw` réteg ugyanazt a
YAML-t generálja, mint amit CLI-ből kézzel írnánk. ✅ Ellenőrizve: a
`tests/webui/test_routes.py::test_full_wan_lan_nat_round_trip_matches_cli_expectations`
teszt böngésző-szimulált (FastAPI `TestClient`) kérésekkel épít fel egy
teljes WAN/LAN/NAT configot, amit aztán `frfw.config.load_config` +
`frfw.nft.build_ruleset` dolgoz fel -- ugyanazon a kódúton, amin a CLI is
menne.

## Kiegészítés – AI IDS/IPS (mock) — **kész**

A 3. fázis után, a 4. fázis (XDP/eBPF) előtt beillesztett kiegészítés,
mivel a UI és a konfigurációs mag már készen állt a fogadására. **Nem
része az eredeti 6 fázisnak** — ide azért került, mert a valós
megvalósítás előfeltétele (a Phase 4 traffic capture) még nem létezik.

- [x] `ai_ids` séma-szekció (`enabled`/`learning_days`/`retrain_time`/
      `excluded_macs`), teljes `frfw.config.loader` validációval
- [x] `frfw.ai_ids.AIIDSEngine` — **explicit mock motor**: a DHCP statikus
      foglalásokból építi az "ismert eszközök" listáját, MAC-alapú
      determinisztikus (nem re-random) kitalált profilokkal (kockázati
      címke, top protokollok, ismert domainek száma), és egy perzisztált
      állapottal (locked/retrain-időbélyeg) a szimulált tanulási %-hoz.
      `train_isolation_forest` egy explicit `NotImplementedError`-t dobó
      stub a jövőbeli scikit-learn integrációhoz.
- [x] `firewall-cli ai-ids-retrain` (unprivileged) +
      `fr-ai-ids-retrain.timer`/`.service` (napi, alapból 03:30) —
      infrastruktúra a napi újratanításhoz, magát a (mock) újratanítást
      végrehajtva
- [x] WebUI: "AI IDS/IPS" képernyő (eszköztáblázat, Force
      Retrain/Lock Profile gombok, beállítások), dashboard globális
      tanulási progress bar — mindegyik jól látható "MOCK DATA"
      figyelmeztetéssel
- [x] **Biztonsági modell konzisztencia**: a Force Retrain/Lock Profile
      *nem* megy a `frfw.helper`-en át (nincs rá szükség, root-mentes
      userspace állapotváltás) — csak a config-mentés (`ai_ids` szekció)
      megy a szokásos `save_config`-on keresztül. Ld.
      [ARCHITECTURE.md](ARCHITECTURE.md#ai-idsips-mock).

**Elfogadási kritérium**: a webUI-n keresztül be- és kikapcsolható az AI
IDS, az eszköztáblázat DHCP-foglalásokból populálódik, Force
Retrain/Lock Profile azonnal látható hatással jár, és a képernyő
egyértelműen jelzi, hogy az adatok mock-ok. ✅ Ellenőrizve:
`tests/test_ai_ids_schema.py`, `tests/test_ai_ids_engine.py`,
`tests/webui/test_ai_ids_routes.py` — a meglévő 108 teszt is hibátlanul
fut tovább (141 összesen).

**Nyitva maradt kérdés a jövőre**: a `fr-ai-ids-retrain.timer` statikus
`OnCalendar=03:30`-at használ, nem követi automatikusan az
`ai_ids.retrain_time` config-értéket (ehhez egy privilegizált
timer-drop-in újraírás kellene — kis hatókörű, de nem triviális
kiegészítés).

## 4. fázis – XDP/eBPF gyors útvonal: kernel-szintű TLS SNI szűrő — **kernel-program + Python orchestrator + webUI kész, teljesítménymérés nyitott**

A hatókör a felhasználóval egyeztetve a korábban itt tervezett generikus
IP fast-drop blocklistról egy konkrétabb, gyakorlatiasabb funkcióra
módosult: **TLS ClientHello-ból kiolvasott SNI (domain név) alapján
kernel-térben eldobott/átengedett forgalom**. A teljes indoklás,
architektúra és a BPF verifier-rel folytatott (meglepően hosszú) küzdelem
összefoglalója: [ARCHITECTURE.md](ARCHITECTURE.md#xdpebpf-gyors-útvonal-kernel-szintű-tls-sni-szűrő-fázis-4).

- [x] **Kernel-oldali program megírva és valósan verifikálva**
      (`bpf/xdp_sni_filter.c`): TLS record/handshake/ClientHello/
      extensions parsing, SNI kiolvasás, `BPF_MAP_TYPE_LPM_TRIE`
      blocklist-keresés (`reverse("." + hostname)` kulcs-séma, ami
      helyesen blokkolja az al-domaineket, de nem a csak
      karakter-szinten hasonló, nem-al-domain neveket), `XDP_DROP`
      találat esetén, async `BPF_MAP_TYPE_RINGBUF` esemény userspace
      naplózáshoz. Nem csak lefordult -- ténylegesen betöltve és
      elfogadva a valódi kernel BPF verifier által
      (`ip link set dev lo xdpgeneric obj xdp_sni_filter.o sec xdp`),
      és egy kézzel összeállított, valós TLS 1.3 ClientHello-val
      végponttól-végpontig letesztelve: egy blokklistás SNI-jű
      kapcsolat kapcsolat teljesen elakad (minden retranszmisszió is
      eldobásra kerül), egy nem-blokkolt SNI hiánytalanul átmegy, és a
      ring buffer esemény helyesen dekódolódik userspace oldalon.
- [x] **`frfw.xdp` Python orchestrator megírva**: fordítás
      (`ensure_compiled`, csak ha nincs előre lefordított `.o`),
      betöltés + pinning egyszer minden interfészhez megosztva
      (`load_and_pin`, `bpftool prog loadall ... pinmaps ...`),
      natív→generic XDP mód fallback-kel csatolás (`attach`), blocklist
      szinkronizálás a configgal (`sync_blocklist`), és egy közvetlen
      `ctypes` `libbpf` binding a ring buffer lock-mentes olvasásához
      (`RingBufferReader`) -- mindegyik valósan letesztelve ebben a
      sandboxban, mock nélkül, a valódi kernel/bpftool/libbpf ellen.
- [x] **Config-séma + betöltő validáció**: `xdp_sni_filter` szekció
      (`enabled`, `interfaces`, `blocklist`), hosztnév-formátum és a
      kernel-oldali `MAX_SNI_LEN` korlát ellenőrzésével.
- [x] **`frfw.provision.apply_all`** negyedik lépésként hívja
      `frfw.xdp.sync_sni_filter`-t.
- [x] **`fr-xdp-sni-logger` systemd daemon**: a ring buffert folyamatosan
      olvassa (blokkoló poll, nem busy-wait) és journald-ba naplózza a
      találatokat.
- [x] **`firewall-cli xdp-status`**: csatolt interfészek + csomag-
      számlálók megjelenítése.
- [x] **WebUI képernyő** (`/xdp`): állapot-kártya (interfész + zöld/sárga/
      piros badge natív/generic/letiltva-vagy-még-nem-alkalmazva
      állapothoz), beállítások (enabled/interfészek/blocklist,
      `frfw.webui.actions.try_save`-en keresztül mentve, ugyanaz a
      "csak a configot módosítja, a tényleges csatolás a következő
      apply-nál történik" minta, mint minden más képernyőn), egyenkénti
      domain-eltávolítás, és egy élő napló Server-Sent Events-en
      keresztül (`GET /xdp/logs/stream`, `journalctl -u
      fr-xdp-sni-logger.service -f` tail-elve -- nem a kernel ring
      buffer közvetlen, root-only olvasása), sima vanilla JS
      `EventSource`-szal a frontend oldalon, SPA-keretrendszer nélkül.
- [ ] **Live-build integráció**: a `.o` fájl előre-fordítása és
      image-be csomagolása a build pipeline részeként.
- [ ] Teljesítményteszt (iperf3-szerű, valós TLS-forgalommal) 10G/40GbE
      hardveren, natív (`xdpdrv`) módban — ez a sandbox erre alkalmatlan
      (nincs megfelelő NIC/forgalom-generátor); a program *helyessége*
      igazolt, a natív módú, nagy csomagsebességű *teljesítmény-előny*
      viszont csak megfelelő teszthardveren mérhető.
- [ ] Döntés: elég-e az XDP, vagy szükséges a DPDK (a fenti
      teljesítménymérés eredményétől függ)
- [ ] **AI IDS valós adatgyűjtés**: a mock `frfw.ai_ids` motor lecserélése
      valós per-eszköz flow-jellemzőkre (csomagméret/-időzítés eloszlás,
      protokoll-mix, cél-diverzitás) épülő detekcióra, `scikit-learn`
      `IsolationForest`-tel (`frfw.ai_ids.train_isolation_forest` már
      előkészített, de jelenleg `NotImplementedError`-t dobó stub) --
      ez egy külön, a TLS SNI szűrőtől független adatforrást igényelne,
      amit a fenti munka nem old meg.

**Elfogadási kritérium** (eredeti megfogalmazás): mért, dokumentált
teljesítményjavulás XDP be- és kikapcsolt állapot között, ugyanazon a
hardveren -- ez a rész továbbra is nyitott, valós 10G/40GbE hardver
hiányában (ld. fent). A funkcionális helyesség (a szűrő ténylegesen,
bizonyíthatóan biztonságosan és a specifikáció szerint működik) viszont
ebben a fázisban igazolást nyert.

## 5. fázis – Automatikus installer

- [x] live-build alapú hibrid live ISO (`installer/live-build/`,
      `installer/build-live-image.sh`) -- teljes frfw stack (nftables,
      Kea DHCP, Python/pip csomagok, webUI, AI IDS mock) előre telepítve
      a squashfs image-be
- [x] First-boot script (`scripts/fr-first-boot.sh` +
      `systemd/fr-first-boot.service`): admin jelszó generálás
      (`firewall-cli set-admin-password --generate`), interfész-detekció,
      összes fr-*.service engedélyezése és elindítása -- idempotens, csak
      egyszer fut le
- [x] Build pipeline CI-ból is indítható (`.github/workflows/build-installer.yml`,
      `workflow_dispatch`)
- [x] **Valós, végponttól-végpontig futtatott build ellenőrizve**: a teljes
      `installer/build-live-image.sh` pipeline ténylegesen lefutott, és egy
      valódi, bootolható (`file`: "ISO 9660 CD-ROM filesystem data
      (DOS/MBR boot sector), bootable") ~327 MB hibrid ISO-t adott --
      a squashfs-t kicsomagolva és ellenőrizve: a `frfw` csomag pip-pel
      telepítve, `firewall-cli` a helyén, mind a 7 `fr-*.service`/`.timer`
      egység a helyén, `fr-first-boot.service` engedélyezve
      (`multi-user.target.wants/`-ban), az ideiglenes `/opt/frfw-src`
      forráskönyvtár helyesen eltávolítva. A first-boot hook logikáját
      (pip install + service enable) manuálisan, chroot-on belül külön is
      lefuttattam ugyanezzel az eredménnyel.
- [ ] **Még nem ellenőrzött**: az ISO tényleges elindítása virtuális vagy
      valódi gépen (BIOS boot, first-boot script valós lefutása friss
      rendszeren, webUI elérése első bootnál) -- a fenti ellenőrzés a
      build kimenetét (squashfs tartalma) validálta statikusan, nem egy
      élő boot-ot.

**Ismert korlátozások** (ennek az egy konkrét, nagyon régi,
Ubuntu-patch-elt live-build snapshotnak (`3.0~a57`) a limitációi -- lásd
`installer/live-build/auto/config` fejléc-kommentjeit a teljes,
forráskód-szintű indoklásért minden pontról):
- Csak BIOS/syslinux, nincs UEFI támogatás.
- `--debian-installer false`: a live-build saját "telepítsd a lemezre"
  varázslója (`--debian-installer live`) nincs bekapcsolva, mert ez a
  snapshot egy hardcode-olt, nem létező csomaglistát (`lilo`,
  `linux-image-2.6-amd64`) próbálna telepíteni hozzá minden nem-Ubuntu
  módban. Emiatt a jelenlegi ISO egy **teljes, működő live rendszer**,
  amibe be lehet bootolni és rögtön használható -- de nem egy "másold a
  lemezre" klasszikus telepítő varázsló. Egy friss (nem ennek a
  sandboxnak az) live-build csomaggal ez valószínűleg simán bekapcsolható.
- Több apró, ugyanennek a snapshotnak Debian-inkompatibilis
  alapértelmezéséből eredő hiba lett kézzel javítva/dokumentálva:
  Ubuntu-specifikus mirror/kulcs/kernel-csomagnevek, hiányzó `rsvg`
  bináris (splash grafika eltávolítva), hiányzó `bootlogo` cpio
  archívum, `isohybrid` rossz csomagnévről történő keresése, és a
  chroot hook-oknak egy régebbi `config/hooks/*.chroot` konvenciót kell
  használniuk (`config/hooks/live/` almappa itt csendben figyelmen
  kívül van hagyva).

**Elfogadási kritérium**: USB-ről telepítve, semmilyen manuális
csomagtelepítés/terminálmunka nélkül működő webUI-t kap a felhasználó.
A build oldal (squashfs tartalma) ellenőrizve, ✅. A tényleges USB-ről
bootolás + first-boot élmény valós/virtuális gépen még nincs
kipróbálva -- ez a fázis lezárása előtti utolsó, hardver/VM-hozzáférést
igénylő lépés.

## 6. fázis – Frissítési mechanizmus — **kész**

- [x] Verzióellenőrzés + changelog: `frfw.update.check_latest`/`list_releases`,
      a konfigurált (vagy alapértelmezett) GitHub repo Releases API-ja
      ellen, jogosultság nélkül, minden webUI oldalbetöltéskor frissen
      lekérdezve (nincs külön "utoljára ellenőrizve" állapot -- lásd a
      modul docstringjét, miért nem kell)
- [x] WebUI-ból indítható update-folyamat: `/update` képernyő + egy
      külön, privilegizált `fr-update-helper` daemon/socket (szándékosan
      NEM a meglévő tűzfal-apply-helper bővítve -- az ő egész
      tervezése "csak CONFIG_PATH/BACKUP_DIR-hoz nyúl, nincs általános
      parancsvégrehajtás", a csomagtelepítés/service-restart ennél
      sokkal szélesebb jogosultsági felület, lásd
      `frfw.helper.update_protocol` docstringjét)
- [x] Rollback: `apply_update` az update előtti verziót
      `previous_version`-ként megjegyzi; `rollback_update` azt
      újratelepíti. Egy szintig megy vissza (rollback-et visszagörgetni
      nem lehet). Ha a korábbi verzió kicsomagolt forrása még megvan
      `/opt/fr_os/releases` alatt (egy sikeres update sosem törli),
      a rollback hálózat nélkül is működik -- pont akkor hasznos, ha a
      hibás update a hálózatot is elrontotta.
- [x] `firewall-cli update check/apply/rollback` -- ugyanaz a
      minta, mint `apply`/`rollback`-nél: a CLI azzal a jogosultsággal
      fut, amivel az operátor elindította, a webUI viszont soha nem hívja
      őket közvetlenül, csak a privilegizált socketen keresztül
- [x] Tesztek: `frfw.update` (verzió-parse/összehasonlítás,
      check_latest/list_releases minden HTTP-ági monkeypatch-csal, teljes
      apply/rollback folyamat sikeres és hibás ággal, path-traversal
      védelem a tarball-kicsomagoláson), az update-helper socket
      protokoll (mint a tűzfal apply-helperé), webUI útvonalak,
      config séma/loader -- lásd `tests/test_update*.py`,
      `tests/webui/test_update_routes.py`

**Ismert korlátozás, nyíltan kimondva**: nincs kriptográfiai aláírás-
ellenőrzés a letöltött release-en -- a HTTPS-kapcsolat GitHub-hoz az
egyetlen bizalmi határ jelenleg, ugyanúgy, mint egy sima `git clone`
vagy egy nem rögzített indexből futtatott `pip install` esetén. Release
aláírás (pl. `cosign`-nal vagy egy GPG-aláírt checksum fájllal) egy
ésszerű következő lépés, mihelyt vannak valós, taggelt release-ek amiket
alá lehet írni.

**Még nem ellenőrzött valós forgatókönyvön**: ennek a repónak jelenleg
(0.1.0, fejlesztés alatt) nincsenek valódi GitHub release-ei, úgyhogy
"frissítés egy régebbi verzióról egy valós újabbra" végpontig-végpontig
sosem futott le éles GitHub release-ek ellen -- csak monkeypatch-elt
hálózati réteggel (lásd fent) és a `check_latest`/`list_releases`
tényleges, élő hívásával a projekt saját (jelenleg üres) repója ellen
(ami helyesen "nincs még kiadás" választ ad, 404-ként kezelve). Amint
lesz első valódi tag/release, érdemes egy teljes VM-en végigfuttatni a
webUI Update képernyőjéről egy tényleges frissítést.

**Elfogadási kritérium**: egy régebbi telepítésű VM webUI-ból frissíthető
terminál használata nélkül, sikeres/hibás frissítés is jól kezelt. A
mechanizmus (check/apply/rollback, hibaágak, state-perzisztencia)
egységtesztekkel ellenőrizve; a "régebbi telepítésű VM valós
frissítése" végpontig-végpontig forgatókönyv valós release hiányában
egyelőre nincs kipróbálva (lásd fent).

## 7. fázis – Identitás-alapú Zero Trust hálózati hozzáférés (ZTNA) — **kész**

Cél: 100% lokális (nincs Okta/Azure AD/felhő-függőség), homelab-barát
identitás-alapú belépési kapu a LAN/"Production Server Zone" elé, ahol
az adatsík (a tényleges csomagszűrés) továbbra is 100%-ban kernel-térben
(nftables) fut -- nincs userspace reverse proxy (Envoy/Squid) a
forgalomban, tehát a 40 Gbps-es célsebesség nem sérül. Teljes indoklás,
architektúra és a `flush ruleset`-tel folytatott küzdelem: [ARCHITECTURE.md](ARCHITECTURE.md#identitás-alapú-zero-trust-hálózati-hozzáférés-ztna-fázis-7).

- [x] **Séma**: `ztna` konfig-szekció (`enabled`, `session_ttl_seconds`,
      `users` -- felhasználónév + PBKDF2-HMAC-SHA256 jelszó-hash, a
      meglévő `frfw.admin_account` sémáját újrahasznosítva), teljes
      `frfw.config.loader` validációval (érvényes felhasználónév-formátum,
      egyedi felhasználónevek, TTL-tartomány, "enabled igaz esetén
      legalább egy felhasználó kötelező"). A meglévő `Rule` dataclass egy
      `require_ztna: bool` mezőt kapott -- nincs külön "védett zóna"
      fogalom, a meglévő szabály-motor illesztő logikáját hasznosítja
      újra.
- [x] **Adatsík**: `frfw.nft.builder` egy `authenticated_ztna_users`
      nevű, `flags dynamic,timeout` nftables named set-et renderel (csak
      ha `ztna.enabled`); minden `require_ztna: true` szabály egy `ip
      saddr @authenticated_ztna_users` illesztést kap. A halmaz elemei
      saját, egyedi TTL-lel kerülnek be -- a lejárt IP-ket a **kernel**
      dobja ki magától, nulla cron job/userspace háttérfolyamat nélkül.
      Valósan tesztelve: egy 5 másodperces TTL-lel felvett elem 6
      másodpercen belül eltűnt a halmazból.
- [x] **Vezérlősík**: `GET/POST /ztna/login` (`frfw.webui.routes.ztna`,
      publikus route) időzítés-biztos módon ellenőriz a tárolt hash-ek
      ellen, majd sikeres belépéskor egy új `authorize_ztna`
      unix-socket paranccsal (`frfw.helper.protocol/server/client`)
      kéri meg a root alatt futó `fr-apply-helper`-t, hogy vegye fel a
      kliens forrás-IP-jét a kernel halmazba a configban beállított
      TTL-lel. `GET /ztna/status` (szintén publikus) egy új
      `ztna_status` helper-paranccsal kérdezi le élőben a hátralévő
      session-időt -- **nincs külön böngésző-session-cookie**, az
      egyetlen tekintélyforrás a kernel halmaz aktuális tartalma.
      Felismerés: még a csak-olvasó `nft list` is root-ot/
      `CAP_NET_ADMIN`-t igényel, ezért a `ztna_status` lekérdezés is a
      privilegizált helperen megy át, nem a webUI processzből
      közvetlenül.
- [x] **`flush ruleset` probléma megoldva**: `frfw.provision.apply_all`
      az nftables-alkalmazási lépést `frfw.ztna.snapshot_before_reload`/
      `restore_after_reload`-dal zárójelezi, hogy egy tetszőleges
      config-mentés (pl. egy DHCP-beállítás) ne jelentkeztessen ki
      véletlenül egy aktív ZTNA-session-t a `flush ruleset` miatt.
      Valós, nem mockolt integrációs teszttel megerősítve (valódi nft
      halmaz flush + restore, helyes hátralévő TTL-lel).
- [x] **Admin képernyő** (`/ztna`): be/ki kapcsolás + TTL beállítás,
      felhasználó-kezelés (hozzáadás jelszó-hosszkorláttal, eltávolítás),
      és a `require_ztna: true` szabályok listája -- ugyanaz a
      "csak a configot módosítja, a tényleges kapuzás a következő
      apply-nál lép életbe" minta, mint minden más képernyőn.
- [x] Tesztek: `tests/test_ztna.py` (a `frfw.ztna` modul, valós kernel-
      kiürüléses teszttel), `tests/test_ztna_schema.py` (séma/loader),
      `tests/test_builder.py` (halmaz-renderelés, `require_ztna`
      illesztés, valós `nft -c` szintaxis-ellenőrzés), `tests/test_helper.py`
      (a socket-protokoll új parancsai), `tests/test_provision.py`
      (snapshot/restore huzalozás), `tests/webui/test_ztna_routes.py`
      (admin + publikus route-ok) -- a teljes tesztsorozat (310 teszt)
      regresszió nélkül fut.

**Ismert korlátozás, nyíltan kimondva**: nincs rate-limiting/lockout a
`/ztna/login`-on -- ez konzisztens a meglévő admin `/login`-nal, de
egyik sem véd brute-force ellen éles környezetben. A "titkosított YAML"
eredeti felvetés helyett PBKDF2 jelszó-hashelés készült el (nem
visszafejthető titkosítás) -- ez a helyes, biztonságosabb megközelítés
tárolt hitelesítő adatokhoz.

**Elfogadási kritérium**: egy `require_ztna: true` szabály által védett
zóna csak sikeres `/ztna/login` után érhető el, a session a konfigurált
TTL lejártával a kernel által automatikusan megszűnik (userspace kód
futása nélkül), és egy egyidejű config-mentés/apply nem szakítja meg egy
másik felhasználó aktív session-jét. ✅ Ellenőrizve egységtesztekkel és
valós (nem mockolt) nftables-integrációs tesztekkel; 40 Gbps-es valós
teljesítménymérés ugyanazon okból nyitott, mint a 4. fázis XDP szűrőjéé
(nincs megfelelő teszthardver ebben a sandboxban).

## 8. fázis – Hibrid poszt-kvantum kulcscsere a menedzsment-rétegen — **kész, valós PQC-build nélkül tesztelve**

Cél: a webUI HTTPS-e és a host sshd-je (ha van) hibrid
(klasszikus+PQC) kulcscserét ajánljon fel, régebbi kliensre/hostra
észrevétlenül visszaesve. Teljes indoklás, a két verzió-küszöb, és a
"`SSLContext` nem tud csoport-listát" felismerés:
[ARCHITECTURE.md](ARCHITECTURE.md#hibrid-poszt-kvantum-kulcscsere-a-menedzsment-rétegen-fázis-8).

- [x] **Séma**: `pqc.enabled` (`frfw.config.schema.PqcConfig`), teljes
      `frfw.config.loader` validációval.
- [x] **TLS**: `frfw.pqc.write_openssl_pqc_conf` generálja az OpenSSL
      config-fragmentet (`Groups = X25519MLKEM768:X25519:P-256` vagy
      csak klasszikus, `MinProtocol`/`MaxProtocol = TLSv1.3`), amire
      `fr-webui.service` feltétel nélkül `OPENSSL_CONF=`-fal mutat --
      ez, nem a Python `ssl.SSLContext`, az egyetlen ténylegesen működő
      mechanizmus egy TLS 1.3 csoport-lista beállítására (ld.
      ARCHITECTURE.md a `set_ecdh_curve`-ről szóló, közvetlen teszttel
      igazolt korlátozásért). A ténylegesen `ssl.SSLContext`-en
      beállítható rész (TLS 1.3-only) `frfw.pqc.tls_ssl_context_factory`-
      ként valósult meg, uvicorn `ssl_context_factory=` bővítési
      pontján keresztül -- valós `uvicorn.Config(...).load()` hívással
      és valódi generált tanúsítvánnyal is leellenőrizve.
- [x] **SSH**: `frfw.pqc.sync_ssh_kex` egy `/etc/ssh/sshd_config.d/
      50-fr_os-pqc-kex.conf` drop-in-t ír/töröl (sosem a fő
      sshd_config-ot), a telepített sshd tényleges, `sshd -Q kex`-szel
      frissen lekérdezett képességéhez igazítva -- egy `mlkem768x25519-
      sha256` nevet sosem ír le anélkül, hogy a build ezt már ne
      jelezte volna vissza. A generált drop-in-t `sshd -t` validálja
      alkalmazás előtt; sikertelen validáció esetén az előző tartalom
      (vagy annak hiánya) visszaáll, sosem marad sshd számára
      feldolgozhatatlan config a lemezen. A démont *reload*, sosem
      *restart* frissíti (élő SSH-session-öket nem szakítja meg).
- [x] **`frfw.provision.apply_all`** 6. lépésként hívja
      `sync_tls_pqc_conf`-ot és `sync_ssh_kex`-et.
- [x] **WebUI**: `GET /system` admin-képernyő (host-képesség vs.
      alkalmazott állapot táblázatosan, be/ki kapcsolás), és egy kis
      jelvény a dashboardon (`quantum-safe` csak akkor zöld, ha a
      config be van kapcsolva, a legutóbbi apply hibrid csoportot írt,
      **és** a host OpenSSL-je ezt ténylegesen támogatja -- egyik
      feltétel hiánya sem takarható el a másik kettővel).
- [x] Tesztek: `tests/test_pqc.py` (38+ eset: verzió-küszöb, a
      `set_ecdh_curve` korlátozás közvetlen igazolása, valós
      `uvicorn.Config` integráció, a `sshd -t`-sikertelen-validáció
      visszaállítási garancia, root-igény, dry-run-biztonság),
      `tests/test_pqc_schema.py`, `tests/webui/test_system_routes.py`,
      `tests/test_webui_server.py`, kiegészített
      `tests/test_provision.py` -- a teljes tesztsorozat (360 teszt)
      regresszió nélkül fut.

**Ismert korlátozás, nyíltan kimondva**: ez a modul **nincs valós
OpenSSL 3.5+ vagy OpenSSH 9.9+ build ellen tesztelve** -- ez a
fejlesztői sandbox OpenSSL 3.0.13-at futtat és sshd egyáltalán nincs
telepítve rajta. Minden képesség-ellenőrzést közvetlenül, éles
binárison/interpreteren igazoltunk *a hiány helyes felismerésére*, a
pozitív ("a hibrid csoport ténylegesen létrejön egy valós PQC-képes
klienssel/sshd-vel") ág viszont specifikáció szerint implementáltnak
tekintendő, nem ugyanolyan szintű, függetlenül ellenőrzött ténynek, mint
a projekt kernel-közeli alrendszerei (nftables, XDP, ZTNA) esetében.
Emellett a saját live-build installer alapképe (5. fázis) egy régi
snapshot-ot használ, aminek OpenSSL/OpenSSH verziója szinte biztosan a
küszöb alatt van, tehát ott ma ez a funkció ténylegesen csak a
"TLS 1.3-only, klasszikus csoportok" ágon fut.

**Elfogadási kritérium**: a webUI-n bekapcsolható a PQC hibrid mód,
alkalmazás után a `/system` képernyő és a dashboard jelvénye pontosan
tükrözi a host tényleges képességét (sosem állít biztonságosabb
állapotot a valóságosnál), és egy régi OpenSSL/OpenSSH build esetén a
rendszer csendben, hiba nélkül klasszikus módra esik vissza. ✅
Ellenőrizve egységtesztekkel és a fent felsorolt valós integrációkkal
(uvicorn Config, tényleges `set_ecdh_curve` viselkedés); a valós
hibrid handshake végponttól-végpontig futtatása egy tényleges PQC-képes
build hiányában nyitott, ugyanúgy, ahogy a 4. fázis XDP szűrőjének
10G/40GbE mérése is az volt valós teszthardver hiányában.

## 9. fázis – Helyi DNS/XDP hirdetésblokkoló — **kész**

Cél: hosts-formátumú blokklisták (StevenBlack "unified" hosts, alapból)
letöltése, deduplikálása, és kiszolgálása egy 100% lokális, memória-
hatékony DNS-rezolverből, opcionális kis "kritikus" részhalmazzal a
meglévő 4. fázis XDP LPM trie-jában. **Pontosítás**: a projektnek eddig
sosem volt saját DNS-rezolvere (a Kea csak DHCP-t végzett) -- ez a
fázis vezeti be az elsőt, nem egy meglévőt bővít. Teljes indoklás:
[ARCHITECTURE.md](ARCHITECTURE.md#helyi-dnsxdp-hirdetésblokkoló-fázis-9).

- [x] **Séma**: `adblocker` konfig-szekció (`enabled`, `source_urls`,
      `xdp_critical_limit`), teljes `frfw.config.loader` validációval
      (URL-formátum, "enabled igaz esetén legalább egy forrás
      kötelező", nem-negatív egész limit).
- [x] **Letöltés/parse/dedup** (`src/frfw/adblock/__init__.py`): stdlib
      `urllib.request`-alapú letöltés (a projekt egyetlen meglévő
      hálózati precedensét, `frfw.update`-et követve -- nincs új
      futásidejű függőség), `concurrent.futures.ThreadPoolExecutor`-ral
      párhuzamosítva több forrás esetén, kommentek/IP-k eltávolítása,
      egyedi domainek kinyerése és `/etc/fr_os/adblock.hosts`-ba
      deduplikálva, hosts-formátumban visszaírva.
- [x] **Dedikált DNS-rezolver** (`src/frfw/adblock/dns_service.py`):
      egy saját, teljes dnsmasq-konfiguráció (`fr-adblock-dns.service`)
      -- sosem a rendszer alapértelmezett `dnsmasq.service`/
      `dnsmasq.conf`-ja, ugyanaz a "egy teljes generált config, egy
      dedikált service" minta, mint a Kea DHCP-motoré.
- [x] **Letöltés sosem `apply`-on belül**: `firewall-cli adblock-refresh`
      (napi `fr-adblock-refresh.timer`) vagy a webUI "Refresh now"
      gombja (új `refresh_adblock` apply-helper socket-parancs) végzi a
      tényleges letöltést; `frfw.provision.apply_all` csak a resolver
      fut/áll állapotát egyezteti a configgal, a hálózathoz sosem nyúl.
- [x] **XDP újrahasznosítás, nem második kernel-térkép**: a "kritikus"
      domainek a meglévő `xdp_sni_filter.blocklist`/
      `frfw.xdp.sync_blocklist` mechanizmusába kerülnek, memórián belül
      egyesítve (`config.yaml`-ba sosem visszaírva) -- `xdp_critical_
      limit == 0` (alapérték) esetén ez a lépés az XDP-t egyáltalán
      nem érinti.
- [x] **WebUI**: `GET /adblock` (élő domain-számláló és resolver-
      státusz, jogosultság nélkül számolva -- egy hosts-fájl sorainak
      megszámolása és `systemctl is-active` egyaránt nem igényel
      root-ot), be/ki kapcsolás + forráslisták + XDP-limit beállítás,
      "Refresh now" gomb; dashboard-összegzés.
- [x] Tesztek: `tests/test_adblock.py` (parse/dedup/fetch/refresh, 21
      eset), `tests/test_adblock_schema.py` (séma/loader, 13 eset),
      `tests/test_adblock_dns_service.py` (config-renderelés,
      resolver-egyeztetés, valós `dnsmasq --test` szintaxis-ellenőrzés,
      18 eset), `tests/webui/test_adblock_routes.py` (9 eset),
      kiegészített `tests/test_provision.py` (adblock+XDP egyesítés) és
      `tests/test_helper.py` (`refresh_adblock` socket-parancs) -- a
      teljes tesztsorozat (425 teszt) regresszió nélkül fut.

**Ismert korlátozás, nyíltan kimondva**: a DHCP-kliensek DNS-szervere
nincs automatikusan erre a rezolverre átállítva (`DhcpPool.dns_servers`
változatlanul azt szolgáltatja, amit az admin explicit beállított) --
ez egy külön, nem triviális integrációs lépés lenne, amit ez a fázis
tudatosan nem végzett el csendes mellékhatásként. A tényleges blokkolási
mechanizmust kézzel, élesben megerősítettük (`dig` egy valós dnsmasq-
példány ellen, `0.0.0.0`-ra oldódó listás domain, felfelé továbbított
nem-listás domain) -- ez a konkrét élő-lekérdezéses forgatókönyv
azonban nem került be automatizált tesztként, mert ebben a
CI-sandboxban egy pytest-en belülről indított dnsmasq-gyermekfolyamat
nem válaszol lekérdezésekre annak ellenére, hogy a helyes portra
bind-el -- egy környezeti sajátosság, nem frfw-kód hiba (ld.
ARCHITECTURE.md a részletes diagnózisért).

**Elfogadási kritérium**: a webUI-n bekapcsolható a hirdetésblokkoló,
"Refresh now"-ra letöltődnek és deduplikálódnak a konfigurált listák,
`apply`-ra elindul a dedikált DNS-rezolver a friss listával, és a
`/adblock` képernyő pontos, élő domain-számot mutat. ✅ Ellenőrizve
egységtesztekkel, valós `dnsmasq --test` szintaxis-ellenőrzéssel, és
kézi, élő `dig`-es végpontig-végpontig teszteléssel (ld. fent, miért
nem automatizált ez utóbbi ebben a sandboxban).

## 10. fázis – Memória- és kernel-szintű brute-force védelem — **kész**

Cél: a `/login` és `/ztna/login` végpontok elleni jelszó-találgatást
két, szigorúan elválasztott rétegben megállítani: a nem-root webUI
folyamat számol emlékezetben forrás-IP-nkénti sikertelen próbálkozást,
majd 5 hibás próbálkozás/5 perc küszöb felett a privilegizált
`fr-apply-helper`-en keresztül szól a kernelnek, ami az adott IP-t egy
`bruteforce_jail` nevű nftables named set-be teszi, natív kernel
timeout-tal (alapból 1 óra) -- áradás közben nulla userspace CPU-terhelés,
Redis/fail2ban/egyéb külső függőség nélkül. Teljes indoklás:
[ARCHITECTURE.md](ARCHITECTURE.md#memória--és-kernel-szintű-brute-force-védelem-fázis-10).

- [x] **`frfw.webui.auth_rate_limiter`**: szálbiztos (`threading.Lock` --
      a projekt route-jai plain `def`, nem `async def`, tehát uvicorn
      szálkészletben futtatja őket, nem `asyncio.Lock` a helyes primitív),
      csúszóablakos `BruteforceGuard` (5 hibás próbálkozás / 300 mp),
      memóriakorlátos, dedikált takarító szál nélkül (minden 100. hívás
      után egy soron következő seprés dobja a rég lejárt, egyszeri
      IP-ket). A megosztott `reject_failed_login()` segédfüggvényt mind
      `/login`, mind `/ztna/login` hívja.
- [x] **Unix-socket protokoll bővítés**: új `ban_ip` parancs
      (`frfw.helper.protocol/server/client`) -- a webUI dönt *mikor*
      kell tiltani, de a tényleges `nft`-hívás mindig a root alatt futó
      helperen megy át, ugyanaz a privilégium-szeparáció, mint a ZTNA
      `authorize_ztna` parancsánál.
- [x] **`frfw.bruteforce`** (a `frfw.ztna` szándékos strukturális
      tükörképe): `ban_ip()`, `snapshot_before_reload()`/
      `restore_after_reload()` a `flush ruleset` probléma megoldására
      (ld. lent).
- [x] **Nftables séma** (`frfw.nft.builder`): mindig (nem feltételesen,
      szemben a ZTNA-halmazzal) renderelt `bruteforce_jail` named set
      (`flags timeout`) és egy `ip saddr @bruteforce_jail drop` szabály
      a `chain input` legelső soraként -- még a `lo` accept előtt.
- [x] **`frfw.provision.apply_all`**: a jail-halmaz snapshot/restore-ral
      zárójelezve az nftables-alkalmazás körül, ugyanúgy, mint a ZTNA
      session-halmaz -- egy admin-oldali, teljesen független
      config-mentés (`flush ruleset`) sosem old fel csendben egy aktív
      tiltást.
- [x] Tesztek: `tests/test_bruteforce.py` (12 eset, ebből 4 valós,
      root alatt futó `nft`-integráció -- egy 2 mp-es timeout-tal
      felvett elemet a kernel saját maga dob ki futó kód nélkül),
      `tests/test_auth_rate_limiter.py` (13 eset, köztük egy 5 szálas
      konkurrencia-teszt, ami megerősíti, hogy a küszöb pontosan
      egyszer lép át), kiegészített `tests/test_builder.py` (2 új eset),
      `tests/test_provision.py` (3 új eset), `tests/test_helper.py`
      (5 új eset a `ban_ip` socket-parancsra) és a két webUI
      route-tesztfájl (`tests/webui/test_auth.py` +4,
      `tests/webui/test_ztna_routes.py` +3, köztük egy, ami
      megerősíti, hogy a számláló IP-nkénti, nem végpontonkénti -- egy
      támadó nem kerülheti ki a küszöböt a két bejelentkezési forma
      váltogatásával) -- a teljes tesztsorozat (467 teszt) regresszió
      nélkül fut.

**Pontosítások az eredeti megfogalmazáshoz képest** (ld. részletesen
ARCHITECTURE.md): a kért `{"action": "ban_ip", ...}` helyett a meglévő
`"cmd"` mezőt használtuk (konzisztencia a teljes protokollal); az "async
lock" helyett `threading.Lock`-ot (a route-ok szinkron `def`-ek); a
"provision/ csomag" helyett a tényleges `frfw/nft/builder.py`-ban
(halmaz/szabály) és `frfw/provision.py`-ban (snapshot/restore-
zárójelezés) helyeztük el a logikát; és a `flags dynamic,timeout`
helyett a szó szerint kért `flags timeout`-ot használtuk, miután valós
`nft`-parancsokkal közvetlenül megerősítettük, hogy ez önmagában is
elegendő az elem-szintű timeout-felülíráshoz ezen az nftables-
verzión.

**Elfogadási kritérium**: 5 egymást követő hibás jelszó ugyanarról a
forrás-IP-ről akár a `/login`, akár a `/ztna/login` végponton belül 5
percen belül az adott IP-t a kernel `bruteforce_jail` halmazába
juttatja (1 órás alapértelmezett tiltással), és minden onnantól érkező
csomagját a tűzfal a legelső szabályon eldobja -- mindezt anélkül, hogy
a webUI-folyamat egyetlen root-jogosultságú parancsot is futtatna. ✅
Ellenőrizve egységtesztekkel, valós `nft`-integrációval (a kernel saját
maga üríti ki a lejárt tiltást) és a teljes bejelentkezési útvonalon
végigfutó webUI-szintű integrációs tesztekkel.

