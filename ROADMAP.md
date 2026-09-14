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

## 4. fázis – XDP/eBPF gyors útvonal

- [ ] XDP program a nagy forgalmú interfészeken (kernel-stack megkerülése)
- [ ] Teljesítményteszt (iperf3) 10G/40GbE hardveren, ha elérhető
- [ ] Döntés: elég-e az XDP, vagy szükséges a DPDK
- [ ] **AI IDS valós adatgyűjtés**: a mock `frfw.ai_ids` motor lecserélése
      valós per-eszköz flow-jellemzőkre (csomagméret/-időzítés eloszlás,
      protokoll-mix, cél-diverzitás) épülő detekcióra, `scikit-learn`
      `IsolationForest`-tel (`frfw.ai_ids.train_isolation_forest` már
      előkészített, de jelenleg `NotImplementedError`-t dobó stub)

**Elfogadási kritérium**: mért, dokumentált teljesítményjavulás XDP be- és
kikapcsolt állapot között, ugyanazon a hardveren.

## 5. fázis – Automatikus installer

- [ ] Debian preseed / live-build alapú telepítő image
- [ ] First-boot script: firewall-motor, webUI, systemd service-ek
      automatikus telepítése, biztonságos alapkonfiggal
- [ ] Bootolható ISO/USB image build pipeline (később CI-ból is)

**Elfogadási kritérium**: USB-ről telepítve, semmilyen manuális
csomagtelepítés/terminálmunka nélkül működő webUI-t kap a felhasználó.

## 6. fázis – Frissítési mechanizmus

- [ ] WebUI-ból indítható update-folyamat (rendszer + community edition)
- [ ] Verzióellenőrzés, changelog megjelenítés, rollback lehetőség

**Elfogadási kritérium**: egy régebbi telepítésű VM webUI-ból frissíthető
terminál használata nélkül, sikeres/hibás frissítés is jól kezelt.
