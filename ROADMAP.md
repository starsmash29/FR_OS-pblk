# Roadmap

Fázisonkénti fejlesztési terv. Minden fázis végén a rendszernek működő,
tesztelhető állapotban kell lennie egy sima Debian VM-en, mielőtt a következő
fázis elkezdődik. Az architektúra döntéseket lásd: [ARCHITECTURE.md](ARCHITECTURE.md).

## 1. fázis – Firewall-motor magja — **folyamatban**

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

## 2. fázis – Rendszerintegráció

- [ ] systemd unit a firewall-motorhoz (boot-kori automatikus config-apply)
- [ ] systemd unit a webUI-hoz (előkészítés, tényleges UI a 3. fázisban)
- [ ] Hálózati interfészek automatikus felismerése (`ip link` alapján),
      WAN/LAN/OPT hozzárendelési segédlet (pfSense-szerű telepítő lépés)
- [ ] Konfig-perzisztencia: `/etc/fr_os/config.yaml` kanonikus hely,
      alkalmazás előtti backup/rollback logika
- [ ] Root-jogosultság elválasztás: unprivileged webUI + privileged
      "apply helper" service, jól definiált (unix socket) interfésszel

**Elfogadási kritérium**: friss Debian VM-en `systemctl enable --now
fr-firewall` után a rendszer boot-kor automatikusan alkalmazza az utoljára
mentett konfigurációt; interfész-felismerés parancssorból lefuttatható.

## 3. fázis – WebUI

- [ ] FastAPI backend a `frfw` motor fölött (nem duplikálja a logikát)
- [ ] Alapképernyők: interfészek, szabályok, NAT, DHCP, státusz/dashboard
- [ ] Admin bejelentkezés (auth), HTTPS alapból (self-signed induláskor)
- [ ] Config mentés/visszaállítás, git-alapú verziózás a háttérben

**Elfogadási kritérium**: böngészőből elérhető felületen létrehozható egy
teljes WAN/LAN szabálykészlet + NAT, mentés után a `frfw` réteg ugyanazt a
YAML-t generálja, mint amit CLI-ből kézzel írnánk.

## 4. fázis – XDP/eBPF gyors útvonal

- [ ] XDP program a nagy forgalmú interfészeken (kernel-stack megkerülése)
- [ ] Teljesítményteszt (iperf3) 10G/40GbE hardveren, ha elérhető
- [ ] Döntés: elég-e az XDP, vagy szükséges a DPDK

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
