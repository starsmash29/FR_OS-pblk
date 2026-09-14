# FR_OS

Egyedi, Linux-alapú firewall/router operációs rendszer homelab használatra,
pfSense-szerű felhasználói élménnyel — de szélesebb NIC-támogatással és
natív Linux XDP/eBPF gyors útvonallal 10G/40GbE forgalomhoz.

A döntéseket és a fázisonkénti fejlesztési tervet lásd itt:

- [ARCHITECTURE.md](ARCHITECTURE.md) — technológiai döntések és indoklásuk
- [ROADMAP.md](ROADMAP.md) — fázisonkénti terv és elfogadási kritériumok
- [docs/CONFIG_SCHEMA.md](docs/CONFIG_SCHEMA.md) — a YAML konfig-séma teljes leírása

## Állapot

**1. fázis (firewall-motor magja)** — kész. A `frfw` Python csomag YAML
konfigurációból nftables ruleset-et generál és tölt be; ez az egyetlen
"config → tűzfalszabályok" fordítási logika, amit a CLI, a systemd
integráció és a webUI (3. fázis) is közösen használ.

**2. fázis (rendszerintegráció)** — kész. Kanonikus config-hely
(`/etc/fr_os/config.yaml`), boot-kori automatikus alkalmazás systemd-vel,
ruleset backup/rollback, hálózati interfész-felismerés és
WAN/LAN/OPT-hozzárendelési segédlet, illetve a jövőbeli (3. fázis) webUI-nak
szánt privilegizált apply-helper egy Unix socketen keresztül.

## Gyorsindítás

Igényel: Debian (vagy más Linux) `nftables` csomaggal, Python 3.11+.

```bash
pip install -e ".[dev]"

# Konfig ellenőrzése (séma-validáció, nftables-t nem érinti)
firewall-cli validate examples/config.yaml

# A generált nftables ruleset kiírása (nem alkalmazza)
firewall-cli render examples/config.yaml

# Alkalmazás: szintaxis-ellenőrzés (nft -c), majd tényleges betöltés (root kell)
sudo firewall-cli apply examples/config.yaml

# Csak ellenőrzés, tényleges alkalmazás nélkül
firewall-cli apply examples/config.yaml --dry-run
```

Tesztek futtatása (a valós `nft -c` szintaxis-ellenőrzést is lefuttatja, ha
az `nft` bináris elérhető):

```bash
python3 -m pytest
```

## Rendszerbe illesztés (2. fázis)

Egy tényleges router-gépen (nem csak fejlesztői gépen) a config alapból a
kanonikus `/etc/fr_os/config.yaml`-ból töltődik:

```bash
# Interfészek felismerése (sysfs alapján, root nem kell hozzá)
firewall-cli detect-interfaces

# Minimális, érvényes config generálása a felismert NIC-ekből
sudo firewall-cli assign-interfaces --wan eth0 --lan eth1 --opt dmz:eth2

# systemd unit-ok + /etc/fr_os telepítése
sudo scripts/install-system-integration.sh
sudo systemctl enable --now fr-firewall
sudo systemctl enable --now fr-apply-helper.socket

# Ha egy alkalmazott config elrontja a hálózatot: visszaállás az előzőre
sudo firewall-cli rollback --list
sudo firewall-cli rollback
```

Az apply-helper (`fr-apply-helper.socket`/`.service`) egy Unix socketen
fogad `apply`/`rollback` kéréseket root jogosultsággal, hogy a 3. fázis
unprivileged webUI-ja ne igényeljen root-ot. Részletek:
[ARCHITECTURE.md](ARCHITECTURE.md#biztonsági-modell).

## Licenc

[Apache License 2.0](LICENSE).
