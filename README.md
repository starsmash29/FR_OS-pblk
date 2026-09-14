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
konfigurációból nftables ruleset-et generál és tölt be; ez lesz az egyetlen
"config → tűzfalszabályok" fordítási logika, amit a CLI, a systemd
integráció (2. fázis) és a webUI (3. fázis) is közösen használ majd.

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

## Licenc

[Apache License 2.0](LICENSE).
