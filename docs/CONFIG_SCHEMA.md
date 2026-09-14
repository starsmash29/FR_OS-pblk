# Konfigurációs séma (v1)

A `frfw` motor bemenete egy YAML fájl. Ez a dokumentum a `version: 1` séma
mezőit írja le. A validációt a `frfw.config.loader` implementálja
(`ConfigError`-t dob hibás mezőre, konkrét mező/érték megnevezésével).

Teljes példa: [`examples/config.yaml`](../examples/config.yaml).

## Névformátum

Interfész-, zóna-, szabály- és port-forward nevek: kisbetűvel kezdődő,
kisbetűket/számjegyeket/`-`/`_` karaktereket tartalmazó azonosítók
(`^[a-z][a-z0-9_-]*$`).

## Felső szint

```yaml
version: 1          # kötelező, jelenleg csak 1 támogatott
hostname: fr-router  # kötelező, nem üres string
interfaces: {...}    # kötelező, ld. lent
zones: {...}         # kötelező, ld. lent
rules: [...]         # opcionális, alapértelmezett: []
nat: {...}           # opcionális, alapértelmezett: üres
```

## `interfaces`

Logikai interfész név → fizikai eszköz + zóna leképezés.

```yaml
interfaces:
  wan:
    device: eth0        # kötelező, egyedi kell legyen (egy eszköz = egy interfész)
    zone: wan            # kötelező, a zones alatt deklarált zóna neve
    description: "..."   # opcionális, szabad szöveg
```

## `zones`

Logikai csoportok, amikre a szabályok és a NAT hivatkozik. Minden itt
deklarált zónát legalább egy interfésznek kell használnia (és fordítva:
minden interfész zónája itt kell szerepeljen) — a betöltő mindkét irányban
ellenőrzi a konzisztenciát.

```yaml
zones:
  wan:
    description: "..."   # opcionális
```

A `self` zónanév fenntartott: nem deklarálható a `zones` alatt, hanem a
szabályokban `to_zone: self` értékként használható — ez a routernek magának
címzett forgalmat jelenti (nftables `input` lánc), szemben a zónák közötti,
továbbított forgalommal (`forward` lánc).

## `rules`

Szűrési szabályok listája, deklarálási sorrendben kerülnek a generált
ruleset-be (első találat dönt, ahogy nftables-ben megszokott).

```yaml
rules:
  - name: allow-ssh-from-lan-to-router  # kötelező, egyedi
    action: accept        # kötelező: accept | drop | reject
    from_zone: lan         # opcionális, hiányzik = bármelyik zóna
    to_zone: self           # opcionális, hiányzik = bármelyik zóna; "self" = router maga
    proto: tcp               # opcionális, alapértelmezett: any; any|tcp|udp|icmp
    dst_port: 22               # opcionális, csak proto: tcp/udp esetén; int vagy "1000-2000" range string
    src_address: 10.0.0.0/24    # opcionális, IPv4 cím/hálózat
    dst_address: 10.0.0.5         # opcionális, IPv4 cím/hálózat
    log: false                     # opcionális, alapértelmezett: false
```

`to_zone: self` esetén a szabály az `input` láncba kerül (nincs `oifname`
megkötés, hiszen a cél maga a router); egyébként a `forward` láncba.

## `nat`

```yaml
nat:
  masquerade:
    - out_zone: wan          # kötelező, kimeneti zóna, ahonnan a forgalom távozik

  port_forwards:
    - name: forward-https-to-dmz-web  # kötelező, egyedi
      in_zone: wan                     # kötelező, bejövő zóna
      proto: tcp                        # kötelező: tcp | udp
      dst_port: 443                      # kötelező, 1-65535
      to_address: 10.0.2.10               # kötelező, IPv4 cím
      to_port: 443                         # opcionális, alapértelmezett: dst_port
```

## Ismert korlátok (1. fázis)

- Csak IPv4 címek/hálózatok támogatottak `src_address`/`dst_address`/
  `to_address` mezőkben (IPv6 tervezett, ld. [ROADMAP.md](../ROADMAP.md)).
- Nincs hairpin/reflection NAT a port-forwardokhoz (belső kliens nem éri el
  a saját WAN-oldali portforwardolt szolgáltatását a publikus IP-n
  keresztül) — ez később, igény szerint kerül be.
- Egy `apply` mindig a teljes nftables ruleset-et lecseréli (`flush
  ruleset` + betöltés), nem lehet kézzel írt, frfw-n kívüli szabályokkal
  keverni.
