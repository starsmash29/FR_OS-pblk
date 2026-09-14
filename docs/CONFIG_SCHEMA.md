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
dhcp: {...}          # opcionális, alapértelmezett: üres
```

## `interfaces`

Logikai interfész név → fizikai eszköz + zóna leképezés.

```yaml
interfaces:
  wan:
    device: eth0        # kötelező, egyedi kell legyen (egy eszköz = egy interfész)
    zone: wan            # kötelező, a zones alatt deklarált zóna neve
    address: 10.0.0.1/24  # opcionális, IPv4 cím CIDR-prefixel; frfw.ifaddr alkalmazza
    description: "..."   # opcionális, szabad szöveg
```

Az `address` a router saját, statikus IPv4 címe azon az interfészen —
`ip addr replace`-el kerül alkalmazásra (`frfw.ifaddr`). Csak akkor
kötelező, ha a zónának DHCP pool-t akarunk adni (ld. `dhcp` lent); egy
DHCP-kliens által menedzselt (pl. tipikus WAN) interfészen hagyjuk üresen.

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

## `dhcp`

Zónánkénti DHCPv4 pool, Kea-val kiszolgálva (`frfw.kea`).

```yaml
dhcp:
  lan:
    range_start: 10.0.0.100      # kötelező, IPv4 cím, az interfész alhálózatán belül
    range_end: 10.0.0.200          # kötelező, IPv4 cím, range_start-nál nem korábbi
    dns_servers: [1.1.1.1, 9.9.9.9]  # kötelező, nem üres lista, IPv4 címek
    lease_time: 3600                   # opcionális, alapértelmezett: 3600 (mp)
    reservations:                       # opcionális, alapértelmezett: []
      - mac: aa:bb:cc:dd:ee:ff             # kötelező, aa:bb:cc:dd:ee:ff formátum
        address: 10.0.0.50                  # kötelező, az alhálózaton belül
        hostname: nas                         # opcionális
```

Előfeltételek egy zóna DHCP-kiszolgálásához:

- A zónának **pontosan egy** interfésze lehet, és annak `address` mezője
  kötelezően ki van töltve — ebből számolódik a pool alhálózata és
  gateway-e (`routers` option a Kea configban).
- `range_start`/`range_end` és minden foglalás címe az interfész
  alhálózatán belül kell legyen, és nem eshet egybe a gateway (az
  interfész saját) címével.
- A foglalások címei/MAC-jei zónán belül egyediek kell legyenek; a MAC-ek
  kisbetűsre normalizálódnak.

## Ismert korlátok

- Csak IPv4 címek/hálózatok támogatottak `src_address`/`dst_address`/
  `to_address`/`address` mezőkben (IPv6 tervezett, ld. [ROADMAP.md](../ROADMAP.md)).
- Nincs hairpin/reflection NAT a port-forwardokhoz (belső kliens nem éri el
  a saját WAN-oldali portforwardolt szolgáltatását a publikus IP-n
  keresztül) — ez később, igény szerint kerül be.
- Egy `apply` mindig a teljes nftables ruleset-et lecseréli (`flush
  ruleset` + betöltés), nem lehet kézzel írt, frfw-n kívüli szabályokkal
  keverni.
- DHCP csak olyan zónán állítható be, aminek pontosan egy interfésze van;
  több interfészes zóna (pl. bridge-elt LAN portok) DHCP-kiszolgálása egy
  jövőbeli iteráció.
- `frfw.ifaddr` csak alkalmaz/frissít címeket, nem távolítja el azokat,
  amik kikerülnek a configból — egy törölt `address:` után a régi cím a
  gépen marad, amíg kézzel vagy újraindításkor el nem tűnik.
