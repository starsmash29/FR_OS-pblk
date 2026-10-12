# Integrator handover

State and working agreements for the next session of the integrating agent
(Claude Code), so work picks up where it stopped. Last updated 2026-10-12,
`main` at `6ad07e5`.

## How the owner and the integrator work

- **Language.** Chat with the owner is in Hungarian. Everything committed
  is in English (AGENTS.md).
- **One item per PR.** The sequence for each one:
  1. A short design, written in Hungarian.
  2. The owner says "Mehet".
  3. Implement, with tests, docs and a boot test.
  4. Open the PR, report in Hungarian, and ask "Mehet?".
  5. Merge with a merge commit (pass `expectedHeadSha`).
  
  Merge only after **all** of these hold:
  - the owner's explicit "Mehet" for that PR;
  - both full suites are green;
  - the boot test is green on BIOS and UEFI;
  - `main` is an ancestor of the PR head. If it isn't, merge `main` in (never rebase) and run the boot test again on the merged head.
- **Design first** for the privileged helpers, the update/signing path, the builder's rule order, and the installer/boot sequence.
- **Never:**
  - force-push;
  - handle the release signing key;
  - commit a secret;
  - change the signing/review steps of `build-installer.yml` unasked;
  - put model identifiers in commits or PRs;
  - unfreeze the JARVIS agent fleet;
  - reproduce offensive VLAN-hopping material.
- **Commit trailers:** `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and
  `Claude-Session: <session link>`.
- **PR bodies** end with the Claude Code footer and the session link.
- **Full suites,** run separately:
  - `python3 -m pytest tests --ignore=tests/webui -q`
  - `python3 -m pytest tests/webui -q`
  - Mount bpffs first and remove `/sys/fs/bpf/fr_os_xdp`.
  - Run them with Python 3.11, the router's (`python3.11 -m venv` plus `pip install -e '.[webui,dev]'`). Under another Python, `test_the_offline_check_passes_a_clean_medium` fails because it cannot check the router's compiled files.
- **Boot test.** Dispatch: `POST repos/starsmash29/FR_OS-pblk/actions/workflows/build-installer.yml/dispatches` with
  `ref=<branch>`, `inputs[boot_test]=true`. Logs come through the GitHub MCP `get_job_logs`. The run's `fr-os-installer` artifact is the ISO the owner writes to a stick.

## Recently merged

| PR | Item | What |
|---|---|---|
| #76 | SEC-26, SEC-27 | Apply held until confirmed, reverted at the deadline; only the admin moves the webUI's addresses |
| #77 | SEC-23 | Fuller kernel-trial health contract (`staged/expect.json`) |
| #78 | SEC-24 | XDP drops out-of-order segments of a followed split hello |
| #79 | SEC-28 | XDP checks a followed segment's TCP checksum. It drops hellos it can't follow (>16 segments, 30 s, >2048 bytes), and turns GRO off where the filter runs in generic mode (`XdpState.gro_off`). Measured on the 6.1 verifier: split ≈64.5k, main ≈756k instructions |
| #80 | NET-12 | LAN default `10.73.1.1/24`, moved out of the upstream's DHCP-offered network (fallbacks `172.29.73.1/24`, `192.168.173.1/24`). The boot test's upstream is `192.168.1.0/24` |
| #81 | NET-13 | First boot reads port links *after* the DHCP probe. The LAN is the port with a link; the console lists every port and its link |
| #84 | P5-1, FND-2 | `docs/hardware.md`: the owner's box, verified |
| #85 | FND-4 | `firmware-realtek` in the image |
| #86 | NET-14 | Console port summary (`fr-console-ports`): every port's link, role and address, live; warns about a misplaced LAN cable, never moves a role |
| #87 | SEC-22 | verify-medium reports what the persistence layer adds or changes outside FR_OS's files and the router's own state |
| #88 | SEC-15 | The record check reports a deleted file on any Python (`Distribution.files` hides them since 3.12) |
| #89 | SEC-29 | verify-medium judges the accounts, sshd, PAM and fstab files against the image and lists who can log in (`--login-ok NAME` for the admin's own SSH users) |
| #90 | DNS-1 | Local names and split-horizon overrides in the router's resolver (`local_dns`), never blocked, never asked upstream |
| #91 | FND-1a | The router's own IPv6 on the WAN (`ipv6.enabled`): dhcpcd in a sandbox (SLAAC RFC 7217, DHCPv6, PD recorded), IPv6 dropped but what the WAN needs; the boot test has an IPv6 provider (radvd + kea-dhcp6 in a netns) |
| #92 | FND-1b | IPv6 on the LAN: `ia_pd` /64 per LAN zone (`ipv6.lan_zones`), RA-only dnsmasq `fr-ra.service` (no RDNSS), forwarding only while a LAN has IPv6, WAN-new drop, BCP 38, `meta l4proto` rules, IDS quarantine by MAC; zones behind an IPv4-only protection stay off IPv6 |

## Hardware test (owner's box): passed

- **Box:** ASRock Q1900M (J1900), recorded in `docs/hardware.md`.
  - Onboard Realtek r8169 `enp4s0` → Telekom router (`192.168.1.0/24`, router at `.1`): WAN.
  - Axagon PCEE-GRF PCIe card (Realtek) `enp3s0` → laptop: LAN. The link runs at 100 Mbit/s, the card's limit per the owner.
  - Mellanox ConnectX-3 Pro (dual QSFP, `enp2s0`/`enp2s0d1`), cable-less. Its FlexBoot *Virtualization mode* is now None (it was SR-IOV); Linux sees the card.
- **Result (2026-10-10, ISO from run 37578866392, NET-13):** the LAN came out as `enp3s0`; the laptop reached `https://10.73.1.1/`, logged in, changed the password, and has internet through the router.
- **Not yet verified on this hardware:**
  - generic-mode XDP with GRO off on r8169;
  - the ConnectX-3 under load (P4-2).
- **Console access.** There is no console login user by design; everything goes through the webUI. The first-boot password shows on tty2 (Alt+F2).

## Open, candidates for next

- **FND-1 (IPv6), four stages agreed with the owner:** 1a the router's own IPv6 on the WAN (done, #91), 1b the LAN (delegated prefix, RA, forwarding; done, #92), 1c services over IPv6 and inbound pinholes (done, branch `claude/project-thread-gq31th`: ULA, RDNSS, DNS, `management.ipv6` off by default, no DHCPv6 server by decision, `ipv6.pinholes`), 1d agreed as four PRs (design `fnd-1d/terv.md` in the project files): first the fix of 1c's /64 jail (H3: per host by MAC, `bruteforce_jail_mac`, helper `source_device`), then 1d-1 WireGuard over IPv6 with the full tunnel's IPv6 leak (H1), 1d-2 the XDP SNI filter over IPv6 with IPv4 tiny fragments (H2), 1d-3 address rules, ZTNA and the AI IDS over IPv6. FND-1c gotchas: the boot test's SSH is off (nobody has a key), so over IPv6 it shows as "refused" (let through, nothing listens); pinholes are config-only, so the boot test writes one into config.yaml after boot 2; the container's kernel has no IPv6, so everything with packets is in the boot test. FR_OS is a community edition: every provider (prefix, address only, nothing) must work and be explained.

- **FND-4:** Realtek firmware (`firmware-realtek`) is in the image (Partly). Other vendors' NIC firmware is still out.
- **P5-1 / FND-2:** the owner's box is recorded in `docs/hardware.md` (Partly). Add boxes as they are tested.
- **P4-2:** XDP performance on 10G/40G in native mode. The ConnectX-3 Pro pair is available.
- **Unverified (SEC-28):** GRO merging on a physical NIC in generic mode is reasoned from the kernel source, not reproduced. veth didn't merge in the lab.
