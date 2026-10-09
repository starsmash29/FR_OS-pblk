# Integrator handover

State and working agreements for the next session of the integrating agent
(Claude Code), so work picks up where it stopped. Last updated 2026-10-09,
`main` at `5df6a97`.

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

## Hardware test in progress (owner's box)

- **Box:** ASRock Q1900M (J1900).
  - Onboard Realtek r8169 `enp4s0` → Telekom router (`192.168.1.0/24`, router at `.1`): WAN.
  - Axagon PCEE-GRF PCIe card (Realtek) `enp3s0` → laptop: intended LAN.
  - Mellanox ConnectX-3 Pro (dual QSFP, `enp2s0`/`enp2s0d1`), cable-less. Its FlexBoot *Virtualization mode* is now None (it was SR-IOV); Linux sees the card.
- **First run with the NET-12 image:** the LAN came out as `enp2s0`, the empty QSFP port. That is the NET-13 bug, fixed in #81. The laptop's DHCP was dropped on the unassigned `enp3s0`.
- **Next step:** the owner rewrites the stick with the ISO from run 37578866392 (NET-13; same code as `main` 5df6a97). Expected console line (Alt+F2): `LAN port (enp3s0)`, then the webUI at `https://10.73.1.1/` from the laptop.
- **Not yet verified on this hardware:**
  - the webUI and routing end to end;
  - generic-mode XDP with GRO off on r8169;
  - the ConnectX-3 under load (P4-2).
- **Console access.** There is no console login user by design; everything goes through the webUI. The first-boot password shows on tty2 (Alt+F2).

## Open, candidates for next

- **Console:** show a short port/link summary on the console after first boot too, not only in the first-boot reason line. Small, NET-13 follow-up.
- **SEC-22:** integrity checks cover FR_OS's own files only.
- **FND-4:** non-free NIC firmware in the image (some Realtek revisions want `rtl_nic`).
- **P5-1 / FND-2:** reference hardware list. Record the owner's box once the test passes.
- **P4-2:** XDP performance on 10G/40G in native mode. The ConnectX-3 Pro pair is available.
- **Unverified (SEC-28):** GRO merging on a physical NIC in generic mode is reasoned from the kernel source, not reproduced. veth didn't merge in the lab.
