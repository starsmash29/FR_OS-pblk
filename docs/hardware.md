# Reference hardware

Physical machines FR_OS has been installed and run on, and what was checked
on each (ROADMAP P5-1, FND-2). The QEMU boot test (`installer/qemu-boot-test.py`)
covers the image on every change; this list is what it can't: real NICs, real
firmware and real cabling.

A box is listed only after an owner-run test. Each entry says which image was
used, what was verified, and what is still unverified on it.

## ASRock Q1900M (Intel Celeron J1900)

**Tested:** 2026-10-10, image from the *Build installer ISO* run 37578866392
(NET-13, commit `044648d`, same code as `main` at `5df6a97`).

| Port | Hardware | Driver | Role in the test |
|---|---|---|---|
| `enp4s0` | Onboard Realtek | `r8169` | WAN, to the ISP router (`192.168.1.0/24`, DHCP) |
| `enp3s0` | Axagon PCEE-GRF PCIe card (Realtek) | `r8169` | LAN, to a laptop |
| `enp2s0`, `enp2s0d1` | Mellanox ConnectX-3 Pro, dual QSFP | `mlx4_en` | No cable |

The ConnectX-3's FlexBoot *Virtualization mode* had to be set to *None* (it
was SR-IOV); after that Linux saw the card.

**Verified:**
- The ISO boots and installs.
- First boot picks the port with a link as the LAN (NET-13): the console
  (Alt+F2) shows `LAN port (enp3s0)`, with the empty QSFP ports not chosen.
  With the NET-12 image, before that fix, the LAN came out as the cable-less
  `enp2s0`.
- The laptop gets a DHCP lease in `10.73.1.0/24` (NET-12) and reaches the
  webUI at `https://10.73.1.1/`.
- Login with the first-boot password from tty2, and the password change.
- Routing and NAT: the laptop reaches the internet through the router.

**Notes:**
- The LAN link runs at 100 Mbit/s, which the owner reports is the network
  card's limit. Throughput through this box was not measured beyond that.

**Not yet verified on this box:**
- Generic-mode XDP with GRO turned off on `r8169` (SEC-28, `XdpState.gro_off`).
- The ConnectX-3 Pro under load, and native-mode XDP on it (P4-2).
- Whether any Realtek revision here needs the non-free `rtl_nic` firmware;
  both ports worked without it, on an image from before FND-4 put it in.
