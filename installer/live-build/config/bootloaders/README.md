# config/bootloaders/isolinux/ override

live-build checks `config/bootloaders/<bootloader>` before falling back to
its own bundled theme (see the `_SOURCE=` logic in
`/usr/lib/live/build/lb_binary_syslinux`) -- this directory exists
because this build's live-build package (3.0~a57, a very old
Ubuntu-patched snapshot) ships a bundled isolinux theme, dated 2012, whose
`isolinux.bin` and `vesamenu.c32` are symlinks to
`/usr/lib/syslinux/isolinux.bin` and `/usr/lib/syslinux/vesamenu.c32` --
a file layout that predates the current syslinux packaging (Debian moved
`isolinux.bin` to `/usr/lib/ISOLINUX/isolinux.bin`, and `vesamenu.c32`
into `/usr/lib/syslinux/modules/bios/`, years ago). Those symlinks 404
during the binary-image assembly step every time, with no config flag to
fix it.

This directory is a copy of that same bundled theme with just the two
symlinks repointed at the correct modern paths; everything else
(`isolinux.cfg`, `menu.cfg`, `splash.svg.in`, ...) is untouched.

**On a current live-build** (Debian's own package on a real Debian host,
not this sandbox's ancient snapshot) this override likely isn't needed at
all -- try removing this directory first when building for real, and only
keep it if the same symlink targets turn out to still be wrong there too.
