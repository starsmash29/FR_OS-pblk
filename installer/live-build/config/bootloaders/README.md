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

This directory is a copy of that same bundled theme with the two symlinks
repointed at the correct modern paths, and the SVG splash graphic dropped
(see below); everything else (`isolinux.cfg`, `menu.cfg`, ...) is
untouched.

**`splash.svg.in` removed, `menu background splash.png` line dropped from
`stdmenu.cfg`:** rendering the splash graphic (`lb_binary_syslinux`,
guarded by `if [ -e "${_TARGET}/splash.svg.in" ]`) shells out to a plain
`rsvg --format png ...` command. That binary was dropped from
`librsvg2-bin` years ago in favor of `rsvg-convert` -- confirmed missing
both inside the build chroot (Debian bookworm's librsvg2-bin 2.54.7) and
on this sandbox's Ubuntu host, so it's not a this-old-live-build-only
problem, and there's no config flag to swap in `rsvg-convert` instead.
Since the whole splash step is purely a cosmetic PNG background behind
the BIOS boot menu, removing `splash.svg.in` (which skips the guard
entirely) and the now-dangling `menu background` line was the simplest
fix -- boots to a plain-color vesamenu instead of a branded splash image.
To get the splash back on an environment where `rsvg` (or a shim calling
`rsvg-convert`) is actually resolvable both on the host and inside the
chroot, restore `splash.svg.in` from live-build's own bundled theme
(`/usr/share/live/build/bootloaders/isolinux/splash.svg.in` in this
snapshot) and the `menu background splash.png` line in `stdmenu.cfg`.

**`bootlogo` (empty cpio archive, added):** near the end of
`lb_binary_syslinux` there's an unconditional "hack around the removal of
support in gfxboot" step that does `cpio -i < ${_TARGET}/bootlogo`
regardless of distribution. But the only code path in this snapshot that
ever *creates* `${_TARGET}/bootlogo` is gated on `LB_MODE = ubuntu` (it
untars Ubuntu's `gfxboot-theme-ubuntu` package into the theme dir) -- so
under `--mode debian` no `bootlogo` file is ever produced, and that later
unconditional read always fails with "No such file". Since this whole
gfxboot/bootlogo mechanism is Ubuntu-specific and irrelevant to the plain
isolinux/vesamenu theme used here, the fix is to ship an already-valid,
empty cpio archive named `bootlogo` in this theme override -- it copies
into place alongside the other theme files, the unconditional step reads
it successfully (finds nothing to add, since none of `*.fnt/*.hlp/*.jpg/
*.pcx/*.tr/*.cfg` exist standalone in this theme), and re-writes it back
out unchanged. Generated with:
`(cd "$(mktemp -d)" && ls -1 | cpio --quiet -o) > bootlogo`.

**On a current live-build** (Debian's own package on a real Debian host,
not this sandbox's ancient snapshot) the isolinux.bin/vesamenu.c32
override likely isn't needed at all -- try removing this directory first
when building for real, and only keep it if the same symlink targets
turn out to still be wrong there too. The splash removal is unrelated to
the snapshot's age (current Debian's librsvg2-bin has the same gap) and
should be revisited independently.
