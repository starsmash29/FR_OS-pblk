#!/bin/sh
# Compile the XDP SNI filter (bpf/xdp_sni_filter.c) into the BPF object
# FR_OS loads (ROADMAP P4-1). The image build and the release packaging
# run it, so the image and every release tarball carry the program
# compiled; a router never compiles it -- the image has no compiler, and
# root must not run whatever `clang` is first on its PATH (ROADMAP
# SEC-19). In a from-source checkout, frfw.xdp.ensure_compiled runs it too.
#
# Needs clang, libbpf's headers (libbpf-dev) and the kernel UAPI headers
# (linux-libc-dev).
set -eu

usage="usage: build-xdp-object.sh SOURCE.c OUTPUT.o"
src=${1:?$usage}
out=${2:?$usage}

mkdir -p -- "$(dirname -- "$out")"
exec clang -O2 -g -target bpf -I "/usr/include/$(uname -m)-linux-gnu" -c "$src" -o "$out"
