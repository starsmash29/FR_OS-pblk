// XDP TLS 1.3 ClientHello SNI filter -- kernel-space fast path, phase 4.
//
// Everything below runs in the kernel, before any context switch to
// userspace: parse Ethernet/IPv4/TCP, find a TLS ClientHello, extract
// the SNI (Server Name Indication) extension, and look it up in an
// LPM trie blocklist. A match returns XDP_DROP; everything else (not
// TLS, not a ClientHello, SNI absent, no match) returns XDP_PASS. Match
// events are pushed to a ring buffer for userspace (frfw.xdp) to log --
// userspace never touches the drop decision itself. With the
// SETTING_REPORT_PASS switch on (phase 16's app identification), an
// extracted SNI that did *not* match is reported too, as action 0.
//
// With SETTING_REPORT_HELLO (phase 19's TLS fingerprinting) the raw
// bytes of every ClientHello -- and of the next few segments of the same
// flow, since modern hellos often span two -- go to a second ring buffer
// for userspace to reassemble and fingerprint (JA3/JA4). This is copying,
// not parsing: the program still never waits for or depends on it.
//
// XDP only sees packets a device *receives*. To filter the ClientHellos
// LAN clients send out, attach this to the LAN-side interfaces -- on
// the WAN interface it only sees connections arriving from the internet.
//
// Read this file's three "IMPORTANT" comments before touching the
// parsing logic or the LPM key construction; they document real
// correctness/security properties, not style preferences.
//
// IMPORTANT -- what this deliberately does NOT do (and why):
//
// 1. No TCP stream reassembly. A TLS ClientHello can span multiple TCP
//    segments (common in practice: Chrome pads ClientHello specifically
//    to exercise fragmentation and catch broken middleboxes, and a
//    ClientHello with a large key_share/supported_groups list routinely
//    exceeds one MTU). XDP sees one packet at a time with no per-flow
//    state; correctly reassembling a TCP stream in-kernel is a
//    fundamentally different architecture (per-flow buffering, typically
//    at the TC/sockops layer, not XDP) and is out of scope here. This
//    program only inspects a ClientHello that is *entirely contained in
//    a single packet*, and does so completely statelessly: it looks at
//    whatever TCP payload starts with a TLS handshake record header
//    (byte 0x16) at offset 0. A mid-handshake continuation segment
//    never starts with 0x16, so it is naturally and correctly ignored
//    (XDP_PASS) without tracking any per-connection state at all. Net
//    effect: some fraction of real-world ClientHellos are invisible to
//    this filter and pass through unfiltered. This is a deliberate
//    fail-open design (never block what we can't fully see), not an
//    oversight -- see ARCHITECTURE.md's phase 4 section for the
//    numbers/reasoning.
//
// 2. No Encrypted Client Hello (ECH) support. When the client and
//    server negotiate ECH, the *real* SNI is inside an encrypted
//    payload this program cannot decrypt; only an unrelated placeholder
//    "public name" is visible in cleartext. ECH adoption is growing
//    (Chrome, Firefox); this is a known, unavoidable bypass for any
//    cleartext-SNI filter, not specific to this implementation.
//
// 3. No spoofed TCP RST generation. Returning XDP_DROP silently is the
//    safe, always-correct action; synthesizing a valid in-window RST
//    from XDP requires tracking the peer's sequence number, rewriting
//    and recomputing checksums, and re-injecting via XDP_TX -- real,
//    but meaningfully more complex and harder to get right than a
//    drop. Not implemented here; XDP_DROP is what ships.
//
// IMPORTANT -- LPM trie key construction (domain suffix matching):
//
// Blocking "example.com" must also block "www.example.com" but must
// NOT block an unrelated domain that merely shares trailing
// *characters*, e.g. "notexample.com" or "ple.com" (which is a literal
// character-suffix of "example.com": "example.com"[-7:] == "ple.com").
// A naive LPM key of reverse(hostname) gets this wrong, because a
// prefix match on the reversed string is really a suffix match on the
// original string, and plain byte suffixes don't respect label (dot)
// boundaries.
//
// Fix: build the key from reverse("." + hostname), not reverse(hostname).
// The blocklist entry for "example.com" is stored as reverse(".example.com")
// = "moc.elpmaxe." with prefixlen = 12 bytes (96 bits). Looking up
// ".www.example.com" reversed = "moc.elpmaxe.www." shares the full
// 12-byte stored prefix -> match (correctly blocks the subdomain).
// Looking up ".notexample.com" reversed = "moc.elpmaxeton." differs at
// byte 12 ('t' vs '.') -> no match (correctly rejects the unrelated
// domain). The leading dot forces every accepted match to fall exactly
// on a label boundary. See tests/test_xdp_sni_key.py (or the equivalent
// Python reference implementation) for worked examples.
//
// IMPORTANT -- IPv4 only. Matches the rest of frfw (frfw.nft, DHCP/Kea
// etc. are all IPv4-only today); IPv6 support is a follow-up, not a
// silent gap specific to this file.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// --- tunables ---------------------------------------------------------

// Longest hostname this program will match against the blocklist.
// Real hostnames are essentially always well under this; the cap
// exists because building the LPM key (see build_lpm_key's "barrel
// shifter" comment) needs several MAX_SNI_LEN-sized scratch buffers
// live at once inside one BPF program, and BPF programs have a hard,
// non-negotiable 512-byte total stack limit enforced by the kernel
// itself (not a tunable) -- there is no version of this feature that
// both fits that budget and accepts arbitrarily long hostnames. A
// hostname over this length is treated as unparseable and fails open
// (XDP_PASS), exactly like a segmented ClientHello.
#define MAX_SNI_LEN 32
#define LPM_KEY_LEN (MAX_SNI_LEN + 1)  // + 1 for the leading '.' (see above)
#define MAX_TLS_EXTENSIONS 32    // bounded-loop cap for the extension walk

// TLS wire constants (RFC 8446 / RFC 6066)
#define TLS_CONTENT_TYPE_HANDSHAKE 22
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define TLS_EXT_SERVER_NAME 0
#define TLS_SNI_NAME_TYPE_HOST_NAME 0

// stats[] array indices -- cheap counters for the dashboard/tests,
// deliberately separate from the (heavier) per-match ringbuf events.
enum {
	STAT_PASS_NOT_TLS = 0,   // not TCP/443, or payload doesn't start a TLS record
	STAT_PASS_TRUNCATED,     // looked like a ClientHello but didn't fit in this packet
	STAT_PASS_NO_SNI,        // complete ClientHello, no server_name extension
	STAT_PASS_NO_MATCH,      // SNI extracted, not in the blocklist
	STAT_DROP_MATCH,         // SNI extracted, matched the blocklist
	STAT_MAX,
};

// --- maps ---------------------------------------------------------------

struct lpm_sni_key {
	__u32 prefixlen; // in BITS, per BPF_MAP_TYPE_LPM_TRIE convention
	unsigned char reversed[LPM_KEY_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_sni_key);
	__type(value, __u8); // value unused (presence == blocked); kept tiny
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC); // required for LPM_TRIE
} sni_blocklist SEC(".maps");

struct sni_event {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8 action; // 0 = pass (only with SETTING_REPORT_PASS), 1 = drop
	__u16 sni_len;
	char sni[MAX_SNI_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // 256KiB, plenty for burst logging
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, STAT_MAX);
} stats SEC(".maps");

// Runtime switches written by userspace (frfw.xdp.set_report_pass), one
// __u32 bit field at index 0. An ARRAY map is zero-initialised, so a
// freshly loaded program behaves exactly like before this map existed:
// only drops are reported.
#define SETTING_REPORT_PASS 0x1
#define SETTING_REPORT_HELLO 0x2

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} settings SEC(".maps");

// A pass event is only queued while less than this much unread data is
// in the ring buffer. Pass events (one per TLS connection with a visible
// SNI, for phase 16's app identification) vastly outnumber drops; without
// this cap a busy network could fill the buffer and starve the drop
// events the AI IDS scores. The upper half stays reserved for drops.
#define PASS_EVENT_MAX_BACKLOG (128 * 1024)

// --- phase 19: raw ClientHello segments for fingerprinting ------------------

// Bytes copied per segment. A full-size segment on a 1500-byte MTU
// carries 1460; anything longer (jumbo frames) is cut here, which leaves a
// gap userspace can't fill -- that hello simply isn't fingerprinted.
#define HELLO_SNAP 2048

// Segments that follow a ClientHello's first one and are still reported.
// A ~2 KB hello needs one more; 3 leaves room for small MSS values.
#define HELLO_MAX_EXTRA_SEGMENTS 3

struct hello_flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
};

struct hello_flow {
	__u32 segments; // continuation segments reported so far
};

// Flows whose ClientHello didn't fit its first segment. LRU, so flows
// that never complete (the client gave up) age out on their own.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct hello_flow_key);
	__type(value, struct hello_flow);
	__uint(max_entries, 4096);
} hello_flows SEC(".maps");

struct hello_pkt {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 seq;
	__u16 len;   // bytes of TCP payload in data[]
	__u8 first;  // 1 = the segment where the ClientHello starts
	__u8 pad;
	__u8 data[HELLO_SNAP];
};

// 1 MiB: ~500 segments of backlog. A separate buffer from `events`, so
// fingerprinting can never crowd out the drop events.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} hello_pkts SEC(".maps");

static __always_inline void bump(__u32 idx)
{
	__u64 *counter = bpf_map_lookup_elem(&stats, &idx);
	if (counter)
		__sync_fetch_and_add(counter, 1);
}

// --- parsing --------------------------------------------------------------

// Every step below follows the same shape: check `cursor + N <= data_end`
// BEFORE reading N bytes at cursor, then advance cursor by N. This is the
// only pattern the BPF verifier can statically prove safe for
// packet-data pointers; there is no shortcut around checking at each step.

static __always_inline __u16 read_u16(unsigned char *p)
{
	return (p[0] << 8) | p[1];
}

// Optimization barrier: forces the compiler to treat `p`'s value as
// opaque from this point on, rather than algebraically simplifying later
// arithmetic on it using knowledge of how it was originally constructed.
// Needed below because, e.g., `p += 4; ...; read_u16(p - 4)` is exactly
// `(p_original + 4) - 4`, which clang happily strength-reduces straight
// back down to `p_original` -- silently undoing the very restructuring
// (advance-then-check-then-read-from-the-checked-pointer) that the
// verifier needs to see in the compiled output for its range proof to
// actually attach to the register the read uses. Round-tripping through
// this empty asm statement (which the verifier never sees -- it operates
// on the compiled BPF bytecode, and this compiles to zero instructions)
// blocks that simplification: everything after it is forced to treat `p`
// as a fresh, independent value with no traceable relationship to the
// register it was computed from, so `p - 4` here is a genuine
// instruction operating on the checked pointer, not an inference back to
// an earlier one.
static __always_inline unsigned char *opaque(unsigned char *p)
{
	asm volatile("" : "+r"(p));
	return p;
}

// Checks and reads a 4-byte TLS extension header (type(2), length(2)),
// as a real (__noinline) BPF-to-BPF call rather than inlined at its call
// site inside extract_sni's extension-walk loop.
//
// Isolating this in its own small stack frame was tried, at the time,
// as a fix for register pressure inside that loop forcing `p` to be
// spilled between the `p + 4 <= end` check and the read that depends on
// it, with the reload picking up a fresh register whose safety had never
// itself been re-established. That diagnosis wasn't wrong exactly, but
// it also wasn't the *actual* reason the loop couldn't verify -- see the
// comment below (around `if (len_raw > 4095)`) for the real root cause,
// found only after this split was already in place. What this function
// still legitimately buys, independent of that: check-then-read here
// happens with only two pointers and two output slots live, which is
// what makes the "advance p first, check it, then read backward from
// the checked value" shape below actually work (see that shape's own
// comment) -- a shape that was hard to get clang to preserve faithfully
// once *anything* else was competing for the same handful of registers.
__attribute__((noinline))
static int read_ext_header(unsigned char *p, unsigned char *end,
			    __u16 *ext_type, __u32 *ext_len_raw)
{
	// Advances `p` itself by the full checked width *before* testing
	// it against `end`, then reads backward from that now-checked
	// pointer via freshly-derived (p - k) expressions, rather than
	// checking a temporary (p + 4) while reading through the original,
	// already-existing `p`. Empirically these are not equivalent to
	// the verifier: a register that already existed before the check
	// -- even one proven to share the exact same packet-pointer id as
	// the register the comparison was actually performed on -- did not
	// pick up the resulting range refinement here, while a register
	// derived (via pointer arithmetic) from the just-checked pointer
	// *after* the check reliably does. Doing the pointer-arithmetic
	// step first and testing its result directly, then working
	// backward from that exact tested value, sidesteps needing that
	// propagation at all.
	p += 4;
	if (p > end)
		return 0;
	p = opaque(p);
	*ext_type = read_u16(p - 4);
	__u32 len_raw = read_u16(p - 2);
	// `len_raw` is a raw 16-bit field, so the verifier's own tracked
	// range for it is the full 0..65535 -- checking `len_raw > 4095`
	// here and rejecting rather than clamping means the *only* value
	// that ever reaches the caller through *ext_len_raw is one already
	// proven <= 4095, but a bare runtime check like this does not, by
	// itself, reliably narrow the *static* range the verifier attaches
	// to the value for everything downstream (the same class of
	// precision loss documented in xdp_sni_filter() around `sni_len`).
	// Masking it right here, immediately after the check that proves
	// the mask is a no-op for every value that reaches this line,
	// gives the verifier a hard, reload-surviving bound instead of one
	// resting on a branch it may not keep tracking -- this is exactly
	// what let `xdp_sni_filter.c`'s `advance` accumulate an essentially
	// unbounded (0..65535-per-iteration) tracked upper bound across
	// this loop's 32 unrolled iterations despite the `<= 4095` check at
	// the call site, which in turn was the actual reason the packet
	// pointer's own tracked range became too wide for later checks
	// against `end` to verify -- not register pressure, not a stray
	// pointer-vs-pointer comparison, both of which were also fixed
	// along the way but were not, in the end, the root cause.
	if (len_raw > 4095)
		return 0;
	*ext_len_raw = len_raw & 4095;
	return 1;
}

// Parses a server_name extension's body -- list_length(2), then
// {name_type(1), name_length(2), name[name_length]} -- starting at `p`
// (the first byte *after* the 4-byte extension header). Same
// __noinline-for-register-pressure reasoning as read_ext_header() above:
// isolating this chain in its own small stack frame is what lets each
// bounds check actually protect the read right next to it. On success,
// returns 1 and sets *name_ptr to the first byte of the hostname and
// *name_len to its length (guaranteed 0 < *name_len < MAX_SNI_LEN, with
// a full MAX_SNI_LEN bytes of packet verified readable from *name_ptr --
// the caller's unconditional MAX_SNI_LEN-byte copy relies on that).
__attribute__((noinline))
static int parse_sni_body(unsigned char *p, unsigned char *end,
			   __u32 *name_len, unsigned char **name_ptr)
{
	// Same "advance p first, check the advanced value itself, then
	// read backward from it" shape as read_ext_header() above, and for
	// the same reason: reading via a `p` that already existed before
	// the check that was meant to justify it -- even unadvanced, even
	// same id -- did not reliably keep the verifier's proof attached.
	p += 2; // server_name_list length -- unused
	if (p > end)
		return 0;
	p = opaque(p);

	p += 1;
	if (p > end)
		return 0;
	p = opaque(p);
	__u8 name_type = p[-1];
	if (name_type != TLS_SNI_NAME_TYPE_HOST_NAME)
		return 0;

	p += 2;
	if (p > end)
		return 0;
	p = opaque(p);
	__u32 name_len_raw = read_u16(p - 2);
	if (name_len_raw == 0 || name_len_raw >= MAX_SNI_LEN)
		return 0;

	unsigned char *name_end = p + MAX_SNI_LEN;
	if (name_end > end)
		return 0;
	// `p` itself (not name_end) is handed back via *name_ptr, to be
	// read forward by the caller after this function has returned --
	// barrier it too, so its checked-ness doesn't get optimized away
	// across the call boundary the same way it would have within this
	// function.
	p = opaque(p);

	*name_len = name_len_raw;
	*name_ptr = p;
	return 1;
}

// Extracts the SNI hostname (if any, and if it fully fits in this
// packet) from a ClientHello body. Returns the hostname length written
// into `out_sni` (0..MAX_SNI_LEN), or a negative value if the
// ClientHello is malformed or truncated (caller treats that as
// STAT_PASS_TRUNCATED, never as a match).
//
// Deliberately written as one flat sequence with the pointer kept in a
// single local variable `p`, never behind a struct field accessed via
// `->`. Round-tripping a "cursor" pointer through a struct field
// between a bounds check and the later dereference is a well-known BPF
// verifier trap: the check and the read end up as two separate loads
// from the stack slot, and the verifier's pointer-range refinement
// (attached to the exact register compared against data_end) does not
// reliably carry over to the reloaded value, even though they are
// provably the same address. Every `if (p + n > end) return ...; use
// p[0..n-1]; p += n;` step below reads `p` immediately after checking
// it and before anything could force a reload -- the same shape as the
// (verifier-clean) Ethernet/IP/TCP parsing above it in this file.
// __noinline (its own BPF-to-BPF call, own stack frame) rather than
// __always_inline: this function calls read_ext_header()/parse_sni_body()
// (themselves __noinline), and the kernel verifier sums the stack of
// every frame on a call path and rejects it past 512 bytes total. With
// extract_sni() inlined into xdp_sni_filter(), that sum included
// xdp_sni_filter()'s own locals (the ring buffer event, the LPM key,
// the Ethernet/IP/TCP header pointers) *plus* extract_sni()'s locals
// *plus* whichever helper it called -- "combined stack size of 2 calls
// is 672. Too large". Giving extract_sni() its own frame removes
// xdp_sni_filter()'s locals from that sum entirely, since they are no
// longer live in the same frame as the call.
__attribute__((noinline))
static int extract_sni(unsigned char *p, unsigned char *end, char *out_sni)
{
	// client_version(2) + random(32)
	if (p + 34 > end)
		return -1;
	p += 34;

	// session_id: 1-byte length (RFC 8446 caps this at 32) + variable body
	if (p + 1 > end)
		return -1;
	__u32 session_id_len = p[0];
	p += 1;
	if (session_id_len > 32)
		return -1;
	if (p + session_id_len > end)
		return -1;
	p += session_id_len;

	// cipher_suites: 2-byte length (in bytes) + variable body. The
	// verifier's ability to keep tracking `p` as a bounds-checkable
	// packet pointer through the *later* checks (compression_methods,
	// extensions) depends on how tight a range it can prove for this
	// value -- clamping it to a generous-but-real maximum (a couple
	// hundred real cipher suites is already an enormous ClientHello)
	// keeps that range small. Without this clamp the verifier still
	// accepts the immediately-following check, but loses precision by
	// the time it reaches the extension-walk loop several fields later
	// and rejects a later, individually-correct bounds check -- this
	// clamp is load-bearing, not defensive styling.
	if (p + 2 > end)
		return -1;
	__u32 cipher_suites_len = read_u16(p);
	p += 2;
	if (cipher_suites_len > 512)
		return -1;
	if (p + cipher_suites_len > end)
		return -1;
	p += cipher_suites_len;

	// compression_methods: 1-byte length (practically always 1) + variable body
	if (p + 1 > end)
		return -1;
	__u32 compression_len = p[0];
	p += 1;
	if (compression_len > 16)
		return -1;
	if (p + compression_len > end)
		return -1;
	p += compression_len;

	// extensions: 2-byte total length, then a sequence of
	// {type(2), length(2), data[length]} -- if this length field is
	// itself absent, there are no extensions (legal, if unusual) so
	// there's no SNI to find; that's a normal "no match", not truncation.
	if (p + 2 > end)
		return -2; // signal "no extensions block" separately from malformed
	__u32 ext_total = read_u16(p);
	p += 2;
	if (ext_total > 4095)
		ext_total = 4095;
	// Where to stop walking extensions is tracked as a plain integer
	// byte count (`consumed` below), not a second packet pointer
	// compared against `p`: a pointer-vs-pointer comparison (neither
	// side being the special data_end register) isn't a pattern the
	// verifier's range-propagation recognizes, and empirically it
	// disrupted range tracking on `p` itself at the actual read sites
	// further down (a comparison against `ext_end` intervening between
	// the `p + 4 <= end` safety check and the dereference was enough to
	// make the verifier lose track of the checked register by the time
	// of the read). Plain integer comparisons carry no such risk.

	// No `break`/`continue` anywhere in this loop -- every iteration
	// always runs, in full. Every potentially-unsafe read is behind a
	// genuine `if` inside read_ext_header()/parse_sni_body() (see their
	// comments) that both performs the bounds check *and* the read in
	// the same statement, never a ternary that merely *looks* like it
	// gates a read computed elsewhere: a ternary like
	// `some_flag ? read_u16(p) : 0`, where `some_flag` was set by an
	// *earlier*, separate check, does not actually stop the read from
	// running when unsafe -- the C abstract machine sees an ordinary,
	// side-effect-free integer load with no undefined behavior, so LLVM
	// is free to (and, empirically, did, before this loop was
	// restructured around those two helper functions) speculate BOTH
	// branches and select between the results afterwards, which the
	// verifier then correctly rejects as an out-of-bounds access. The
	// ternaries that remain in this loop (advance amounts, the
	// `found`/`found_sp` tracking) are fine precisely because they only
	// ever *select between two already-computed, already-safe* values
	// -- nothing there triggers a new memory access.
	int done = 0;
	int found = 0;
	__u32 found_len = 0;
	unsigned char *found_sp = p; // dummy init, only meaningful when found
	// `consumed` (bytes into the extensions block) is the *only* state
	// that carries from one iteration to the next; each iteration's
	// working pointer is then computed fresh as `ext_start + consumed`
	// (see below) rather than by repeatedly adding `advance` onto a
	// running pointer. The difference matters a great deal to the
	// verifier: accumulating `p = p + advance` 32 times means its
	// tracked upper bound is the *sum* of all 32 iterations' individual
	// per-iteration maximums, even though `past_ext_end` guarantees the
	// dynamic value can only ever exceed `ext_total` (<= 4095) by at
	// most one iteration's overshoot -- the verifier's static analysis
	// doesn't reliably derive that cross-iteration invariant on its
	// own, so the tracked bound just keeps compounding, and by the
	// later iterations it becomes so wide relative to `end`'s own
	// (small, real-packet-sized) tracked bound that comparisons against
	// `end` stop verifying at all, even inside an isolated, minimal,
	// otherwise-correct helper. Recomputing from a fixed base plus a
	// *masked* running total every iteration keeps the pointer's
	// tracked bound at the same (small) value on every iteration,
	// because it is always exactly `ext_start`'s bound plus the mask's
	// fixed constant -- it never compounds.
	unsigned char *ext_start = p;
	__u32 consumed = 0;

	// Deliberately *not* `#pragma unroll` here, unlike every other loop
	// in this file: unrolling all MAX_TLS_EXTENSIONS=32 iterations
	// verifies each one as a separate, fully-inlined copy, and even
	// after the fixes above stopped the packet pointer's tracked range
	// from blowing up, the sheer number of resulting instructions and
	// distinct explored states exceeded the kernel's fixed 1,000,000-
	// instruction verifier processing budget (a hard limit, not
	// something this program can be clever its way around by staying
	// "more correct" -- it has to actually be smaller). A real loop
	// with a back-edge is verified once via the kernel's bounded-loop
	// support (5.3+): the verifier explores the body repeatedly only
	// until the register/stack state reaches a fixed point, which is
	// far cheaper here now that the loop-carried state is just a
	// bitmask-bounded scalar (`consumed`) and a pointer recomputed
	// fresh from it every iteration -- exactly the shape that widens
	// cleanly, unlike the byte-array indexing elsewhere in this file
	// that made real loops unusable for build_lpm_key.
	for (int i = 0; i < MAX_TLS_EXTENSIONS; i++) {
		unsigned char *p = ext_start + (consumed & 16383);
		// `end` (data_end) is the *only* memory-safety gate for the
		// read inside read_ext_header() below. `past_ext_end` (a
		// plain integer comparison against `ext_total`, computed a
		// few lines down) is a *correctness*-only concern -- whether
		// we've logically walked past the declared extensions length
		// -- and never gates a memory access; an earlier version of
		// this function used a second *pointer* (`ext_end`) for that
		// same purpose and compared it directly against `p`, which
		// turned out to actively interfere with the verifier's
		// ability to prove the `p + 4 <= end` check below still
		// applied at the read site (see read_ext_header()'s comment
		// for the actual, more fundamental cause this masked at the
		// time). Tracking the same fact as a plain integer instead
		// removes that risk entirely, which is why `ext_total` and
		// `consumed` are both scalars, never packet pointers.
		//
		// The check-and-read itself happens inside read_ext_header(),
		// a real (__noinline) call -- see that function's comment for
		// why: inlined directly here, register pressure from this
		// loop's many other live locals forced `p` to be spilled and
		// separately re-loaded between the comparison and the read,
		// and the verifier does not carry a proven range across that
		// particular kind of reload. A dedicated small stack frame
		// with only these two pointers live sidesteps the spill
		// entirely.
		__u16 ext_type = 0;
		__u32 ext_len_raw = 0;
		int have_header = !done && read_ext_header(p, end, &ext_type, &ext_len_raw);
		// Once `consumed` has reached/passed the declared extensions
		// length, stop walking further extensions -- purely a
		// correctness bound (see the comment above `ext_total`'s
		// declaration for why this is a plain integer compare rather
		// than a second pointer compared against `p`).
		int past_ext_end = consumed >= ext_total;
		int header_ok = have_header && !past_ext_end && (ext_len_raw <= 4095);
		__u32 ext_len = header_ok ? ext_len_raw : 0;
		int is_sni = header_ok && (ext_type == TLS_EXT_SERVER_NAME);

		// server_name extension body -- see parse_sni_body()'s comment
		// for why this is its own __noinline function rather than
		// inlined here: same register-pressure-forces-a-spill problem
		// as read_ext_header() above, just for this chain's reads.
		__u32 name_len = 0;
		unsigned char *name_ptr = p; // dummy init, meaningful only when ok4
		int ok4 = is_sni && parse_sni_body(p + 4, end, &name_len, &name_ptr);

		// Track only a pointer + length through the loop, not the
		// bytes themselves: the alternative (copying MAX_SNI_LEN bytes
		// on every one of MAX_TLS_EXTENSIONS iterations, self-
		// referencing the output buffer to preserve it across
		// non-matching iterations) is exactly the self-referential
		// array-write pattern that overflowed the BPF stack budget in
		// build_lpm_key -- multiplied here by MAX_TLS_EXTENSIONS, it
		// is worse, not better. A single pointer/length pair is cheap
		// to carry forward (safe as a ternary: name_ptr is already
		// valid whenever ok4 is true, no new access happens here); the
		// actual (one-time) byte copy happens once, after the loop,
		// only if something matched.
		if (!found && ok4) {
			found_len = name_len;
			found_sp = name_ptr;
			found = 1;
		}

		// Advance past this extension only when it was a valid,
		// non-SNI one we're skipping; 0 in every other case (malformed,
		// truncated, or the SNI extension itself -- either way there is
		// nothing further worth walking for this packet). Safe as a
		// ternary: it only picks between two already-known integers,
		// no read happens here.
		__u32 advance = (header_ok && !is_sni) ? (4 + ext_len) : 0;
		consumed = (consumed + advance) & 16383;
		done = done || !have_header || past_ext_end || is_sni;
	}

	if (found) {
#pragma unroll
		for (int j = 0; j < MAX_SNI_LEN; j++)
			out_sni[j] = (j < found_len) ? found_sp[j] : 0;
		return (int)found_len;
	}

	return -2; // walked all visible extensions, found no server_name
}

// Builds the label-boundary-safe LPM lookup key described in this
// file's header comment: reverse("." + hostname). sni[] is already
// zero-padded past sni_len (see extract_sni's copy loop).
//
// This needs a variable-*distance* shift (the meaningful bytes must
// end up left-aligned at position 0 regardless of hostname length),
// and every attempt to express that as `buf[runtime_expression]`
// failed, in three different ways:
//   - fully unrolled with a data-dependent read index: clang cannot
//     even emit the object file ("BPF stack limit exceeded" at compile
//     time -- synthesizing a dynamic gather from a small stack array,
//     repeated MAX_SNI_LEN times, is simply too much code/spill space
//     for the 512-byte BPF stack budget);
//   - the same read routed through bpf_xdp_load_bytes() per byte to
//     dodge the stack-array gather: crashes clang's backend outright
//     (each helper call's register-spill sequence, repeated
//     MAX_SNI_LEN times, is *also* too much);
//   - a plain, non-unrolled loop over a runtime bound (relying on the
//     verifier's native bounded-loop support, kernel >= 5.3): compiles
//     and the *first* iteration verifies fine, but the verifier's
//     state widening across the loop's back-edge loses the tight
//     value range it had proven for iteration 1, and a later iteration
//     is rejected as an "unbounded variable-offset read from stack".
//
// The fix is a textbook barrel shifter: decompose the runtime shift
// distance into its bits, and apply a *fixed*-distance conditional
// shift per bit (6 stages cover any shift up to 63, comfortably more
// than LPM_KEY_LEN's current 33 ever needs, each shifting by a
// compile-time-constant 32, 16, 8, 4, 2 or 1). Every single memory
// access here uses a compile-time-constant address; the only runtime
// value involved is a boolean ("is this particular bit of the shift
// amount set") gating whether a given fixed-distance stage runs at
// all -- the same "constant address, runtime-gated use" shape as
// extract_sni's copy loop above, which does compile and verify cleanly.
__attribute__((noinline))
static void build_lpm_key(struct lpm_sni_key *key, const char *sni, __u32 sni_len)
{
	key->prefixlen = (sni_len + 1) * 8;

	// key->reversed[] = reverse("." + hostname), *right-aligned*, built
	// directly with no intermediate "." + hostname buffer: buf[0]='.'
	// and buf[k]=sni[k-1] for k=1..MAX_SNI_LEN was always immediately
	// followed by key->reversed[i]=buf[LPM_KEY_LEN-1-i] and nothing
	// else ever read buf[], so substituting k=LPM_KEY_LEN-1-i directly
	// below produces the identical bytes while removing an entire
	// LPM_KEY_LEN-byte local array (and the now-pointless loop that
	// used to zero-fill it before every element was unconditionally
	// overwritten anyway) -- this function's own stack usage is on the
	// combined-call-stack budget along with whichever frame calls it,
	// so a whole redundant buffer here is not free. Still a pure
	// compile-time index into key->reversed (part of the *caller's*
	// struct, not this frame's stack) on one side and into `sni` on
	// the other: the real content of length (sni_len + 1) ends up at
	// the far end of key->reversed, at offset (LPM_KEY_LEN - 1 -
	// sni_len), exactly as before.
	// The '.' byte is written separately (its position, LPM_KEY_LEN-1,
	// is a compile-time constant) so the loop below never needs a
	// conditional -- and, critically, never needs to *write down* an
	// expression like `sni[MAX_SNI_LEN - 1 - i]` for the case that
	// would make that index negative. A ternary guarding it (`i ==
	// LPM_KEY_LEN-1 ? '.' : sni[...]`) would very likely still have
	// been fine here specifically -- with `i` a compile-time constant
	// in a fully-unrolled loop, the condition folds to a literal at
	// compile time, unlike the genuinely runtime-dependent conditions
	// elsewhere in this file where a ternary was shown *not* to stop
	// the read from being evaluated -- but "very likely fine" isn't
	// the standard the rest of this file holds reads to, and there is
	// a version that simply never expresses the out-of-bounds access
	// at all.
	key->reversed[LPM_KEY_LEN - 1] = '.';
#pragma unroll
	for (int i = 0; i < MAX_SNI_LEN; i++)
		key->reversed[i] = sni[MAX_SNI_LEN - 1 - i];

	// Barrel-shift left by exactly that offset to bring the real
	// content to the front. `tmp` is declared once and reused by every
	// stage so its stack slot doesn't multiply by the number of
	// stages.
	// Each stage is a real runtime `if` around the whole copy, not a
	// per-byte select: a single branch that either runs a
	// compile-time-addressed copy or skips it entirely is far cheaper
	// (in both code size and the stack space clang needs to synthesize
	// it) than LPM_KEY_LEN per-byte ternaries -- the latter is what
	// overflowed the 512-byte stack budget here even at this reduced
	// MAX_SNI_LEN.
	__u32 shift = LPM_KEY_LEN - 1 - sni_len;
	char tmp[LPM_KEY_LEN]; // one shared scratch slot, reused by every stage
#pragma unroll
	for (int bit = 5; bit >= 0; bit--) {
		__u32 amount = 1u << bit; // 32, 16, 8, 4, 2, 1
		if (shift & amount) {
#pragma unroll
			for (int i = 0; i < LPM_KEY_LEN; i++)
				tmp[i] = (i + amount < LPM_KEY_LEN) ? key->reversed[i + amount] : 0;
#pragma unroll
			for (int i = 0; i < LPM_KEY_LEN; i++)
				key->reversed[i] = tmp[i];
		}
	}
}

static __always_inline __u32 setting_flags(void)
{
	__u32 idx = 0;
	__u32 *flags = bpf_map_lookup_elem(&settings, &idx);
	return flags ? *flags : 0;
}

static __always_inline int report_pass_enabled(void)
{
	return setting_flags() & SETTING_REPORT_PASS;
}

// Copy one segment's TCP payload to hello_pkts. Best effort, like
// emit_event(): a full buffer just loses the segment.
static __always_inline void emit_hello_segment(struct xdp_md *ctx, struct iphdr *ip,
					       struct tcphdr *tcp, __u32 offset,
					       __u32 payload_len, __u8 first)
{
	if (payload_len < 1)
		return;
	__u32 n = payload_len > HELLO_SNAP ? HELLO_SNAP : payload_len;
	// Same trick as build_lpm_key's bound (see xdp_sni_filter()): a mask
	// gives the verifier a provable [1, HELLO_SNAP] range that survives
	// the compiler's register shuffling, which the comparisons alone
	// don't. HELLO_SNAP is a power of two, so this changes no value.
	n = ((n - 1) & (HELLO_SNAP - 1)) + 1;
	struct hello_pkt *pkt = bpf_ringbuf_reserve(&hello_pkts, sizeof(*pkt), 0);
	if (!pkt)
		return;
	pkt->saddr = ip->saddr;
	pkt->daddr = ip->daddr;
	pkt->sport = bpf_ntohs(tcp->source);
	pkt->dport = bpf_ntohs(tcp->dest);
	pkt->seq = bpf_ntohl(tcp->seq);
	pkt->first = first;
	pkt->pad = 0;
	pkt->len = n;
	if (bpf_xdp_load_bytes(ctx, offset, pkt->data, n) < 0) {
		bpf_ringbuf_discard(pkt, 0);
		return;
	}
	bpf_ringbuf_submit(pkt, 0);
}

// Best effort: if the ring buffer is full the event is simply lost --
// the drop/pass decision never depends on userspace keeping up.
static __always_inline void emit_event(struct iphdr *ip, struct tcphdr *tcp,
				       const char *sni, __u32 name_len, __u8 action)
{
	struct sni_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return;
	ev->saddr = ip->saddr;
	ev->daddr = ip->daddr;
	ev->sport = bpf_ntohs(tcp->source);
	ev->dport = bpf_ntohs(tcp->dest);
	ev->action = action;
	ev->sni_len = name_len;
#pragma unroll
	for (int i = 0; i < MAX_SNI_LEN; i++)
		ev->sni[i] = (i < name_len) ? sni[i] : 0;
	bpf_ringbuf_submit(ev, 0);
}

SEC("xdp")
int xdp_sni_filter(struct xdp_md *ctx)
{
	unsigned char *data = (unsigned char *)(long)ctx->data;
	unsigned char *data_end = (unsigned char *)(long)ctx->data_end;

	struct ethhdr *eth = (struct ethhdr *)data;
	if ((unsigned char *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (struct iphdr *)(eth + 1);
	if ((unsigned char *)(ip + 1) > data_end)
		return XDP_PASS;
	if (ip->protocol != IPPROTO_TCP)
		return XDP_PASS;
	if (ip->ihl < 5)
		return XDP_PASS;
	unsigned char *ip_opts_end = (unsigned char *)ip + (ip->ihl * 4);
	if (ip_opts_end > data_end)
		return XDP_PASS;

	struct tcphdr *tcp = (struct tcphdr *)ip_opts_end;
	if ((unsigned char *)(tcp + 1) > data_end)
		return XDP_PASS;
	if (tcp->dest != bpf_htons(443))
		return XDP_PASS;
	if (tcp->doff < 5)
		return XDP_PASS;
	unsigned char *payload = (unsigned char *)tcp + (tcp->doff * 4);
	if (payload > data_end)
		return XDP_PASS;

	// Phase 19: the rest of a ClientHello that didn't fit its first
	// segment. Checked before the "starts a TLS record" test below,
	// since a continuation segment never does.
	// Offset and length as plain scalars from header fields (the IP total
	// length also excludes any Ethernet padding); pointer differences
	// would be rejected by the verifier once the compiler shifts them.
	__u32 hdr_len = (__u32)ip->ihl * 4 + (__u32)tcp->doff * 4;
	__u32 ip_len = bpf_ntohs(ip->tot_len);
	__u32 payload_off = sizeof(struct ethhdr) + hdr_len;
	__u32 payload_len = ip_len > hdr_len ? ip_len - hdr_len : 0;
	int report_hello = setting_flags() & SETTING_REPORT_HELLO;
	struct hello_flow_key flow_key = {
		.saddr = ip->saddr, .daddr = ip->daddr,
		.sport = tcp->source, .dport = tcp->dest,
	};
	// (A pointer comparison, not payload_len > 0: the verifier only
	// accepts a packet read it can prove in bounds that way.)
	if (report_hello && payload + 1 <= data_end && payload[0] != TLS_CONTENT_TYPE_HANDSHAKE) {
		struct hello_flow *flow = bpf_map_lookup_elem(&hello_flows, &flow_key);
		if (flow) {
			emit_hello_segment(ctx, ip, tcp, payload_off, payload_len, 0);
			flow->segments += 1;
			if (flow->segments >= HELLO_MAX_EXTRA_SEGMENTS)
				bpf_map_delete_elem(&hello_flows, &flow_key);
		}
	}

	// TLS record header: content_type(1) version(2) length(2). Only a
	// fresh handshake record starting exactly here can be a
	// ClientHello -- a mid-stream continuation segment never starts
	// with byte 0x16, so this check alone gives us statelessness (see
	// this file's header comment, point 1).
	if (payload + 5 > data_end) {
		bump(STAT_PASS_NOT_TLS);
		return XDP_PASS;
	}
	if (payload[0] != TLS_CONTENT_TYPE_HANDSHAKE) {
		bump(STAT_PASS_NOT_TLS);
		return XDP_PASS;
	}

	unsigned char *hs = payload + 5;
	if (hs + 4 > data_end) {
		bump(STAT_PASS_TRUNCATED);
		return XDP_PASS;
	}
	if (hs[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
		bump(STAT_PASS_NOT_TLS);
		return XDP_PASS;
	}

	if (report_hello) {
		emit_hello_segment(ctx, ip, tcp, payload_off, payload_len, 1);
		// Record length (header bytes 3-4) larger than what this segment
		// carries: remember the flow so its next segments are reported too.
		__u32 record_len = ((__u32)payload[3] << 8) | payload[4];
		if (record_len + 5 > payload_len) {
			struct hello_flow fresh = { .segments = 0 };
			bpf_map_update_elem(&hello_flows, &flow_key, &fresh, BPF_ANY);
		}
	}

	char sni[MAX_SNI_LEN] = {};
	int sni_len = extract_sni(hs + 4, data_end, sni);

	if (sni_len == -1) {
		bump(STAT_PASS_TRUNCATED);
		return XDP_PASS;
	}
	if (sni_len == -2 || sni_len == 0) {
		bump(STAT_PASS_NO_SNI);
		return XDP_PASS;
	}
	// Unreachable in practice: extract_sni() already refuses to return a
	// value over MAX_SNI_LEN. Re-checked and, crucially, re-derived via
	// a bitmask anyway: sni_len lives on the BPF stack by this point
	// (this function has too many live values to keep everything in
	// registers), and a plain `if (sni_len > MAX_SNI_LEN) return ...`
	// branch's range refinement does not reliably survive the *next*
	// reload of that same stack slot inside build_lpm_key() -- the
	// verifier rejects the reload as an unbounded "variable-offset
	// stack read" even though the value is provably safe by
	// construction. Masking with (MAX_SNI_LEN - 1) gives the verifier
	// an unconditional, trivially-provable bound that does survive a
	// reload, which a comparison-based branch does not; MAX_SNI_LEN is
	// a power of 2 specifically so this mask is exact for every value
	// this function actually produces ([1, MAX_SNI_LEN-1], since
	// extract_sni already rejects anything >= MAX_SNI_LEN).
	if (sni_len < 1 || sni_len >= MAX_SNI_LEN) {
		bump(STAT_PASS_NO_SNI);
		return XDP_PASS;
	}
	__u32 name_len = (__u32)sni_len & (MAX_SNI_LEN - 1);

	struct lpm_sni_key key;
	build_lpm_key(&key, sni, name_len);

	__u8 *blocked = bpf_map_lookup_elem(&sni_blocklist, &key);
	if (!blocked) {
		bump(STAT_PASS_NO_MATCH);
		if (report_pass_enabled() &&
		    bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA) < PASS_EVENT_MAX_BACKLOG)
			emit_event(ip, tcp, sni, name_len, 0);
		return XDP_PASS;
	}

	bump(STAT_DROP_MATCH);
	emit_event(ip, tcp, sni, name_len, 1);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
