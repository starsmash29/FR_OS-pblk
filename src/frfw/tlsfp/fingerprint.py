"""JA3 and JA4 TLS client fingerprints (phase 19).

Both summarize *how* a client speaks TLS -- which cipher suites,
extensions, groups and signature algorithms its TLS library offers, in
what order -- without decrypting anything: all of it is cleartext in the
ClientHello. Two connections from the same app usually share a
fingerprint; a device suddenly presenting a new one is running a
different TLS stack.

- JA3 (Salesforce, BSD 3-Clause): MD5 of the raw lists *in wire order*.
  Chrome and Firefox randomize their extension order per connection
  (Chrome since v110), so a browser's JA3 changes constantly -- which is
  why JA4 exists.
- JA4 (FoxIO, BSD 3-Clause -- unlike the other JA4+ methods, which are
  under the non-permissive FoxIO License and deliberately not
  implemented here): sorted lists, so extension shuffling doesn't change
  it, plus a readable prefix. Implemented from the published
  specification (technical_details/JA4.md in FoxIO-LLC/ja4) and checked
  against its reference outputs for real captures.
"""

from __future__ import annotations

import hashlib

from frfw.tlsfp.clienthello import EXT_ALPN, EXT_SERVER_NAME, ClientHello, is_grease

_TLS_VERSIONS = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
    0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}


def _no_grease(values: list[int]) -> list[int]:
    return [v for v in values if not is_grease(v)]


def ja3_string(hello: ClientHello) -> str:
    fields = [
        [hello.legacy_version],
        _no_grease(hello.ciphers),
        _no_grease(hello.extensions),
        _no_grease(hello.supported_groups),
        hello.ec_point_formats,
    ]
    return ",".join("-".join(str(v) for v in values) for values in fields)


def ja3(hello: ClientHello) -> str:
    return hashlib.md5(ja3_string(hello).encode()).hexdigest()


def _alpn_chars(alpn: list[bytes]) -> str:
    if not alpn or not alpn[0]:
        return "00"
    first = alpn[0]
    a, b = first[0], first[-1]
    if chr(a).isascii() and chr(a).isalnum() and chr(b).isascii() and chr(b).isalnum():
        return chr(a) + chr(b)
    hexed = first.hex()
    return hexed[0] + hexed[-1]


def _sha12(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def ja4_parts(hello: ClientHello, transport: str = "t") -> tuple[str, str, str]:
    """(a, raw cipher list, raw extension+sigalg list) -- `ja4_r` style."""
    versions = _no_grease(hello.supported_versions)
    version = max(versions) if versions else hello.legacy_version
    ciphers = _no_grease(hello.ciphers)
    extensions = _no_grease(hello.extensions)
    a = (
        f"{transport}{_TLS_VERSIONS.get(version, '00')}"
        f"{'d' if EXT_SERVER_NAME in extensions else 'i'}"
        f"{min(len(ciphers), 99):02d}{min(len(extensions), 99):02d}"
        f"{_alpn_chars(hello.alpn)}"
    )
    cipher_list = ",".join(f"{c:04x}" for c in sorted(ciphers))
    ext_list = ",".join(f"{e:04x}" for e in sorted(extensions) if e not in (EXT_SERVER_NAME, EXT_ALPN))
    sigalgs = ",".join(f"{s:04x}" for s in _no_grease(hello.signature_algorithms))
    return a, cipher_list, f"{ext_list}_{sigalgs}" if sigalgs else ext_list


def ja4(hello: ClientHello, transport: str = "t") -> str:
    a, cipher_list, ext_list = ja4_parts(hello, transport)
    b = _sha12(cipher_list) if cipher_list else "000000000000"
    c = _sha12(ext_list) if ext_list.split("_")[0] else "000000000000"
    return f"{a}_{b}_{c}"
