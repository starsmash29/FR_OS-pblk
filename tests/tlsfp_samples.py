"""Synthetic TLS ClientHellos for the phase 19 tests, built from RFC 8446
structures -- no captured traffic from third parties is bundled."""

from __future__ import annotations

import struct

GREASE = 0x3A3A

#: Chrome-like cipher suites (TLS 1.3 + 1.2 ECDHE/RSA), with a GREASE value first.
CHROME_LIKE_CIPHERS = [GREASE, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
                       0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]

#: X25519MLKEM768 (group 0x11ec) key share: 1184-byte ML-KEM-768 key + 32-byte X25519 key.
MLKEM_GROUP, MLKEM_SHARE_LEN = 0x11EC, 1216


def _u16(v: int) -> bytes:
    return struct.pack("!H", v)


def _vec16(data: bytes) -> bytes:
    return _u16(len(data)) + data


def extension(ext_type: int, body: bytes) -> bytes:
    return _u16(ext_type) + _vec16(body)


def default_extensions(sni: str | None = "example.com", alpn=(b"h2", b"http/1.1"), pq: bool = True) -> list[bytes]:
    exts = []
    if sni is not None:
        name = sni.encode()
        exts.append(extension(0x0000, _vec16(b"\x00" + _vec16(name))))
    exts += [
        extension(GREASE, b""),
        extension(0x0017, b""),                                         # extended_master_secret
        extension(0xFF01, b"\x00"),                                     # renegotiation_info
        extension(0x000A, _vec16(b"".join(_u16(g) for g in [GREASE, MLKEM_GROUP, 0x001D, 0x0017, 0x0018]))),
        extension(0x000B, b"\x01\x00"),                                 # ec_point_formats
        extension(0x0023, b""),                                         # session_ticket
        extension(0x000D, _vec16(b"".join(_u16(s) for s in SIGALGS))),
        extension(0x002B, bytes([6]) + _u16(GREASE) + _u16(0x0304) + _u16(0x0303)),
        extension(0x002D, b"\x01\x01"),                                 # psk_key_exchange_modes
    ]
    if alpn:
        exts.append(extension(0x0010, _vec16(b"".join(bytes([len(p)]) + p for p in alpn))))
    if pq:
        # Chrome also sends a GREASE encrypted_client_hello of ~250 bytes;
        # together with the ML-KEM share its hellos are ~1.8 KB.
        exts.append(extension(0xFE0D, bytes(250)))
    shares = _u16(GREASE) + _vec16(b"\x00")
    if pq:
        shares += _u16(MLKEM_GROUP) + _vec16(bytes(MLKEM_SHARE_LEN))
    shares += _u16(0x001D) + _vec16(bytes(32))
    exts.append(extension(0x0033, _vec16(shares)))                    # key_share
    return exts


def client_hello(extensions: list[bytes], ciphers=CHROME_LIKE_CIPHERS, legacy_version=0x0303) -> bytes:
    """The handshake message (type byte first)."""
    body = (
        _u16(legacy_version) + bytes(32) + b"\x20" + bytes(32)
        + _vec16(b"".join(_u16(c) for c in ciphers)) + b"\x01\x00"
        + _vec16(b"".join(extensions))
    )
    return b"\x01" + struct.pack("!I", len(body))[1:] + body


def tls_records(message: bytes, record_size: int = 16384) -> bytes:
    """Wrap a handshake message in TLS handshake records."""
    out = b""
    for i in range(0, len(message), record_size):
        chunk = message[i:i + record_size]
        out += b"\x16\x03\x01" + _u16(len(chunk)) + chunk
    return out
