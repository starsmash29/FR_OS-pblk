"""Strict, bounded parsing of a TLS ClientHello (phase 19).

Input is untrusted packet data from any LAN host, so every length is
checked against what is actually there and anything malformed raises
ParseError -- never an IndexError, never an unbounded loop. Only the
fields fingerprinting needs are extracted.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

TLS_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01

#: A ClientHello is one handshake message; its 24-bit length allows 16 MiB,
#: but real ones are a few KiB. Anything larger is not worth buffering.
MAX_HELLO_BYTES = 16 * 1024

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B


class ParseError(ValueError):
    pass


def is_grease(value: int) -> bool:
    """RFC 8701 GREASE values: 0x0a0a, 0x1a1a, ... 0xfafa."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


@dataclass
class ClientHello:
    legacy_version: int
    ciphers: list[int]
    extensions: list[int]  # in wire order
    supported_groups: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    alpn: list[bytes] = field(default_factory=list)
    server_name: str | None = None


class _Reader:
    def __init__(self, data: bytes, what: str):
        self.data, self.pos, self.what = data, 0, what

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ParseError(f"{self.what}: truncated")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    def u24(self) -> int:
        b = self.take(3)
        return (b[0] << 16) | (b[1] << 8) | b[2]

    def vec(self, len_bytes: int) -> bytes:
        n = self.u8() if len_bytes == 1 else self.u16()
        return self.take(n)

    def done(self) -> bool:
        return self.pos == len(self.data)


def _u16_list(data: bytes, what: str) -> list[int]:
    if len(data) % 2:
        raise ParseError(f"{what}: odd length")
    return [v for (v,) in struct.iter_unpack("!H", data)]


def handshake_from_records(stream: bytes) -> bytes | None:
    """The first handshake message from the start of a client's TLS byte
    stream, reassembled across TLS records if it spans several. None if
    more bytes are needed; ParseError if this isn't a TLS handshake."""
    body = bytearray()
    pos = 0
    while True:
        if len(body) >= 4:
            needed = 4 + ((body[1] << 16) | (body[2] << 8) | body[3])
            if needed > MAX_HELLO_BYTES:
                raise ParseError("handshake message too large")
            if len(body) >= needed:
                return bytes(body[:needed])
        if pos + 5 > len(stream):
            return None
        content_type, version, length = struct.unpack("!BHH", stream[pos:pos + 5])
        if content_type != TLS_HANDSHAKE or (version >> 8) != 0x03:
            raise ParseError("not a TLS handshake record")
        if length == 0 or length > 16384 + 2048:
            raise ParseError("bad TLS record length")
        if pos + 5 + length > len(stream):
            # Take what is there; the rest comes with later segments.
            if len(body) == 0 and pos + 5 < len(stream) and stream[pos + 5] != HANDSHAKE_CLIENT_HELLO:
                raise ParseError("not a ClientHello")
            return None
        body += stream[pos + 5:pos + 5 + length]
        pos += 5 + length
        if body and body[0] != HANDSHAKE_CLIENT_HELLO:
            raise ParseError("not a ClientHello")


def parse_client_hello(message: bytes) -> ClientHello:
    """Parse one complete handshake message (type byte first)."""
    r = _Reader(message, "ClientHello")
    if r.u8() != HANDSHAKE_CLIENT_HELLO:
        raise ParseError("not a ClientHello")
    body = _Reader(r.take(r.u24()), "ClientHello body")
    legacy_version = body.u16()
    body.take(32)       # random
    body.vec(1)         # legacy_session_id
    ciphers = _u16_list(body.vec(2), "cipher_suites")
    body.vec(1)         # legacy_compression_methods
    hello = ClientHello(legacy_version=legacy_version, ciphers=ciphers, extensions=[])
    if body.done():     # a ClientHello may legally carry no extensions
        return hello

    exts = _Reader(body.vec(2), "extensions")
    while not exts.done():
        ext_type = exts.u16()
        data = exts.vec(2)
        hello.extensions.append(ext_type)
        if len(hello.extensions) > 256:
            raise ParseError("too many extensions")
        try:
            _parse_extension(hello, ext_type, data)
        except ParseError:
            # The outer structure is intact, only this extension's body is
            # odd (e.g. empty): keep its type -- it still counts for the
            # fingerprint -- and ignore its contents, as Wireshark does.
            pass
    return hello


def _parse_extension(hello: ClientHello, ext_type: int, data: bytes) -> None:
    what = f"extension 0x{ext_type:04x}"
    if ext_type == EXT_SERVER_NAME and data:
        names = _Reader(_Reader(data, what).vec(2), what)
        while not names.done():
            name_type = names.u8()
            name = names.vec(2)
            if name_type == 0 and hello.server_name is None:
                hello.server_name = name.decode("ascii", errors="replace")
    elif ext_type == EXT_SUPPORTED_GROUPS:
        hello.supported_groups = _u16_list(_Reader(data, what).vec(2), what)
    elif ext_type == EXT_EC_POINT_FORMATS:
        hello.ec_point_formats = list(_Reader(data, what).vec(1))
    elif ext_type == EXT_SIGNATURE_ALGORITHMS:
        hello.signature_algorithms = _u16_list(_Reader(data, what).vec(2), what)
    elif ext_type == EXT_SUPPORTED_VERSIONS:
        hello.supported_versions = _u16_list(_Reader(data, what).vec(1), what)
    elif ext_type == EXT_ALPN and data:
        protocols = _Reader(_Reader(data, what).vec(2), what)
        while not protocols.done():
            hello.alpn.append(protocols.vec(1))
