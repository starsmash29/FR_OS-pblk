"""Rebuild ClientHellos that span several TCP segments (phase 19).

A modern browser's ClientHello often doesn't fit one packet: the hybrid
post-quantum key share (X25519MLKEM768, on by default in Chrome and
Firefox) alone is 1,216 bytes, so the hello is ~1.7-2 KB and arrives in
two segments. Fingerprinting only the first would miss most of it.

The XDP program (bpf/xdp_sni_filter.c, SETTING_REPORT_HELLO) hands over
the first segment of every ClientHello plus the next few segments of the
same flow. This keeps a small per-flow buffer, places segments by TCP
sequence number (so retransmissions and reordering are harmless), and
returns the handshake message once it is complete. Everything is bounded:
flows, bytes per flow, and age.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from frfw.tlsfp.clienthello import MAX_HELLO_BYTES, ParseError, handshake_from_records

MAX_FLOWS = 4096
FLOW_TIMEOUT_SECONDS = 5.0

FlowKey = tuple[str, int, str, int]  # (src ip, src port, dst ip, dst port)


@dataclass
class _Flow:
    isn: int                      # sequence number of the hello's first byte
    started: float
    chunks: dict[int, bytes] = field(default_factory=dict)  # offset -> bytes


class Reassembler:
    def __init__(self, *, max_flows: int = MAX_FLOWS, timeout: float = FLOW_TIMEOUT_SECONDS):
        self._flows: dict[FlowKey, _Flow] = {}
        self.max_flows = max_flows
        self.timeout = timeout

    def __len__(self) -> int:
        return len(self._flows)

    def add(self, key: FlowKey, seq: int, payload: bytes, now: float, *, first: bool) -> bytes | None:
        """Feed one segment. `first` marks the segment that starts the
        hello (its payload begins with the TLS record header). Returns
        the complete handshake message once available, else None."""
        self._expire(now)
        flow = self._flows.get(key)
        if first:
            if flow is None and len(self._flows) >= self.max_flows:
                oldest = min(self._flows, key=lambda k: self._flows[k].started)
                del self._flows[oldest]
            flow = self._flows[key] = _Flow(isn=seq, started=now)
        elif flow is None:
            return None
        offset = (seq - flow.isn) & 0xFFFFFFFF
        if offset >= MAX_HELLO_BYTES + 5 * 4:
            return None  # not part of this hello (or a wrapped, stale seq)
        flow.chunks.setdefault(offset, payload[: MAX_HELLO_BYTES])
        stream = self._contiguous(flow)
        try:
            message = handshake_from_records(stream)
        except ParseError:
            del self._flows[key]
            raise
        if message is not None:
            del self._flows[key]
        return message

    @staticmethod
    def _contiguous(flow: _Flow) -> bytes:
        out = bytearray()
        for offset in sorted(flow.chunks):
            chunk = flow.chunks[offset]
            if offset > len(out):
                break  # a gap: wait for the missing segment
            out += chunk[len(out) - offset:]
        return bytes(out)

    def _expire(self, now: float) -> None:
        stale = [k for k, f in self._flows.items() if now - f.started > self.timeout]
        for k in stale:
            del self._flows[k]
