"""Turn a USB capture into a DUML command trace.

Supports classic pcap and pcapng files with USBPcap (Windows, link type 249)
or usbmon (Linux, link types 189 and 220) records. Bulk payloads are
reassembled per device and endpoint, so frames split across transfers or
packed several to a transfer are both recovered.

This is the tool for establishing what DJI Assistant really sends while it
flashes a given model, before any procedure is marked as verified.
"""
from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .errors import DumlError
from .frame import Frame, StreamParser

DLT_USB_LINUX = 189
DLT_USB_LINUX_MMAPPED = 220
DLT_USBPCAP = 249
_BULK = 3
_STALL_SECONDS = 0.2


class CaptureError(DumlError):
    pass


@dataclass(frozen=True)
class BulkChunk:
    time: float
    bus: int
    device: int
    endpoint: int  # bit 7 set = IN (device to host)
    data: bytes


@dataclass(frozen=True)
class TraceEntry:
    time: float
    bus: int
    device: int
    endpoint: int
    frame: Frame

    @property
    def direction(self) -> str:
        return "IN " if self.endpoint & 0x80 else "OUT"


def _exact(handle, size: int) -> bytes | None:
    data = handle.read(size)
    return data if len(data) == size else None  # None: capture cut mid-record


def _records(path: Path) -> Iterator[tuple[int, float, bytes]]:
    """Stream (link type, time, packet) so multi-gigabyte captures fit in memory."""
    with open(path, "rb") as handle:
        magic = handle.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            handle.seek(0)
            yield from _pcapng(handle)
            return
        for order, raw, divisor in (
            ("<", b"\xd4\xc3\xb2\xa1", 1e6), (">", b"\xa1\xb2\xc3\xd4", 1e6),
            ("<", b"\x4d\x3c\xb2\xa1", 1e9), (">", b"\xa1\xb2\x3c\x4d", 1e9),
        ):
            if magic == raw:
                break
        else:
            raise CaptureError("Not a pcap or pcapng file.")
        rest = _exact(handle, 20)
        if rest is None:
            raise CaptureError("Capture file is too short.")
        linktype = struct.unpack_from(order + "I", rest, 16)[0] & 0x0FFFFFFF
        while (header := _exact(handle, 16)) is not None:
            seconds, fraction, captured, _ = struct.unpack(order + "IIII", header)
            packet = _exact(handle, captured)
            if packet is None:
                break
            yield linktype, seconds + fraction / divisor, packet


def _pcapng(handle) -> Iterator[tuple[int, float, bytes]]:
    order = "<"
    interfaces: list[tuple[int, float]] = []
    while (head := _exact(handle, 12)) is not None:
        block_type = struct.unpack_from(order + "I", head, 0)[0]
        if block_type == 0x0A0D0D0A:
            order = "<" if head[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
            interfaces = []
        length = struct.unpack_from(order + "I", head, 4)[0]
        if length < 12:
            break
        rest = _exact(handle, length - 12)
        if rest is None:
            break
        body = head[8:] + rest[:-4]
        if block_type == 1:
            linktype = struct.unpack_from(order + "H", body, 0)[0]
            interfaces.append((linktype, _pcapng_resolution(body[8:], order)))
        elif block_type == 6 and len(body) >= 20:
            index, high, low, captured, _ = struct.unpack_from(order + "IIIII", body, 0)
            if index < len(interfaces) and 20 + captured <= len(body):
                linktype, resolution = interfaces[index]
                yield linktype, ((high << 32) | low) * resolution, body[20:20 + captured]


def _pcapng_resolution(options: bytes, order: str) -> float:
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack_from(order + "HH", options, offset)
        if code == 0:
            break
        if code == 9 and length >= 1 and offset + 4 < len(options):  # if_tsresol
            value = options[offset + 4]
            return 2.0 ** -(value & 0x7F) if value & 0x80 else 10.0 ** -value
        offset += 4 + (length + 3 & ~3)
    return 1e-6


def _usbpcap(time: float, packet: bytes) -> BulkChunk | None:
    # USBPCAP_BUFFER_PACKET_HEADER, packed: headerLen, irpId, status, function,
    # info, bus, device, endpoint, transfer, dataLength.
    if len(packet) < 27:
        return None
    header_len, _, _, _, info, bus, device, endpoint, transfer, length = struct.unpack_from(
        "<HQIHBHHBBI", packet, 0,
    )
    if transfer != _BULK or header_len < 27 or length == 0:
        return None
    # Data travels with the request for OUT and with the completion for IN.
    completion = bool(info & 1)
    if bool(endpoint & 0x80) != completion:
        return None
    payload = packet[header_len:header_len + length]
    return BulkChunk(time, bus, device, endpoint, payload) if payload else None


def _usbmon(time: float, packet: bytes, header_len: int) -> BulkChunk | None:
    if len(packet) < header_len:
        return None
    event, transfer, endpoint, device, bus = struct.unpack_from("<BBBBH", packet, 8)
    captured = struct.unpack_from("<I", packet, 36)[0]
    if transfer != _BULK or captured == 0:
        return None
    submit = event == ord("S")
    if not submit and event != ord("C"):
        return None
    if bool(endpoint & 0x80) == submit:
        return None
    payload = packet[header_len:header_len + captured]
    return BulkChunk(time, bus, device, endpoint, payload) if payload else None


def bulk_chunks(path: str | Path) -> Iterator[BulkChunk]:
    seen = False
    for linktype, time, packet in _records(Path(path)):
        if linktype == DLT_USBPCAP:
            chunk = _usbpcap(time, packet)
        elif linktype == DLT_USB_LINUX_MMAPPED:
            chunk = _usbmon(time, packet, 64)
        elif linktype == DLT_USB_LINUX:
            chunk = _usbmon(time, packet, 48)
        else:
            raise CaptureError(f"Unsupported link type {linktype}; expected USBPcap or usbmon.")
        seen = True
        if chunk is not None:
            yield chunk
    if not seen:
        raise CaptureError("Capture contains no packets.")


@dataclass
class TraceStats:
    chunks: int = 0
    bytes: int = 0
    frames: int = 0
    discarded: int = 0


def decode(path: str | Path, *, device: int | None = None,
           endpoints: set[int] | None = None) -> tuple[list[TraceEntry], TraceStats]:
    """Decode every DUML frame in the capture, in capture order."""
    parsers: dict[tuple[int, int, int], StreamParser] = {}
    last_seen: dict[tuple[int, int, int], BulkChunk] = {}
    entries: list[TraceEntry] = []
    stats = TraceStats()

    def release(key) -> None:
        # A frame candidate that did not complete is noise: drop it so the
        # valid frames queued behind it are not lost.
        parser, origin = parsers[key], last_seen[key]
        while parser.pending:
            for frame in parser.resync():
                entries.append(TraceEntry(origin.time, origin.bus, origin.device,
                                          origin.endpoint, frame))

    for chunk in bulk_chunks(path):
        if device is not None and chunk.device != device:
            continue
        if endpoints is not None and chunk.endpoint not in endpoints:
            continue
        stats.chunks += 1
        stats.bytes += len(chunk.data)
        key = (chunk.bus, chunk.device, chunk.endpoint)
        parser = parsers.setdefault(key, StreamParser())
        if parser.pending and chunk.time - last_seen[key].time > _STALL_SECONDS:
            release(key)
        last_seen[key] = chunk
        for frame in parser.feed(chunk.data):
            entries.append(TraceEntry(chunk.time, chunk.bus, chunk.device, chunk.endpoint, frame))
    for key in parsers:
        release(key)
    entries.sort(key=lambda entry: entry.time)
    stats.frames = len(entries)
    stats.discarded = sum(parser.discarded for parser in parsers.values())
    return entries, stats
