"""DUML v1 frame codec and a resynchronising stream parser.

Layout (little-endian):

    0      0x55 start of frame
    1..2   length (10 bits) | protocol version (6 bits)
    3      CRC8 of bytes 0..2
    4      sender   (type: low 5 bits, index: high 3 bits)
    5      receiver (same split)
    6..7   sequence number
    8      command type: bit 7 response, bits 6..5 ack, bits 2..0 encryption
    9      command set
    10     command id
    11..   payload
    -2..   CRC16 of everything before it
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, replace
from enum import IntEnum

from .crc import crc8, crc16

SOF = 0x55
HEADER_SIZE = 11
OVERHEAD = HEADER_SIZE + 2
MAX_FRAME = 0x3FF
MAX_PAYLOAD = MAX_FRAME - OVERHEAD


class FrameError(ValueError):
    pass


class AckType(IntEnum):
    NONE = 0
    BEFORE_EXEC = 1
    AFTER_EXEC = 2
    RESERVED = 3


def address(device_type: int, index: int = 0) -> int:
    if not (0 <= device_type <= 31 and 0 <= index <= 7):
        raise FrameError("Device type must be 0..31 and index 0..7.")
    return device_type | index << 5


def format_address(value: int) -> str:
    return f"{value & 31:02d}{value >> 5:02d}"


@dataclass(frozen=True)
class Frame:
    sender: int
    receiver: int
    seq: int
    cmd_set: int
    cmd_id: int
    payload: bytes = b""
    response: bool = False
    ack: AckType = AckType.AFTER_EXEC
    encrypt: int = 0
    reserved: int = 0
    version: int = 1

    def __post_init__(self):
        object.__setattr__(self, "payload", bytes(self.payload))
        object.__setattr__(self, "ack", AckType(self.ack))
        for name, limit in (("sender", 0xFF), ("receiver", 0xFF), ("seq", 0xFFFF),
                            ("cmd_set", 0xFF), ("cmd_id", 0xFF), ("encrypt", 7),
                            ("reserved", 3), ("version", 63)):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= limit:
                raise FrameError(f"{name} must be an integer in 0..{limit}.")
        if len(self.payload) > MAX_PAYLOAD:
            raise FrameError(f"Payload exceeds {MAX_PAYLOAD} bytes.")

    @property
    def cmd_type(self) -> int:
        return (self.response << 7) | (self.ack << 5) | (self.reserved << 3) | self.encrypt

    def encode(self) -> bytes:
        length = OVERHEAD + len(self.payload)
        head = struct.pack("<BH", SOF, length | self.version << 10)
        body = head + bytes((crc8(head), self.sender, self.receiver)) + struct.pack(
            "<HBBB", self.seq, self.cmd_type, self.cmd_set, self.cmd_id,
        ) + self.payload
        return body + struct.pack("<H", crc16(body))

    @classmethod
    def decode(cls, data: bytes) -> "Frame":
        """Decode exactly one frame; any inconsistency raises FrameError."""
        data = bytes(data)
        if len(data) < OVERHEAD:
            raise FrameError("Frame is shorter than the fixed overhead.")
        if data[0] != SOF:
            raise FrameError("Missing 0x55 start of frame.")
        tag = data[1] | data[2] << 8
        if crc8(data[:3]) != data[3]:
            raise FrameError("Header CRC8 mismatch.")
        if tag & 0x3FF != len(data):
            raise FrameError("Declared length does not match the data.")
        if crc16(data[:-2]) != data[-2] | data[-1] << 8:
            raise FrameError("Frame CRC16 mismatch.")
        seq, cmd_type, cmd_set, cmd_id = struct.unpack_from("<HBBB", data, 6)
        return cls(
            sender=data[4], receiver=data[5], seq=seq, cmd_set=cmd_set, cmd_id=cmd_id,
            payload=data[HEADER_SIZE:-2], response=bool(cmd_type & 0x80),
            ack=AckType(cmd_type >> 5 & 3), encrypt=cmd_type & 7,
            reserved=cmd_type >> 3 & 3, version=tag >> 10,
        )

    def make_reply(self, payload: bytes = b"") -> "Frame":
        return replace(self, sender=self.receiver, receiver=self.sender,
                       response=True, ack=AckType.NONE, payload=payload)

    def answers(self, request: "Frame") -> bool:
        return (self.response and not request.response
                and self.seq == request.seq
                and self.cmd_set == request.cmd_set and self.cmd_id == request.cmd_id
                and self.sender == request.receiver and self.receiver == request.sender)

    def describe(self) -> str:
        kind = "ack" if self.response else "req"
        return (f"{format_address(self.sender)}>{format_address(self.receiver)} "
                f"seq={self.seq:04x} {kind} set={self.cmd_set:02x} id={self.cmd_id:02x} "
                f"[{len(self.payload)}] {self.payload.hex()}")


class StreamParser:
    """Extract frames from a byte stream that may contain noise or partial data.

    Bytes that are not part of a CRC-valid version 1 frame are skipped one at
    a time and counted in :attr:`discarded`, so a damaged frame never hides
    the valid frames after it.
    """

    def __init__(self):
        self._buffer = bytearray()
        self.discarded = 0
        self.frames = 0

    @property
    def pending(self) -> int:
        return len(self._buffer)

    def feed(self, data: bytes) -> list[Frame]:
        self._buffer.extend(data)
        buffer = self._buffer
        found: list[Frame] = []
        while True:
            start = buffer.find(SOF)
            if start < 0:
                self.discarded += len(buffer)
                buffer.clear()
                break
            if start:
                self.discarded += start
                del buffer[:start]
            if len(buffer) < 4:
                break
            tag = buffer[1] | buffer[2] << 8
            length = tag & 0x3FF
            if crc8(buffer[:3]) != buffer[3] or length < OVERHEAD or tag >> 10 != 1:
                self.discarded += 1
                del buffer[:1]
                continue
            if len(buffer) < length:
                break
            try:
                found.append(Frame.decode(buffer[:length]))
            except FrameError:
                self.discarded += 1
                del buffer[:1]
                continue
            del buffer[:length]
        self.frames += len(found)
        return found

    def resync(self) -> list[Frame]:
        """Give up on a frame candidate that never completed.

        Noise can look like a header announcing up to 1023 bytes; without this
        the valid frames behind it would wait until that many bytes arrived.
        """
        if not self._buffer:
            return []
        self.discarded += 1
        del self._buffer[:1]
        return self.feed(b"")
