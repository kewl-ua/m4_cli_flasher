"""DUML v1 checksums.

Header CRC8: reflected polynomial 0x8C, seed 0x77, over the first 3 bytes.
Frame CRC16: reflected polynomial 0x8408, seed 0x3692, over everything
before the two CRC bytes. Both match the public dji-firmware-tools tables
and the values measured on the M4T capture described in the README.
"""
from __future__ import annotations

import binascii

CRC8_SEED = 0x77
CRC16_SEED = 0x3692


def _table(polynomial: int) -> tuple[int, ...]:
    table = []
    for value in range(256):
        for _ in range(8):
            value = (value >> 1) ^ polynomial if value & 1 else value >> 1
        table.append(value)
    return tuple(table)


_CRC8 = _table(0x8C)
_CRC16 = _table(0x8408)


def crc8(data: bytes, seed: int = CRC8_SEED) -> int:
    value = seed
    for byte in data:
        value = _CRC8[(value ^ byte) & 0xFF]
    return value


def crc16_reference(data: bytes, seed: int = CRC16_SEED) -> int:
    """Table-driven reference; crc16 must always agree with it."""
    value = seed
    for byte in data:
        value = (value >> 8) ^ _CRC16[(value ^ byte) & 0xFF]
    return value


#: Bit-reversed bytes: a reflected CRC equals the bit-reversed plain CRC of
#: bit-reversed input, which binascii computes at C speed (~17x faster; a
#: firmware transfer encodes about 680,000 frames).
_REVERSED = bytes(int(f"{value:08b}"[::-1], 2) for value in range(256))


def _reverse16(value: int) -> int:
    return _REVERSED[value & 0xFF] << 8 | _REVERSED[value >> 8]


def crc16(data: bytes, seed: int = CRC16_SEED) -> int:
    return _reverse16(binascii.crc_hqx(bytes(data).translate(_REVERSED), _reverse16(seed)))
