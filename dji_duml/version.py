from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

_PATTERN = re.compile(r"[Vv]?(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?")


@total_ordering
@dataclass(frozen=True)
class FirmwareVersion:
    """Three-part DJI version: major.minor.build, printed as 17.02.0501.

    The wire form is a little-endian uint32: build (uint16), minor, major.
    DJI download names split the build into two pairs (17.02.05.01); both
    spellings parse to the same value.
    """

    major: int
    minor: int
    build: int

    def __post_init__(self):
        if not (0 <= self.major <= 255 and 0 <= self.minor <= 255 and 0 <= self.build <= 0xFFFF):
            raise ValueError(f"Firmware version out of range: {self.major}.{self.minor}.{self.build}")

    @classmethod
    def parse(cls, text: str) -> "FirmwareVersion":
        match = _PATTERN.fullmatch(text.strip())
        if not match:
            raise ValueError(f"Invalid firmware version: {text!r}")
        major, minor, third, fourth = match.groups()
        if fourth is None:
            return cls(int(major), int(minor), int(third))
        if len(third) != 2 or len(fourth) != 2:
            raise ValueError(f"Four-part version must use two-digit pairs: {text!r}")
        return cls(int(major), int(minor), int(third) * 100 + int(fourth))

    @classmethod
    def from_wire(cls, raw: bytes) -> "FirmwareVersion":
        if len(raw) != 4:
            raise ValueError("Wire version must be exactly 4 bytes.")
        return cls(raw[3], raw[2], raw[0] | raw[1] << 8)

    def to_wire(self) -> bytes:
        return bytes((self.build & 0xFF, self.build >> 8, self.minor, self.major))

    def _key(self) -> tuple[int, int, int]:
        return self.major, self.minor, self.build

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, FirmwareVersion):
            return NotImplemented
        return self._key() < other._key()

    def __str__(self) -> str:
        return f"{self.major:02d}.{self.minor:02d}.{self.build:04d}"
