"""Smart-battery dynamic data (command set 0x0D, id 0x02): read only.

The host asks the battery (DUML device type 11) for ``0D/02`` and gets a
45-byte block. The field layout is verified against a real M4T reply and the
public dji-firmware-tools ``battery_dynamic_data`` dissector, and cross-checked
on live captures: ``state_of_charge`` equals ``remaining / full_charge`` and
``pack_voltage / cell_count`` lands on a Li-ion per-cell curve (e.g. 14399 mV /
4 = 3.60 V at 30 %, 16302 mV / 4 = 4.08 V at 89 %).

The 15-byte tail past the public layout is kept raw: it is not decoded here and
may carry pack-identifying bytes, so it is shown as hex, not published. The
status word reads 0 (healthy) in every sample seen, so its individual bits are
not decoded. Nothing here changes the battery; it sends only the ``0D/02`` get.
"""
from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

from . import commands
from .client import DumlClient
from .errors import UnexpectedReply
from .frame import Frame, address

BATTERY = commands.BATTERY       # 0x0D
DYNAMIC_DATA = 0x02
#: The smart battery, DUML type 11 index 0.
BATTERY_ADDRESS = address(11, 0)
#: The get request DJI Assistant sends, verbatim.
GET_REQUEST = bytes.fromhex("00000105")
#: Smallest reply that carries every field through the status word.
MIN_REPLY = 30


@dataclass(frozen=True)
class BatteryData:
    voltage_mv: int
    current_ma: int
    full_capacity_mah: int
    remaining_mah: int
    temperature_dc: int      # tenths of a degree Celsius
    cell_count: int
    state_of_charge: int     # percent, as the battery reports it
    status: int              # 64-bit field; 0 = healthy, bit meanings not decoded
    tail: bytes              # undecoded bytes past the public layout; may identify the pack
    raw: bytes

    @property
    def voltage(self) -> float:
        return self.voltage_mv / 1000.0

    @property
    def current(self) -> float:
        return self.current_ma / 1000.0

    @property
    def temperature(self) -> float:
        return self.temperature_dc / 10.0

    @property
    def cell_voltage(self) -> float | None:
        """Mean volts per cell, or None if the cell count is missing."""
        return self.voltage_mv / self.cell_count / 1000.0 if self.cell_count else None


def get_request() -> bytes:
    return GET_REQUEST


def parse(payload: bytes) -> BatteryData:
    """Decode a ``0D/02`` reply. Only the verified fields are named; the rest
    stays in ``tail``."""
    if len(payload) < MIN_REPLY:
        raise UnexpectedReply(f"Battery data reply is too short "
                              f"({len(payload)} < {MIN_REPLY}): {payload.hex()}")
    voltage, current, full, remaining = struct.unpack_from("<IiII", payload, 2)
    temperature = struct.unpack_from("<H", payload, 18)[0]
    cell_count, soc = payload[20], payload[21]
    status = struct.unpack_from("<Q", payload, 22)[0]
    return BatteryData(voltage, current, full, remaining, temperature, cell_count, soc,
                       status, tail=bytes(payload[30:]), raw=bytes(payload))


def read(client: DumlClient, receiver: int = BATTERY_ADDRESS, *, timeout: float = 2.0
         ) -> BatteryData:
    """Read the battery's dynamic data. It only reads, so it is retried."""
    reply = client.request(receiver, BATTERY, DYNAMIC_DATA, get_request(),
                           timeout=timeout, retries=2)
    return parse(reply.payload)


def from_frames(frames: Iterable[Frame]) -> BatteryData | None:
    """The last ``0D/02`` reply a capture holds, or None."""
    found = None
    for frame in frames:
        if (frame.cmd_set == BATTERY and frame.cmd_id == DYNAMIC_DATA and frame.response
                and len(frame.payload) >= MIN_REPLY):
            try:
                found = parse(frame.payload)
            except UnexpectedReply:
                continue
    return found
