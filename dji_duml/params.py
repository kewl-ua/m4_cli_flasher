"""Flight controller parameters: config table 0 of command set 0x03, read only.

Layouts from DJI Assistant's connect in idle.pcap (2026-10-04) and the public
dji-firmware-tools dissector:

* 03/E0 ``table u16`` -> ``status u16 | table u16 | crc u32 | count u32``;
* 03/E1 ``table u16 | index u16`` -> ``status u16 | table u16 | index u16 |
  type u16 | size u16 | default, minimum, maximum (4 bytes each) | name\\0``,
  or status 0x0E for an index without an item (656 of the M4T's 1563);
* 03/E2 ``table u16 | 1 u16 | index u16`` -> ``status u16 | table u16 |
  index u16 | value (size bytes)``.

Assistant first sends 03/DF ("Assistant Unlock"). This module sends only the
three reads above, never 03/DF, the writes 03/E3 and 03/E4, or 03/E9, whose
positive arguments run commands: ``_ask`` refuses anything else.
"""
from __future__ import annotations

import math
import struct
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace

from .client import DumlClient
from .commands import FLYC
from .errors import CommandRejected, UnexpectedReply
from .frame import Frame, address

FLIGHT_CONTROLLER = address(3, 0)
TABLE_ATTRIBUTE, ITEM_ATTRIBUTE, ITEM_VALUE = 0xE0, 0xE1, 0xE2
READS = frozenset({TABLE_ATTRIBUTE, ITEM_ATTRIBUTE, ITEM_VALUE})
NO_ITEM = 0x0E

#: type id -> (name, struct format of a value, how the 4-byte limits read)
TYPES = {
    0: ("u8", "<B", "<I"), 1: ("u16", "<H", "<I"), 2: ("u32", "<I", "<I"),
    3: ("u64", "<Q", "<I"), 4: ("i8", "<b", "<i"), 5: ("i16", "<h", "<i"),
    6: ("i32", "<i", "<i"), 7: ("i64", "<q", "<i"), 8: ("f32", "<f", "<f"),
    9: ("f64", "<d", "<f"),
}


@dataclass(frozen=True)
class Table:
    table: int
    crc: int
    count: int


@dataclass(frozen=True)
class Param:
    table: int
    index: int
    type_id: int
    size: int
    default: int | float
    minimum: int | float
    maximum: int | float
    name: str
    raw: bytes | None = None  # the value as read; None when it was not

    @property
    def type_name(self) -> str:
        return TYPES[self.type_id][0] if self.type_id in TYPES else f"t{self.type_id}"

    @property
    def value(self) -> int | float | None:
        form = TYPES.get(self.type_id, (None, None))[1]
        if self.raw is None or form is None or struct.calcsize(form) != len(self.raw):
            return None
        value = struct.unpack(form, self.raw)[0]
        return _round(value) if form == "<f" else value  # f64 values stay exact

    @property
    def changed(self) -> bool:
        """The value differs from the default (floats as the device's f32)."""
        value = self.value
        if value is None:
            return False
        if isinstance(value, float) or isinstance(self.default, float):
            return not math.isclose(value, self.default, rel_tol=1e-6, abs_tol=1e-9)
        return value != self.default

    def shown(self) -> str:
        value = self.value
        if value is None:
            return "-" if self.raw is None else self.raw.hex()
        return f"{value:g}" if isinstance(value, float) else str(value)


def _round(value: float) -> float:
    return float(f"{value:.7g}")


def table_request(table: int = 0) -> bytes:
    return struct.pack("<H", table)


def item_request(table: int, index: int) -> bytes:
    return struct.pack("<HH", table, index)


def value_request(table: int, index: int) -> bytes:
    return struct.pack("<HHH", table, 1, index)  # 1 as Assistant sends it


def _status(payload: bytes, command: str) -> int:
    if len(payload) < 2:
        raise UnexpectedReply(f"{command} reply is too short: {payload.hex()}")
    return struct.unpack_from("<H", payload)[0]


def parse_table(payload: bytes) -> Table:
    status = _status(payload, "Cfg Table Attribute")
    if status:
        raise CommandRejected("Cfg Table Attribute", status)
    if len(payload) != 12:
        raise UnexpectedReply(f"Cfg Table Attribute reply is not 12 bytes: {payload.hex()}")
    return Table(*struct.unpack_from("<HII", payload, 2))


def parse_item(payload: bytes) -> Param | None:
    """The item's attributes, or None for an index without one (status 0x0E);
    any other non-zero status is a refusal, not an empty index."""
    status = _status(payload, "Cfg Item Attribute")
    if status == NO_ITEM:
        return None
    if status:
        raise CommandRejected("Cfg Item Attribute", status)
    if len(payload) < 22:
        raise UnexpectedReply(f"Cfg Item Attribute reply is too short: {payload.hex()}")
    table, index, type_id, size = struct.unpack_from("<HHHH", payload, 2)
    form = TYPES.get(type_id, (None, None, "<I"))[2]
    limits = [struct.unpack_from(form, payload, offset)[0] for offset in (10, 14, 18)]
    limits = [_round(item) if isinstance(item, float) else item for item in limits]
    name = payload[22:].split(b"\0", 1)[0].decode("ascii", "backslashreplace")
    return Param(table, index, type_id, size, *limits, name)


def parse_value(payload: bytes) -> tuple[int, int, bytes] | None:
    """(table, index, value bytes), or None when the read was refused."""
    if _status(payload, "Cfg Item Value") or len(payload) < 7:
        return None
    table, index = struct.unpack_from("<HH", payload, 2)
    return table, index, payload[6:]


class _Reader:
    def __init__(self, client: DumlClient, receiver: int, timeout: float):
        self.client, self.receiver, self.timeout = client, receiver, timeout

    def ask(self, cmd_id: int, payload: bytes) -> bytes:
        if cmd_id not in READS:  # the guarantee in the module docstring
            raise ValueError(f"03/{cmd_id:02X} is not a read; params never sends it.")
        return self.client.request(self.receiver, FLYC, cmd_id, payload,
                                   timeout=self.timeout, retries=2).payload


def read(client: DumlClient, receiver: int = FLIGHT_CONTROLLER, table: int = 0, *,
         timeout: float = 1.0, on_progress: Callable[[int, int], None] | None = None
         ) -> tuple[Table, list[Param]]:
    """Every item of a table, attributes then value, one request at a time.
    Only reads, so each request is retried."""
    reader = _Reader(client, receiver, timeout)
    info = parse_table(reader.ask(TABLE_ATTRIBUTE, table_request(table)))
    if info.table != table:
        raise UnexpectedReply(f"Asked for config table {table}, got {info.table}.")
    if info.count > 0x10000:  # indexes are u16; the M4T has about 1560
        raise UnexpectedReply(f"Config table {table} claims {info.count} indexes.")
    found = []
    for index in range(info.count):
        item = parse_item(reader.ask(ITEM_ATTRIBUTE, item_request(table, index)))
        if item is not None:
            if (item.table, item.index) != (table, index):
                raise UnexpectedReply(
                    f"Asked for item {table}/{index}, got {item.table}/{item.index}.")
            value = parse_value(reader.ask(ITEM_VALUE, value_request(table, index)))
            if value is not None and value[:2] == (table, index):
                item = replace(item, raw=value[2])
            found.append(item)
        if on_progress is not None:
            on_progress(index + 1, info.count)
    return info, found


def from_frames(frames: Iterable[Frame], receiver: int = FLIGHT_CONTROLLER) -> list[Param]:
    """The items of the last table read a capture holds, each with a value
    only if it was read after that item's attributes. Replies are matched to
    their requests by seq, and the request says which item is meant; a read
    starts over at index 0, so items of an earlier read never linger."""
    pending: dict[tuple[int, int, int], Frame] = {}
    items: dict[tuple[int, int], Param] = {}
    values: dict[tuple[int, int], bytes] = {}
    for frame in frames:
        if frame.cmd_set != FLYC or frame.cmd_id not in (ITEM_ATTRIBUTE, ITEM_VALUE):
            continue
        if not frame.response:
            if frame.receiver == receiver:
                pending[(frame.cmd_id, frame.seq, frame.sender)] = frame
                if frame.cmd_id == ITEM_ATTRIBUTE and frame.payload[2:4] == b"\x00\x00":
                    items.clear()  # a new read of the table
                    values.clear()
            continue
        request = pending.pop((frame.cmd_id, frame.seq, frame.receiver), None)
        if request is None or not frame.answers(request):
            continue
        if frame.cmd_id == ITEM_ATTRIBUTE and len(request.payload) == 4:
            key = struct.unpack("<HH", request.payload)
        elif frame.cmd_id == ITEM_VALUE and len(request.payload) == 6:
            key = struct.unpack_from("<H", request.payload)[0], \
                struct.unpack_from("<H", request.payload, 4)[0]
        else:
            continue
        try:
            if frame.cmd_id == ITEM_ATTRIBUTE:
                values.pop(key, None)  # a value counts only if read after these
                item = parse_item(frame.payload)
                if item is None:
                    items.pop(key, None)
                elif (item.table, item.index) == key:
                    items[key] = item
            elif (value := parse_value(frame.payload)) is not None and value[:2] == key:
                values[key] = value[2]
        except (CommandRejected, UnexpectedReply):
            continue
    return [replace(item, raw=values.get(key)) for key, item in sorted(items.items())]
