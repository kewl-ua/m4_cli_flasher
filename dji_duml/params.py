"""Flight controller parameters: the config table of command set 0x03.

Layouts from DJI Assistant's idle capture of an M4T (2026-10-05) and the
public dji-firmware-tools flyc dissector. On connect Assistant sends 03/DF
01000000 ("Assistant Unlock"), then reads table 0: 03/E0 for its size, 03/E1
for each item's attribute (type, limits, name) and 03/E2 for each value.
Only these three reads are ever sent here; 03/DF, 03/E3 (set item) and
03/E9 (whose positive arguments execute commands) are not.
"""
from __future__ import annotations

import math
import struct
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .client import DumlClient
from .commands import FLYC
from .errors import CommandRejected, UnexpectedReply
from .frame import Frame, address

FLIGHT_CONTROLLER = address(3, 0)
TABLE_ATTRIBUTE = 0xE0
ITEM_ATTRIBUTE = 0xE1
ITEM_VALUE = 0xE2

#: Status of 03/E1 for an index that has no item; 656 of the M4T's 1563
#: indexes answer it, and Assistant then does not read their values.
NO_ITEM = 0x0E

#: type id -> (struct format of the value, kind of the limits)
TYPES = {
    0: ("<B", "I"), 1: ("<H", "I"), 2: ("<I", "I"), 3: ("<Q", "I"),
    4: ("<b", "i"), 5: ("<h", "i"), 6: ("<i", "i"), 7: ("<q", "i"),
    8: ("<f", "f"), 9: ("<d", "f"), 10: (None, "I"),
}
TYPE_NAMES = {0: "u8", 1: "u16", 2: "u32", 3: "u64", 4: "i8", 5: "i16", 6: "i32",
              7: "i64", 8: "f32", 9: "f64", 10: "t10"}


@dataclass(frozen=True)
class TableInfo:
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
    raw: bytes | None = None

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.type_id, f"t{self.type_id}")

    @property
    def value(self) -> int | float | None:
        return None if self.raw is None else decode_value(self.type_id, self.raw)

    @property
    def changed(self) -> bool:
        """Value differs from the default (floats compared as 32-bit)."""
        value = self.value
        if value is None:
            return False
        if isinstance(value, float):
            return not math.isclose(value, float(self.default), rel_tol=1e-6, abs_tol=1e-9)
        return value != self.default


def table_request(table: int = 0) -> bytes:
    return struct.pack("<H", table)


def item_request(table: int, index: int) -> bytes:
    return struct.pack("<HH", table, index)


def value_request(table: int, index: int) -> bytes:
    """table, 1 (as Assistant sends; one item?), index."""
    return struct.pack("<HHH", table, 1, index)


def _status(payload: bytes, command: str) -> int:
    if len(payload) < 2:
        raise UnexpectedReply(f"{command} reply is too short: {payload.hex()}")
    return struct.unpack_from("<H", payload)[0]


def parse_table(payload: bytes) -> TableInfo:
    """status u16, table u16, crc u32, item count u32."""
    status = _status(payload, "Config table attribute")
    if status:
        raise CommandRejected("Config table attribute", status)
    if len(payload) != 12:
        raise UnexpectedReply(f"Config table attribute reply is not 12 bytes: {payload.hex()}")
    return TableInfo(*struct.unpack_from("<HII", payload, 2))


def _limit(kind: str, data: bytes) -> int | float:
    value = struct.unpack("<" + kind, data)[0]
    return round(value, 7) if kind == "f" else value


def parse_item(payload: bytes) -> Param | None:
    """status u16, table u16, index u16, type u16, size u16, default, min and
    max (4 bytes each, as the type's limit kind), NUL-terminated name. None
    for an index without an item."""
    status = _status(payload, "Config item attribute")
    if status:
        return None
    if len(payload) < 22:
        raise UnexpectedReply(f"Config item attribute reply is too short: {payload.hex()}")
    table, index, type_id, size = struct.unpack_from("<HHHH", payload, 2)
    kind = TYPES.get(type_id, (None, "I"))[1]
    limits = [_limit(kind, payload[offset:offset + 4]) for offset in (10, 14, 18)]
    name = payload[22:].split(b"\0", 1)[0].decode("ascii", "backslashreplace")
    return Param(table, index, type_id, size, *limits, name)


def parse_value(payload: bytes) -> tuple[int, bytes] | None:
    """status u16, u16 (0), index u16, value bytes. None when rejected."""
    status = _status(payload, "Config item value")
    if status or len(payload) < 7:
        return None
    return struct.unpack_from("<H", payload, 4)[0], payload[6:]


def decode_value(type_id: int, raw: bytes) -> int | float | None:
    form = TYPES.get(type_id, (None, ""))[0]
    if form is None or struct.calcsize(form) != len(raw):
        return None
    value = struct.unpack(form, raw)[0]
    return round(value, 7) if type_id == 8 else value


def format_value(param: Param) -> str:
    value = param.value
    if value is None:
        return "-" if param.raw is None else param.raw.hex()
    return f"{value:g}" if isinstance(value, float) else str(value)


def from_frames(frames: Iterable[Frame], receiver: int = FLIGHT_CONTROLLER) -> list[Param]:
    """Parameters whose attribute and value replies are in a capture. Replies
    are matched to their requests, which carry the table number; the last
    value read wins."""
    pending: dict[tuple[int, int, int], Frame] = {}
    items: dict[tuple[int, int], Param] = {}
    values: dict[tuple[int, int], bytes] = {}
    for frame in frames:
        if frame.cmd_set != FLYC or frame.cmd_id not in (ITEM_ATTRIBUTE, ITEM_VALUE):
            continue
        if not frame.response:
            if frame.receiver == receiver:
                pending[(frame.cmd_id, frame.seq, frame.sender)] = frame
            continue
        request = pending.pop((frame.cmd_id, frame.seq, frame.receiver), None)
        if request is None or not frame.answers(request):
            continue
        try:
            if frame.cmd_id == ITEM_ATTRIBUTE:
                item = parse_item(frame.payload)
                if item is not None:
                    items[(item.table, item.index)] = item
            elif len(request.payload) == 6:
                table = struct.unpack_from("<H", request.payload)[0]
                value = parse_value(frame.payload)
                if value is not None:
                    values[(table, value[0])] = value[1]
        except UnexpectedReply:
            continue
    return [Param(**{**item.__dict__, "raw": values.get(key)})
            for key, item in sorted(items.items())]


def read(client: DumlClient, receiver: int = FLIGHT_CONTROLLER, table: int = 0, *,
         timeout: float = 1.0, on_progress: Callable[[int, int], None] | None = None
         ) -> tuple[TableInfo, list[Param]]:
    """Read every item of a table, attribute then value, one request at a time.
    Only reads, so each request is retried."""
    def ask(cmd_id: int, payload: bytes) -> bytes:
        return client.request(receiver, FLYC, cmd_id, payload, timeout=timeout,
                              retries=2).payload

    info = parse_table(ask(TABLE_ATTRIBUTE, table_request(table)))
    if info.table != table:
        raise UnexpectedReply(f"Asked for config table {table}, got {info.table}.")
    found = []
    for index in range(info.count):
        item = parse_item(ask(ITEM_ATTRIBUTE, item_request(table, index)))
        if item is not None:
            if (item.table, item.index) != (table, index):
                raise UnexpectedReply(
                    f"Asked for item {table}/{index}, got {item.table}/{item.index}.")
            value = parse_value(ask(ITEM_VALUE, value_request(table, index)))
            if value is not None and value[0] == index:
                item = Param(**{**item.__dict__, "raw": value[1]})
            found.append(item)
        if on_progress is not None:
            on_progress(index + 1, info.count)
    return info, found
