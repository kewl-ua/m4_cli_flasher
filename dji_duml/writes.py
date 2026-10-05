"""Writing one flight-controller config parameter, safely.

The write command is ``03/E3`` "Cfg Item Set". Its request is the project's
verified ``E2`` read request -- ``table u16 | 1 u16 | index u16`` -- with the
new value appended, and its reply has the ``E2`` value-reply shape --
``status u16 | table u16 | index u16 | value`` -- where the device echoes the
value it stored. That layout is cross-confirmed by dji-firmware-tools
(comm_og_service_tool / comm_mkdupc) and the Wireshark dji-dumlv1-flyc
dissector, but no M4T write was ever captured, so this module trusts nothing:

* it reads the item first and validates the requested value against the
  item's own type, size and ``[minimum..maximum]`` reported by ``E1``;
* it refuses unless the caller states the value it believes is set now
  (``expected``), guarding against a write from a stale assumption;
* it sends ``E3`` once with ``retries=0`` -- a changing command is never
  retried -- and treats only ``status 0`` as the device's acceptance;
* it reads the value back and confirms it byte-for-byte, so even the first
  real write is self-verifying;
* on a device rejection it may send ``03/DF`` "Assistant Unlock" once and
  retry, because reads work without the unlock but writes may not.

Only ``03/E3`` and ``03/DF`` are ever sent from here. The reset ``03/E4``,
the command table ``03/E9`` (a positive argument *runs* an action) and the
by-hash ``F`` series (a hash collision would write the wrong parameter) are
never sent.
"""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass, replace

from .client import DumlClient
from .commands import FLYC
from .errors import CommandRejected, NoReply, UnexpectedReply, WriteFailed, WriteRefused
from .params import FLIGHT_CONTROLLER, TYPES, Param, read_one, value_request

SET_ITEM = 0xE3           # Cfg Item Set
ASSISTANT_UNLOCK = 0xDF   # enables Assistant's privileged access for the session
#: The only command ids this module ever sends.
SENDS = frozenset({SET_ITEM, ASSISTANT_UNLOCK})


@dataclass(frozen=True)
class Plan:
    """A validated, not-yet-sent write."""
    param: Param
    old: int | float | None   # value read from the device, None if it did not read
    new: int | float          # value as it will read back (device precision)
    data: bytes               # the exact value bytes to send


@dataclass(frozen=True)
class WriteResult:
    param: Param
    old: int | float | None
    new: int | float
    echoed: int | float | None   # value the E3 reply echoed, None if it carried none
    read_back: int | float | None
    unlocked: bool               # whether 03/DF was sent to get the write accepted


def _value_format(param: Param) -> str:
    fmt = TYPES.get(param.type_id, (None, None))[1]
    if fmt is None:
        raise WriteRefused(f"{param.name!r} has unknown type t{param.type_id}; refusing to write.")
    return fmt


def parse_number(param: Param, text: str) -> int | float:
    """A value string in the param's natural type: ``int(text, 0)`` (so
    ``0x..`` works) for integers, ``float`` for f32/f64."""
    fmt = _value_format(param)
    try:
        return float(text) if fmt in ("<f", "<d") else int(text, 0)
    except (TypeError, ValueError) as exc:
        raise WriteRefused(f"{text!r} is not a valid {param.type_name} value.") from exc


def encode_value(param: Param, number: int | float) -> bytes:
    """The value bytes to write, checked against the item's type, device
    limits and byte size. Raises WriteRefused on any mismatch -- nothing is
    sent on the strength of an unvalidated value."""
    fmt = _value_format(param)
    if fmt in ("<f", "<d"):
        number = float(number)
        if not math.isfinite(number):  # NaN slips past every < / > check
            raise WriteRefused(f"{number} is not a finite {param.type_name} value for "
                               f"{param.name!r}.")
    else:
        if isinstance(number, float) and not number.is_integer():
            raise WriteRefused(f"{number} is not a whole number for {param.type_name} "
                               f"{param.name!r}.")
        number = int(number)
    if number < param.minimum or number > param.maximum:
        raise WriteRefused(f"{number} is outside [{param.minimum}..{param.maximum}] for "
                           f"{param.name!r}.")
    try:
        data = struct.pack(fmt, number)
    except struct.error as exc:
        raise WriteRefused(f"{number} does not fit {param.type_name} {param.name!r}: {exc}.")
    if len(data) != param.size:
        raise WriteRefused(f"{param.name!r} is {param.size} bytes but {param.type_name} packs "
                           f"{len(data)}; refusing to write.")
    return data


def _decode(param: Param, data: bytes) -> int | float | None:
    """The value a Param with these bytes would report (device precision)."""
    return replace(param, raw=data).value


def _same(param: Param, value: int | float, other: int | float) -> bool:
    if isinstance(value, float) or isinstance(other, float):
        return math.isclose(value, other, rel_tol=1e-6, abs_tol=1e-9)
    return value == other


def plan_write(param: Param, value_text: str, expected_text: str | None) -> Plan:
    """Validate a write without sending anything. Checks the new value and,
    when ``expected_text`` is given, that the item currently holds it."""
    data = encode_value(param, parse_number(param, value_text))
    old = param.value
    if expected_text is not None:
        want = parse_number(param, expected_text)
        if old is None:
            raise WriteRefused(f"the current value of {param.name!r} did not read back; cannot "
                               f"confirm it is {want} before writing.")
        if not _same(param, old, want):
            raise WriteRefused(f"{param.name!r} reads {param.shown()} now, not the expected "
                               f"{want}; refusing to write.")
    new = _decode(param, data)
    if new is None:  # the bytes we built do not decode -- a bug, not a device fault
        raise WriteRefused(f"the value for {param.name!r} does not round-trip; refusing to write.")
    return Plan(param, old, new, data)


class _Writer:
    """Sends only the two command ids this module is allowed to send."""

    def __init__(self, client: DumlClient, receiver: int, timeout: float):
        self.client, self.receiver, self.timeout = client, receiver, timeout

    def send(self, cmd_id: int, payload: bytes) -> bytes:
        if cmd_id not in SENDS:
            raise ValueError(f"03/{cmd_id:02X} is not a write this module sends.")
        # retries=0 is mandatory: a changing command is never retried.
        return self.client.request(self.receiver, FLYC, cmd_id, payload,
                                   timeout=self.timeout, retries=0).payload


def set_item_request(table: int, index: int, data: bytes) -> bytes:
    """The E3 request: the verified E2 read request with the value appended."""
    return value_request(table, index) + data


def parse_set_reply(payload: bytes, table: int, index: int) -> bytes:
    """The value the device echoes back (``b""`` when it acknowledges without
    one). Only a non-zero status is a rejection; status 0 is success even if
    the reply is too short to carry an echo -- the read-back then confirms it,
    so a value-less success never reaches the unlock-and-retry path."""
    if len(payload) < 2:
        raise UnexpectedReply(f"Cfg Item Set reply is too short: {payload.hex()}")
    status = struct.unpack_from("<H", payload)[0]
    if status != 0:
        raise CommandRejected("Cfg Item Set", status)
    if len(payload) < 7:
        return b""  # success without an echoed value
    etable, eindex = struct.unpack_from("<HH", payload, 2)
    if (etable, eindex) != (table, index):
        raise UnexpectedReply(f"Cfg Item Set echoed {etable}/{eindex}, asked {table}/{index}.")
    return payload[6:]


def unlock_request(state: int = 1) -> bytes:
    return struct.pack("<I", state)


def parse_unlock(payload: bytes) -> int:
    """The unlock status byte (0 = granted). Never raises: the retry's own
    result is what decides, as og_service_tool does."""
    return payload[0] if payload else -1


def _apply(client: DumlClient, plan: Plan, receiver: int, table: int, timeout: float,
           unlock_on_reject: bool) -> tuple[bytes, bool]:
    """Send E3 for the planned write; on rejection, optionally unlock once and
    retry. Returns (echoed value bytes, whether unlock was sent)."""
    writer = _Writer(client, receiver, timeout)
    request = set_item_request(table, plan.param.index, plan.data)
    try:
        return parse_set_reply(writer.send(SET_ITEM, request), table, plan.param.index), False
    except CommandRejected:
        if not unlock_on_reject:
            raise
    parse_unlock(writer.send(ASSISTANT_UNLOCK, unlock_request(1)))  # best effort, like Assistant
    return parse_set_reply(writer.send(SET_ITEM, request), table, plan.param.index), True


def commit_write(client: DumlClient, plan: Plan, *, receiver: int = FLIGHT_CONTROLLER,
                 table: int = 0, timeout: float = 1.0, unlock_on_reject: bool = True
                 ) -> WriteResult:
    """Send the planned write and confirm it by reading the value back. The
    read-back is authoritative: a mismatch raises WriteFailed carrying what the
    item now holds, so the caller can restore the old value. If the write's own
    reply is lost or malformed the frame may still have been applied, so the
    read-back is done anyway rather than leaving the device state unconfirmed."""
    lost = None
    try:
        echoed_bytes, unlocked = _apply(client, plan, receiver, table, timeout, unlock_on_reject)
    except CommandRejected:
        raise  # the device refused the write outright; nothing changed
    except (NoReply, UnexpectedReply) as exc:
        echoed_bytes, unlocked, lost = b"", False, exc  # E3 was on the wire; confirm by read-back
    confirm = read_one(client, plan.param.index, receiver=receiver, table=table, timeout=timeout)
    read_back = confirm.value if confirm is not None else None
    read_back_bytes = confirm.raw if confirm is not None else None
    if read_back_bytes != plan.data:
        shown = read_back if read_back is not None else "unreadable"
        note = (f" (the write reply was lost: {type(lost).__name__})" if lost is not None
                else " (unlock was sent)" if unlocked else "")
        raise WriteFailed(f"wrote {plan.new} to {plan.param.name!r}, but it reads back as "
                          f"{shown}{note}.", read_back=read_back)
    echoed = _decode(plan.param, echoed_bytes) if echoed_bytes else None
    return WriteResult(plan.param, plan.old, plan.new, echoed, read_back, unlocked)
