"""General command set (0x00): version inquiry and the public upgrade commands.

Payload layouts come from the public dji-firmware-tools dissector and pyduml.
Only the version inquiry has been observed on an M4T; see profiles.py.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from .client import DumlClient
from .errors import CommandRejected, UnexpectedReply
from .frame import Frame
from .version import FirmwareVersion

GENERAL = 0x00
VERSION_INQUIRY = 0x01
ENTER_UPGRADE = 0x07
UPGRADE_DATA_SIZE = 0x08
UPGRADE_DATA = 0x09
UPGRADE_VERIFY = 0x0A
UPGRADE_REPORT = 0x0C
UPGRADE_STATUS = 0x42

GENERAL_NAMES = {
    0x00: "Ping", 0x01: "Version Inquiry", 0x07: "Enter Upgrade Mode",
    0x08: "Upgrade Data Size", 0x09: "Upgrade Data", 0x0A: "Upgrade Verify",
    0x0B: "Reboot Chip", 0x0C: "Get Device State", 0x0E: "Heartbeat",
    0x0F: "Upgrade Self Request", 0x22: "File Send", 0x23: "File Receive",
    0x24: "File Sending", 0x2A: "File Transfer", 0x40: "Fw Update Desc Push",
    0x41: "Fw Update Push Control", 0x42: "Fw Upgrade Push Status",
    0x43: "Fw Upgrade Finish", 0x47: "Power State", 0x4F: "Get Cfg File",
    0x81: "Upgrade Center Info", 0x82: "Upgrade Center State", 0x83: "Upgrade Prepare",
    0x84: "Upgrade Announce", 0x85: "Upgrade Install",
    0x51: "Get Serial Number", 0xFF: "Query Device Info",
    0x32: "Activate Config", 0x4A: "Set Date/Time", 0xF1: "Self Test State",
}

FLYC = 0x03
#: Flight controller commands seen in Assistant's idle capture of an M4T,
#: named after the dji-firmware-tools flyc dissector.
FLYC_NAMES = {
    0x43: "OSD General Data", 0xAF: "Product Config", 0xCE: "Push Forbid Data",
    0xDF: "Assistant Unlock", 0xE0: "Cfg Table Attribute", 0xE1: "Cfg Item Attribute",
    0xE2: "Cfg Item Value", 0xE3: "Cfg Item Set", 0xE4: "Cfg Item Reset",
    0xE5: "Push Cfg Table Attr", 0xE9: "Cfg Command Table",
}


def command_name(cmd_set: int, cmd_id: int) -> str:
    if cmd_set == GENERAL and cmd_id in GENERAL_NAMES:
        return GENERAL_NAMES[cmd_id]
    if cmd_set == FLYC and cmd_id in FLYC_NAMES:
        return FLYC_NAMES[cmd_id]
    return f"set {cmd_set:02x} id {cmd_id:02x}"


@dataclass(frozen=True)
class VersionInfo:
    hardware: str
    loader: FirmwareVersion
    firmware: FirmwareVersion
    raw: bytes


def parse_version_reply(payload: bytes) -> VersionInfo:
    """status, reserved, hardware[16], loader u32, firmware u32, ..."""
    if payload and payload[0] != 0:
        raise CommandRejected("Version Inquiry", payload[0])
    if len(payload) < 26:
        raise UnexpectedReply(f"Version reply too short ({len(payload)} bytes): {payload.hex()}")
    text = payload[2:18].split(b"\0", 1)[0]
    if not text or not all(0x20 <= byte < 0x7F for byte in text):
        raise UnexpectedReply(f"Hardware string is not printable ASCII: {payload.hex()}")
    return VersionInfo(
        hardware=text.decode("ascii"),
        loader=FirmwareVersion.from_wire(payload[18:22]),
        firmware=FirmwareVersion.from_wire(payload[22:26]),
        raw=bytes(payload),
    )


def get_version(client: DumlClient, target: int, *, timeout: float = 2.0,
                retries: int = 2) -> VersionInfo:
    """Read-only and idempotent, so it is the only command that is retried."""
    reply = client.request(target, GENERAL, VERSION_INQUIRY, timeout=timeout, retries=retries)
    return parse_version_reply(reply.payload)


def require_ok(reply: Frame, command: str) -> None:
    if reply.payload and reply.payload[0] != 0:
        raise CommandRejected(command, reply.payload[0])


def enter_upgrade_payload() -> bytes:
    return bytes(9)


def upgrade_report_payload() -> bytes:
    return b"\x00"


def upgrade_size_payload(size: int) -> bytes:
    if not 0 < size <= 0xFFFFFFFF:
        raise ValueError("Firmware size must fit an unsigned 32-bit field.")
    return b"\x00" + struct.pack("<I", size) + bytes(6) + b"\x02\x04"


def upgrade_verify_payload(md5: bytes) -> bytes:
    if len(md5) != 16:
        raise ValueError("MD5 digest must be 16 bytes.")
    return b"\x00" + md5


# -- upgrade center protocol (DJI Assistant -> M4T module 0x48) ---------------
#
# Layouts from two USB captures of DJI Assistant flashing an M4T on 2026-10-04
# (online refresh of 17.01.0516, offline upgrade to 17.02.0501). Only the
# success path was observed; meanings marked "unknown" are copied verbatim.

UPGRADE_PREPARE = 0x83   # [04] -> 00 07 00
UPGRADE_ANNOUNCE = 0x84  # total bytes of all files -> 00
FILE_TRANSFER = 0x2A     # sub 01 open, 04 data, 03 end; progress reports back
UPGRADE_INSTALL = 0x85   # 16 x 00 -> 06 (not an error)
UPGRADE_RESULT = 0x4F    # [04 00000000 ffffffff] -> installed version
PUSH_CONTROL = 0x41      # [04] -> 00, sent after Complete
CENTER_INFO = 0x81       # the device asks the host every second
CENTER_STATE = 0x82      # likewise

FT_OPEN, FT_END, FT_DATA = 0x01, 0x03, 0x04

#: Host replies DJI Assistant gives to the device's 00/81 and 00/82 requests.
CENTER_INFO_REPLY = bytes.fromhex(
    "005063000000000000000000000000000000000000000000000000000000000000010a"
    "0000000000000208000000000000000000000000000000000000000000"
)
CENTER_STATE_REPLY = b"\x00"


def prepare_payload() -> bytes:
    return b"\x04"


def announce_payload(total: int) -> bytes:
    """Total bytes of all files that follow; the tail bytes are unknown."""
    if not 0 < total <= 0xFFFFFFFF:
        raise ValueError("Total transfer size must fit an unsigned 32-bit field.")
    return b"\x00" + struct.pack("<I", total) + bytes(4) + b"\x02\x00\x01"


def file_open_payload(name: str, size: int) -> bytes:
    encoded = name.encode("ascii") + b"\0"
    if len(encoded) > 0xFF or not 0 < size <= 0xFFFFFFFF:
        raise ValueError(f"Cannot announce {name!r} of {size} bytes.")
    return bytes([FT_OPEN]) + struct.pack("<I", size) + bytes([len(encoded)]) + encoded \
        + b"\x00\x01\x01"


def parse_file_open_reply(payload: bytes, command: str = "File open") -> int:
    """Chunk size the device accepts (980 on the M4T)."""
    if payload and payload[0] != 0:
        raise CommandRejected(command, payload[0])
    if len(payload) != 7:
        raise UnexpectedReply(f"{command} reply is not 7 bytes: {payload.hex()}")
    chunk = int.from_bytes(payload[1:3], "little")
    if not 0 < chunk <= 1010 - 5:
        raise UnexpectedReply(f"{command} offers chunk size {chunk}: {payload.hex()}")
    return chunk


def file_data_payload(index: int, chunk: bytes) -> bytes:
    return bytes([FT_DATA]) + struct.pack("<I", index) + chunk


def file_end_payload(md5: bytes) -> bytes:
    if len(md5) != 16:
        raise ValueError("MD5 digest must be 16 bytes.")
    return bytes([FT_END]) + md5


def parse_file_progress(payload: bytes) -> int:
    """Highest chunk index the device has received of the open file."""
    if len(payload) != 5 or payload[0] != 0:
        raise UnexpectedReply(f"Not a file transfer progress report: {payload.hex()}")
    return int.from_bytes(payload[1:5], "little")


def parse_file_gap(payload: bytes) -> tuple[int, int, int]:
    """The report the device sends instead of a progress report when it is
    missing chunks of the open file: (highest chunk received, first missing,
    count). Seen twice in Assistant's 2026-10-05 capture, each time for one
    chunk, which Assistant sent again at once."""
    if len(payload) != 13 or payload[0] != 0:
        raise UnexpectedReply(f"Not a file transfer gap report: {payload.hex()}")
    return (int.from_bytes(payload[1:5], "little"), int.from_bytes(payload[5:9], "little"),
            int.from_bytes(payload[9:13], "little"))


def install_payload() -> bytes:
    return bytes(16)


def result_query_payload() -> bytes:
    return b"\x04" + bytes(4) + b"\xff\xff\xff\xff"


def parse_result_reply(payload: bytes) -> FirmwareVersion:
    """Installed package version: bytes 9..12 hold one decimal field each,
    least significant first (10 05 01 11 = 17.01.05.16 = 17.01.0516)."""
    if payload and payload[0] != 0:
        raise CommandRejected("Upgrade Result", payload[0])
    if len(payload) != 13:
        raise UnexpectedReply(f"Upgrade result reply is not 13 bytes: {payload.hex()}")
    low, high, minor, major = payload[9:13]
    if low > 99 or high > 99:
        raise UnexpectedReply(f"Upgrade result version is not decimal: {payload.hex()}")
    return FirmwareVersion(major, minor, high * 100 + low)


def push_control_payload() -> bytes:
    return b"\x04"


class UpgradeState(IntEnum):
    VERIFY = 1
    USER_CONFIRM = 2
    UPGRADING = 3
    COMPLETE = 4


UPGRADE_RESULTS = {
    1: "Success", 2: "Failure", 3: "FirmwareError", 4: "SameVersion", 5: "UserCancel",
    6: "TimeOut", 7: "MotorWorking", 8: "FirmNotMatch", 9: "IllegalDegrade",
    10: "NoConnectRC",
}


@dataclass(frozen=True)
class ModuleStatus:
    """One entry of an M4T status push: DUML address (0 = all), state, percent."""
    address: int
    state: int
    percent: int


@dataclass(frozen=True)
class UpgradeStatus:
    state: UpgradeState
    percent: int | None = None
    result: int | None = None
    #: Per-module entries of the M4T's long form: state, percent, N, N x 8 bytes.
    modules: tuple[ModuleStatus, ...] = ()

    @property
    def result_name(self) -> str | None:
        if self.result is None:
            return None
        return UPGRADE_RESULTS.get(self.result, f"Unknown({self.result})")


def parse_upgrade_status(payload: bytes) -> UpgradeStatus:
    if not payload:
        raise UnexpectedReply("Empty upgrade status push.")
    try:
        state = UpgradeState(payload[0])
    except ValueError:
        raise UnexpectedReply(f"Unknown upgrade state {payload[0]}: {payload.hex()}") from None
    if state in (UpgradeState.UPGRADING, UpgradeState.COMPLETE) and len(payload) < 2:
        raise UnexpectedReply(f"Truncated upgrade status: {payload.hex()}")
    modules = ()
    if len(payload) > 3 and len(payload) == 3 + 8 * payload[2]:
        modules = tuple(ModuleStatus(entry[0], entry[6], entry[7])
                        for entry in (payload[3 + 8 * i:11 + 8 * i] for i in range(payload[2])))
    if state is UpgradeState.UPGRADING:
        if payload[1] > 100:
            raise UnexpectedReply(f"Upgrade progress above 100%: {payload.hex()}")
        return UpgradeStatus(state, percent=payload[1], modules=modules)
    if state is UpgradeState.COMPLETE:
        return UpgradeStatus(state, result=payload[1], modules=modules)
    return UpgradeStatus(state, modules=modules)
