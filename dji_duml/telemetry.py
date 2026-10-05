"""Typed decoders for DUML telemetry observed on newer DJI products.

Only fields with evidence strong enough to expose as API are decoded here.
Newer products may extend legacy packets; parsers therefore accept longer
payloads and preserve the undecoded tail instead of guessing its layout.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from .errors import UnexpectedReply
from .frame import Frame

FLYC = 0x03
OSD_GENERAL = 0x43


@dataclass(frozen=True)
class FlycOsdGeneral:
    """Verified 36-byte prefix of FLYC 03/43 OSD General.

    The prefix matches the public legacy DUML layout and the same offsets on
    M4T captures. Longitude/latitude are returned exactly as the protocol's
    little-endian doubles; no degree/radian conversion is assumed here.

    M4T currently carries an 84-byte payload, so the tail deliberately remains
    opaque until its fields are established empirically.
    """

    longitude: float
    latitude: float
    relative_height_dm: int
    velocity_x_dms: int
    velocity_y_dms: int
    velocity_z_dms: int
    pitch_tenths: int
    roll_tenths: int
    yaw_tenths: int
    ctrl_info: int
    latest_cmd: int
    controller_state: int
    tail: bytes

    @property
    def relative_height_m(self) -> float:
        return self.relative_height_dm / 10.0

    @property
    def velocity_mps(self) -> tuple[float, float, float]:
        return (
            self.velocity_x_dms / 10.0,
            self.velocity_y_dms / 10.0,
            self.velocity_z_dms / 10.0,
        )

    @property
    def attitude_deg(self) -> tuple[float, float, float]:
        return (
            self.pitch_tenths / 10.0,
            self.roll_tenths / 10.0,
            self.yaw_tenths / 10.0,
        )


_OSD_PREFIX = struct.Struct("<ddhhhhhhhBBI")


def parse_flyc_osd_general(payload: bytes) -> FlycOsdGeneral:
    """Decode only the established prefix of FLYC 03/43."""
    if len(payload) < _OSD_PREFIX.size:
        raise UnexpectedReply(
            f"FLYC 03/43 payload too short for OSD prefix "
            f"({len(payload)} < {_OSD_PREFIX.size}): {payload.hex()}"
        )
    values = _OSD_PREFIX.unpack_from(payload)
    return FlycOsdGeneral(*values, tail=bytes(payload[_OSD_PREFIX.size:]))


def decode_known(frame: Frame):
    """Return a typed object for a telemetry frame we know, else None."""
    if not frame.response and frame.cmd_set == FLYC and frame.cmd_id == OSD_GENERAL:
        return parse_flyc_osd_general(frame.payload)
    return None
