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
GIMBAL = 0x04
OSD_GENERAL = 0x43
GIMBAL_PARAMS = 0x05


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
    if frame.response:
        return None
    if frame.cmd_set == FLYC and frame.cmd_id == OSD_GENERAL:
        return parse_flyc_osd_general(frame.payload)
    if frame.cmd_set == GIMBAL and frame.cmd_id == GIMBAL_PARAMS:
        return parse_gimbal_params(frame.payload)
    return None


@dataclass(frozen=True)
class GimbalParams:
    """Verified pieces of GIMBAL 04/05 on M4T.

    Bytes 0..11 match the public legacy Gimbal Params layout. M4T extends the
    payload to 49 bytes. Bytes 24..39 form four little-endian float32 values
    whose norm is consistently ~1.0 and whose w/z pair reproduces the legacy
    yaw on stationary captures, strongly identifying them as a quaternion.

    Bytes 12..23 and 40..end remain opaque until independently verified.
    """

    pitch_tenths: int
    roll_tenths: int
    yaw_tenths: int
    mode_flags: int
    roll_adjust: int
    yaw_angle_raw: int
    limit_flags: int
    version_flags: int
    middle: bytes
    quaternion_wxyz: tuple[float, float, float, float] | None
    tail: bytes

    @property
    def attitude_deg(self) -> tuple[float, float, float]:
        return (
            self.pitch_tenths / 10.0,
            self.roll_tenths / 10.0,
            self.yaw_tenths / 10.0,
        )

    @property
    def quaternion_norm(self) -> float | None:
        if self.quaternion_wxyz is None:
            return None
        return sum(value * value for value in self.quaternion_wxyz) ** 0.5


_GIMBAL_PREFIX = struct.Struct("<hhhBbHBB")
_GIMBAL_QUATERNION = struct.Struct("<4f")


def parse_gimbal_params(payload: bytes) -> GimbalParams:
    """Decode the established GIMBAL 04/05 fields without guessing gaps."""
    if len(payload) < _GIMBAL_PREFIX.size:
        raise UnexpectedReply(
            f"GIMBAL 04/05 payload too short for params prefix "
            f"({len(payload)} < {_GIMBAL_PREFIX.size}): {payload.hex()}"
        )

    prefix = _GIMBAL_PREFIX.unpack_from(payload)
    quaternion = None
    if len(payload) >= 40:
        quaternion = _GIMBAL_QUATERNION.unpack_from(payload, 24)

    middle_end = 24 if len(payload) >= 24 else len(payload)
    middle = bytes(payload[_GIMBAL_PREFIX.size:middle_end])
    tail = bytes(payload[40:]) if len(payload) >= 40 else bytes(payload[middle_end:])
    return GimbalParams(*prefix, middle=middle,
                        quaternion_wxyz=quaternion, tail=tail)
