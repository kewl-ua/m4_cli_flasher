"""Typed decoders for DUML telemetry observed on newer DJI products.

Only fields with evidence strong enough to expose as API are decoded here.
Newer products may extend legacy packets; parsers therefore accept longer
payloads and preserve the undecoded tail instead of guessing its layout.
"""
from __future__ import annotations

import math
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

    Bytes 12..15 are verified on M4T as a millisecond monotonic timestamp.
    Controlled pitch/yaw captures also establish an empirical yaw reference at
    0x10 (signed int16, 0.01 degree) and a secondary pitch/joint angle at 0x14
    (signed int16, 0.1 degree). The legacy 0x08 yaw angle behaves as relative
    yaw: yaw_reference + relative_yaw predicts packet yaw with sub-degree median
    error in controlled captures. Bytes 0x12..0x13, 0x16..0x17 and 40..end
    remain unnamed until independently verified.
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
    timestamp_ms: int | None
    yaw_reference_hundredths: int | None
    extension_12_raw: int | None
    pitch_joint_tenths: int | None
    extension_16_raw: int | None
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
    def relative_yaw_deg(self) -> float:
        value = self.yaw_angle_raw
        if value & 0x8000:
            value -= 0x10000
        return value / 10.0

    @property
    def yaw_reference_deg(self) -> float | None:
        """Empirical M4T yaw reference at payload 0x10, in 0.01 degrees."""
        if self.yaw_reference_hundredths is None:
            return None
        return self.yaw_reference_hundredths / 100.0

    @property
    def pitch_joint_deg(self) -> float | None:
        """Secondary pitch/joint angle at payload 0x14, in 0.1 degrees."""
        if self.pitch_joint_tenths is None:
            return None
        return self.pitch_joint_tenths / 10.0

    @property
    def predicted_yaw_deg(self) -> float | None:
        """Yaw predicted by the empirically verified reference+relative model."""
        if self.yaw_reference_deg is None:
            return None
        value = self.yaw_reference_deg + self.relative_yaw_deg
        return (value + 180.0) % 360.0 - 180.0

    @property
    def quaternion_norm(self) -> float | None:
        if self.quaternion_wxyz is None:
            return None
        return sum(value * value for value in self.quaternion_wxyz) ** 0.5

    @property
    def quaternion_euler_deg(self) -> tuple[float, float, float] | None:
        """Quaternion converted to (pitch, roll, yaw) degrees.

        M4T samples show the standard w,x,y,z aerospace conversion matching the
        legacy int16 attitude fields to their 0.1-degree quantization.
        """
        if self.quaternion_wxyz is None:
            return None
        w, x, y, z = self.quaternion_wxyz
        roll = math.degrees(math.atan2(
            2.0 * (w * x + y * z),
            1.0 - 2.0 * (x * x + y * y),
        ))
        sin_pitch = 2.0 * (w * y - z * x)
        pitch = math.degrees(math.asin(max(-1.0, min(1.0, sin_pitch))))
        yaw = math.degrees(math.atan2(
            2.0 * (w * z + x * y),
            1.0 - 2.0 * (y * y + z * z),
        ))
        return pitch, roll, yaw

    @property
    def quaternion_orientation_error_deg(self) -> float | None:
        """Angular distance between quaternion and legacy Euler orientation.

        Unlike per-axis Euler comparison this stays valid when pitch crosses
        +/-90 degrees and the equivalent Euler representation changes branch.
        """
        if self.quaternion_wxyz is None:
            return None
        pitch, roll, yaw = (math.radians(value) for value in self.attitude_deg)
        cr, sr = math.cos(roll / 2.0), math.sin(roll / 2.0)
        cp, sp = math.cos(pitch / 2.0), math.sin(pitch / 2.0)
        cy, sy = math.cos(yaw / 2.0), math.sin(yaw / 2.0)
        legacy_q = (
            cr * cp * cy + sr * sp * sy,
            sr * cp * cy - cr * sp * sy,
            cr * sp * cy + sr * cp * sy,
            cr * cp * sy - sr * sp * cy,
        )
        q = self.quaternion_wxyz
        q_norm = sum(value * value for value in q) ** 0.5
        legacy_norm = sum(value * value for value in legacy_q) ** 0.5
        if q_norm <= 0 or legacy_norm <= 0:
            return None
        dot = abs(sum(a * b for a, b in zip(q, legacy_q)) / (q_norm * legacy_norm))
        dot = max(-1.0, min(1.0, dot))
        return math.degrees(2.0 * math.acos(dot))


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
    timestamp_ms = int.from_bytes(payload[12:16], "little") if len(payload) >= 16 else None
    yaw_reference_hundredths = (
        int.from_bytes(payload[16:18], "little", signed=True) if len(payload) >= 18 else None
    )
    extension_12_raw = (
        int.from_bytes(payload[18:20], "little", signed=True) if len(payload) >= 20 else None
    )
    pitch_joint_tenths = (
        int.from_bytes(payload[20:22], "little", signed=True) if len(payload) >= 22 else None
    )
    extension_16_raw = (
        int.from_bytes(payload[22:24], "little", signed=True) if len(payload) >= 24 else None
    )

    quaternion = None
    if len(payload) >= 40:
        quaternion = _GIMBAL_QUATERNION.unpack_from(payload, 24)

    middle_end = 24 if len(payload) >= 24 else len(payload)
    middle = bytes(payload[_GIMBAL_PREFIX.size:middle_end])
    tail = bytes(payload[40:]) if len(payload) >= 40 else bytes(payload[middle_end:])
    return GimbalParams(
        *prefix,
        middle=middle,
        timestamp_ms=timestamp_ms,
        yaw_reference_hundredths=yaw_reference_hundredths,
        extension_12_raw=extension_12_raw,
        pitch_joint_tenths=pitch_joint_tenths,
        extension_16_raw=extension_16_raw,
        quaternion_wxyz=quaternion,
        tail=tail,
    )
