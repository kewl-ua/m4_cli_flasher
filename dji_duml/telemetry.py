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

FLYC_OSD_VERIFIED_PREFIX_SIZE = 36
FLYC_OSD_LEGACY_BASE_SIZE = 50
FLYC_OSD_LEGACY_WM620_SIZE = 55


@dataclass(frozen=True)
class FlycOsdGeneral:
    """Verified 36-byte prefix of FLYC 03/43 OSD General.

    The prefix matches the public legacy DUML layout and the same offsets on
    M4T captures. Longitude/latitude are returned exactly as the protocol's
    little-endian doubles; no degree/radian conversion is assumed here.

    M4T currently carries an 84-byte payload. Public legacy dissectors extend
    the historical layout to 50 bytes (P3) or 55 bytes (WM620), but M4T may
    repurpose those slots. The parser therefore keeps everything after the
    verified 36-byte prefix raw while exposing structural region views only.
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
    def legacy_base_region(self) -> bytes:
        """Raw payload bytes 0x24..0x31 from the historical 50-byte layout."""
        return self.tail[:FLYC_OSD_LEGACY_BASE_SIZE - FLYC_OSD_VERIFIED_PREFIX_SIZE]

    @property
    def legacy_wm620_region(self) -> bytes:
        """Raw payload bytes 0x32..0x36 from the historical 55-byte layout."""
        start = FLYC_OSD_LEGACY_BASE_SIZE - FLYC_OSD_VERIFIED_PREFIX_SIZE
        end = FLYC_OSD_LEGACY_WM620_SIZE - FLYC_OSD_VERIFIED_PREFIX_SIZE
        return self.tail[start:end]

    @property
    def newer_extension(self) -> bytes:
        """Raw bytes after historical offset 0x36 (payload offset 0x37+)."""
        start = FLYC_OSD_LEGACY_WM620_SIZE - FLYC_OSD_VERIFIED_PREFIX_SIZE
        return self.tail[start:]

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


def euler_deg_to_quaternion(
    attitude_deg: tuple[float, float, float],
) -> tuple[float, float, float, float]:
    """Convert (pitch, roll, yaw) degrees to a normalized w,x,y,z quaternion."""
    pitch, roll, yaw = (math.radians(value) for value in attitude_deg)
    cr, sr = math.cos(roll / 2.0), math.sin(roll / 2.0)
    cp, sp = math.cos(pitch / 2.0), math.sin(pitch / 2.0)
    cy, sy = math.cos(yaw / 2.0), math.sin(yaw / 2.0)
    q = (
        cr * cp * cy + sr * sp * sy,
        sr * cp * cy - cr * sp * sy,
        cr * sp * cy + sr * cp * sy,
        cr * cp * sy - sr * sp * cy,
    )
    norm = sum(value * value for value in q) ** 0.5
    return tuple(value / norm for value in q)


def quaternion_conjugate(
    quaternion: tuple[float, float, float, float],
) -> tuple[float, float, float, float]:
    w, x, y, z = quaternion
    return w, -x, -y, -z


def quaternion_multiply(
    left: tuple[float, float, float, float],
    right: tuple[float, float, float, float],
) -> tuple[float, float, float, float]:
    lw, lx, ly, lz = left
    rw, rx, ry, rz = right
    return (
        lw * rw - lx * rx - ly * ry - lz * rz,
        lw * rx + lx * rw + ly * rz - lz * ry,
        lw * ry - lx * rz + ly * rw + lz * rx,
        lw * rz + lx * ry - ly * rx + lz * rw,
    )


def quaternion_axis_angle_deg(
    axis: str,
    angle_deg: float,
) -> tuple[float, float, float, float]:
    """Return an active rotation quaternion around x, y or z."""
    half = math.radians(angle_deg) / 2.0
    s = math.sin(half)
    q = {
        "x": (math.cos(half), s, 0.0, 0.0),
        "y": (math.cos(half), 0.0, s, 0.0),
        "z": (math.cos(half), 0.0, 0.0, s),
    }.get(axis)
    if q is None:
        raise ValueError("axis must be x, y or z")
    return q


def quaternion_angular_distance_deg(
    left: tuple[float, float, float, float],
    right: tuple[float, float, float, float],
) -> float:
    """Shortest angular distance between two orientations."""
    left_norm = sum(value * value for value in left) ** 0.5
    right_norm = sum(value * value for value in right) ** 0.5
    if left_norm <= 0 or right_norm <= 0:
        raise ValueError("zero-norm quaternion")
    dot = abs(sum(a * b for a, b in zip(left, right)) / (left_norm * right_norm))
    dot = max(-1.0, min(1.0, dot))
    return math.degrees(2.0 * math.acos(dot))


def quaternion_average(
    quaternions: list[tuple[float, float, float, float]],
) -> tuple[float, float, float, float]:
    """Average nearby orientations with hemisphere alignment.

    Intended for estimating a constant mounting transform, not for averaging
    arbitrary multimodal orientation distributions.
    """
    if not quaternions:
        raise ValueError("at least one quaternion is required")
    reference = quaternions[0]
    aligned = []
    for quaternion in quaternions:
        norm = sum(value * value for value in quaternion) ** 0.5
        if norm <= 0:
            raise ValueError("zero-norm quaternion")
        q = tuple(value / norm for value in quaternion)
        if sum(a * b for a, b in zip(reference, q)) < 0.0:
            q = tuple(-value for value in q)
        aligned.append(q)
    summed = tuple(sum(q[index] for q in aligned) for index in range(4))
    norm = sum(value * value for value in summed) ** 0.5
    if norm <= 0:
        raise ValueError("degenerate quaternion average")
    return tuple(value / norm for value in summed)


def quaternion_slerp(
    left: tuple[float, float, float, float],
    right: tuple[float, float, float, float],
    fraction: float,
) -> tuple[float, float, float, float]:
    """Shortest-path spherical interpolation between two orientations."""
    if fraction <= 0.0:
        return left
    if fraction >= 1.0:
        return right

    lnorm = sum(value * value for value in left) ** 0.5
    rnorm = sum(value * value for value in right) ** 0.5
    if lnorm <= 0 or rnorm <= 0:
        raise ValueError("zero-norm quaternion")
    a = tuple(value / lnorm for value in left)
    b = tuple(value / rnorm for value in right)

    dot = sum(x * y for x, y in zip(a, b))
    if dot < 0.0:
        b = tuple(-value for value in b)
        dot = -dot
    dot = max(-1.0, min(1.0, dot))

    if dot > 0.9995:
        q = tuple(x + fraction * (y - x) for x, y in zip(a, b))
        norm = sum(value * value for value in q) ** 0.5
        return tuple(value / norm for value in q)

    theta = math.acos(dot)
    sin_theta = math.sin(theta)
    left_weight = math.sin((1.0 - fraction) * theta) / sin_theta
    right_weight = math.sin(fraction * theta) / sin_theta
    return tuple(
        left_weight * x + right_weight * y
        for x, y in zip(a, b)
    )


def quaternion_to_euler_deg(
    quaternion: tuple[float, float, float, float],
) -> tuple[float, float, float]:
    """Convert a w,x,y,z quaternion to (pitch, roll, yaw) degrees."""
    w, x, y, z = quaternion
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


def relative_quaternion(
    parent_world: tuple[float, float, float, float],
    child_world: tuple[float, float, float, float],
) -> tuple[float, float, float, float]:
    """Return child orientation expressed in the parent frame."""
    return quaternion_multiply(quaternion_conjugate(parent_world), child_world)


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
    Controlled body-motion captures establish body-relative pitch and roll
    joint fields at 0x14 and 0x16 (signed int16, 0.1 degree), while the legacy
    0x08 yaw-angle field behaves as body-relative yaw. These three fields track
    the Euler angles recovered from inverse(q_FC) * q_gimbal. Field 0x10 is a
    signed 0.01-degree internal yaw-reference candidate but is not simply
    FC/body yaw. Bytes 0x12..0x13 and 40..end remain unnamed.
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
    roll_joint_tenths: int | None
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
        """Internal M4T yaw-reference candidate at 0x10, in 0.01 degrees.

        Controlled body-rotation captures show this is not simply FC/body yaw.
        The name is intentionally descriptive rather than a physical claim.
        """
        if self.yaw_reference_hundredths is None:
            return None
        return self.yaw_reference_hundredths / 100.0

    @property
    def pitch_joint_deg(self) -> float | None:
        """Body-relative gimbal pitch joint at payload 0x14, in 0.1 degrees."""
        if self.pitch_joint_tenths is None:
            return None
        return self.pitch_joint_tenths / 10.0

    @property
    def roll_joint_deg(self) -> float | None:
        """Body-relative gimbal roll joint at payload 0x16, in 0.1 degrees."""
        if self.roll_joint_tenths is None:
            return None
        return self.roll_joint_tenths / 10.0

    @property
    def joint_angles_deg(self) -> tuple[float | None, float | None, float]:
        """Mechanical/body-relative (pitch, roll, yaw) joint angles."""
        return self.pitch_joint_deg, self.roll_joint_deg, self.relative_yaw_deg

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
        return quaternion_to_euler_deg(self.quaternion_wxyz)

    @property
    def quaternion_orientation_error_deg(self) -> float | None:
        """Angular distance between quaternion and legacy Euler orientation.

        Unlike per-axis Euler comparison this stays valid when pitch crosses
        +/-90 degrees and the equivalent Euler representation changes branch.
        """
        if self.quaternion_wxyz is None:
            return None
        legacy_q = euler_deg_to_quaternion(self.attitude_deg)
        return quaternion_angular_distance_deg(self.quaternion_wxyz, legacy_q)


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
    roll_joint_tenths = (
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
        roll_joint_tenths=roll_joint_tenths,
        quaternion_wxyz=quaternion,
        tail=tail,
    )
