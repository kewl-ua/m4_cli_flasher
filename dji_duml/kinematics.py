"""Empirically derived gimbal kinematics for supported DJI products.

Packet decoding lives in dji_duml.telemetry. This module adds the physical
frame model separately so raw protocol evidence is not conflated with a
device-specific kinematic interpretation.
"""
from __future__ import annotations

from dataclasses import dataclass

from .telemetry import (
    GimbalParams,
    euler_deg_to_quaternion,
    quaternion_angular_distance_deg,
    quaternion_axis_angle_deg,
    quaternion_multiply,
    quaternion_to_euler_deg,
    relative_quaternion,
)

Quaternion = tuple[float, float, float, float]


@dataclass(frozen=True)
class GimbalKinematics:
    """Forward kinematics for three body-relative gimbal joint angles.

    joint_order names rotations in quaternion multiplication order.
    M4T controlled captures currently support yaw -> roll -> pitch, i.e.
    Rz(yaw) * Rx(roll) * Ry(pitch).

    mount_quaternion is kept explicit because a small constant mounting
    transform can be airframe/unit specific. mount_side specifies whether
    that transform is applied before ("left") or after ("right") the mechanical
    joint chain.
    """

    mount_quaternion: Quaternion = (1.0, 0.0, 0.0, 0.0)
    joint_order: tuple[str, str, str] = ("yaw", "roll", "pitch")
    mount_side: str = "left"
    lag_ms: int = 0

    def __post_init__(self) -> None:
        if set(self.joint_order) != {"pitch", "roll", "yaw"}:
            raise ValueError("joint_order must contain pitch, roll and yaw exactly once")
        if self.mount_side not in {"left", "right"}:
            raise ValueError("mount_side must be 'left' or 'right'")

    @classmethod
    def from_mount_euler(
        cls,
        mount_euler_deg: tuple[float, float, float],
        *,
        joint_order: tuple[str, str, str] = ("yaw", "roll", "pitch"),
        mount_side: str = "left",
        lag_ms: int = 0,
    ) -> "GimbalKinematics":
        return cls(
            mount_quaternion=euler_deg_to_quaternion(mount_euler_deg),
            joint_order=joint_order,
            mount_side=mount_side,
            lag_ms=lag_ms,
        )

    @property
    def mount_euler_deg(self) -> tuple[float, float, float]:
        return quaternion_to_euler_deg(self.mount_quaternion)

    def joint_quaternion(self, gimbal: GimbalParams) -> Quaternion:
        """Build the mechanical joint orientation from one 04/05 sample."""
        if gimbal.pitch_joint_deg is None or gimbal.roll_joint_deg is None:
            raise ValueError("gimbal sample does not contain M4T pitch/roll joint fields")
        angles = {
            "pitch": gimbal.pitch_joint_deg,
            "roll": gimbal.roll_joint_deg,
            "yaw": gimbal.relative_yaw_deg,
        }
        axes = {"pitch": "y", "roll": "x", "yaw": "z"}

        result: Quaternion = (1.0, 0.0, 0.0, 0.0)
        for name in self.joint_order:
            result = quaternion_multiply(
                result,
                quaternion_axis_angle_deg(axes[name], angles[name]),
            )
        return result

    def relative_orientation(self, gimbal: GimbalParams) -> Quaternion:
        """Predict camera/gimbal orientation in the FC body frame."""
        joints = self.joint_quaternion(gimbal)
        if self.mount_side == "left":
            return quaternion_multiply(self.mount_quaternion, joints)
        return quaternion_multiply(joints, self.mount_quaternion)

    def relative_euler_deg(self, gimbal: GimbalParams) -> tuple[float, float, float]:
        return quaternion_to_euler_deg(self.relative_orientation(gimbal))

    def world_orientation(
        self,
        fc_attitude_deg: tuple[float, float, float],
        gimbal: GimbalParams,
    ) -> Quaternion:
        """Predict camera/gimbal world orientation from FC attitude + joints."""
        fc_world = euler_deg_to_quaternion(fc_attitude_deg)
        return quaternion_multiply(fc_world, self.relative_orientation(gimbal))

    def world_euler_deg(
        self,
        fc_attitude_deg: tuple[float, float, float],
        gimbal: GimbalParams,
    ) -> tuple[float, float, float]:
        return quaternion_to_euler_deg(self.world_orientation(fc_attitude_deg, gimbal))

    def measured_relative_orientation(
        self,
        fc_attitude_deg: tuple[float, float, float],
        gimbal: GimbalParams,
    ) -> Quaternion:
        """Solve relative orientation from FC attitude and measured 04/05 quaternion."""
        if gimbal.quaternion_wxyz is None:
            raise ValueError("gimbal sample does not contain a measured quaternion")
        fc_world = euler_deg_to_quaternion(fc_attitude_deg)
        return relative_quaternion(fc_world, gimbal.quaternion_wxyz)

    def orientation_error_deg(
        self,
        fc_attitude_deg: tuple[float, float, float],
        gimbal: GimbalParams,
    ) -> float:
        """Angular error between forward model and measured 04/05 quaternion."""
        if gimbal.quaternion_wxyz is None:
            raise ValueError("gimbal sample does not contain a measured quaternion")
        predicted = self.world_orientation(fc_attitude_deg, gimbal)
        return quaternion_angular_distance_deg(predicted, gimbal.quaternion_wxyz)


# Reference fit from controlled M4T captures on 2026-10-05.
# Blocked cross-validation selected:
#   q_relative = q_mount * Rz(yaw@08) * Rx(roll@16) * Ry(pitch@14)
# with a stable stream alignment near +30 ms.
#
# The rotation order and left-side mount model survived multiple independent
# motion runs. The numerical mount is intentionally a REFERENCE preset:
# it has not yet been proven identical across different M4T airframes.
M4T_REFERENCE_GIMBAL_KINEMATICS = GimbalKinematics.from_mount_euler(
    (1.71, -2.77, 0.33),
    joint_order=("yaw", "roll", "pitch"),
    mount_side="left",
    lag_ms=30,
)
