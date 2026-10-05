import struct
import unittest
from dataclasses import replace

from dji_duml.kinematics import GimbalKinematics, M4T_REFERENCE_GIMBAL_KINEMATICS
from dji_duml.telemetry import (
    euler_deg_to_quaternion,
    parse_gimbal_params,
    quaternion_angular_distance_deg,
    quaternion_axis_angle_deg,
    quaternion_multiply,
)


class GimbalKinematicsTests(unittest.TestCase):
    @staticmethod
    def sample(*, pitch=20.0, roll=-5.0, yaw=10.0):
        pitch_raw = round(pitch * 10)
        roll_raw = round(roll * 10)
        yaw_raw = round(yaw * 10) & 0xFFFF
        prefix = struct.pack(
            "<hhhBbHBBIhhhh",
            0, 0, 0,
            0x82, 0,
            yaw_raw,
            0, 1,
            1234,
            0, 0, pitch_raw, roll_raw,
        )
        return parse_gimbal_params(prefix + struct.pack("<4f", 1.0, 0.0, 0.0, 0.0) + bytes(9))

    def test_joint_chain_is_yaw_roll_pitch(self):
        item = self.sample()
        kin = GimbalKinematics()
        actual = kin.joint_quaternion(item)
        expected = (1.0, 0.0, 0.0, 0.0)
        for axis, angle in (("z", 10.0), ("x", -5.0), ("y", 20.0)):
            expected = quaternion_multiply(expected, quaternion_axis_angle_deg(axis, angle))
        self.assertLess(quaternion_angular_distance_deg(actual, expected), 1e-6)

    def test_left_mount_precedes_joint_chain(self):
        item = self.sample()
        mount = euler_deg_to_quaternion((2.0, -3.0, 5.0))
        kin = GimbalKinematics(mount_quaternion=mount, mount_side="left")
        expected = quaternion_multiply(mount, kin.joint_quaternion(item))
        self.assertLess(
            quaternion_angular_distance_deg(kin.relative_orientation(item), expected),
            1e-6,
        )

    def test_inverse_solver_recovers_joint_angles(self):
        item = self.sample(pitch=22.0, roll=-11.0, yaw=37.0)
        kin = GimbalKinematics.from_mount_euler((1.5, -2.5, 0.25))
        solved = kin.solve_joint_angles_deg(kin.relative_orientation(item))
        expected = (item.pitch_joint_deg, item.roll_joint_deg, item.relative_yaw_deg)
        for actual, wanted in zip(solved, expected):
            self.assertAlmostEqual(actual, wanted, places=6)

    def test_forward_world_orientation_matches_measured_quaternion(self):
        item = self.sample(pitch=-15.0, roll=8.0, yaw=25.0)
        kin = GimbalKinematics.from_mount_euler((1.5, -2.5, 0.25))
        fc = (12.0, -7.0, -80.0)
        measured = kin.world_orientation(fc, item)
        item = replace(item, quaternion_wxyz=measured)
        self.assertLess(kin.orientation_error_deg(fc, item), 1e-5)

    def test_measured_joint_solver_matches_packet_fields(self):
        item = self.sample(pitch=-18.0, roll=7.0, yaw=-31.0)
        kin = GimbalKinematics.from_mount_euler((1.5, -2.5, 0.25))
        fc = (14.0, 9.0, -75.0)
        measured = kin.world_orientation(fc, item)
        item = replace(item, quaternion_wxyz=measured)
        solved = kin.measured_joint_angles_deg(fc, item)
        expected = (item.pitch_joint_deg, item.roll_joint_deg, item.relative_yaw_deg)
        for actual, wanted in zip(solved, expected):
            self.assertAlmostEqual(actual, wanted, places=6)

    def test_m4t_reference_preset_metadata(self):
        kin = M4T_REFERENCE_GIMBAL_KINEMATICS
        self.assertEqual(kin.joint_order, ("yaw", "roll", "pitch"))
        self.assertEqual(kin.mount_side, "left")
        self.assertEqual(kin.lag_ms, 30)
        for actual, expected in zip(kin.mount_euler_deg, (1.71, -2.77, 0.33)):
            self.assertAlmostEqual(actual, expected, places=6)

    def test_rejects_invalid_order_and_side(self):
        with self.assertRaises(ValueError):
            GimbalKinematics(joint_order=("yaw", "yaw", "pitch"))
        with self.assertRaises(ValueError):
            GimbalKinematics(mount_side="middle")


if __name__ == "__main__":
    unittest.main()
