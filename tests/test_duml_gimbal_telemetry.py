import math
import unittest

from dji_duml.errors import UnexpectedReply
from dji_duml.frame import Frame
from dji_duml.telemetry import (
    GimbalParams,
    decode_known,
    euler_deg_to_quaternion,
    parse_gimbal_params,
    quaternion_multiply,
    quaternion_to_euler_deg,
    relative_quaternion,
)


class GimbalParamsTests(unittest.TestCase):
    # Real M4T samples from controlled captures, 2026-10-05.
    STATIONARY = bytes.fromhex(
        "00 00 00 00 9b fc 82 00 00 00 00 01"
        " f4 c6 97 00 11 de 00 00 fb ff 0f 00"
        " 6c e4 39 3f 0c ae 81 35 6c b0 d9 b5 f4 02 30 bf"
        " 00 00 00 00 00 00 00 00 00"
    )
    PITCH_ONLY = bytes.fromhex(
        "03 01 ff ff 99 fc 82 00 f7 ff 00 01"
        " 20 c9 9b 00 13 de 00 00 fc 00 18 00"
        " 2f db 34 3f ae 25 1d 3e b5 a9 26 3e e0 e4 2b bf"
        " 00 00 00 00 00 00 00 00 00"
    )
    YAW_ONLY = bytes.fromhex(
        "05 00 1c 00 bd fd 82 00 12 01 00 01"
        " 69 79 9e 00 13 de 00 00 04 00 fb ff"
        " 37 ed 5f 3f a7 d1 bf 3c 3c 25 02 bc 15 d0 f7 be"
        " 00 00 00 00 00 00 00 00 00"
    )

    def test_m4t_legacy_prefix_and_quaternion(self):
        item = parse_gimbal_params(self.STATIONARY)
        self.assertIsInstance(item, GimbalParams)
        self.assertEqual(item.attitude_deg, (0.0, 0.0, -86.9))
        self.assertEqual(item.mode_flags, 0x82)
        self.assertEqual(item.roll_adjust, 0)
        self.assertEqual(item.yaw_angle_raw, 0)
        self.assertEqual(item.limit_flags, 0)
        self.assertEqual(item.version_flags, 1)
        self.assertEqual(item.middle, self.STATIONARY[12:24])
        self.assertEqual(item.timestamp_ms, int.from_bytes(self.STATIONARY[12:16], "little"))
        self.assertEqual(item.tail, bytes(9))
        self.assertAlmostEqual(item.quaternion_norm, 1.0, places=5)
        q_pitch, q_roll, q_yaw = item.quaternion_euler_deg
        self.assertAlmostEqual(q_pitch, 0.0, delta=0.001)
        self.assertAlmostEqual(q_roll, 0.0, delta=0.001)
        self.assertAlmostEqual(q_yaw, -86.8722, places=3)
        self.assertAlmostEqual(q_yaw, item.attitude_deg[2], delta=0.1)
        self.assertLess(item.quaternion_orientation_error_deg, 0.1)

    def test_pitch_only_capture_matches_quaternion_euler(self):
        item = parse_gimbal_params(self.PITCH_ONLY)
        self.assertEqual(item.attitude_deg, (25.9, -0.1, -87.1))
        q_pitch, q_roll, q_yaw = item.quaternion_euler_deg
        self.assertAlmostEqual(q_pitch, 25.8525, places=3)
        self.assertAlmostEqual(q_roll, -0.1105, places=3)
        self.assertAlmostEqual(q_yaw, -87.1146, places=3)
        for legacy, quat in zip(item.attitude_deg, item.quaternion_euler_deg):
            self.assertAlmostEqual(legacy, quat, delta=0.1)
        self.assertLess(item.quaternion_orientation_error_deg, 0.1)
        self.assertAlmostEqual(item.yaw_reference_deg, -86.85, places=2)
        self.assertAlmostEqual(item.pitch_joint_deg, 25.2, places=1)

    def test_yaw_only_capture_matches_quaternion_euler(self):
        item = parse_gimbal_params(self.YAW_ONLY)
        self.assertEqual(item.attitude_deg, (0.5, 2.8, -57.9))
        q_pitch, q_roll, q_yaw = item.quaternion_euler_deg
        self.assertAlmostEqual(q_pitch, 0.50, delta=0.02)
        self.assertAlmostEqual(q_roll, 2.79, delta=0.02)
        self.assertAlmostEqual(q_yaw, -57.90, delta=0.02)
        for legacy, quat in zip(item.attitude_deg, item.quaternion_euler_deg):
            self.assertAlmostEqual(legacy, quat, delta=0.1)
        self.assertLess(item.quaternion_orientation_error_deg, 0.1)
        self.assertAlmostEqual(item.relative_yaw_deg, 27.4, places=1)
        self.assertAlmostEqual(item.yaw_reference_deg, -86.85, places=2)

    def test_quaternion_frame_composition_recovers_relative_orientation(self):
        body = (35.0, -20.0, -60.0)
        relative = (-8.0, 6.0, 15.0)
        body_q = euler_deg_to_quaternion(body)
        relative_q = euler_deg_to_quaternion(relative)
        world_q = quaternion_multiply(body_q, relative_q)
        solved_q = relative_quaternion(body_q, world_q)
        solved = quaternion_to_euler_deg(solved_q)
        for expected, actual in zip(relative, solved):
            self.assertAlmostEqual(expected, actual, places=6)

    def test_quaternion_wz_matches_stationary_legacy_yaw(self):
        item = parse_gimbal_params(self.STATIONARY)
        w, x, y, z = item.quaternion_wxyz
        yaw = math.degrees(math.atan2(2 * (w * z + x * y),
                                     1 - 2 * (y * y + z * z)))
        self.assertAlmostEqual(yaw, item.attitude_deg[2], delta=0.1)

    def test_short_payload_keeps_unverified_extension_opaque(self):
        payload = self.STATIONARY[:12]
        item = parse_gimbal_params(payload)
        self.assertIsNone(item.timestamp_ms)
        self.assertIsNone(item.quaternion_wxyz)
        self.assertEqual(item.middle, b"")
        self.assertEqual(item.tail, b"")

    def test_too_short_is_rejected(self):
        with self.assertRaises(UnexpectedReply):
            parse_gimbal_params(bytes(11))

    def test_generic_decoder_selects_gimbal_push(self):
        frame = Frame(0x04, 0x2A, 1, 0x04, 0x05, self.STATIONARY, ack=0)
        self.assertIsInstance(decode_known(frame), GimbalParams)


if __name__ == "__main__":
    unittest.main()
