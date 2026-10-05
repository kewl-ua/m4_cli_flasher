import math
import unittest

from dji_duml.errors import UnexpectedReply
from dji_duml.frame import Frame
from dji_duml.telemetry import GimbalParams, decode_known, parse_gimbal_params


class GimbalParamsTests(unittest.TestCase):
    SAMPLE = bytes.fromhex(
        "00 00 00 00 9b fc 82 00 00 00 00 01"
        " f4 c6 97 00 11 de 00 00 fb ff 0f 00"
        " 6c e4 39 3f 0c ae 81 35 6c b0 d9 b5 f4 02 30 bf"
        " 00 00 00 00 00 00 00 00 00"
    )

    def test_m4t_legacy_prefix_and_quaternion(self):
        item = parse_gimbal_params(self.SAMPLE)
        self.assertIsInstance(item, GimbalParams)
        self.assertEqual(item.attitude_deg, (0.0, 0.0, -86.9))
        self.assertEqual(item.mode_flags, 0x82)
        self.assertEqual(item.roll_adjust, 0)
        self.assertEqual(item.yaw_angle_raw, 0)
        self.assertEqual(item.limit_flags, 0)
        self.assertEqual(item.version_flags, 1)
        self.assertEqual(item.middle, self.SAMPLE[12:24])
        self.assertEqual(item.tail, bytes(9))
        self.assertAlmostEqual(item.quaternion_norm, 1.0, places=5)
        q_pitch, q_roll, q_yaw = item.quaternion_euler_deg
        self.assertAlmostEqual(q_pitch, 25.8525, places=3)
        self.assertAlmostEqual(q_roll, -0.1105, places=3)
        self.assertAlmostEqual(q_yaw, -87.1146, places=3)
        self.assertAlmostEqual(q_pitch, item.attitude_deg[0], delta=0.1)
        self.assertAlmostEqual(q_roll, item.attitude_deg[1], delta=0.1)
        self.assertAlmostEqual(q_yaw, item.attitude_deg[2], delta=0.1)

    def test_quaternion_wz_matches_stationary_legacy_yaw(self):
        item = parse_gimbal_params(self.SAMPLE)
        w, x, y, z = item.quaternion_wxyz
        yaw = math.degrees(math.atan2(2 * (w * z + x * y),
                                     1 - 2 * (y * y + z * z)))
        self.assertAlmostEqual(yaw, item.attitude_deg[2], delta=0.2)

    def test_short_payload_keeps_unverified_extension_opaque(self):
        payload = self.SAMPLE[:12]
        item = parse_gimbal_params(payload)
        self.assertIsNone(item.quaternion_wxyz)
        self.assertEqual(item.middle, b"")
        self.assertEqual(item.tail, b"")

    def test_too_short_is_rejected(self):
        with self.assertRaises(UnexpectedReply):
            parse_gimbal_params(bytes(11))

    def test_generic_decoder_selects_gimbal_push(self):
        frame = Frame(0x04, 0x2A, 1, 0x04, 0x05, self.SAMPLE, ack=0)
        self.assertIsInstance(decode_known(frame), GimbalParams)


if __name__ == "__main__":
    unittest.main()
