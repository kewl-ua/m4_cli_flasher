import unittest

from dji_duml.errors import UnexpectedReply
from dji_duml.frame import Frame
from dji_duml.telemetry import FlycOsdGeneral, decode_known, parse_flyc_osd_general


class FlycOsdGeneralTests(unittest.TestCase):
    SAMPLE = bytes.fromhex(
        "00 00 00 00 00 00 00 00"
        " 00 00 00 00 00 00 00 00"
        " 00 00 00 00 00 00 00 00"
        " fa ff 04 00 aa fc 86 00"
        " 00 70 80 00"
        " e5 00 00 00 00 8f 8a 20"
    )

    def test_m4t_prefix_decodes_legacy_kinematics_without_guessing_tail(self):
        item = parse_flyc_osd_general(self.SAMPLE)
        self.assertIsInstance(item, FlycOsdGeneral)
        self.assertEqual(item.relative_height_m, 0.0)
        self.assertEqual(item.velocity_mps, (0.0, 0.0, 0.0))
        self.assertEqual(item.attitude_deg, (-0.6, 0.4, -85.4))
        self.assertEqual(item.ctrl_info, 0x86)
        self.assertEqual(item.latest_cmd, 0)
        self.assertEqual(item.controller_state, 0x00807000)
        self.assertEqual(item.tail, self.SAMPLE[36:])

    def test_longer_m4t_payload_is_preserved_not_interpreted(self):
        payload = self.SAMPLE[:36] + bytes(range(48))
        item = parse_flyc_osd_general(payload)
        self.assertEqual(len(payload), 84)
        self.assertEqual(item.tail, bytes(range(48)))

    def test_short_payload_is_rejected(self):
        with self.assertRaises(UnexpectedReply):
            parse_flyc_osd_general(bytes(35))

    def test_generic_decoder_selects_known_pushes_only(self):
        frame = Frame(0x03, 0x0A, 1, 0x03, 0x43, self.SAMPLE, ack=0)
        self.assertIsInstance(decode_known(frame), FlycOsdGeneral)
        self.assertIsNone(decode_known(Frame(0x04, 0x2A, 1, 0x04, 0x06, b"", ack=0)))
        self.assertIsNone(decode_known(
            Frame(0x03, 0x0A, 1, 0x03, 0x43, self.SAMPLE, response=True)
        ))


if __name__ == "__main__":
    unittest.main()
