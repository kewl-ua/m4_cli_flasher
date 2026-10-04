import unittest

from dji_duml.crc import crc8, crc16
from dji_duml.frame import MAX_PAYLOAD, AckType, Frame, FrameError, StreamParser, address
from dji_duml.version import FirmwareVersion

# Byte-exact packets from public tools: two produced by dji-firmware-tools
# comm_mkdupc.py, two hard-coded in pyduml.
REFERENCE = [bytes.fromhex(text) for text in (
    "550d04330a0100ff4002b5ac3b",
    "550d04332a1f1027400001c24a",
    "551604fc2a28655740000700000000000000000027d3",
    "550e04662a28685740000c008820",
)]


class CodecTests(unittest.TestCase):
    def test_fast_crc16_agrees_with_the_table_reference(self):
        import random
        from dji_duml.crc import crc16_reference
        generator = random.Random(2026)
        for length in [*range(40), 985, 998, 1023, 4096]:
            for seed in (0x3692, 0x0000, 0xFFFF, generator.randrange(0x10000)):
                data = generator.randbytes(length)
                with self.subTest(length=length, seed=seed):
                    self.assertEqual(crc16(data, seed), crc16_reference(data, seed))

    def test_reference_packets_decode_and_reencode_byte_exact(self):
        for raw in REFERENCE:
            with self.subTest(raw=raw.hex()):
                self.assertEqual(crc8(raw[:3]), raw[3])
                self.assertEqual(crc16(raw[:-2]), int.from_bytes(raw[-2:], "little"))
                self.assertEqual(Frame.decode(raw).encode(), raw)

    def test_m4t_version_request_matches_public_builder(self):
        frame = Frame(address(10, 1), 0x1F, 0x2710, 0, 1)
        self.assertEqual(frame.encode(), REFERENCE[1])
        self.assertEqual((frame.cmd_type, frame.ack), (0x40, AckType.AFTER_EXEC))

    def test_every_field_survives_a_round_trip(self):
        frame = Frame(0xE3, 0x1F, 0xFFFF, 0x0D, 0xFE, bytes(range(200)), response=True,
                      ack=AckType.BEFORE_EXEC, encrypt=5, reserved=2)
        self.assertEqual(Frame.decode(frame.encode()), frame)

    def test_corruption_is_rejected(self):
        raw = bytearray(REFERENCE[2])
        for index in (0, 1, 3, 5, 12, len(raw) - 1):
            damaged = bytearray(raw)
            damaged[index] ^= 0x01
            with self.subTest(index=index), self.assertRaises(FrameError):
                Frame.decode(bytes(damaged))
        with self.assertRaises(FrameError):
            Frame.decode(bytes(raw[:-1]))

    def test_invalid_fields_and_oversize_payload_are_refused(self):
        with self.assertRaises(FrameError):
            Frame(0x2A, 0x1F, 0x10000, 0, 1)
        with self.assertRaises(FrameError):
            Frame(0x2A, 0x1F, 0, 0, 1, bytes(MAX_PAYLOAD + 1))
        self.assertEqual(len(Frame(0x2A, 0x1F, 0, 0, 1, bytes(MAX_PAYLOAD)).encode()), 0x3FF)

    def test_reply_matching_requires_same_command_and_reversed_addresses(self):
        request = Frame(0x2A, 0x1F, 7, 0, 1)
        reply = request.make_reply(b"\x00")
        self.assertTrue(reply.answers(request))
        for other in (Frame(0x1F, 0x2A, 8, 0, 1, response=True),
                      Frame(0x1F, 0x2A, 7, 0, 2, response=True),
                      Frame(0x28, 0x2A, 7, 0, 1, response=True),
                      Frame(0x1F, 0x2A, 7, 0, 1)):
            self.assertFalse(other.answers(request))


class StreamParserTests(unittest.TestCase):
    def test_frames_survive_any_fragmentation_and_noise(self):
        blob = b"\x00\x55\x55" + b"\x13".join(REFERENCE) + b"\x55\x0d"
        for step in (1, 2, 3, 7, 64, len(blob)):
            parser = StreamParser()
            frames = []
            for offset in range(0, len(blob), step):
                frames += parser.feed(blob[offset:offset + step])
            with self.subTest(step=step):
                self.assertEqual([frame.encode() for frame in frames], REFERENCE)
                self.assertEqual(parser.discarded, 6)
                self.assertEqual(parser.pending, 2)

    def test_damaged_frame_does_not_hide_the_next_one(self):
        damaged = bytearray(REFERENCE[2])
        damaged[-1] ^= 0xFF
        parser = StreamParser()
        frames = parser.feed(bytes(damaged) + REFERENCE[3])
        self.assertEqual([frame.encode() for frame in frames], [REFERENCE[3]])
        self.assertEqual(parser.discarded, len(damaged))

    def test_other_protocol_versions_are_not_decoded(self):
        other = Frame(0x2A, 0x1F, 1, 0, 1, version=2).encode()
        parser = StreamParser()
        self.assertEqual(parser.feed(other + REFERENCE[0]), [Frame.decode(REFERENCE[0])])


class VersionTests(unittest.TestCase):
    def test_wire_bytes_observed_on_m4t(self):
        version = FirmwareVersion.from_wire(bytes.fromhex("f5010211"))
        self.assertEqual(str(version), "17.02.0501")
        self.assertEqual(version.to_wire().hex(), "f5010211")

    def test_three_and_four_part_spellings_are_equal(self):
        self.assertEqual(FirmwareVersion.parse("17.02.05.01"), FirmwareVersion.parse("V17.02.0501"))
        self.assertEqual(FirmwareVersion.parse("17.2.501"), FirmwareVersion.parse("17.02.0501"))
        self.assertLess(FirmwareVersion.parse("17.00.0001"), FirmwareVersion.parse("17.01.0516"))

    def test_invalid_versions(self):
        for text in ("17.02", "17.02.x", "17.02.5.1", "300.1.1", "1.1.70000", ""):
            with self.subTest(text=text), self.assertRaises(ValueError):
                FirmwareVersion.parse(text)


if __name__ == "__main__":
    unittest.main()
