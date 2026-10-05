import unittest

from dji_duml import commands
from dji_duml.frame import AckType, Frame, address
from dji_duml.profiles import M4T
from dji_duml.sim import SimulatedM4T
from dji_duml.topology import Topology, addresses, from_frames, probe_versions, report


class PassiveTopologyTests(unittest.TestCase):
    def test_sender_is_confirmation_receiver_only_is_candidate(self):
        host = address(10, 1)
        fc = address(3, 0)
        gimbal = address(4, 0)
        topology = from_frames([
            Frame(fc, host, 1, 3, 0x43, b"x", ack=AckType.NONE),
            Frame(host, gimbal, 2, 4, 0x02, b""),
        ], host=host)
        self.assertEqual([node.address for node in topology.confirmed], [fc])
        self.assertEqual([node.address for node in topology.candidates], [gimbal])
        self.assertEqual(topology.nodes[fc].commands_sent[(3, 0x43)], 1)
        self.assertEqual(topology.nodes[gimbal].commands_received[(4, 0x02)], 1)

    def test_indexes_are_preserved(self):
        camera0 = address(1, 0)
        camera2 = address(1, 2)
        topology = from_frames([
            Frame(camera0, 0x2A, 1, 2, 0x80, ack=0),
            Frame(camera2, 0x2A, 2, 2, 0x80, ack=0),
        ], host=0x2A)
        self.assertEqual([(n.device_type, n.index) for n in topology.confirmed],
                         [(1, 0), (1, 2)])

    def test_json_shape_keeps_evidence(self):
        fc = address(3, 0)
        topology = from_frames([Frame(fc, 0x2A, 1, 3, 0x57, b"abc", ack=0)], host=0x2A)
        data = topology.as_dict()
        self.assertEqual(data["frames"], 1)
        self.assertEqual(data["confirmed"][0]["legacy_type_name"], "Flight Controller")
        self.assertEqual(data["confirmed"][0]["commands_sent"]["03/57"], 1)

    def test_explicit_address_space(self):
        self.assertEqual(addresses((1, 4), (0, 2)),
                         (address(1, 0), address(1, 2),
                          address(4, 0), address(4, 2)))

    def test_stream_fingerprint_rate_lengths_unique_and_seq(self):
        topology = Topology(host=0x2A)
        frame1 = Frame(0x03, 0x0A, 10, 3, 0x43, b"abc", ack=0)
        frame2 = Frame(0x03, 0x0A, 11, 3, 0x43, b"abd", ack=0)
        frame3 = Frame(0x03, 0x0A, 13, 3, 0x43, b"abd", ack=0)
        topology.observe(frame1, 1.0)
        topology.observe(frame2, 1.5)
        topology.observe(frame3, 2.0)
        stream = topology.streams_from(0x03)[0]
        self.assertEqual(stream.count, 3)
        self.assertEqual(stream.payload_min, 3)
        self.assertEqual(stream.payload_max, 3)
        self.assertEqual(stream.unique_payloads, 2)
        self.assertAlmostEqual(stream.rate_hz, 2.0)
        self.assertEqual(dict(stream.seq_steps), {"+1": 1, "other": 1})
        self.assertEqual(dict(stream.seq_deltas), {1: 1, 2: 1})
        self.assertEqual(stream.sample_payload, b"abc")
        self.assertEqual(stream.changed_offsets, {2})
        verbose = report(topology, verbose=True)
        self.assertIn("2.0 Hz", verbose)
        self.assertIn("unique=2", verbose)
        self.assertIn("ack[none:3]", verbose)
        self.assertIn("seq[+1:1/same:0/other:1]", verbose)
        self.assertIn("sample: 61 62 63", verbose)
        self.assertIn("changed: 0x02", verbose)
        self.assertIn("seq-delta[+1:1,+2:1]", verbose)

    def test_verbose_report_extracts_ascii_and_decodes_osd_prefix(self):
        payload = bytes.fromhex(
            "00 00 00 00 00 00 00 00"
            " 00 00 00 00 00 00 00 00"
            " 00 00 00 00 00 00 00 00"
            " fa ff 04 00 aa fc 86 00"
            " 00 70 80 00"
        ) + b"RTK_Mobile\x00"
        topology = Topology(host=0x2A)
        topology.observe(Frame(0x03, 0x0A, 1, 3, 0x43, payload, ack=0), 1.0)
        text = report(topology, verbose=True)
        self.assertIn("ascii: 'RTK_Mobile'", text)
        self.assertIn("decoded-prefix: h=0.0m", text)
        self.assertIn("att=(-0.6,0.4,-85.4)deg", text)
        self.assertIn("state=0x00807000", text)

    def test_verbose_report_decodes_gimbal_prefix_and_quaternion(self):
        payload = bytes.fromhex(
            "00 00 00 00 9b fc 82 00 00 00 00 01"
            " f4 c6 97 00 11 de 00 00 fb ff 0f 00"
            " 6c e4 39 3f 0c ae 81 35 6c b0 d9 b5 f4 02 30 bf"
            " 00 00 00 00 00 00 00 00 00"
        )
        topology = Topology(host=0x2A)
        topology.observe(Frame(0x04, 0x2A, 1, 4, 5, payload, ack=0), 1.0)
        text = report(topology, verbose=True)
        self.assertIn("decoded-prefix: att=(0.0,0.0,-86.9)deg", text)
        self.assertIn("|q|=1.000000", text)
        self.assertIn("opaque=21B", text)

    def test_report_distinguishes_confirmed_and_candidates(self):
        host = address(10, 1)
        fc = address(3, 0)
        gimbal = address(4, 1)
        topology = from_frames([
            Frame(fc, host, 1, 3, 0x43, ack=0),
            Frame(host, gimbal, 2, 4, 0x02),
        ], host=host, roles={fc: "Primary target"})
        text = report(topology)
        self.assertIn("+ 0x03  Primary target [type=3 legacy:Flight Controller] idx=0", text)
        self.assertIn("03/43 x1", text)
        self.assertIn("? 0x24  type=4 legacy:Gimbal idx=1", text)
        self.assertEqual(topology.as_dict()["confirmed"][0]["role"], "Primary target")


class ActiveTopologyTests(unittest.TestCase):
    def test_version_probe_confirms_real_target_only(self):
        drone = SimulatedM4T(M4T, "17.02.0501")
        topology = Topology(host=M4T.host)
        with drone.client() as client:
            probe_versions(client, topology, [M4T.target, address(4, 0)], timeout=0.01)
        self.assertTrue(topology.nodes[M4T.target].confirmed)
        self.assertEqual(str(topology.nodes[M4T.target].version.firmware), "17.02.0501")
        self.assertNotIn(address(4, 0), topology.nodes)
        sent = [f for f in drone.received if f.cmd_set == commands.GENERAL]
        self.assertTrue(sent)
        self.assertTrue(all(f.cmd_id == commands.VERSION_INQUIRY for f in sent))

    def test_reply_with_unknown_version_layout_still_confirms_address(self):
        target = address(4, 0)

        class Client:
            def request(self, receiver, cmd_set, cmd_id, **options):
                return Frame(receiver, 0x2A, 7, cmd_set, cmd_id, b"\x00", response=True)

        topology = Topology(host=0x2A)
        probe_versions(Client(), topology, [target])
        node = topology.nodes[target]
        self.assertTrue(node.confirmed)
        self.assertIsNone(node.version)
        self.assertIsNotNone(node.version_error)

    def test_host_is_never_probed(self):
        class Client:
            def request(self, *args, **kwargs):
                raise AssertionError("host must not be probed")

        topology = Topology(host=0x2A)
        probe_versions(Client(), topology, [0x2A])


if __name__ == "__main__":
    unittest.main()
