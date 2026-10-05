import math
import struct
import unittest

from dji_duml import commands
from dji_duml.frame import AckType, Frame, address
from dji_duml.profiles import M4T
from dji_duml.sim import SimulatedM4T
from dji_duml.topology import Topology, addresses, from_frames, probe_versions, report
from dji_duml.telemetry import (
    euler_deg_to_quaternion,
    quaternion_axis_angle_deg,
    quaternion_multiply,
    quaternion_slerp,
    quaternion_to_euler_deg,
)


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

    def test_flyc_tail_diagnostics_find_raw_correlation(self):
        topology = Topology(host=0x2A)
        for seq, pitch_tenths in enumerate((-300, -100, 0, 200, 500), 1):
            payload = bytearray(84)
            struct.pack_into(
                "<ddhhhhhhhBBI",
                payload,
                0,
                0.0, 0.0,
                0, 0, 0, 0,
                pitch_tenths, 0, 0,
                0, 0, 0,
            )
            payload[0x28:0x2A] = int(pitch_tenths).to_bytes(
                2, "little", signed=True
            )
            payload[0x33] = 0x10 if seq % 2 else 0x00
            payload[0x35:0x37] = int(pitch_tenths).to_bytes(
                2, "little", signed=True
            )
            payload[0x37] = seq
            topology.observe(
                Frame(0x03, 0x0A, seq, 0x03, 0x43, bytes(payload), ack=0),
                seq * 0.5,
            )

        text = report(topology, verbose=True)
        self.assertIn("tail-changed:", text)
        self.assertIn("0x28-0x29", text)
        self.assertIn("@33=00..10", text)
        self.assertIn("mask10", text)
        self.assertIn("legacy-layout@24..36=", text)
        self.assertIn("m4t-extension@37..53=0x37", text)
        self.assertIn("unknown35?@35=", text)
        self.assertIn("i16@28->pitch=+1.000", text)
        self.assertIn("i16@35->pitch=+1.000", text)
        self.assertIn("tail-state@33:", text)
        self.assertNotIn("tail-state@36:", text)

    def test_flyc_tail_counter_candidate_estimates_frequency(self):
        topology = Topology(host=0x2A)
        value = 10
        for seq in range(1, 9):
            payload = bytearray(84)
            struct.pack_into(
                "<ddhhhhhhhBBI",
                payload,
                0,
                0.0, 0.0,
                0, 0, 0, 0,
                0, 0, 0,
                0, 0, 0,
            )
            payload[0x28] = value & 0xFF
            topology.observe(
                Frame(0x03, 0x0A, seq, 0x03, 0x43, bytes(payload), ack=0),
                seq * 0.5,
            )
            value += 25

        text = report(topology, verbose=True)
        self.assertIn("tail-counter-like:", text)
        self.assertIn("@28=50.00/s", text)

    def test_flyc_tail_body_rate_correlation_uses_quaternion_delta(self):
        topology = Topology(host=0x2A)
        rolls = (0, 100, 300, 600, 1000)
        omega_raw = (0, 20, 40, 60, 80)
        for seq, (roll_tenths, raw35) in enumerate(zip(rolls, omega_raw), 1):
            payload = bytearray(84)
            struct.pack_into(
                "<ddhhhhhhhBBI",
                payload,
                0,
                0.0, 0.0,
                0, 0, 0, 0,
                0, roll_tenths, 0,
                0, 0, 0,
            )
            payload[0x35:0x37] = int(raw35).to_bytes(
                2, "little", signed=True
            )
            topology.observe(
                Frame(0x03, 0x0A, seq, 0x03, 0x43, bytes(payload), ack=0),
                seq * 0.5,
            )

        text = report(topology, verbose=True)
        self.assertIn("tail-body-rate-corr:", text)
        self.assertIn("i16@35->omega_x=+1.000", text)
        self.assertIn("tail-body-rate-fit:", text)
        self.assertIn(
            "i16@35->omega_x lag=+0 corr=+1.000 "
            "scale=+1.00000 bias=+0.00 rmse=0.00",
            text,
        )
        self.assertIn("tail-motion:", text)
        self.assertIn("dominant=roll/x", text)
        self.assertIn("tail-unknown35-fit:", text)
        self.assertIn(
            "omega_x lag=+0 corr=+1.000 "
            "scale=+1.00000 bias=+0.00 rmse=0.00",
            text,
        )

    def test_unknown35_interval_fit_prefers_trapezoid_for_sampled_rate(self):
        topology = Topology(host=0x2A)
        raw_values = (0, 10, 20, 30, 40, 50)
        roll_tenths = (0, 25, 100, 225, 400, 625)
        for seq, (roll_raw, raw35) in enumerate(
            zip(roll_tenths, raw_values), 1
        ):
            payload = bytearray(84)
            struct.pack_into(
                "<ddhhhhhhhBBI",
                payload,
                0,
                0.0, 0.0,
                0, 0, 0, 0,
                0, roll_raw, 0,
                0, 0, 0,
            )
            payload[0x35:0x37] = int(raw35).to_bytes(
                2, "little", signed=True
            )
            topology.observe(
                Frame(0x03, 0x0A, seq, 0x03, 0x43, bytes(payload), ack=0),
                (seq - 1) * 0.5,
            )

        text = report(topology, verbose=True)
        self.assertIn("tail-unknown35-interval-fit:", text)
        self.assertIn(
            "omega_x mode=trapezoid corr=+1.000 "
            "scale=+1.00000 bias=+0.00 rmse=0.00",
            text,
        )

    def test_unknown35_fit_is_reported_below_global_threshold(self):
        topology = Topology(host=0x2A)
        rolls = (0, 80, 200, 360, 550, 750)
        raw35 = (0, 9, 5, 18, 10, 25)
        for seq, (roll_tenths, raw_value) in enumerate(zip(rolls, raw35), 1):
            payload = bytearray(84)
            struct.pack_into(
                "<ddhhhhhhhBBI",
                payload,
                0,
                0.0, 0.0,
                0, 0, 0, 0,
                0, roll_tenths, 0,
                0, 0, 0,
            )
            payload[0x35:0x37] = int(raw_value).to_bytes(
                2, "little", signed=True
            )
            topology.observe(
                Frame(0x03, 0x0A, seq, 0x03, 0x43, bytes(payload), ack=0),
                seq * 0.5,
            )

        text = report(topology, verbose=True)
        self.assertIn("tail-unknown35-fit:", text)
        self.assertIn("omega_x", text)

    def test_flyc_tail_acceleration_correlation(self):
        topology = Topology(host=0x2A)
        rows = (
            (0, 0),
            (10, 0),
            (40, 8),
            (100, 12),
            (200, 16),
        )
        for seq, (pitch_tenths, accel_raw) in enumerate(rows, 1):
            payload = bytearray(84)
            struct.pack_into(
                "<ddhhhhhhhBBI",
                payload,
                0,
                0.0, 0.0,
                0, 0, 0, 0,
                pitch_tenths, 0, 0,
                0, 0, 0,
            )
            payload[0x35:0x37] = int(accel_raw).to_bytes(
                2, "little", signed=True
            )
            topology.observe(
                Frame(0x03, 0x0A, seq, 0x03, 0x43, bytes(payload), ack=0),
                seq * 0.5,
            )

        text = report(topology, verbose=True)
        self.assertIn("tail-accel-corr:", text)
        self.assertIn("i16@35->pitch_accel=+1.000", text)

    def test_flyc_tail_rate_correlation_finds_odd_offset_word(self):
        topology = Topology(host=0x2A)
        rows = (
            (0, 0),
            (10, 20),
            (30, 40),
            (60, 60),
            (100, 80),
        )
        for seq, (pitch_tenths, rate_raw) in enumerate(rows, 1):
            payload = bytearray(84)
            struct.pack_into(
                "<ddhhhhhhhBBI",
                payload,
                0,
                0.0, 0.0,
                0, 0, 0, 0,
                pitch_tenths, 0, 0,
                0, 0, 0,
            )
            payload[0x35:0x37] = int(rate_raw).to_bytes(
                2, "little", signed=True
            )
            topology.observe(
                Frame(0x03, 0x0A, seq, 0x03, 0x43, bytes(payload), ack=0),
                seq * 0.5,
            )

        text = report(topology, verbose=True)
        self.assertIn("tail-rate-corr:", text)
        self.assertIn("i16@35->pitch_rate=+1.000", text)

    def test_gimbal_window_stats_cover_controlled_motion(self):
        stationary = bytes.fromhex(
            "00 00 00 00 9b fc 82 00 00 00 00 01"
            " f4 c6 97 00 11 de 00 00 fb ff 0f 00"
            " 6c e4 39 3f 0c ae 81 35 6c b0 d9 b5 f4 02 30 bf"
            " 00 00 00 00 00 00 00 00 00"
        )
        yaw = bytes.fromhex(
            "05 00 1c 00 bd fd 82 00 12 01 00 01"
            " 69 79 9e 00 13 de 00 00 04 00 fb ff"
            " 37 ed 5f 3f a7 d1 bf 3c 3c 25 02 bc 15 d0 f7 be"
            " 00 00 00 00 00 00 00 00 00"
        )
        topology = Topology(host=0x2A)
        topology.observe(Frame(0x04, 0x2A, 1, 4, 5, stationary, ack=0), 1.0)
        topology.observe(Frame(0x04, 0x2A, 44, 4, 5, yaw, ack=0), 1.1)
        text = report(topology, verbose=True)
        self.assertIn(
            "window-att: pitch=0.0..0.5  roll=0.0..2.8  yaw=-86.9..-57.9 deg",
            text,
        )
        self.assertIn("q-check: |q|=", text)
        self.assertIn("clock@0C:", text)
        self.assertIn("u32@0C=9946868..10385769", text)
        self.assertIn("i16@10=-8687..-8685", text)
        self.assertIn("i16@12=0..0", text)
        self.assertIn("i16@14=-5..4", text)
        self.assertIn("i16@16=-5..15", text)

    def test_gimbal_angle_correlation_finds_pitch_encoder(self):
        topology = Topology(host=0x2A)
        for seq, pitch_tenths in enumerate((-300, -100, 0, 200, 500), 1):
            payload = bytearray(24)
            payload[0:2] = int(pitch_tenths).to_bytes(2, "little", signed=True)
            payload[20:22] = int(pitch_tenths - 5).to_bytes(2, "little", signed=True)
            topology.observe(Frame(0x04, 0x2A, seq, 4, 5, bytes(payload), ack=0),
                             seq * 0.1)
        text = report(topology, verbose=True)
        self.assertIn("angle-corr:", text)
        self.assertIn("i16@14/10[pitch=+1.000", text)

    def test_gimbal_rate_correlation_uses_device_timestamp(self):
        topology = Topology(host=0x2A)
        # Pitch positions 0, 1, 3, 6 deg at 100 ms steps produce
        # pitch rates 10, 20, 30 deg/s. Mirror those in opaque i16@14.
        for seq, (stamp, pitch_tenths, raw14) in enumerate(
            ((0, 0, 0), (100, 10, 10), (200, 30, 20), (300, 60, 30)), 1
        ):
            payload = bytearray(24)
            payload[0:2] = int(pitch_tenths).to_bytes(2, "little", signed=True)
            payload[12:16] = int(stamp).to_bytes(4, "little")
            payload[20:22] = int(raw14).to_bytes(2, "little", signed=True)
            topology.observe(Frame(0x04, 0x2A, seq, 4, 5, bytes(payload), ack=0),
                             seq * 0.2)
        text = report(topology, verbose=True)
        self.assertIn("rate-corr:", text)
        self.assertIn("i16@14[pitch=+1.000", text)

    def test_cross_attitude_recovers_mount_and_joint_order(self):
        topology = Topology(host=0x2A)

        def fc_payload(attitude_deg):
            pitch, roll, yaw = (round(value * 10) for value in attitude_deg)
            return struct.pack(
                "<ddhhhhhhhBBI",
                0.0, 0.0,
                0, 0, 0, 0,
                pitch, roll, yaw,
                0, 0, 0,
            )

        def joint_q(pitch, roll, yaw):
            q = (1.0, 0.0, 0.0, 0.0)
            for axis, value in (("z", yaw), ("x", roll), ("y", pitch)):
                q = quaternion_multiply(q, quaternion_axis_angle_deg(axis, value))
            return q

        def gimbal_payload(stamp, world_q, joints):
            world_deg = quaternion_to_euler_deg(world_q)
            pitch, roll, yaw = (round(value * 10) for value in world_deg)
            rel_pitch, rel_roll, rel_yaw = (round(value * 10) for value in joints)
            prefix = struct.pack(
                "<hhhBbHBBIhhhh",
                pitch, roll, yaw,
                0x82, 0,
                rel_yaw & 0xFFFF,
                0, 1,
                stamp,
                0, 0, rel_pitch, rel_roll,
            )
            return prefix + struct.pack("<4f", *world_q) + bytes(9)

        mount_q = euler_deg_to_quaternion((2.0, -3.0, 5.0))
        body_samples = []
        for index in range(26):
            body_deg = (
                18.0 * math.sin(index * 0.31),
                22.0 * math.sin(index * 0.23 + 0.4),
                -70.0 + index * 3.0,
            )
            body_q = euler_deg_to_quaternion(body_deg)
            body_samples.append((body_deg, body_q))
            topology.observe(
                Frame(0x03, 0x0A, index + 1, 0x03, 0x43,
                      fc_payload(body_deg), ack=0),
                index * 0.5,
            )

        for index in range(25):
            body_mid = quaternion_slerp(
                body_samples[index][1],
                body_samples[index + 1][1],
                0.5,
            )
            joints = (
                20.0 * math.sin(index * 0.41),
                15.0 * math.sin(index * 0.37 + 0.7),
                25.0 * math.sin(index * 0.29 + 1.1),
            )
            world_q = quaternion_multiply(
                body_mid,
                quaternion_multiply(mount_q, joint_q(*joints)),
            )
            topology.observe(
                Frame(
                    0x04, 0x2A, index + 1, 0x04, 0x05,
                    gimbal_payload((index + 1) * 250, world_q, joints),
                    ack=0,
                ),
                index * 0.5 + 0.25,
            )

        text = report(topology, verbose=True)
        self.assertIn("cross-attitude: samples=", text)
        self.assertIn("best-lag=", text)
        self.assertIn("joint-kinematics:", text)
        self.assertIn("mount-fit:", text)
        self.assertIn("left:yaw*roll*pitch=", text)
        self.assertIn("best-mount: side=left order=yaw*roll*pitch", text)


    def test_cross_attitude_skips_insufficient_excitation(self):
        topology = Topology(host=0x2A)
        fc_payload = struct.pack(
            "<ddhhhhhhhBBI",
            0.0, 0.0,
            0, 0, 0, 0,
            10, 20, -800,
            0, 0, 0,
        )
        gimbal_payload = (
            struct.pack(
                "<hhhBbHBBIhhhh",
                0, 0, -800,
                0x82, 0,
                0,
                0, 1,
                1000,
                0, 0, 0, 0,
            )
            + struct.pack("<4f", *euler_deg_to_quaternion((0.0, 0.0, -80.0)))
            + bytes(9)
        )
        for seq in range(1, 6):
            topology.observe(
                Frame(0x03, 0x0A, seq, 0x03, 0x43, fc_payload, ack=0),
                seq * 0.5,
            )
            topology.observe(
                Frame(0x04, 0x2A, seq, 0x04, 0x05, gimbal_payload, ack=0),
                seq * 0.5 + 0.1,
            )

        text = report(topology, verbose=True)
        self.assertIn("cross-attitude: skipped kinematic fit", text)
        self.assertIn("insufficient excitation", text)
        self.assertNotIn("best-mount:", text)

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
