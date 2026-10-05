"""manifest and params: reads Assistant does on connect, from the drone or a capture.

With DJI_DUML_IDLE_CAPTURE set to a capture of Assistant connecting to an M4T
(idle.pcap, 2026-10-04), both are also checked against it.
"""
import contextlib
import io
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dji_duml import commands, installed, params, pcap
from dji_duml.cli import main
from dji_duml.errors import CommandRejected, UnexpectedReply
from dji_duml.frame import Frame, StreamParser
from dji_duml.package import inspect_package
from dji_duml.profiles import M4T
from dji_duml.sim import SimulatedM4T
from duml_fixtures import CURRENT, TARGET, make_tar, manifest, usbpcap_file, usbpcap_record

IDLE = os.environ.get("DJI_DUML_IDLE_CAPTURE")
CENTER = M4T.upgrade_center


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def capture(path, pairs):
    """A USBPcap file of (request, reply) frames, host on 0x04, drone on 0x85."""
    records = []
    for request, reply in pairs:
        records.append(usbpcap_record(0x04, request.encode(), False))
        if reply is not None:
            records.append(usbpcap_record(0x85, reply.encode(), True))
    return usbpcap_file(path, records)


def config_reads(config, seq, stop=None):
    """The 00/4F type 01 exchange that reads ``config``, as the M4T answers it."""
    pairs = []
    for offset in range(0, len(config), 256):
        if stop is not None and offset >= stop:
            break
        chunk = config[offset:offset + 256]
        left = len(config) - offset - len(chunk)
        request = Frame(0x2A, CENTER, seq, 0, commands.UPGRADE_RESULT,
                        installed.config_request(offset))
        pairs.append((request, request.make_reply(
            b"\x00" + struct.pack("<II", len(chunk), left) + chunk)))
        seq += 1
    return pairs


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.tmp = Path(self.directory.name)
        self.config = manifest(TARGET)

    def test_request_and_reply_layout_as_captured(self):
        self.assertEqual(installed.config_request(256).hex(), "0100010000e8030000")
        reply = bytes.fromhex("000001000020630000") + b"IM*H" + bytes(252)
        chunk, left = installed.parse_config_chunk(reply)
        self.assertEqual((len(chunk), left), (256, 25376))
        with self.assertRaises(UnexpectedReply):
            installed.parse_config_chunk(reply[:-1])

    def test_read_from_the_simulator(self):
        drone = SimulatedM4T(M4T, TARGET, installed_config=self.config)
        with drone.client() as client:
            data = installed.read_config(client, CENTER)
        self.assertEqual(data, self.config)
        config = installed.describe(data, "wa345t")
        self.assertEqual(str(config.version), TARGET)
        self.assertEqual(len(config.modules), 1)
        requests = [frame for frame in drone.received if frame.receiver == CENTER]
        self.assertEqual({frame.cmd_id for frame in requests}, {commands.UPGRADE_RESULT})
        self.assertEqual(len(requests), -(-len(self.config) // 256))

    def test_a_size_that_changes_while_read_is_refused(self):
        class Shifting:
            sizes = iter([1000, 900])

            def request(self, *args, **options):
                size = next(self.sizes)
                return Frame(CENTER, 0x2A, 0, 0, 0x4F, b"\x00" + struct.pack("<II", 256, size - 256)
                             + bytes(256), response=True)

        with self.assertRaisesRegex(UnexpectedReply, "size changed"):
            installed.read_config(Shifting(), CENTER)

    def test_capture_gives_the_last_complete_read_never_a_splice(self):
        old = manifest(CURRENT)
        path = capture(self.tmp / "two.pcap", config_reads(old, 100)
                       + config_reads(self.config, 200)
                       + config_reads(old, 300, stop=512))  # cut short
        frames = [entry.frame for entry in pcap.iter_frames(path)]
        self.assertEqual(installed.config_from_frames(frames, CENTER), self.config)
        self.assertIsNone(installed.config_from_frames(frames[:3], CENTER))

    def test_compare_with_a_package(self):
        package = inspect_package(make_tar(self.directory.name, content=self.config))
        same = installed.describe(self.config, "wa345t")
        self.assertEqual(installed.compare(same, package), [])
        other = installed.describe(manifest(CURRENT), "wa345t")
        differences = installed.compare(other, package)
        self.assertIn(f"version: package {TARGET}, drone {CURRENT}", differences)

    def test_cli(self):
        package = make_tar(self.directory.name, content=self.config)
        saved = self.tmp / "drone.cfg.sig"
        with patch("dji_duml.sim._config_for", return_value=self.config):
            code, out, _ = run("--simulate", TARGET, "manifest", "-o", str(saved),
                               "--compare", str(package))
            self.assertEqual(code, 0, out)
            self.assertIn(f"version   {TARGET}", out)
            self.assertIn("runs exactly", out)
            self.assertEqual(saved.read_bytes(), self.config)
            code, _, err = run("--simulate", TARGET, "manifest", "-o", str(saved))
            self.assertEqual(code, 1)  # never overwrites
        code, out, _ = run("--simulate", CURRENT, "manifest", "--compare", str(package))
        self.assertEqual(code, 2)
        self.assertIn("does NOT run", out)
        path = capture(self.tmp / "c.pcap", config_reads(self.config, 10))
        code, out, _ = run("manifest", "--capture", str(path), "--json")
        self.assertEqual((code, json.loads(out)["version"]), (0, TARGET))
        cut = capture(self.tmp / "cut.pcap", config_reads(self.config, 10, stop=256))
        code, _, err = run("manifest", "--capture", str(cut))
        self.assertEqual(code, 2)
        self.assertIn("No complete read", err)


class ParamsTests(unittest.TestCase):
    # Replies as idle.pcap has them.
    TABLE = "0000000086b5b5dd1b060000"
    ITEM_U8 = "0000000009000000010000000000000000001200000073776565705f746573745f666c616700"
    ITEM_F32 = ("000000000c0008000400000034430000000000007a447377656570"
                "5f746f74616c5f745f415f5f505242535f706572696f6400")
    VALUE_F32 = "000000000c0000003443"

    def test_layouts_as_captured(self):
        self.assertEqual(params.parse_table(bytes.fromhex(self.TABLE)),
                         params.Table(0, 0xDDB5B586, 1563))
        item = params.parse_item(bytes.fromhex(self.ITEM_U8))
        self.assertEqual((item.index, item.type_name, item.maximum, item.name),
                         (9, "u8", 18, "sweep_test_flag"))
        item = params.parse_item(bytes.fromhex(self.ITEM_F32))
        self.assertEqual((item.default, item.minimum, item.maximum), (180.0, 0.0, 1000.0))
        self.assertIsNone(params.parse_item(bytes.fromhex("0e00")))
        self.assertEqual(params.parse_value(bytes.fromhex(self.VALUE_F32)),
                         (0, 12, bytes.fromhex("00003443")))
        self.assertEqual(params.value_request(0, 9).hex(), "000001000900")

    def test_read_sends_only_the_three_reads(self):
        drone = SimulatedM4T(M4T, CURRENT)
        with drone.client() as client:
            info, items = params.read(client)
        self.assertEqual((info.count, len(items)), (7, 4))
        sent = {frame.cmd_id for frame in drone.received if frame.cmd_set == commands.FLYC}
        self.assertEqual(sent, set(params.READS))
        changed = [item.name for item in items if item.changed]
        self.assertEqual(changed, ["basic_gain_roll_usr"])
        self.assertEqual([item.value for item in items], [0, 180.0, 120, 0])

    def test_nothing_but_reads_can_be_sent(self):
        reader = params._Reader(None, params.FLIGHT_CONTROLLER, 1.0)
        for cmd_id in (0xDF, 0xE3, 0xE4, 0xE9):
            with self.subTest(f"{cmd_id:02X}"), self.assertRaisesRegex(ValueError, "not a read"):
                reader.ask(cmd_id, b"")

    def test_from_a_capture(self):
        drone = SimulatedM4T(M4T, CURRENT)
        pairs = []
        for seq, (cmd_id, payload) in enumerate(((0xE1, params.item_request(0, 4)),
                                                 (0xE2, params.value_request(0, 4)),
                                                 (0xE1, params.item_request(0, 3)),
                                                 (0xE1, params.item_request(0, 2))), 500):
            request = Frame(0x2A, params.FLIGHT_CONTROLLER, seq, commands.FLYC, cmd_id, payload)
            link = drone.connect()
            link.write(request.encode())
            pairs.append((request, StreamParser().feed(link.read(0.01))[0]))
        with tempfile.TemporaryDirectory() as tmp:
            path = capture(Path(tmp) / "params.pcap", pairs)
            items = params.from_frames(entry.frame for entry in pcap.iter_frames(path))
            self.assertEqual([(item.index, item.value) for item in items], [(2, None), (4, 120)])
            code, out, _ = run("params", "--capture", str(path), "--changed")
            self.assertEqual(code, 0)
            self.assertIn("basic_gain_roll_usr", out)
            self.assertNotIn("sweep_total", out)
            code, out, _ = run("params", "--capture", str(path), "--json", "--name", "SWEEP")
            self.assertEqual([item["name"] for item in json.loads(out)],
                             ["sweep_total_t_A__PRBS_period"])

    def test_cli_on_the_simulator(self):
        code, out, err = run("--simulate", CURRENT, "params")
        self.assertEqual(code, 0)
        self.assertIn("table 0: 7 indexes, 4 parameters", err)
        self.assertIn("120* default 100", out)
        self.assertIn("[0..4294967295]", out)


def exchange(drone, cmd_set, cmd_id, payload, seq, receiver):
    """One request to the simulator and its reply, as a capture would hold them."""
    request = Frame(0x2A, receiver, seq, cmd_set, cmd_id, payload)
    link = drone.connect()
    link.write(request.encode())
    replies = StreamParser().feed(link.read(0.01))
    return request, (replies[0] if replies else None)


class ReviewRegressionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.tmp = Path(self.directory.name)

    def test_params_reads_are_never_mixed(self):
        old = SimulatedM4T(M4T, CURRENT, params=[
            (1, 6, 0, 0, 50000, "rth_altitude_cm", struct.pack("<i", 42)),
            (3, 0, 0, 0, 1, "removed_in_new_fw", b"\x01")])
        new = SimulatedM4T(M4T, CURRENT, params=[
            (1, 6, 0, 0, 50000, "rth_altitude_cm", struct.pack("<i", 7))])
        pairs, seq = [], 100
        for drone, cut in ((old, False), (new, True)):
            for index in range(4):
                pairs.append(exchange(drone, commands.FLYC, 0xE1,
                                      params.item_request(0, index), seq, params.FLIGHT_CONTROLLER))
                seq += 1
                if index in (1, 3) and not (cut and index == 1):
                    pairs.append(exchange(drone, commands.FLYC, 0xE2,
                                          params.value_request(0, index), seq,
                                          params.FLIGHT_CONTROLLER))
                    seq += 1
        frames = [frame for pair in pairs for frame in pair if frame is not None]
        items = params.from_frames(frames)
        self.assertEqual([(item.name, item.value) for item in items], [("rth_altitude_cm", None)])

    def test_a_refusing_flight_controller_is_not_an_empty_table(self):
        with self.assertRaises(CommandRejected):
            params.parse_item(b"\x01\x00")
        self.assertIsNone(params.parse_item(b"\x0e\x00"))
        code, _, err = run("--simulate", CURRENT, "params")
        self.assertEqual(code, 0)
        with patch("dji_duml.sim.SIM_PARAMS", []):
            code, _, err = run("--simulate", CURRENT, "params")
        self.assertEqual(code, 2)
        self.assertIn("listed no parameters", err)

    def test_f64_values_stay_exact_and_tables_are_bounded(self):
        item = params.Param(0, 1, 9, 8, 0.0, 0.0, 0.0, "imu0.lati",
                            struct.pack("<d", 0.123456789012345))
        self.assertEqual(item.value, 0.123456789012345)

        class Huge:
            def request(self, receiver, cmd_set, cmd_id, payload, **options):
                return Frame(receiver, 0x2A, 0, cmd_set, cmd_id,
                             struct.pack("<HHII", 0, 0, 0, 70000), response=True)

        with self.assertRaisesRegex(UnexpectedReply, "70000 indexes"):
            params.read(Huge())

    def test_manifest_capture_never_splices_after_a_lost_first_reply(self):
        first, second = manifest(CURRENT), manifest(TARGET)
        reads = config_reads(first, 100, stop=256)
        lost = config_reads(second, 200)
        lost[0] = (lost[0][0], None)  # the drone's reply to offset 0 is not in the capture
        path = capture(self.tmp / "lost.pcap", reads + lost)
        frames = [entry.frame for entry in pcap.iter_frames(path)]
        self.assertIsNone(installed.config_from_frames(frames, CENTER))

    def test_manifest_output_rules(self):
        saved = self.tmp / "exists.cfg.sig"
        saved.write_bytes(b"old")
        drone = SimulatedM4T(M4T, TARGET)
        with patch("dji_duml.cli._drone", return_value=drone):
            code, _, err = run("--simulate", TARGET, "manifest", "-o", str(saved))
        self.assertEqual(code, 1)
        self.assertEqual(saved.read_bytes(), b"old")
        self.assertEqual([frame for frame in drone.received if frame.receiver == CENTER], [])
        odd = manifest(TARGET).replace(b"</release>", b"</release><release version=\"x\"/>")
        raw = self.tmp / "odd.cfg.sig"
        with patch("dji_duml.sim._config_for", return_value=odd):
            code, _, err = run("--simulate", TARGET, "manifest", "-o", str(raw))
        self.assertEqual(code, 1)
        self.assertEqual(raw.read_bytes(), odd)  # kept although it does not parse

    def test_manifest_json_holds_the_comparison(self):
        package = make_tar(self.directory.name, content=manifest(TARGET))
        with patch("dji_duml.sim._config_for", return_value=manifest(CURRENT)):
            code, out, _ = run("--simulate", TARGET, "manifest", "--json", "--compare",
                               str(package))
        self.assertEqual(code, 2)
        result = json.loads(out)
        self.assertFalse(result["compare"]["matches"])
        self.assertIn(f"version: package {TARGET}, drone {CURRENT}",
                      result["compare"]["differences"])

    def test_params_output_is_safe(self):
        nan = struct.pack("<f", float("nan"))
        table = [(1, 8, float("nan"), float("-inf"), float("inf"), "x\x1b[2J\x07y", nan)]
        with patch("dji_duml.sim.SIM_PARAMS", table):
            code, out, _ = run("--simulate", CURRENT, "params", "--json")
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)[0]["value"], None)
            self.assertNotIn("NaN", out)
            code, out, _ = run("--simulate", CURRENT, "params")
        self.assertNotIn("\x1b", out)
        self.assertIn("x\\x1b[2J\\x07y", out)


@unittest.skipUnless(IDLE, "set DJI_DUML_IDLE_CAPTURE to a capture of Assistant connecting")
class IdleCaptureTests(unittest.TestCase):
    def test_reads_in_the_capture(self):
        frames = [entry.frame for entry in pcap.iter_frames(IDLE)]
        config = installed.describe(installed.config_from_frames(frames, CENTER), "wa345t")
        self.assertEqual((str(config.version), len(config.data), len(config.modules)),
                         ("17.02.0501", 25632, 22))
        items = params.from_frames(frames)
        self.assertEqual(len(items), 907)
        self.assertTrue(all(item.value is not None for item in items))


if __name__ == "__main__":
    unittest.main()
