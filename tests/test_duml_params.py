import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dji_duml import commands, installed, params
from dji_duml.errors import CommandRejected
from dji_duml.frame import Frame
from dji_duml.package import inspect_package
from dji_duml.profiles import M4T
from dji_duml.sim import FC_PARAMS, SimulatedM4T, installed_config
from dji_duml.version import FirmwareVersion
from duml_fixtures import (
    CURRENT, TARGET, VERSION_BODY, make_tar, manifest, usbpcap_file, usbpcap_record,
    version_request,
)
from test_duml_cli import run

HOST, FC, CENTER = M4T.host, params.FLIGHT_CONTROLLER, M4T.upgrade_center

# Replies from DJI Assistant's idle capture of an M4T (2026-10-05).
TABLE_REPLY = bytes.fromhex("0000000086b5b5dd1b060000")
FLOAT_ITEM = bytes.fromhex(
    "000000000c0008000400000034430000000000007a4473776565705f746f74616c5f745f415f5f505242"
    "535f706572696f6400")
U8_ITEM = bytes.fromhex(
    "0000000009000000010000000000000000001200000073776565705f746573745f666c616700")
I16_VALUE = bytes.fromhex("000000003b006400")
CONFIG_REPLY_HEAD = bytes.fromhex("000001000020630000")


def exchange(request, reply_payload):
    return [request, request.make_reply(reply_payload)]


class ParamParsingTests(unittest.TestCase):
    def test_captured_replies(self):
        self.assertEqual(params.parse_table(TABLE_REPLY), params.TableInfo(0, 0xDDB5B586, 1563))
        with self.assertRaises(CommandRejected):
            params.parse_table(bytes.fromhex("0900"))
        item = params.parse_item(FLOAT_ITEM)
        self.assertEqual((item.index, item.type_name, item.default, item.minimum, item.maximum,
                          item.name), (12, "f32", 180.0, 0.0, 1000.0,
                                       "sweep_total_t_A__PRBS_period"))
        item = params.parse_item(U8_ITEM)
        self.assertEqual((item.index, item.type_name, item.maximum, item.name),
                         (9, "u8", 18, "sweep_test_flag"))
        self.assertIsNone(params.parse_item(bytes.fromhex("0e00")))
        self.assertEqual(params.parse_value(I16_VALUE), (59, b"\x64\x00"))
        self.assertEqual(params.decode_value(5, b"\x9c\xff"), -100)
        self.assertIsNone(params.decode_value(5, b"\x01"))

    def test_requests_are_the_ones_assistant_sends(self):
        self.assertEqual(params.table_request(0).hex(), "0000")
        self.assertEqual(params.item_request(0, 0x61a).hex(), "00001a06")
        self.assertEqual(params.value_request(0, 9).hex(), "000001000900")

    def test_from_frames_pairs_replies_with_requests(self):
        frames = [
            *exchange(Frame(HOST, FC, 1, 3, 0xE1, params.item_request(0, 12)), FLOAT_ITEM),
            *exchange(Frame(HOST, FC, 2, 3, 0xE1, params.item_request(0, 13)), b"\x0e\x00"),
            *exchange(Frame(HOST, FC, 3, 3, 0xE2, params.value_request(0, 12)),
                      struct.pack("<HHH", 0, 0, 12) + struct.pack("<f", 200.0)),
            # A reply without its request is not trusted.
            Frame(FC, HOST, 9, 3, 0xE1, U8_ITEM, response=True),
        ]
        found = params.from_frames(frames)
        self.assertEqual([(item.index, item.value, item.changed) for item in found],
                         [(12, 200.0, True)])

    def test_read_from_simulated_drone(self):
        drone = SimulatedM4T(M4T, CURRENT)
        with drone.client() as client:
            info, found = params.read(client)
        self.assertEqual(info.count, max(FC_PARAMS) + 1)
        self.assertEqual({item.index: item.value for item in found},
                         {index: entry[6] for index, entry in FC_PARAMS.items()})
        self.assertEqual([item.name for item in found if item.changed],
                         ["g_config.flying_limit.max_height"])
        sent = {(frame.cmd_set, frame.cmd_id) for frame in drone.received}
        self.assertEqual(sent, {(3, 0xE0), (3, 0xE1), (3, 0xE2)})


class InstalledConfigTests(unittest.TestCase):
    def test_captured_chunk_header(self):
        chunk, left = installed.parse_config_chunk(CONFIG_REPLY_HEAD + b"IM*H" + bytes(252))
        self.assertEqual((len(chunk), left), (256, 25376))
        self.assertEqual(installed.config_request(0x6100).hex(), "0100610000e8030000")

    def test_read_from_simulated_drone_and_from_frames(self):
        config = manifest(TARGET)
        drone = SimulatedM4T(M4T, TARGET, config=config)
        with drone.client() as client:
            self.assertEqual(installed.read_config(client, CENTER), config)
        frames = []
        for request in drone.received:
            offset = struct.unpack_from("<I", request.payload, 1)[0]
            chunk = config[offset:offset + 256]
            frames += exchange(request, b"\x00" + struct.pack(
                "<II", len(chunk), len(config) - offset - len(chunk)) + chunk)
        self.assertEqual(installed.config_from_frames(frames, CENTER), config)
        self.assertIsNone(installed.config_from_frames(frames[2:], CENTER))
        described = installed.describe(config, "wa345t")
        self.assertEqual((described.version, len(described.modules)),
                         (FirmwareVersion.parse(TARGET), 1))

    def test_compare_with_package(self):
        with tempfile.TemporaryDirectory() as directory:
            same = inspect_package(make_tar(directory))
            other = inspect_package(make_tar(directory, name="old.bin", version=CURRENT))
            drone = installed.describe(manifest(TARGET), "wa345t")
            self.assertEqual(installed.compare(drone, same), [])
            differences = installed.compare(drone, other)
        self.assertIn(f"version: package {CURRENT}, drone {TARGET}", differences)

    def test_flasher_result_query_still_gets_the_version(self):
        drone = SimulatedM4T(M4T, TARGET)
        with drone.client() as client:
            reply = client.request(CENTER, 0, commands.UPGRADE_RESULT,
                                   commands.result_query_payload())
        self.assertEqual(commands.parse_result_reply(reply.payload),
                         FirmwareVersion.parse(TARGET))


class CliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)

    def test_params_on_simulated_drone(self):
        code, out, err = run("--simulate", CURRENT, "params", "--changed")
        self.assertEqual(code, 0)
        self.assertIn("*          500  default 120", out)
        self.assertIn("1 of 5 parameters shown", err)
        code, out, _ = run("--simulate", CURRENT, "params", "--name", "LATI", "--json")
        self.assertEqual(json.loads(out.splitlines()[-1])["name"], "imu0.lati")

    def test_params_and_manifest_from_capture(self):
        config = manifest(TARGET)
        records = []
        for seq, (request, reply) in enumerate((
                (params.item_request(0, 9), U8_ITEM),
                (params.value_request(0, 9), struct.pack("<HHHB", 0, 0, 9, 3)))):
            frame = Frame(HOST, FC, seq, 3, 0xE1 + seq, request)
            records += [usbpcap_record(0x04, frame.encode(), False),
                        usbpcap_record(0x85, frame.make_reply(reply).encode(), True)]
        for seq, offset in enumerate(range(0, len(config), 256), start=10):
            chunk = config[offset:offset + 256]
            frame = Frame(HOST, CENTER, seq, 0, 0x4F, installed.config_request(offset))
            reply = b"\x00" + struct.pack("<II", len(chunk), len(config) - offset - len(chunk))
            records += [usbpcap_record(0x04, frame.encode(), False),
                        usbpcap_record(0x85, frame.make_reply(reply + chunk).encode(), True)]
        capture = usbpcap_file(self.path / "idle.pcap", records)
        code, out, _ = run("params", "--capture", str(capture))
        self.assertEqual(code, 0)
        self.assertIn("*            3  default 0          [0..18]  sweep_test_flag", out)
        package = make_tar(self.path)
        code, out, _ = run("manifest", "--capture", str(capture), "--compare", str(package))
        self.assertEqual(code, 0, out)
        self.assertIn(f"version   {TARGET}", out)
        self.assertIn("The drone runs exactly dji_system.bin", out)
        request = version_request()
        empty = usbpcap_file(self.path / "version.pcap", [
            usbpcap_record(0x04, request.encode(), False),
            usbpcap_record(0x85, request.make_reply(VERSION_BODY).encode(), True)])
        self.assertEqual(run("manifest", "--capture", str(empty))[0], 2)
        self.assertEqual(run("params", "--capture", str(empty))[0], 2)

    def test_manifest_on_simulated_drone(self):
        saved = self.path / "drone.cfg.sig"
        old = make_tar(self.path, name="old.bin", version=CURRENT)
        with patch("dji_duml.sim.installed_config", lambda version: manifest(str(version))):
            code, out, _ = run("--simulate", TARGET, "manifest", "-o", str(saved),
                               "--compare", str(old))
        self.assertEqual(code, 2)
        self.assertIn("The drone does not run old.bin", out)
        self.assertEqual(saved.read_bytes(), manifest(TARGET))
        code, _, err = run("--simulate", TARGET, "manifest", "-o", str(saved))
        self.assertEqual(code, 1)
        self.assertIn("exists", err)

    def test_decode_names_flight_controller_commands(self):
        self.assertEqual(commands.command_name(3, 0xE1), "Cfg Item Attribute")
        self.assertEqual(commands.command_name(0, 0x32), "Activate Config")
        self.assertEqual(commands.command_name(3, 0xE3), "Cfg Item Set")

    def test_simulated_default_config_is_readable(self):
        self.assertEqual(installed.describe(installed_config(FirmwareVersion.parse(TARGET)),
                                            "wa345t").version, FirmwareVersion.parse(TARGET))


if __name__ == "__main__":
    unittest.main()
