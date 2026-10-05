"""Smart-battery dynamic data (0D/02): read-only decode, from the drone or a
capture. The reference vector is a real M4T frame from idle2.pcap (30% pack)."""
import contextlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from dji_duml import battery, commands, pcap
from dji_duml.cli import main
from dji_duml.errors import UnexpectedReply
from dji_duml.frame import Frame
from dji_duml.profiles import M4T
from dji_duml.sim import SimulatedM4T
from duml_fixtures import usbpcap_file, usbpcap_record

# Real M4T 0D/02 reply captured at 30% charge (no serial, no coordinates).
IDLE2 = bytes.fromhex("00003f3800007cfeffffd4190000ed0700004201041e00000000000000000001ff00008d8200000000f2808c03")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def battery_capture(path, payload=IDLE2):
    request = Frame(0x2A, battery.BATTERY_ADDRESS, 0x317b, commands.BATTERY,
                    battery.DYNAMIC_DATA, battery.get_request())
    reply = request.make_reply(payload)
    return usbpcap_file(path, [usbpcap_record(0x04, request.encode(), False),
                              usbpcap_record(0x85, reply.encode(), True)])


class ParseTests(unittest.TestCase):
    def test_layout_matches_the_real_frame(self):
        data = battery.parse(IDLE2)
        self.assertEqual(data.voltage_mv, 14399)
        self.assertEqual(data.current_ma, -388)
        self.assertEqual((data.full_capacity_mah, data.remaining_mah), (6612, 2029))
        self.assertEqual(data.temperature_dc, 322)
        self.assertEqual((data.cell_count, data.state_of_charge), (4, 30))
        self.assertEqual(data.status, 0)
        self.assertEqual(data.tail, IDLE2[30:])
        self.assertAlmostEqual(data.cell_voltage, 3.600, places=3)
        self.assertAlmostEqual(data.temperature, 32.2, places=1)

    def test_state_of_charge_matches_capacity(self):
        data = battery.parse(IDLE2)
        self.assertAlmostEqual(data.state_of_charge,
                               100 * data.remaining_mah / data.full_capacity_mah, delta=1.0)

    def test_short_reply_is_rejected(self):
        with self.assertRaisesRegex(UnexpectedReply, "too short"):
            battery.parse(IDLE2[:20])

    def test_get_request_is_what_assistant_sends(self):
        self.assertEqual(battery.get_request().hex(), "00000105")


class ReadTests(unittest.TestCase):
    def test_read_from_the_simulator(self):
        drone = SimulatedM4T(M4T, "16.01.0006", battery_data=IDLE2)
        with drone.client() as client:
            data = battery.read(client)
        self.assertEqual((data.state_of_charge, data.cell_count), (30, 4))
        sent = [frame for frame in drone.received
                if frame.cmd_set == commands.BATTERY and frame.cmd_id == battery.DYNAMIC_DATA]
        self.assertEqual(len(sent), 1)

    def test_default_simulator_block_is_self_consistent(self):
        drone = SimulatedM4T(M4T, "16.01.0006")  # default block ~95%
        with drone.client() as client:
            data = battery.read(client)
        self.assertAlmostEqual(data.state_of_charge,
                               100 * data.remaining_mah / data.full_capacity_mah, delta=1.0)

    def test_from_frames(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = battery_capture(Path(tmp) / "b.pcap")
            data = battery.from_frames(entry.frame for entry in pcap.iter_frames(path))
            self.assertEqual(data.state_of_charge, 30)


class CliTests(unittest.TestCase):
    def test_simulate_plain_and_json(self):
        code, out, _ = run("--simulate", "16.01.0006", "battery")
        self.assertEqual(code, 0)
        self.assertIn("V/cell", out)
        self.assertIn("discharging", out)
        code, out, _ = run("--simulate", "16.01.0006", "battery", "--json")
        obj = json.loads(out)
        self.assertEqual(obj["cell_count"], 4)
        self.assertAlmostEqual(obj["cell_voltage"], obj["voltage_mv"] / 4 / 1000, places=3)

    def test_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(battery_capture(Path(tmp) / "b.pcap"))
            code, out, _ = run("battery", "--capture", path)
            self.assertEqual(code, 0)
            self.assertIn("30%", out)
            self.assertIn("3.600 V/cell", out)
            code, _, err = run("battery", "--capture", str(battery_capture(
                Path(tmp) / "empty.pcap", payload=IDLE2[:10])))
            self.assertEqual(code, 2)
            self.assertIn("No battery data", err)


if __name__ == "__main__":
    unittest.main()
