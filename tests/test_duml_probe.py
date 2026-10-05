"""Read-only module discovery (`probe`): Version Inquiry (00/01) and, with
--serial, Get Serial Number (00/51). Serials are synthetic here; the command
hides hardware/serial strings unless --serial is given."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from dji_duml import commands
from dji_duml.cli import main
from dji_duml.frame import Frame
from duml_fixtures import VERSION_BODY, usbpcap_file, usbpcap_record

# 00/51 reply shape: status u8 | 6 header bytes | ASCII serial (offset 7). Synthetic value.
SERIAL_BODY = b"\x00" + bytes(6) + b"SYNTH-SERIAL-00000001"
NO_SERIAL = b"\xd6"  # a one-byte status, as 0801 answers


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def probe_capture(path):
    records = []

    def pair(addr, cmd_id, payload, seq):
        request = Frame(0x2A, addr, seq, commands.GENERAL, cmd_id,
                        b"\x01" if cmd_id == commands.GET_SERIAL else b"")
        reply = request.make_reply(payload)
        records.append(usbpcap_record(0x04, request.encode(), False))
        records.append(usbpcap_record(0x85, reply.encode(), True))

    pair(0x03, commands.VERSION_INQUIRY, VERSION_BODY, 1)          # FC
    pair(0x68, commands.VERSION_INQUIRY, VERSION_BODY, 2)          # SoC with a serial
    pair(0x68, commands.GET_SERIAL, SERIAL_BODY, 3)
    pair(0x28, commands.VERSION_INQUIRY, VERSION_BODY, 4)          # SoC without a serial
    pair(0x28, commands.GET_SERIAL, NO_SERIAL, 5)
    return usbpcap_file(path, records)


class SerialParseTests(unittest.TestCase):
    def test_parse_serial(self):
        self.assertEqual(commands.parse_serial(SERIAL_BODY), "SYNTH-SERIAL-00000001")
        self.assertIsNone(commands.parse_serial(NO_SERIAL))                 # one-byte status
        self.assertIsNone(commands.parse_serial(b"\x00" + bytes(6) + b"\xff\xff"))  # not ASCII
        self.assertIsNone(commands.parse_serial(b"\x01" + bytes(26)))       # non-zero status


class ProbeCaptureTests(unittest.TestCase):
    def test_default_hides_identifiers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(probe_capture(Path(tmp) / "p.pcap"))
            code, out, _ = run("probe", "--capture", path)
            self.assertEqual(code, 0)
            self.assertIn("fw 17.02.0501", out)             # firmware shown (non-sensitive)
            self.assertIn("3 module(s) seen", out)
            self.assertNotIn("SYNTH-SERIAL", out)           # serial hidden by default
            self.assertNotIn("WA345T AC Ver.A", out)        # hardware string hidden by default

    def test_serial_flag_shows_and_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(probe_capture(Path(tmp) / "p.pcap"))
            code, out, _ = run("probe", "--capture", path, "--serial")
            self.assertEqual(code, 0)
            self.assertIn("SYNTH-SERIAL-00000001", out)     # the 0803 serial
            self.assertIn("(no serial)", out)               # 0801 answers without one
            self.assertIn("do not publish", out)            # the privacy note

    def test_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(probe_capture(Path(tmp) / "p.pcap"))
            code, out, _ = run("probe", "--capture", path, "--json")
            data = {entry["address"]: entry for entry in json.loads(out)}
            self.assertEqual(data["0300"]["firmware"], "17.02.0501")
            self.assertNotIn("serial", data["0300"])        # no --serial -> no serial key


class ProbeArgTests(unittest.TestCase):
    def test_serial_flag_does_not_clobber_the_usb_serial_filter(self):
        # probe's --serial must not overwrite the global --serial (USB device
        # selector); otherwise the transport opens with serial=True and fails.
        from dji_duml.cli import build_parser
        args = build_parser().parse_args(["probe", "--serial"])
        self.assertTrue(args.read_serial)
        self.assertIsNone(args.serial)


class ProbeLiveTests(unittest.TestCase):
    # Probe a small explicit set so non-responders do not each wait the timeout.
    def test_simulate_perception_does_not_respond(self):
        code, out, _ = run("--simulate", "16.01.0006", "probe", "--timeout", "0.3",
                           "--address", "0x1f", "--address", "0x18")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"2400\s+\S.*-- no response")  # 0x18 = type24 perception
        self.assertIn("1 of 2 responded", out)

    def test_simulate_json(self):
        code, out, _ = run("--simulate", "16.01.0006", "probe", "--json", "--timeout", "0.3",
                           "--address", "0x18")
        data = {entry["address"]: entry for entry in json.loads(out)}
        self.assertFalse(data["2400"]["responds"])          # perception: no endpoint


if __name__ == "__main__":
    unittest.main()
