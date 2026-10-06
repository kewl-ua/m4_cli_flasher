"""00/51 serial-selector sweep (serial-scan): read-only enumeration of which
selector bytes make a target SoC return a serial. All serials here are synthetic;
no real device identifiers appear."""
import contextlib
import io
import json
import unittest

from dji_duml import commands
from dji_duml.cli import main
from dji_duml.errors import NoReply
from dji_duml.profiles import M4T
from dji_duml.sim import SimulatedM4T


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def serial_payload(text: str) -> bytes:
    """A 00/51 reply: status 0, six header bytes, then the ASCII serial."""
    return b"\x00" + bytes(6) + text.encode()


# A SoC that returns different serials for different selectors, a "no serial here"
# status (0xd6) for some, and nothing for the rest -- so a sweep can discriminate.
SERIALS = {
    (0x68, 0x01): serial_payload("SYNTH-0803-01"),
    (0x68, 0x04): serial_payload("SYNTH-0803-04"),
    (0x68, 0x06): serial_payload("SYNTH-0803-06"),
    (0x68, 0x00): b"\xd6",
    (0x28, 0x01): b"\xd6",
}


class ScanSerialTests(unittest.TestCase):
    def test_selector_picks_the_serial(self):
        drone = SimulatedM4T(M4T, "16.01.0006", serials=SERIALS)
        with drone.client() as client:
            self.assertEqual(commands.scan_serial(client, 0x68, 0x04), (0, "SYNTH-0803-04"))
            self.assertEqual(commands.scan_serial(client, 0x68, 0x06), (0, "SYNTH-0803-06"))
            self.assertEqual(commands.scan_serial(client, 0x68, 0x00), (0xd6, None))
            self.assertEqual(commands.scan_serial(client, 0x28, 0x01), (0xd6, None))

    def test_the_selector_byte_is_what_gets_sent(self):
        drone = SimulatedM4T(M4T, "16.01.0006", serials=SERIALS)
        with drone.client() as client:
            commands.scan_serial(client, 0x68, 0x06)
        bodies = [bytes(f.payload) for f in drone.received if f.cmd_id == commands.GET_SERIAL]
        self.assertEqual(bodies, [b"\x06"])

    def test_get_serial_honours_the_selector(self):
        drone = SimulatedM4T(M4T, "16.01.0006", serials=SERIALS)
        with drone.client() as client:
            self.assertEqual(commands.get_serial(client, 0x68, selector=0x04), "SYNTH-0803-04")
            self.assertEqual(commands.get_serial(client, 0x68), "SYNTH-0803-01")  # default 0x01

    def test_unknown_selector_times_out(self):
        drone = SimulatedM4T(M4T, "16.01.0006", serials=SERIALS)
        with drone.client() as client:
            with self.assertRaises(NoReply):
                commands.scan_serial(client, 0x68, 0x09, timeout=0.02, retries=0)


class CliTests(unittest.TestCase):
    def test_simulate_plain(self):
        # The default simulator answers 0x68/00051 for any selector and 0x28 with 0xd6.
        code, out, _ = run("--simulate", "16.01.0006", "serial-scan", "--max-selector", "0x02")
        self.assertEqual(code, 0)
        self.assertIn("selector 0x00", out)   # 0x68 returns a serial at every selector
        self.assertIn("no serials", out)      # 0x28 returns status 0xd6, no serial
        self.assertIn("do not publish", out)

    def test_simulate_json(self):
        code, out, _ = run("--simulate", "16.01.0006", "serial-scan",
                           "--address", "0x68", "--max-selector", "0x01", "--json")
        self.assertEqual(code, 0)
        rows = json.loads(out)
        self.assertEqual({row["selector"] for row in rows}, {0, 1})
        self.assertTrue(all(row["target"] == "0803" for row in rows))


if __name__ == "__main__":
    unittest.main()
