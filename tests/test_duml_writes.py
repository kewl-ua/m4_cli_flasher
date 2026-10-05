"""Writing one flight controller parameter: validate, send 03/E3, confirm by
read-back, stay reversible. No hardware; the simulator stands in for the FC."""
import contextlib
import io
import struct
import tempfile
import unittest
from pathlib import Path

from dji_duml import commands, params, pcap, writes
from dji_duml.cli import main
from dji_duml.errors import CommandRejected, UnexpectedReply, WriteFailed, WriteRefused
from dji_duml.frame import Frame, StreamParser
from dji_duml.params import Param
from dji_duml.profiles import M4T
from dji_duml.sim import SimulatedM4T
from duml_fixtures import CURRENT, usbpcap_file, usbpcap_record

FLYC = commands.FLYC
FC = params.FLIGHT_CONTROLLER


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def i16(index=4, type_id=5, default=100, lo=20, hi=150, value=120, name="basic_gain_roll_usr"):
    return Param(0, index, type_id, 2, default, lo, hi, name, struct.pack("<h", value))


def f32(index=2, default=180.0, lo=0.0, hi=1000.0, value=180.0, name="sweep"):
    return Param(0, index, 8, 4, default, lo, hi, name, struct.pack("<f", value))


def fc_ids(drone, response=False):
    return [frame.cmd_id for frame in drone.received
            if frame.cmd_set == FLYC and frame.response == response]


class ValueTests(unittest.TestCase):
    def test_parse_number(self):
        self.assertEqual(writes.parse_number(i16(), "130"), 130)
        self.assertEqual(writes.parse_number(i16(), "0x10"), 16)  # 0x.. accepted for ints
        f = i16(index=2, type_id=8, default=180.0, lo=0.0, hi=1000.0, value=180)
        self.assertEqual(writes.parse_number(f, "200.5"), 200.5)
        with self.assertRaisesRegex(WriteRefused, "not a valid"):
            writes.parse_number(i16(), "abc")

    def test_encode_value_checks_range_and_size(self):
        self.assertEqual(writes.encode_value(i16(), 130), struct.pack("<h", 130))
        with self.assertRaisesRegex(WriteRefused, "outside"):
            writes.encode_value(i16(), 200)
        with self.assertRaisesRegex(WriteRefused, "outside"):
            writes.encode_value(i16(), 0)  # below minimum 20
        with self.assertRaisesRegex(WriteRefused, "whole number"):
            writes.encode_value(i16(), 130.5)  # non-integer for an int type
        with self.assertRaisesRegex(WriteRefused, "unknown type"):
            writes.encode_value(i16(type_id=42), 1)
        with self.assertRaisesRegex(WriteRefused, "not a finite"):
            writes.encode_value(f32(), float("nan"))  # NaN slips past < / > range checks
        with self.assertRaisesRegex(WriteRefused, "not a finite|outside"):
            writes.encode_value(f32(), float("inf"))

    def test_request_is_the_read_request_plus_value(self):
        data = struct.pack("<h", 130)
        self.assertEqual(writes.set_item_request(0, 4, data),
                         params.value_request(0, 4) + data)

    def test_parse_set_reply(self):
        ok = struct.pack("<HHH", 0, 0, 4) + struct.pack("<h", 130)
        self.assertEqual(writes.parse_set_reply(ok, 0, 4), struct.pack("<h", 130))
        with self.assertRaises(CommandRejected):  # non-zero status
            writes.parse_set_reply(struct.pack("<H", 9), 0, 4)
        self.assertEqual(writes.parse_set_reply(struct.pack("<HH", 0, 0), 0, 4), b"")  # status 0,
        self.assertEqual(writes.parse_set_reply(b"\x00\x00", 0, 4), b"")  # no echo -> success
        with self.assertRaises(UnexpectedReply):  # echoes the wrong item
            writes.parse_set_reply(struct.pack("<HHH", 0, 0, 5) + b"\x00\x00", 0, 4)

    def test_plan_write_expected_guard(self):
        plan = writes.plan_write(i16(), "130", "120")
        self.assertEqual((plan.old, plan.new, plan.data), (120, 130, struct.pack("<h", 130)))
        with self.assertRaisesRegex(WriteRefused, "not the expected"):
            writes.plan_write(i16(), "130", "121")
        unread = Param(0, 4, 5, 2, 100, 20, 150, "basic_gain_roll_usr", None)  # raw=None
        with self.assertRaisesRegex(WriteRefused, "did not read back"):
            writes.plan_write(unread, "130", "120")

    def test_plan_write_without_expected(self):
        plan = writes.plan_write(i16(), "130", None)
        self.assertEqual(plan.new, 130)


class CommitTests(unittest.TestCase):
    def commit(self, drone, index=4, value="130", expected="120", **kw):
        with drone.client() as client:
            param = params.read_one(client, index)
            plan = writes.plan_write(param, value, expected)
            return writes.commit_write(client, plan, **kw)

    def test_write_and_confirm(self):
        drone = SimulatedM4T(M4T, CURRENT)
        result = self.commit(drone)
        self.assertEqual((result.old, result.new, result.read_back, result.unlocked),
                         (120, 130, 130, False))
        self.assertEqual(result.echoed, 130)
        self.assertEqual(drone.writes, [(4, struct.pack("<h", 130))])
        # the write took effect: a fresh read sees 130
        with drone.client() as client:
            self.assertEqual(params.read_one(client, 4).value, 130)
        self.assertEqual(fc_ids(drone).count(0xE3), 1)  # sent exactly once (retries=0)
        self.assertNotIn(0xE4, fc_ids(drone))           # reset never sent
        self.assertNotIn(0xE9, fc_ids(drone))           # command table never sent

    def test_unlock_on_reject(self):
        drone = SimulatedM4T(M4T, CURRENT, require_unlock=True)
        result = self.commit(drone)
        self.assertTrue(result.unlocked)
        self.assertTrue(drone.unlocked)
        self.assertEqual(result.read_back, 130)
        self.assertEqual(fc_ids(drone).count(0xDF), 1)  # unlocked once
        self.assertEqual(fc_ids(drone).count(0xE3), 2)  # rejected, then retried

    def test_no_unlock_lets_the_rejection_stand(self):
        drone = SimulatedM4T(M4T, CURRENT, require_unlock=True)
        with self.assertRaises(CommandRejected):
            self.commit(drone, unlock_on_reject=False)
        self.assertNotIn(0xDF, fc_ids(drone))
        self.assertFalse(drone.unlocked)

    def test_readback_mismatch_is_write_failed(self):
        drone = SimulatedM4T(M4T, CURRENT, ignore_writes={4})  # accepts but reverts
        with self.assertRaises(WriteFailed) as caught:
            self.commit(drone)
        self.assertEqual(caught.exception.read_back, 120)  # still the old value

    def test_lost_reply_still_reads_back(self):
        # The sim applies the E3 then drops its reply; commit_write must confirm
        # by read-back and NOT resend the changing command (retries=0).
        drone = SimulatedM4T(M4T, CURRENT, lose_reply=frozenset({0xE3}))
        result = self.commit(drone)
        self.assertEqual(result.read_back, 130)          # confirmed despite the lost echo
        self.assertEqual(fc_ids(drone).count(0xE3), 1)   # one send only, no retry
        self.assertEqual(len(drone.writes), 1)

    def test_f64_round_trip(self):
        drone = SimulatedM4T(M4T, CURRENT, params=[
            (7, 9, 1.0, 0.0, 1000.0, "test_f64", struct.pack("<d", 1.0))])
        result = self.commit(drone, index=7, value="42.5", expected="1")
        self.assertEqual(result.read_back, 42.5)
        with drone.client() as client:
            self.assertEqual(params.read_one(client, 7).value, 42.5)

    def test_negative_signed_value(self):
        drone = SimulatedM4T(M4T, CURRENT, params=[
            (8, 6, 0, -100, 100, "test_i32", struct.pack("<i", -5))])
        self.assertEqual(self.commit(drone, index=8, value="-50", expected="-5").read_back, -50)
        with self.assertRaisesRegex(WriteRefused, "outside"):
            self.commit(SimulatedM4T(M4T, CURRENT, params=[
                (8, 6, 0, -100, 100, "test_i32", struct.pack("<i", -5))]),
                index=8, value="-200", expected="-5")

    def test_unlock_then_silent_revert_is_write_failed(self):
        drone = SimulatedM4T(M4T, CURRENT, require_unlock=True, ignore_writes={4})
        with self.assertRaises(WriteFailed) as caught:
            self.commit(drone)
        self.assertEqual(caught.exception.read_back, 120)       # reverted to the old value
        self.assertIn("unlock was sent", str(caught.exception))
        self.assertTrue(drone.unlocked)

    def test_only_e3_and_df_can_be_sent(self):
        writer = writes._Writer(None, FC, 1.0)
        for cmd_id in (0xE2, 0xE4, 0xE9, 0xF9):
            with self.subTest(f"{cmd_id:02X}"), self.assertRaisesRegex(ValueError, "not a write"):
                writer.send(cmd_id, b"")


def param_capture(path, index=4):
    """A capture of the E1/E2 reads of one item, host 0x04, drone 0x85."""
    drone = SimulatedM4T(M4T, CURRENT)
    records = []
    for seq, (cmd_id, payload) in enumerate(((0xE1, params.item_request(0, index)),
                                             (0xE2, params.value_request(0, index))), 700):
        request = Frame(0x2A, FC, seq, FLYC, cmd_id, payload)
        link = drone.connect()
        link.write(request.encode())
        reply = StreamParser().feed(link.read(0.01))[0]
        records.append(usbpcap_record(0x04, request.encode(), False))
        records.append(usbpcap_record(0x85, reply.encode(), True))
    return usbpcap_file(path, records)


class CliTests(unittest.TestCase):
    def test_dry_run_then_write(self):
        code, out, _ = run("--simulate", CURRENT, "set-param", "--index", "4",
                           "--value", "130", "--expected", "120")
        self.assertEqual(code, 0)
        self.assertIn("120 -> 130", out)
        self.assertIn("dry run", out)
        code, out, _ = run("--simulate", CURRENT, "set-param", "--index", "4",
                           "--value", "130", "--expected", "120", "--yes")
        self.assertEqual(code, 0)
        self.assertIn("readback  130: confirmed", out)
        self.assertIn("undo      dji-duml set-param --index 4 --value 120 --expected 130 --yes",
                      out)

    def test_by_name_and_json(self):
        code, out, _ = run("--simulate", CURRENT, "set-param", "--name", "basic_gain_roll_usr",
                           "--value", "140", "--expected", "120", "--yes", "--json")
        self.assertEqual(code, 0)
        import json
        obj = json.loads(out)
        self.assertEqual((obj["name"], obj["new"], obj["read_back"], obj["applied"]),
                         ("basic_gain_roll_usr", 140, 140, True))

    def test_out_of_range_refused(self):
        code, _, err = run("--simulate", CURRENT, "set-param", "--index", "4",
                           "--value", "200", "--expected", "120", "--yes")
        self.assertEqual(code, 2)
        self.assertIn("outside", err)

    def test_expected_mismatch_refused(self):
        code, _, err = run("--simulate", CURRENT, "set-param", "--index", "4",
                           "--value", "130", "--expected", "121", "--yes")
        self.assertEqual(code, 2)
        self.assertIn("not the expected", err)

    def test_unknown_name_refused(self):
        code, _, err = run("--simulate", CURRENT, "set-param", "--name", "no_such_param",
                           "--value", "1", "--expected", "0", "--yes")
        self.assertEqual(code, 2)
        self.assertIn("No parameter named", err)

    def test_index_out_of_range_refused(self):
        code, _, err = run("--simulate", CURRENT, "set-param", "--index", "70000",
                           "--value", "1", "--expected", "0")
        self.assertEqual(code, 2)  # a clean refusal, not a struct.error traceback
        self.assertIn("out of range", err)

    def test_undo_command_formatting(self):
        from dji_duml.cli import _exact, _setparam_cmd
        self.assertNotIn("--table", _setparam_cmd(5, 10, 8, 0))
        self.assertIn("--table 1", _setparam_cmd(5, 10, 8, 1))
        self.assertEqual(_exact(0.1234567), repr(0.1234567))      # full precision, not %g
        self.assertIn("0.1234567", _setparam_cmd(2, 0.1234567, 0.0, 0))

    def test_capture_is_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(param_capture(Path(tmp) / "p.pcap"))
            code, out, _ = run("set-param", "--capture", path, "--index", "4",
                               "--value", "130", "--expected", "120")
            self.assertEqual(code, 0)
            self.assertIn("read-only", out)
            self.assertIn("120 -> 130", out)
            code, _, err = run("set-param", "--capture", path, "--index", "4",
                               "--value", "130", "--expected", "120", "--yes")
            self.assertEqual(code, 2)
            self.assertIn("read-only", err)
            code, _, err = run("set-param", "--capture", path, "--index", "4", "--table", "1",
                               "--value", "130", "--expected", "120")
            self.assertEqual(code, 2)  # --table is silently dropped by capture; refuse it
            self.assertIn("table 0 only", err)


if __name__ == "__main__":
    unittest.main()
