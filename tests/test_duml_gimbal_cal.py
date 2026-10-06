"""Gimbal calibration triggers (gimbal-cal): the 04/08 commands reversed from the
Dr. Failov repair tool's DUML. Action commands, so the tests only build and inspect
the frames (and exercise the CLI against the simulator); nothing touches hardware."""
import contextlib
import io
import unittest

from dji_duml import gimbal
from dji_duml.cli import main
from dji_duml.frame import AckType


class Recorder:
    """A stand-in client that records what calibrate()/factory_mode() would send."""
    def __init__(self, host=0x2A):
        self.sent = []
        self.host = host

    def send_frame(self, frame, *, log=True):
        self.sent.append(frame)
        return frame


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class BuildTests(unittest.TestCase):
    def test_dev_mode_frame_matches_the_tool(self):
        frame = gimbal.build("dev-mode")
        self.assertEqual((frame.sender, frame.receiver, frame.seq), (0x02, 0x04, 0))
        self.assertEqual((frame.cmd_set, frame.cmd_id, frame.payload), (0x04, 0x08, b"\x71"))
        self.assertEqual(frame.ack, AckType.AFTER_EXEC)
        self.assertFalse(frame.response)

    def test_joint_and_linear_selectors_and_app_sender(self):
        joint = gimbal.build("joint-coarse")
        linear = gimbal.build("linear-hall")
        self.assertEqual((joint.sender, joint.payload), (0x0A, b"\x01"))
        self.assertEqual((linear.sender, linear.payload), (0x0A, b"\x02"))

    def test_only_dev_mode_is_confirmed(self):
        self.assertTrue(gimbal.CALIBRATIONS["dev-mode"].confirmed)
        self.assertFalse(gimbal.CALIBRATIONS["joint-coarse"].confirmed)
        self.assertFalse(gimbal.CALIBRATIONS["linear-hall"].confirmed)

    def test_calibrate_sends_once(self):
        recorder = Recorder()
        frame = gimbal.calibrate(recorder, "dev-mode")
        self.assertEqual(recorder.sent, [frame])
        self.assertEqual(recorder.sent[0].payload, b"\x71")


class FactoryModeTests(unittest.TestCase):
    def test_enter_frames_match_the_tool(self):
        first, second, reboot = gimbal.factory_mode_frames(0x2A, True)
        self.assertEqual((first.sender, first.receiver, first.cmd_set, first.cmd_id),
                         (0x2A, 0x8F, 0x00, 0x44))
        self.assertEqual(first.payload, b"\x80\x0astart_factory\x00")
        self.assertEqual(second.receiver, 0x68)
        self.assertEqual(second.payload, b"\x80\x0astart_factory\x00")
        self.assertEqual((reboot.receiver, reboot.cmd_set, reboot.cmd_id), (0x0B, 0x00, 0x0B))
        self.assertEqual(reboot.payload, b"\x00\x01" + bytes(12))
        for frame in (first, second, reboot):
            self.assertEqual((frame.seq, frame.ack), (0, AckType.AFTER_EXEC))

    def test_exit_uses_stop_factory_and_mode_byte_2(self):
        first, _second, reboot = gimbal.factory_mode_frames(0x2A, False)
        self.assertEqual(first.payload, b"\x80\x0astop_factory\x00")
        self.assertEqual(reboot.payload, b"\x00\x02" + bytes(12))

    def test_factory_mode_sends_three_frames(self):
        recorder = Recorder()
        sent = gimbal.factory_mode(recorder, True)
        self.assertEqual(len(sent), 3)
        self.assertEqual(recorder.sent, sent)


class CliTests(unittest.TestCase):
    def test_dev_mode_sends(self):
        code, out, _ = run("--simulate", "16.01.0006", "gimbal-cal", "dev-mode")
        self.assertEqual(code, 0)
        self.assertIn("DevMode", out)
        self.assertIn("0200>0400", out)
        self.assertIn("71", out)

    def test_unconfirmed_needs_force(self):
        code, out, _ = run("--simulate", "16.01.0006", "gimbal-cal", "joint-coarse")
        self.assertEqual(code, 2)
        self.assertIn("force", out.lower())
        code, out, _ = run("--simulate", "16.01.0006", "gimbal-cal", "joint-coarse", "--force")
        self.assertEqual(code, 0)
        self.assertIn("JointCoarse", out)
        self.assertIn("note:", out)

    def test_factory_mode_enter_and_exit(self):
        code, out, _ = run("--simulate", "16.01.0006", "factory-mode", "enter")
        self.assertEqual(code, 0)
        self.assertIn("start_factory", out)
        self.assertIn("reboot", out.lower())
        code, out, _ = run("--simulate", "16.01.0006", "factory-mode", "exit")
        self.assertEqual(code, 0)
        self.assertIn("stop_factory", out)


if __name__ == "__main__":
    unittest.main()
