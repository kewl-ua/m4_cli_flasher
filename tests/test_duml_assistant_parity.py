"""Parity with DJI Assistant: what we would send equals what Assistant sent.

Needs a package and the 00/2A requests of a capture of Assistant flashing it,
so it runs only when both are given:

    DJI_DUML_PACKAGE=...M4T_UAV_17.02.05.01_pro.zip
    DJI_DUML_CAPTURE=...offline_usb.pcap

The capture is decoded once. Flasher._send_files itself runs against a stand-in
client, and every file open, data chunk and end it produces is compared with
Assistant's; so are the 83/84/85/4F/41 control payloads. Where the device
reported a chunk missing, the stand-in reports it at the same point, and the
chunks sent again must be Assistant's, byte for byte.
"""
import os
import unittest
from collections import deque

from dji_duml import commands, pcap
from dji_duml.flasher import Flasher
from dji_duml.frame import Frame
from dji_duml.package import inspect_package, verify_files
from dji_duml.profiles import M4T

PACKAGE = os.environ.get("DJI_DUML_PACKAGE")
CAPTURE = os.environ.get("DJI_DUML_CAPTURE")


def split_transfer(frames):
    """Assistant's 00/2A requests in order, without the chunks it sent again;
    those chunks; and each gap report with the number of requests before it."""
    first_pass, again, gaps, highest = [], [], [], -1
    for frame in frames:
        payload = frame.payload
        if frame.response:
            if len(payload) == 13:
                gaps.append((len(first_pass), payload))
            continue
        if payload[:1] == bytes([commands.FT_OPEN]):
            highest = -1
        elif payload[:1] == bytes([commands.FT_DATA]):
            index = int.from_bytes(payload[1:5], "little")
            if index <= highest:
                again.append(payload)
                continue
            highest = index
        first_pass.append(payload)
    return first_pass, again, gaps


class Recorder:
    """Stands in for DumlClient: answers the upgrade center like the M4T did
    and compares every 00/2A payload with the next one Assistant sent."""

    def __init__(self, expected, again=(), gaps=()):
        self.expected = iter(expected)
        self.again = iter(again)
        self.gaps = deque(gaps)
        self.compared = self.mismatch = self.resent = 0
        self.first_mismatch = None
        self.inbox = deque()
        self.parser = type("Parser", (), {"pending": 0})()
        self.last = -1

    def _check(self, payload, expected=None):
        theirs = next(self.expected if expected is None else expected, None)
        self.compared += 1
        if payload != theirs:
            self.mismatch += 1
            if self.first_mismatch is None:
                self.first_mismatch = (self.compared, payload[:16].hex(), (theirs or b"")[:16].hex())

    def request(self, receiver, cmd_set, cmd_id, payload=b"", **options):
        self._check(payload)
        if payload[:1] == bytes([commands.FT_OPEN]):
            self.last, reply = -1, bytes.fromhex("00d40388130101")
        else:
            reply = b"\x00"
        return Frame(receiver, 0x2A, 0, cmd_set, cmd_id, reply, response=True, ack=0)

    def send_batch(self, receiver, cmd_set, cmd_id, payloads, **options):
        for payload in payloads:
            index = int.from_bytes(payload[1:5], "little")
            if index <= self.last:
                self.resent += 1
                self._check(payload, self.again)
            else:
                self._check(payload)
                self.last = index
        return len(payloads)

    def poll(self, timeout):
        if self.gaps and self.gaps[0][0] <= self.compared - self.resent:
            report = self.gaps.popleft()[1]
        else:
            report = b"\x00" + self.last.to_bytes(4, "little")
        return [Frame(0x48, 0x2A, 0, 0, commands.FILE_TRANSFER, report, response=True, ack=0)]


@unittest.skipUnless(PACKAGE and CAPTURE, "set DJI_DUML_PACKAGE and DJI_DUML_CAPTURE")
class AssistantParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.package = inspect_package(PACKAGE)
        entries, _ = pcap.decode(CAPTURE)
        center = {(0x2A, 0x48), (0x48, 0x2A)}
        frames = [entry.frame for entry in entries if entry.frame.cmd_set == commands.GENERAL
                  and (entry.frame.sender, entry.frame.receiver) in center]
        cls.requests = [frame for frame in frames if not frame.response]
        cls.transfer = split_transfer(frame for frame in frames
                                      if frame.cmd_id == commands.FILE_TRANSFER)

    def sent(self, cmd_id):
        return [frame.payload for frame in self.requests if frame.cmd_id == cmd_id]

    def test_flasher_sends_every_file_transfer_payload_assistant_sent(self):
        first_pass, again, gaps = self.transfer
        recorder = Recorder(first_pass, again, gaps)
        flasher = Flasher(lambda: recorder, M4T)
        flasher._digests = verify_files(self.package)
        flasher._send_files(recorder, self.package)
        self.assertIsNone(recorder.first_mismatch)
        self.assertEqual(recorder.compared, len(first_pass) + len(again))
        self.assertEqual(recorder.resent, len(again))
        self.assertEqual(len(recorder.gaps), 0)

    def test_control_payloads_are_identical(self):
        self.assertEqual(set(self.sent(commands.UPGRADE_PREPARE)), {commands.prepare_payload()})
        self.assertEqual(self.sent(commands.UPGRADE_ANNOUNCE),
                         [commands.announce_payload(self.package.files_size)])
        self.assertEqual(self.sent(commands.UPGRADE_INSTALL), [commands.install_payload()])
        self.assertEqual(self.sent(commands.UPGRADE_RESULT)[-1], commands.result_query_payload())
        self.assertEqual(self.sent(commands.PUSH_CONTROL), [commands.push_control_payload()])


if __name__ == "__main__":
    unittest.main()
