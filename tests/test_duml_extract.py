"""dji-duml extract: files rebuilt from the 00/2A frames of a USB capture.

The parity test at the end runs only with a package and a capture of it being
flashed (DJI Assistant's or ours):

    DJI_DUML_PACKAGE=...M4T_UAV_17.02.05.01_pro.zip
    DJI_DUML_CAPTURE=...offline_usb.pcap
"""
import contextlib
import hashlib
import io
import json
import os
import random
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from dji_duml import commands
from dji_duml.cli import main
from dji_duml.extract import REPORT, ExtractError, extract
from dji_duml.flasher import sent_name
from dji_duml.frame import Frame
from dji_duml.package import inspect_package, open_file
from duml_fixtures import CURRENT, MODULE_DATA, manifest, module_name, usbpcap_file, usbpcap_record

HOST, CENTER = 0x2A, 0x48
OUT, IN = 0x04, 0x85
CHUNK = 980
CONFIG = "wa345t.cfg.sig"
SECOND = "wa345t_0100_v17.01.05.16_20260101.pro.fw.sig"
SECOND_DATA = random.Random(2).randbytes(5000)
PACKAGE = os.environ.get("DJI_DUML_PACKAGE")
CAPTURE = os.environ.get("DJI_DUML_CAPTURE")


def open_reply(status=0, chunk=CHUNK):
    return bytes([status]) + chunk.to_bytes(2, "little") + bytes.fromhex("88130101")


class Upload:
    """The frames of an upload to the upgrade center, in capture order."""

    def __init__(self, device=47, sender=HOST):
        self.seq = 0x100
        self.events = []
        self.device, self.sender = device, sender

    def out(self, payload):
        self.seq += 1
        frame = Frame(self.sender, CENTER, self.seq, commands.GENERAL, commands.FILE_TRANSFER,
                      payload)
        self.events.append((OUT, frame.encode(), self.device))
        return frame

    def reply(self, request, payload):
        self.events.append((IN, request.make_reply(payload).encode(), self.device))

    def send(self, name, data, *, md5=None, reply="early", open_answer=None, order=None,
             repeat=(), resend=None, skip=(), end=True, end_answer=b"\x00"):
        opened = self.out(commands.file_open_payload(name, len(data)))
        answer = open_reply() if open_answer is None else open_answer
        if reply == "early":
            self.reply(opened, answer)
        count = -(-len(data) // CHUNK)
        for index in order if order is not None else range(count):
            if index in skip:
                continue
            chunk = data[index * CHUNK:(index + 1) * CHUNK]
            self.out(commands.file_data_payload(index, chunk))
            if index in repeat:
                self.out(commands.file_data_payload(index, chunk))
            if resend and index in resend:
                self.out(commands.file_data_payload(index, resend[index]))
            if index % 8 == 7:  # unsolicited progress report
                self.reply(opened, b"\x00" + index.to_bytes(4, "little"))
        if reply == "late":
            self.reply(opened, answer)
        if end:
            ended = self.out(commands.file_end_payload(md5 or hashlib.md5(data).digest()))
            if reply == "after end":
                self.reply(opened, answer)
            self.reply(ended, end_answer)

    def session(self, modules=None, listed=None):
        """Configuration, then each module, as Assistant sends them."""
        modules = [(module_name(), MODULE_DATA), (SECOND, SECOND_DATA)] if modules is None \
            else modules
        config = manifest(CURRENT, modules=modules if listed is None else listed)
        self.send(CONFIG, config)
        for name, data in modules:
            self.send(name, data)

    def write(self, path, transfer=None):
        """Host bytes go out in USB transfers of ``transfer`` bytes, so frames
        straddle transfers and transfers carry several frames."""
        records, stream, streaming = [], b"", None

        def flush():
            nonlocal stream
            step = transfer or len(stream)
            for start in range(0, len(stream), max(step, 1)):
                records.append(usbpcap_record(OUT, stream[start:start + step], False,
                                              device=streaming))
            stream = b""

        for endpoint, data, device in self.events:
            if endpoint == OUT and transfer:
                if device != streaming:
                    flush()
                    streaming = device
                stream += data
                continue
            flush()
            records.append(usbpcap_record(endpoint, data, endpoint == IN, device=device))
        flush()
        return usbpcap_file(path, records)


def interleave(*uploads):
    """Several uploads in one capture, event by event."""
    merged, queues = Upload(), [list(upload.events) for upload in uploads]
    while any(queues):
        for queue in queues:
            if queue:
                merged.events.append(queue.pop(0))
    return merged


def crc32_twin(data):
    """Two different chunks of the length of ``data`` with the same CRC32:
    appending a message's own CRC32 always gives the same CRC32."""
    head, other = data[:-4], bytes(byte ^ 0xFF for byte in data[:-4])
    return (head + zlib.crc32(head).to_bytes(4, "little"),
            other + zlib.crc32(other).to_bytes(4, "little"))


class ExtractTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.tmp = Path(self.directory.name)
        self.out = self.tmp / "out"

    def run_upload(self, upload, transfer=None):
        capture = upload.write(self.tmp / "capture.pcap", transfer)
        return extract(capture, self.out)

    def by_name(self, result):
        return {item.name: item for item in result.files}

    def test_clean_session_passes_every_check(self):
        upload = Upload()
        upload.session()
        result = self.run_upload(upload)
        self.assertTrue(result.ok)
        self.assertEqual([item.saved_as for item in result.files],
                         [CONFIG, module_name(), SECOND])
        self.assertEqual((self.out / module_name()).read_bytes(), MODULE_DATA)
        self.assertEqual((self.out / SECOND).read_bytes(), SECOND_DATA)
        self.assertEqual(result.sessions[0]["version"], CURRENT)
        self.assertEqual(result.sessions[0]["missing"], [])
        items = self.by_name(result)
        self.assertEqual(items[SECOND].manifest, "matches the manifest")
        self.assertEqual(items[SECOND].notes, [])
        report = json.loads((self.out / REPORT).read_text(encoding="utf-8"))
        self.assertTrue(report["ok"])
        self.assertEqual(report["files"][1]["md5"], hashlib.md5(MODULE_DATA).hexdigest())
        self.assertEqual(sorted(path.name for path in self.out.iterdir()),
                         sorted([REPORT, CONFIG, module_name(), SECOND]))

    def test_frames_straddling_usb_transfers(self):
        for transfer in (1, 333, 4096):
            with self.subTest(transfer=transfer):
                upload = Upload()
                upload.session()
                result = extract(upload.write(self.tmp / f"{transfer}.pcap", transfer),
                                 self.tmp / f"out{transfer}")
                self.assertTrue(result.ok)
                self.assertEqual((self.tmp / f"out{transfer}" / SECOND).read_bytes(),
                                 SECOND_DATA)

    def test_chunks_out_of_order_and_identical_repeats(self):
        upload = Upload()
        upload.send(SECOND, SECOND_DATA, order=[5, 0, 3, 1, 4, 2], repeat={0, 4})
        result = self.run_upload(upload)
        self.assertTrue(result.ok)
        self.assertEqual(result.files[0].duplicates, 2)
        self.assertEqual((self.out / SECOND).read_bytes(), SECOND_DATA)

    def test_missing_chunk_keeps_the_file_incomplete(self):
        upload = Upload()
        upload.send(SECOND, SECOND_DATA, skip={2})
        result = self.run_upload(upload)
        self.assertFalse(result.ok)
        item = result.files[0]
        self.assertEqual(item.saved_as, SECOND + ".incomplete")
        self.assertIn("1 of 6 chunk(s) missing", item.problems)
        self.assertIn("MD5 differs from the end frame", item.problems)
        self.assertFalse((self.out / SECOND).exists())

    def test_repeat_with_different_data(self):
        upload = Upload()
        upload.send(SECOND, SECOND_DATA, resend={1: bytes(CHUNK)})
        item = self.run_upload(upload).files[0]
        self.assertEqual(item.problems, ["1 chunk(s) repeated with different data"])
        self.assertEqual(item.saved_as, SECOND + ".incomplete")

    def test_repeat_with_the_same_crc32_is_still_a_conflict(self):
        first, twin = crc32_twin(SECOND_DATA[CHUNK:2 * CHUNK])
        self.assertEqual(zlib.crc32(first), zlib.crc32(twin))
        self.assertNotEqual(first, twin)
        data = SECOND_DATA[:CHUNK] + first + SECOND_DATA[2 * CHUNK:]
        upload = Upload()
        upload.send(SECOND, data, resend={1: twin})
        item = self.run_upload(upload).files[0]
        self.assertEqual(item.problems, ["1 chunk(s) repeated with different data"])

    def test_md5_of_the_end_frame(self):
        upload = Upload()
        upload.send(SECOND, SECOND_DATA, md5=bytes(16))
        item = self.run_upload(upload).files[0]
        self.assertEqual(item.problems, ["MD5 differs from the end frame"])

    def test_module_differs_from_the_signed_manifest(self):
        other = bytes(len(SECOND_DATA))
        upload = Upload()
        upload.session(modules=[(SECOND, SECOND_DATA)], listed=[(SECOND, other)])
        result = self.run_upload(upload)
        item = self.by_name(result)[SECOND]
        self.assertEqual(item.manifest, "differs from the manifest")
        self.assertEqual(item.problems, ["size or MD5 differs from the signed manifest"])
        self.assertEqual(item.saved_as, SECOND + ".incomplete")
        self.assertFalse(result.ok)

    def test_module_listed_but_never_sent(self):
        upload = Upload()
        upload.session(modules=[(SECOND, SECOND_DATA)],
                       listed=[(module_name(), MODULE_DATA), (SECOND, SECOND_DATA)])
        result = self.run_upload(upload)
        self.assertTrue(all(item.ok for item in result.files))
        self.assertEqual(result.sessions[0]["missing"], [module_name()])
        self.assertFalse(result.ok)

    def test_file_not_in_the_manifest(self):
        upload = Upload()
        upload.session(modules=[(SECOND, SECOND_DATA)])
        upload.send(module_name(), MODULE_DATA)
        result = self.run_upload(upload)
        item = self.by_name(result)[module_name()]
        self.assertEqual(item.problems, ["not listed in the signed manifest"])
        self.assertEqual(result.sessions[0]["unlisted"], [module_name()])

    def test_files_without_a_manifest(self):
        upload = Upload()
        upload.send(SECOND, SECOND_DATA)
        result = self.run_upload(upload)
        self.assertTrue(result.ok)
        self.assertEqual(result.files[0].manifest, "no manifest in the capture")

    def test_file_sent_before_the_manifest(self):
        upload = Upload()
        upload.send(SECOND, bytes(len(SECOND_DATA)))
        upload.session(modules=[(SECOND, SECOND_DATA)])
        result = self.run_upload(upload)
        early = result.files[0]
        self.assertEqual(early.problems, ["sent before the .cfg.sig, so not checked against it"])
        self.assertEqual(early.saved_as, SECOND + ".incomplete")
        self.assertEqual(result.files[2].saved_as, SECOND)
        self.assertEqual((self.out / SECOND).read_bytes(), SECOND_DATA)
        self.assertFalse(result.ok)

    def test_files_after_an_unusable_manifest_fail(self):
        upload = Upload()
        upload.send(CONFIG, manifest(CURRENT, modules=[(SECOND, SECOND_DATA)]), skip={0})
        upload.send(SECOND, bytes(len(SECOND_DATA)))
        result = self.run_upload(upload)
        self.assertEqual(result.sessions[0]["error"], "the configuration did not arrive intact")
        self.assertEqual(result.files[1].problems,
                         ["not checked: the manifest before it is unusable"])
        self.assertEqual(result.files[1].saved_as, SECOND + ".incomplete")

    def test_malformed_manifests_are_refused_not_crashed_on(self):
        twice = manifest(CURRENT, modules=[(SECOND, SECOND_DATA),
                                           (SECOND, bytes(len(SECOND_DATA)))])
        superscript = manifest(CURRENT, modules=[(SECOND, SECOND_DATA)]).replace(
            f'size="{len(SECOND_DATA)}"'.encode(), 'size="²"'.encode())
        for number, (config, error) in enumerate(((twice, "lists a module file twice"),
                                                  (superscript, "Malformed module entry"))):
            with self.subTest(error=error):
                upload = Upload()
                upload.send(CONFIG, config)
                upload.send(SECOND, SECOND_DATA)
                result = extract(upload.write(self.tmp / f"{number}.pcap"),
                                 self.tmp / f"out{number}")
                self.assertIn(error, result.sessions[0]["error"])
                self.assertFalse(result.files[1].ok)

    def test_two_drones_in_one_capture(self):
        first, second = Upload(device=47), Upload(device=48)
        first.session()
        second.session(modules=[(SECOND, SECOND_DATA)])
        for transfer in (None, 333):
            with self.subTest(transfer=transfer):
                result = extract(interleave(first, second).write(self.tmp / "two.pcap", transfer),
                                 self.tmp / f"two{transfer}")
                self.assertTrue(result.ok,
                                [item.report() for item in result.files if not item.ok])
                self.assertEqual([session["usb"] for session in result.sessions],
                                 ["1:47", "1:48"])

    def test_capture_cut_before_the_end(self):
        upload = Upload()
        upload.send(SECOND, SECOND_DATA, end=False)
        item = self.run_upload(upload).files[0]
        self.assertEqual(item.problems, ["no end frame for this file"])
        self.assertEqual(item.saved_as, SECOND + ".incomplete")

    def test_next_file_opened_before_the_end(self):
        upload = Upload()
        upload.send(SECOND, SECOND_DATA, end=False)
        upload.send(module_name(), MODULE_DATA)
        result = self.run_upload(upload)
        first, second = result.files
        self.assertIn("the host opened the next file before ending this one", first.problems)
        self.assertTrue(second.ok)

    def test_open_reply_after_the_data(self):
        upload = Upload()
        upload.send(SECOND, SECOND_DATA, reply="late", order=[5, 4, 3, 2, 1, 0])
        result = self.run_upload(upload)
        self.assertTrue(result.ok)
        self.assertEqual(result.files[0].notes, [])
        self.assertEqual((self.out / SECOND).read_bytes(), SECOND_DATA)

    def test_open_reply_after_the_end_of_a_one_chunk_file(self):
        upload = Upload()
        upload.send(SECOND, SECOND_DATA[:300], reply="after end")
        item = self.run_upload(upload).files[0]
        self.assertTrue(item.ok, item.problems)
        self.assertEqual(item.notes, [])

    def test_no_open_reply_infers_the_chunk_size(self):
        big = random.Random(3).randbytes(CHUNK * 300 + 17)
        upload = Upload()
        upload.send(SECOND, big, reply=None)
        result = self.run_upload(upload)
        self.assertTrue(result.ok)
        self.assertEqual(result.files[0].chunk_size, CHUNK)
        self.assertIn("no open reply in the capture; chunk size taken from the data",
                      result.files[0].notes)
        self.assertEqual((self.out / SECOND).read_bytes(), big)

    def test_device_rejections(self):
        upload = Upload()
        upload.send(SECOND, SECOND_DATA, end_answer=b"\x0b")
        upload.send(module_name(), MODULE_DATA, open_answer=open_reply(0x05), end=False,
                    skip=range(30))
        first, second = self.run_upload(upload).files
        self.assertEqual(first.problems, ["the device rejected the file: status 0x0b"])
        self.assertIn("the device rejected the open: status 0x05", second.problems)

    def test_short_rejections_count_too(self):
        upload = Upload()
        upload.send(SECOND, SECOND_DATA, open_answer=b"\x05")
        upload.send(module_name(), MODULE_DATA, end_answer=b"\x0b\x00")
        first, second = self.run_upload(upload).files
        self.assertIn("the device rejected the open: status 0x05", first.problems)
        self.assertEqual(second.problems, ["the device rejected the file: status 0x0b"])

    def test_repeated_open_is_one_transfer(self):
        upload = Upload()
        upload.out(commands.file_open_payload(SECOND, len(SECOND_DATA)))
        upload.send(SECOND, SECOND_DATA)
        result = self.run_upload(upload)
        self.assertEqual(len(result.files), 1)
        self.assertTrue(result.ok)

    def test_disk_use_is_bounded_by_the_capture(self):
        upload = Upload()
        opened = upload.out(commands.file_open_payload(SECOND, 1 << 30))
        upload.reply(opened, open_reply())
        upload.out(commands.file_data_payload(1_000_000, bytes(CHUNK)))
        upload.out(commands.file_end_payload(bytes(16)))
        capture = upload.write(self.tmp / "capture.pcap")
        item = extract(capture, self.out).files[0]
        self.assertIn("1 chunk(s) lie beyond the data in the capture", item.problems)
        self.assertLessEqual((self.out / item.saved_as).stat().st_size, capture.stat().st_size)

    def test_too_many_files_open_at_once(self):
        uploads = []
        for sender in range(20):
            upload = Upload(sender=sender)
            upload.out(commands.file_open_payload(f"f{sender}.bin", 10))
            uploads.append(upload)
        result = self.run_upload(interleave(*uploads))
        self.assertEqual(len(result.files), 20)
        self.assertEqual(sum("too many files open at once on this device" in item.problems
                             for item in result.files), 4)

    def test_unsafe_names_are_not_used(self):
        upload = Upload()
        for name in ("../../evil.bin", "CON.txt", "a\x1b[2Jb", "C:x",
                     SECOND + ".incomplete"):
            upload.send(name, SECOND_DATA)
        result = self.run_upload(upload)
        self.assertTrue(result.ok)
        self.assertEqual([item.saved_as for item in result.files],
                         [f"transfer-{n:03d}.bin" for n in range(1, 6)])
        self.assertEqual(result.files[2].name, "a\\x1b[2Jb")
        self.assertFalse((self.tmp / "evil.bin").exists())
        self.assertEqual(sorted(path.name for path in self.tmp.iterdir()), ["capture.pcap", "out"])

    def test_same_name_twice(self):
        upload = Upload()
        for skip in ((), (), {1}, {1}):
            upload.send(SECOND, SECOND_DATA, skip=skip)
        result = self.run_upload(upload)
        self.assertEqual([item.saved_as for item in result.files],
                         [SECOND, SECOND + ".2", SECOND + ".incomplete",
                          SECOND + ".2.incomplete"])

    def test_a_name_that_cannot_be_created_falls_back(self):
        upload = Upload()
        upload.send(SECOND, SECOND_DATA)
        original = Path.replace

        def no_long_names(path, target):
            if Path(target).name == SECOND:
                raise OSError("path too long")
            return original(path, target)

        with patch.object(Path, "replace", no_long_names):
            item = self.run_upload(upload).files[0]
        self.assertTrue(item.ok)
        self.assertEqual(item.saved_as, "transfer-001.bin")
        self.assertIn("the announced name could not be created here", item.notes)

    def test_failure_while_saving_leaves_the_directory_empty(self):
        upload = Upload()
        upload.send(SECOND, SECOND_DATA)
        upload.send(module_name(), MODULE_DATA)
        capture = upload.write(self.tmp / "capture.pcap")
        original, calls = Path.replace, []

        def flaky(path, target):
            calls.append(target)
            if len(calls) > 1:
                raise OSError("disk full")
            return original(path, target)

        with patch.object(Path, "replace", flaky), self.assertRaises(OSError):
            extract(capture, self.out)
        self.assertEqual(list(self.out.iterdir()), [])
        self.assertTrue(extract(capture, self.out).ok)

    def test_output_must_be_new_or_empty(self):
        upload = Upload()
        upload.send(SECOND, SECOND_DATA)
        capture = upload.write(self.tmp / "capture.pcap")
        self.out.mkdir()
        (self.out / "old").write_bytes(b"")
        with self.assertRaises(ExtractError):
            extract(capture, self.out)

    def test_unreadable_capture_creates_nothing(self):
        with self.assertRaises(OSError):
            extract(self.tmp / "missing.pcap", self.out)
        self.assertFalse(self.out.exists())

    def test_cli_exit_codes(self):
        good, bad = Upload(), Upload()
        good.session()
        bad.send(SECOND, SECOND_DATA, skip={0}, reply=None)
        for upload, code in ((good, 0), (bad, 2)):
            capture = upload.write(self.tmp / f"{code}.pcap")
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["extract", str(capture), "-o", str(self.tmp / str(code))]),
                                 code)
            self.assertIn("report:", out.getvalue())
            if code:
                self.assertIn("FAIL", out.getvalue())
                self.assertIn("note: no open reply in the capture", out.getvalue())
                self.assertIn("NOT a complete, verified set of files", out.getvalue())
            else:
                self.assertIn(f"Manifest {CONFIG} (USB 1:47): version {CURRENT}",
                              out.getvalue())


@unittest.skipUnless(PACKAGE and CAPTURE, "set DJI_DUML_PACKAGE and DJI_DUML_CAPTURE")
class CaptureParityTest(unittest.TestCase):
    def test_extracted_files_equal_the_package(self):
        package = inspect_package(PACKAGE)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            result = extract(CAPTURE, out)
            self.assertTrue(result.ok, [item.report() for item in result.files if not item.ok])
            names = [sent_name(package, position) for position in range(len(package.files))]
            self.assertEqual([item.saved_as for item in result.files], names)
            for name, item in zip(names, package.files):
                with open_file(package, item.name) as theirs, open(out / name, "rb") as ours:
                    while block := theirs.read(1 << 20):
                        self.assertEqual(ours.read(len(block)), block, name)
                    self.assertEqual(ours.read(1), b"", name)


if __name__ == "__main__":
    unittest.main()
