"""dji-duml pack: a package for flash from the files extract recovered."""
import contextlib
import hashlib
import io
import json
import random
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dji_duml.cli import main
from dji_duml.extract import extract
from dji_duml.flasher import UPGRADE_CENTER, Flasher
from dji_duml.pack import PackError, pack
from dji_duml.package import PackageError
from dji_duml.profiles import M4T
from dji_duml.sim import SimulatedM4T
from dji_duml.version import FirmwareVersion
from duml_fixtures import CURRENT, MODULE_DATA, manifest, module_name
from test_duml_extract import Upload

CONFIG = "wa345t.cfg.sig"
SECOND = "wa345t_0100_v17.01.05.16_20260101.pro.fw.sig"
SECOND_DATA = random.Random(5).randbytes(5000)
MODULES = [(module_name(), MODULE_DATA), (SECOND, SECOND_DATA)]


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class PackTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.tmp = Path(self.directory.name)
        self.files = self.tmp / "files"
        self.files.mkdir()
        (self.files / CONFIG).write_bytes(manifest(CURRENT, modules=MODULES))
        for name, data in MODULES:
            (self.files / name).write_bytes(data)
        self.out = self.tmp / "17.01.0516_dji_system.bin"

    def test_package_is_laid_out_like_dji_system_bin(self):
        packed = pack(self.files, self.out)
        self.assertEqual(str(packed.package.version), CURRENT)
        self.assertEqual([item.name for item in packed.package.files],
                         [CONFIG, module_name(), SECOND])
        with tarfile.open(self.out) as archive:
            members = archive.getmembers()
            self.assertEqual([member.name for member in members], [CONFIG, module_name(), SECOND])
            self.assertEqual({member.mtime for member in members}, {0})
            self.assertEqual(archive.extractfile(SECOND).read(), SECOND_DATA)
        self.assertEqual(packed.ignored, ())
        self.assertIn("no report.json", packed.notes[0])
        self.assertEqual(list(self.tmp.glob("*.part")), [])

    def test_same_files_give_the_same_package(self):
        pack(self.files, self.out)
        again = self.tmp / "again.bin"
        pack(self.files, again)
        self.assertEqual(hashlib.md5(self.out.read_bytes()).digest(),
                         hashlib.md5(again.read_bytes()).digest())

    def test_simulated_flash_of_a_packed_package(self):
        packed = pack(self.files, self.out)
        drone = SimulatedM4T(M4T, CURRENT, image_version=CURRENT)
        flasher = Flasher(drone.client, M4T, poll_interval=0.01, reconnect_interval=0.001,
                          command_timeout=0.2, start_timeout=0.2, settle_timeout=0.2,
                          greet_delay=0.01)
        result = flasher.run(packed.package, target=FirmwareVersion.parse(CURRENT),
                             expected_current=FirmwareVersion.parse(CURRENT), confirm=True,
                             procedure=UPGRADE_CENTER, allow_same_version=True, timeout=5)
        self.assertEqual(str(result.installed), CURRENT)
        self.assertEqual(drone.files[SECOND], SECOND_DATA)

    def test_from_extract_output(self):
        upload = Upload()
        upload.send(CONFIG, manifest(CURRENT, modules=MODULES))
        for name, data in MODULES:
            upload.send(name, data)
        extracted = self.tmp / "extracted"
        self.assertTrue(extract(upload.write(self.tmp / "capture.pcap"), extracted).ok)
        packed = pack(extracted, self.out)
        self.assertEqual(packed.notes, ())
        self.assertEqual([item.name for item in packed.package.files],
                         [CONFIG, module_name(), SECOND])

    def test_report_must_vouch_for_the_configuration(self):
        (self.files / "report.json").write_text(json.dumps({"files": [
            {"saved_as": CONFIG, "ok": True, "md5": "00" * 16}]}))
        with self.assertRaisesRegex(PackError, "does not show"):
            pack(self.files, self.out)
        (self.files / "report.json").write_text("{")
        with self.assertRaisesRegex(PackError, "Unreadable"):
            pack(self.files, self.out)

    def test_refusals(self):
        (self.files / SECOND).rename(self.files / (SECOND + ".incomplete"))
        with self.assertRaisesRegex(PackError, "missing, only a copy that failed extraction"):
            pack(self.files, self.out)
        (self.files / (SECOND + ".incomplete")).rename(self.files / SECOND)
        (self.files / SECOND).write_bytes(bytes(len(SECOND_DATA)))
        with self.assertRaisesRegex(PackError, "differs from the size or MD5"):
            pack(self.files, self.out)
        (self.files / SECOND).write_bytes(SECOND_DATA)
        (self.files / "other.cfg.sig").write_bytes(b"x")
        with self.assertRaisesRegex(PackError, "found 2"):
            pack(self.files, self.out)
        (self.files / "other.cfg.sig").unlink()
        self.out.write_bytes(b"old")
        with self.assertRaisesRegex(PackError, "already exists"):
            pack(self.files, self.out)
        self.assertEqual(self.out.read_bytes(), b"old")
        (self.files / CONFIG).write_bytes(b"IM*H no manifest")
        with self.assertRaisesRegex(PackError, "no readable manifest"):
            pack(self.files, self.tmp / "new.bin")
        self.assertFalse((self.tmp / "new.bin").exists())

    def test_failure_while_writing_leaves_nothing(self):
        for target, error in (("tarfile.TarFile.addfile", KeyboardInterrupt),
                              ("dji_duml.pack.verify_files", PackageError("changed"))):
            with self.subTest(target), patch(target, side_effect=error), \
                    self.assertRaises((KeyboardInterrupt, PackError)):
                pack(self.files, self.out)
            self.assertEqual(sorted(path.name for path in self.tmp.iterdir()), ["files"])

    def test_two_sessions_in_one_directory_are_refused(self):
        upload = Upload()
        for version in (CURRENT, "14.01.0012"):
            upload.send(CONFIG, manifest(version, modules=MODULES))
            for name, data in MODULES:
                upload.send(name, data)
        extracted = self.tmp / "extracted"
        extract(upload.write(self.tmp / "capture.pcap"), extracted)
        self.assertTrue((extracted / (CONFIG + ".2")).exists())
        with self.assertRaisesRegex(PackError, "one flashing session per directory"):
            pack(extracted, self.out)
        (extracted / (CONFIG + ".2")).unlink()
        with self.assertRaisesRegex(PackError, "lists 2 flashing sessions"):
            pack(extracted, self.out)

    def test_twice_listed_module_is_refused(self):
        (self.files / CONFIG).write_bytes(manifest(CURRENT, modules=MODULES + MODULES[1:]))
        with self.assertRaises(PackageError):
            pack(self.files, self.out)

    def test_ignored_files_are_named(self):
        (self.files / "notes.txt").write_text("x")
        self.assertEqual(pack(self.files, self.out).ignored, ("notes.txt",))

    def test_cli(self):
        code, out, _ = run("pack", str(self.files), "-o", str(self.out))
        self.assertEqual(code, 0)
        self.assertIn(f"version   {CURRENT}", out)
        self.assertIn(f"--target {CURRENT}", out)
        self.assertIn("--yes", out)
        code, out, _ = run("inspect", str(self.out))
        self.assertEqual(code, 0)
        code, _, err = run("pack", str(self.files), "-o", str(self.out))
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)


if __name__ == "__main__":
    unittest.main()
