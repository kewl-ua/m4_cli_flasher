"""The upgrade-center procedure (DJI Assistant's, for the M4T) on SimulatedM4T."""
import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from dji_duml import commands
from dji_duml.errors import FlashAborted, FlashFailed, FlashOutcomeUnknown, FlashRefused
from dji_duml.flasher import UPGRADE_CENTER, Flasher, Stage, plan
from dji_duml.frame import Frame
from dji_duml.journal import Journal
from dji_duml.package import inspect_package
from dji_duml.profiles import M4T
from dji_duml.sim import SimulatedM4T
from dji_duml.version import FirmwareVersion
from duml_fixtures import CURRENT, MODULE_DATA, TARGET, make_tar, make_zip, manifest, module_name

CENTER = M4T.upgrade_center
CHANGING = {commands.UPGRADE_PREPARE, commands.UPGRADE_ANNOUNCE, commands.FILE_TRANSFER,
            commands.UPGRADE_INSTALL}


class CenterTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.package = inspect_package(make_tar(self.directory.name))
        self.stages = []

    def flash(self, drone, **options):
        journal = options.pop("journal", None)
        options.setdefault("target", FirmwareVersion.parse(TARGET))
        options.setdefault("expected_current", FirmwareVersion.parse(CURRENT))
        flasher = Flasher(
            drone.client, M4T, journal=journal,
            on_progress=lambda progress: self.stages.append(progress.stage),
            poll_interval=0.01, reconnect_interval=0.001, command_timeout=0.2,
            start_timeout=0.2, settle_timeout=0.2, greet_delay=0.01,
        )
        return flasher.run(self.package, confirm=True, accept_unverified=True,
                           procedure=UPGRADE_CENTER, timeout=options.pop("timeout", 5), **options)

    def center_commands(self, drone):
        return [frame.cmd_id for frame in drone.received
                if frame.receiver == CENTER and not frame.response]

    def test_upgrade_through_reboots_as_assistant_does_it(self):
        for reboots in (1, 2):
            with self.subTest(reboots=reboots):
                drone = SimulatedM4T(M4T, CURRENT, image_version=TARGET, reboots=reboots)
                result = self.flash(drone)
                self.assertEqual(str(result.installed), TARGET)
                self.assertTrue(result.completion_observed)
                self.assertEqual(drone.errors, [])
                self.assertEqual(list(drone.files), ["wa345t.cfg.sig", module_name()])
                self.assertEqual(drone.files[module_name()], MODULE_DATA)
                self.assertEqual(drone.announced_total, self.package.files_size)
                sent = self.center_commands(drone)
                self.assertEqual(sent[:2], [commands.UPGRADE_PREPARE, commands.UPGRADE_ANNOUNCE])
                self.assertEqual(sent[-3:], [commands.UPGRADE_INSTALL, commands.UPGRADE_RESULT,
                                             commands.PUSH_CONTROL])
                for once in CHANGING - {commands.FILE_TRANSFER}:
                    self.assertEqual(sent.count(once), 1)
                self.assertTrue(drone.finished)
                self.assertEqual(drone.host_answers[commands.CENTER_INFO],
                                 commands.CENTER_INFO_REPLY)
                self.assertEqual(drone.host_answers[commands.CENTER_STATE], b"\x00")
                # One full greeting at the start and one after every reboot.
                self.assertEqual(drone.greeted, 4 * (1 + reboots))
                self.assertIn(Stage.REBOOT, self.stages)
                # After Complete only the version is read back: not a reboot.
                self.assertEqual(self.stages[-2:], [Stage.CONFIRM, Stage.DONE])

    def test_offline_zip_is_sent_like_assistant_sends_it(self):
        self.package = inspect_package(make_zip(self.directory.name, "offline.zip",
                                                content=manifest()))
        drone = SimulatedM4T(M4T, CURRENT, image_version=TARGET)
        self.flash(drone)
        self.assertEqual(list(drone.files), ["wa345t.cfg.sig", module_name()])

    def test_same_version_refresh_is_proven_by_completion(self):
        drone = SimulatedM4T(M4T, TARGET, image_version=TARGET)
        result = self.flash(drone, expected_current=FirmwareVersion.parse(TARGET),
                            allow_same_version=True)
        self.assertTrue(result.completion_observed)

    def test_window_never_runs_ahead_of_the_progress_reports(self):
        big = bytes(range(256)) * 400  # 102400 bytes, 105 chunks
        drone = SimulatedM4T(M4T, CURRENT, image_version=TARGET, progress_every=7)
        with patch("dji_duml.flasher.WINDOW", 10):
            self.package = inspect_package(self._tar_with(big))
            self.flash(drone)
        self.assertEqual(drone.errors, [])
        self.assertEqual(drone.files[module_name()], big)
        self.assertLessEqual(drone.max_ahead, 10)

    def _tar_with(self, data):
        import io
        import tarfile
        path = Path(self.directory.name) / "window.bin"
        with tarfile.open(path, "w") as archive:
            for name, content in (("wa345t.cfg.sig", manifest(modules=[(module_name(), data)])),
                                  (module_name(), data)):
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        return path

    def test_zero_version_after_reboot_means_not_ready(self):
        drone = SimulatedM4T(M4T, CURRENT, image_version=TARGET, zero_version_reads=4)
        path = Path(self.directory.name) / "journal.jsonl"
        with Journal(path) as journal:
            result = self.flash(drone, journal=journal)
        self.assertEqual(str(result.installed), TARGET)
        self.assertIn('"version-not-ready"', path.read_text())

    # -- refused / aborted: the installation never starts -------------------------

    def test_package_that_does_not_match_its_manifest_is_refused_before_usb(self):
        tampered = make_tar(self.directory.name, "tampered.bin",
                            content=manifest(modules=[(module_name(), bytes(len(MODULE_DATA)))]))
        self.package = inspect_package(tampered)
        drone = SimulatedM4T(M4T, CURRENT, image_version=TARGET)
        with self.assertRaisesRegex(FlashRefused, "does not match the MD5"):
            self.flash(drone)
        self.assertEqual(drone.received, [])

    def test_failures_before_install_never_send_install(self):
        cases = [
            ("prepare rejected", dict(reject={commands.UPGRADE_PREPARE: 0xE0}), "did not accept"),
            ("prepare silent", dict(silent=frozenset({commands.UPGRADE_PREPARE})), "did not accept"),
            ("end rejected", dict(end_status={module_name(): 0xE1}), "End of"),
            ("no progress", dict(mute_progress=True), "stopped acknowledging"),
            ("link lost", dict(stop_after_files=1), "not started"),
        ]
        for name, options, message in cases:
            with self.subTest(case=name):
                drone = SimulatedM4T(M4T, CURRENT, image_version=TARGET, **options)
                with self.assertRaisesRegex(FlashAborted, message):
                    self.flash(drone)
                self.assertNotIn(commands.UPGRADE_INSTALL, self.center_commands(drone))
                self.assertEqual(drone.firmware, FirmwareVersion.parse(CURRENT))

    # -- failed / unknown -------------------------------------------------------------

    def test_device_reported_failure(self):
        drone = SimulatedM4T(M4T, CURRENT, image_version=TARGET, fail_result=9)
        with self.assertRaisesRegex(FlashFailed, "IllegalDegrade"):
            self.flash(drone)

    def test_unacknowledged_install_without_pushes_is_unknown(self):
        drone = SimulatedM4T(M4T, CURRENT, image_version=TARGET,
                             silent=frozenset({commands.UPGRADE_INSTALL}))
        with self.assertRaisesRegex(FlashOutcomeUnknown, "neither acknowledged"):
            self.flash(drone)
        self.assertEqual(self.center_commands(drone).count(commands.UPGRADE_INSTALL), 1)

    def test_installed_version_other_than_target_is_unknown(self):
        drone = SimulatedM4T(M4T, CURRENT, image_version=TARGET, install=False)
        with self.assertRaisesRegex(FlashOutcomeUnknown, f"reports {CURRENT} installed"):
            self.flash(drone)

    def test_status_from_another_module_is_not_the_verdict(self):
        drone = SimulatedM4T(M4T, TARGET, image_version=TARGET, reboots=0)
        finish = drone._finish_install

        def foreign_success_first(link):
            link.out += Frame(0x1F, 0x2A, 1, 0, commands.UPGRADE_STATUS, bytes([4, 1, 0]),
                              ack=0).encode()
            finish(link)

        drone._finish_install = foreign_success_first
        path = Path(self.directory.name) / "journal.jsonl"
        with Journal(path) as journal:
            result = self.flash(drone, expected_current=FirmwareVersion.parse(TARGET),
                                allow_same_version=True, journal=journal)
        self.assertTrue(result.completion_observed)
        self.assertIn('"status-ignored"', path.read_text())

    # -- dry run ------------------------------------------------------------------------

    # -- regressions found by independent review ------------------------------------

    def _tar_of(self, name, modules):
        import io
        import tarfile
        path = Path(self.directory.name) / name
        with tarfile.open(path, "w") as archive:
            for member, content in (("wa345t.cfg.sig", manifest(modules=modules)), *modules):
                info = tarfile.TarInfo(member)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        return path

    def test_progress_left_over_from_the_previous_file_is_not_taken_for_the_next(self):
        # The device repeats a file's last report between the end and its reply
        # (captured); for the next file that value is stale.
        first, second = bytes(range(256)) * 80, bytes(reversed(range(256))) * 400
        self.package = inspect_package(self._tar_of("two.bin", [
            ("wa345t_1200_v01.35.01.13_20231229_mc01.pro.fw.sig", first),
            ("wa345t_0802_v10.00.21.17_20260529.ar0.pro.fw.sig", second)]))
        drone = SimulatedM4T(M4T, CURRENT, image_version=TARGET, progress_every=7)
        path = Path(self.directory.name) / "journal.jsonl"
        with patch("dji_duml.flasher.WINDOW", 10), Journal(path) as journal:
            self.flash(drone, journal=journal)
        self.assertEqual(drone.errors, [])
        self.assertLessEqual(drone.max_ahead, 10)
        self.assertEqual(drone.files["wa345t_0802_v10.00.21.17_20260529.ar0.pro.fw.sig"], second)

    def lossy_flash(self, label, lose, **options):
        drone = SimulatedM4T(M4T, CURRENT, image_version=TARGET,
                             progress_every=options.pop("progress_every", 4), lose=lose,
                             tick=0.005, **options)
        path = Path(self.directory.name) / f"{label}.jsonl"
        with patch("dji_duml.flasher.TAIL_WAIT", 0.03), \
                patch("dji_duml.flasher.RESEND_RETRY", 0.03), Journal(path) as journal:
            result = self.flash(drone, journal=journal)
        self.assertEqual(str(result.installed), TARGET)
        self.assertEqual(drone.errors, [])
        self.assertEqual(drone.duplicates, [])
        self.assertEqual(drone.files[module_name()], MODULE_DATA)
        return drone, path.read_text()

    def test_lost_chunks_are_sent_again_as_assistant_does(self):
        # Assistant's 2026-10-05 capture: the device twice reported one chunk
        # missing in place of a progress report, and Assistant sent it again.
        # The device learns of a gap when a later chunk arrives.
        config_chunks = -(-self.package.files[0].size // 980)
        cases = {"mid-file": {(1, 5)}, "configuration": {(0, 0)},
                 "two in a row": {(1, 3), (1, 4)}, "two gaps": {(1, 2), (1, 9)},
                 "every other": {(1, index) for index in range(0, 20, 2)}}
        for label, lose in cases.items():
            with self.subTest(label):
                drone, journal = self.lossy_flash(label, lose)
                self.assertEqual(sorted(drone.lost), sorted(lose))
                self.assertEqual(sorted(drone.resent), sorted(lose))
                self.assertIn('"chunks-resent"', journal)
        # Nothing follows a lost last chunk, so the device cannot report it:
        # the tail goes again once the report stays short of the end.
        for label, lose in {"last chunk": {(1, 20)}, "last two": {(1, 19), (1, 20)},
                            "configuration's last": {(0, config_chunks - 1)}}.items():
            with self.subTest(label):
                drone, journal = self.lossy_flash(label, lose)
                self.assertEqual(sorted(drone.lost), sorted(lose))
                self.assertIn('"tail": true', journal)

    def test_a_chunk_lost_again_is_sent_once_more(self):
        drone, _ = self.lossy_flash("twice", {(1, 5): 2, (1, 20): 2})
        self.assertEqual(drone.lost.count((1, 5)), 2)
        self.assertEqual(drone.resent, [(1, 5)])

    def test_reports_read_in_a_burst_get_one_resend(self):
        drone, _ = self.lossy_flash("burst", {(1, 5)}, repeat_reports=6)
        self.assertEqual(drone.resent, [(1, 5)])

    def test_loss_at_the_edge_of_the_window(self):
        with patch("dji_duml.flasher.WINDOW", 10):
            drone, _ = self.lossy_flash("window", {(1, 9), (1, 10), (1, 11)})
        self.assertLessEqual(drone.max_ahead, 13)

    def test_chunks_no_longer_kept_are_read_from_the_package_again(self):
        for kind in ("tar", "zip"):
            with self.subTest(kind):
                if kind == "zip":
                    self.package = inspect_package(make_zip(self.directory.name, "offline.zip",
                                                            content=manifest()))
                with patch("dji_duml.flasher.RESEND_BUFFER", 2):
                    _, journal = self.lossy_flash(kind, {(1, 5)})
                self.assertIn('"reread": true', journal)

    def test_a_gap_that_never_fills_stops_like_any_stall(self):
        drone = SimulatedM4T(M4T, CURRENT, image_version=TARGET, progress_every=4,
                             lose={(1, 5): 10 ** 6})
        started = time.monotonic()
        with patch("dji_duml.flasher.RESEND_RETRY", 0.01), \
                self.assertRaisesRegex(FlashAborted, "stopped acknowledging"):
            self.flash(drone)
        self.assertLess(time.monotonic() - started, 3)
        self.assertNotIn(commands.UPGRADE_INSTALL, self.center_commands(drone))

    def test_gap_report_for_chunks_never_sent_aborts(self):
        from dji_duml.flasher import _Resend
        flasher = Flasher(lambda: None, M4T)
        resend = _Resend(self.package, module_name(), module_name(), 980)
        with self.assertRaisesRegex(FlashAborted, "asks for chunks 50\\+1"):
            flasher._send_again(None, (10, 50, 1), 20, module_name(), resend, 0.0)
        gap = b"\x00" + (10).to_bytes(4, "little") + (50).to_bytes(4, "little") \
            + (1).to_bytes(4, "little")
        self.assertEqual(commands.parse_file_gap(gap), (10, 50, 1))

    def test_unreadable_package_after_announce_is_not_started(self):
        drone = SimulatedM4T(M4T, CURRENT, image_version=TARGET)
        real = __import__("dji_duml.package", fromlist=["open_file"]).open_file

        def failing(package, name):
            if name == module_name():
                raise OSError(5, "Input/output error")
            return real(package, name)

        with patch("dji_duml.flasher.open_file", failing), \
                self.assertRaisesRegex(FlashAborted, "OSError.*not started"):
            self.flash(drone)
        self.assertNotIn(commands.UPGRADE_INSTALL, self.center_commands(drone))

    def test_package_error_during_transfer_is_an_abort(self):
        from dji_duml.errors import PackageError
        drone = SimulatedM4T(M4T, CURRENT, image_version=TARGET)
        real = __import__("dji_duml.package", fromlist=["open_file"]).open_file

        def failing(package, name):
            if name == module_name():
                raise PackageError("Cannot read the module from the package.")
            return real(package, name)

        with patch("dji_duml.flasher.open_file", failing), \
                self.assertRaisesRegex(FlashAborted, "PackageError.*not started"):
            self.flash(drone)

    def test_rejected_open_is_reported_at_once(self):
        drone = SimulatedM4T(M4T, CURRENT, reject={commands.FILE_TRANSFER: 0xE3})
        with self.assertRaisesRegex(FlashAborted, "Open of wa345t.cfg.sig: status 0xE3"):
            self.flash(drone)
        self.assertNotIn(commands.UPGRADE_INSTALL, self.center_commands(drone))

    def test_without_the_centers_verdict_a_new_version_is_not_success(self):
        drone = SimulatedM4T(M4T, CURRENT, image_version=TARGET)

        def install_silently(link):
            drone.firmware = drone.image_version  # main firmware changed, no verdict

        drone._finish_install = install_silently
        with self.assertRaisesRegex(FlashOutcomeUnknown, "verdict .Complete. was not received"):
            self.flash(drone, timeout=0.5)

    def test_plan_lists_the_frames_assistant_sends(self):
        lines = plan(M4T, self.package)
        def hex_bytes(line):
            tokens = line.split()[1:]
            return bytes.fromhex("".join(
                token for token in tokens
                if len(token) == 2 and all(c in "0123456789abcdef" for c in token)))

        frames = [Frame.decode(raw) for raw in map(hex_bytes, lines) if len(raw) >= 13]
        center = [frame for frame in frames if frame.receiver == CENTER]
        self.assertEqual([frame.cmd_id for frame in center],
                         [0x83, 0x84, 0x2A, 0x2A, 0x2A, 0x2A, 0x85, 0x4F, 0x41])
        self.assertEqual(center[2].payload,
                         commands.file_open_payload("wa345t.cfg.sig", self.package.files[0].size))
        self.assertEqual(center[5].payload,
                         commands.file_end_payload(hashlib.md5(MODULE_DATA).digest()))


if __name__ == "__main__":
    unittest.main()
