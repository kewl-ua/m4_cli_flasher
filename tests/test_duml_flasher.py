import tempfile
import unittest
from pathlib import Path

from dji_duml import commands
from dji_duml.errors import (
    FlashAborted, FlashFailed, FlashOutcomeUnknown, FlashRefused, TransportError,
)
from dji_duml.flasher import LEGACY_FTP, DeviceLock, Flasher, Stage, plan
from dji_duml.frame import Frame
from dji_duml.journal import Journal
from dji_duml.package import inspect_package
from dji_duml.profiles import M4T
from dji_duml.sim import SimulatedDrone
from dji_duml.version import FirmwareVersion
from duml_fixtures import CURRENT, TARGET, make_tar, make_zip

WRITES = {commands.ENTER_UPGRADE, commands.UPGRADE_REPORT, commands.UPGRADE_DATA_SIZE,
          commands.UPGRADE_VERIFY}


class FlasherTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.package = inspect_package(make_tar(self.directory.name))
        self.stages = []

    def flasher(self, drone, **options):
        options.setdefault("upload", drone.upload)
        return Flasher(
            drone.client, M4T, on_progress=lambda progress: self.stages.append(progress.stage),
            poll_interval=0.01, reconnect_interval=0.001, command_timeout=0.05,
            start_timeout=0.05, settle_timeout=0.05, upload_stop_timeout=1, **options,
        )

    def run_flash(self, drone, **options):
        flasher_options = {key: options.pop(key) for key in ("upload", "journal")
                           if key in options}
        options.setdefault("target", FirmwareVersion.parse(TARGET))
        options.setdefault("expected_current", FirmwareVersion.parse(CURRENT))
        options.setdefault("confirm", True)
        options.setdefault("accept_unverified", True)
        options.setdefault("timeout", 5)
        options.setdefault("procedure", LEGACY_FTP)
        return self.flasher(drone, **flasher_options).run(self.package, **options)

    def sent(self, drone):
        return [frame.cmd_id for frame in drone.received]

    def assert_no_write_repeated(self, drone):
        for cmd_id in WRITES:
            self.assertLessEqual(self.sent(drone).count(cmd_id), 1, f"cmd {cmd_id:#04x} repeated")

    # -- success ---------------------------------------------------------------

    def test_successful_upgrade_sends_each_write_once_in_order(self):
        for read_size in (None, 5):  # 5: frames trickle in over many USB reads
            with self.subTest(read_size=read_size):
                self.stages = []
                drone = SimulatedDrone(M4T, CURRENT, image_version=TARGET, read_size=read_size)
                result = self.run_flash(drone)
                self.assertEqual((str(result.previous), str(result.installed)), (CURRENT, TARGET))
                self.assertTrue(result.completion_observed)
                self.assertEqual(self.sent(drone), [0x01, 0x07, 0x0C, 0x08, 0x0A, 0x01])
                self.assertEqual(drone.uploads, 1)
                self.assertEqual(drone.announced_size, self.package.size)
                self.assertEqual(self.stages[0], Stage.PREFLIGHT)
                self.assertEqual(self.stages[-1], Stage.DONE)

    def test_link_loss_during_upgrade_is_resolved_by_version_readback(self):
        drone = SimulatedDrone(M4T, CURRENT, image_version=TARGET, drop_link_at=50,
                               boot_attempts=4)
        result = self.run_flash(drone)
        self.assertEqual(str(result.installed), TARGET)
        self.assertFalse(result.completion_observed)
        self.assert_no_write_repeated(drone)

    def test_same_version_requires_explicit_refresh(self):
        drone = SimulatedDrone(M4T, TARGET, image_version=TARGET)
        with self.assertRaisesRegex(FlashRefused, "already runs"):
            self.run_flash(drone, expected_current=FirmwareVersion.parse(TARGET))
        self.assertEqual(self.sent(drone), [0x01])
        result = self.run_flash(drone, expected_current=FirmwareVersion.parse(TARGET),
                                allow_same_version=True)
        self.assertEqual(str(result.installed), TARGET)

    def test_journal_has_begin_frames_and_end(self):
        path = Path(self.directory.name) / "journal.jsonl"
        drone = SimulatedDrone(M4T, CURRENT, image_version=TARGET)
        with Journal(path) as journal:
            Flasher(lambda: drone.client(journal), M4T, journal=journal, upload=drone.upload,
                    reconnect_interval=0.001, settle_timeout=0.05).run(
                self.package, target=FirmwareVersion.parse(TARGET),
                expected_current=FirmwareVersion.parse(CURRENT), confirm=True,
                accept_unverified=True, procedure=LEGACY_FTP)
        text = path.read_text()
        for marker in ('"flash-begin"', self.package.sha256, '"tx"', '"rx"', '"device"',
                       '"flash-end", "ok": true'):
            self.assertIn(marker, text)

    # -- refused: nothing device-changing is sent ------------------------------

    def test_preconditions_refuse_before_any_write(self):
        zip_package = inspect_package(make_zip(self.directory.name))
        other = inspect_package(make_tar(self.directory.name, "other.bin", "wm220.cfg.sig"))
        cases = [
            ("no confirm", SimulatedDrone(M4T, CURRENT), dict(confirm=False), None),
            ("unverified", SimulatedDrone(M4T, CURRENT), dict(accept_unverified=False), None),
            ("procedure", SimulatedDrone(M4T, CURRENT), dict(procedure="magic"), None),
            ("zip", SimulatedDrone(M4T, CURRENT), {}, zip_package),
            ("product", SimulatedDrone(M4T, CURRENT), {}, other),
            ("current", SimulatedDrone(M4T, "17.00.0001"), {}, None),
            ("hardware", SimulatedDrone(M4T, CURRENT, hardware="WM220 AC Ver.A"), {}, None),
            ("no reply", SimulatedDrone(M4T, CURRENT, silent=frozenset({0x01})), {}, None),
        ]
        for name, drone, options, package in cases:
            with self.subTest(case=name):
                if package is not None:
                    self.package = package
                with self.assertRaises(FlashRefused):
                    self.run_flash(drone, **options)
                self.assertFalse(WRITES & set(self.sent(drone)))
                self.assertEqual(drone.uploads, 0)
                self.package = inspect_package(Path(self.directory.name) / "dji_system.bin")

    def test_package_version_is_checked_against_target_before_usb(self):
        # dji_system.bin states its version only in the .cfg.sig manifest; the
        # real image found next to this project is 17.00.0001.
        cases = [
            ("other version", make_tar(self.directory.name, "V17.00.0001_wa345t_dji_system.bin",
                                       version="17.00.0001"), "Package is 17.00.0001"),
            ("no manifest", make_tar(self.directory.name, "sealed.bin", version=None),
             "states no firmware version"),
        ]
        for name, path, message in cases:
            with self.subTest(case=name):
                self.package = inspect_package(path)
                drone = SimulatedDrone(M4T, CURRENT, image_version=TARGET)
                with self.assertRaisesRegex(FlashRefused, message):
                    self.run_flash(drone)
                self.assertEqual(self.sent(drone), [])

    def test_zip_version_must_match_target_even_if_transfer_were_supported(self):
        package = inspect_package(make_zip(self.directory.name))
        flasher = self.flasher(SimulatedDrone(M4T, CURRENT))
        with self.assertRaisesRegex(FlashRefused, "Only the dji_system.bin"):
            flasher.check(package, FirmwareVersion.parse(TARGET), procedure="legacy-ftp",
                          accept_unverified=True)

    def test_package_modified_after_inspection_is_refused(self):
        with open(self.package.path, "ab") as handle:
            handle.write(b"tampered")
        drone = SimulatedDrone(M4T, CURRENT)
        with self.assertRaisesRegex(FlashRefused, "changed"):
            self.run_flash(drone)
        self.assertEqual(self.sent(drone), [0x01])

    def test_usb_unavailable_is_refused(self):
        def no_device():
            raise TransportError("no device")
        flasher = Flasher(no_device, M4T)
        with self.assertRaisesRegex(FlashRefused, "Nothing was sent"):
            flasher.run(self.package, target=FirmwareVersion.parse(TARGET),
                        expected_current=FirmwareVersion.parse(CURRENT), confirm=True,
                        accept_unverified=True, procedure=LEGACY_FTP)

    def test_second_process_is_locked_out(self):
        drone = SimulatedDrone(M4T, CURRENT)
        with DeviceLock(M4T.key):
            with self.assertRaisesRegex(FlashRefused, "another flash operation"):
                self.run_flash(drone)
        self.assertEqual(self.sent(drone), [])

    def test_lock_file_of_another_user_is_opened_read_only(self):
        # Linux refuses an O_CREAT open of another user's file in /tmp
        # (fs.protected_regular), even to root; flock works on a read-only fd.
        import os
        from unittest.mock import patch
        from dji_duml.flasher import _open_lock_file

        path = Path(tempfile.mkdtemp()) / "dji-duml-test.lock"
        path.write_bytes(b"")
        real = os.open
        modes = []

        def protected(name, flags, *mode):
            modes.append(flags)
            if flags & os.O_CREAT:
                raise PermissionError(13, "Permission denied")
            return real(name, flags, *mode)

        with patch("dji_duml.flasher.os.open", protected):
            handle = _open_lock_file(path)
        handle.close()
        self.assertEqual(modes[-1], os.O_RDONLY)

    # -- aborted: upgrade mode entered, flashing never started -----------------

    def test_failures_before_start_never_request_start(self):
        def broken_upload(host, source, on_bytes):
            raise ConnectionRefusedError("ftp down")

        def corrupting_upload(host, source, on_bytes):
            on_bytes(1)
            return bytes(16)

        cases = [
            ("enter silent", SimulatedDrone(M4T, CURRENT, silent=frozenset({0x07})), {}),
            ("enter rejected", SimulatedDrone(M4T, CURRENT, reject={0x07: 0xE0}), {}),
            ("report silent", SimulatedDrone(M4T, CURRENT, silent=frozenset({0x0C})), {}),
            ("ftp down", SimulatedDrone(M4T, CURRENT), dict(upload=broken_upload)),
            ("md5 differs", SimulatedDrone(M4T, CURRENT), dict(upload=corrupting_upload)),
            ("size rejected", SimulatedDrone(M4T, CURRENT, reject={0x08: 0xE1}), {}),
        ]
        for name, drone, options in cases:
            with self.subTest(case=name):
                with self.assertRaisesRegex(FlashAborted, "not started|differ"):
                    self.run_flash(drone, **options)
                self.assertNotIn(commands.UPGRADE_VERIFY, self.sent(drone))
                self.assert_no_write_repeated(drone)
                self.assertEqual(drone.firmware, FirmwareVersion.parse(CURRENT))

    def test_failure_push_during_transfer_aborts(self):
        # Before start a failure from any module stops the flash.
        for sender in (M4T.target, 0x0E):
            with self.subTest(sender=sender):
                drone = SimulatedDrone(M4T, CURRENT)

                def upload(host, source, on_bytes, drone=drone, sender=sender):
                    drone._link.out += Frame(sender, 0x2A, 9, 0, 0x42, bytes([4, 7, 1]),
                                             ack=0).encode()
                    import time
                    time.sleep(0.1)
                    return self.package.md5

                with self.assertRaisesRegex(FlashAborted, "MotorWorking"):
                    self.run_flash(drone, upload=upload)
                self.assertNotIn(commands.UPGRADE_VERIFY, self.sent(drone))

    # -- failed / unknown -------------------------------------------------------

    def test_device_reported_failure(self):
        drone = SimulatedDrone(M4T, CURRENT, image_version=TARGET, fail_result=9)
        with self.assertRaisesRegex(FlashFailed, "IllegalDegrade"):
            self.run_flash(drone)
        self.assert_no_write_repeated(drone)

    def test_start_rejected_by_device(self):
        drone = SimulatedDrone(M4T, CURRENT, reject={0x0A: 0xE2})
        with self.assertRaisesRegex(FlashFailed, "refused"):
            self.run_flash(drone)

    def test_unacknowledged_start_is_unknown_and_never_retried(self):
        drone = SimulatedDrone(M4T, CURRENT, silent=frozenset({0x0A}))
        with self.assertRaisesRegex(FlashOutcomeUnknown, "Do not retry"):
            self.run_flash(drone)
        self.assertEqual(self.sent(drone).count(commands.UPGRADE_VERIFY), 1)

    def test_completion_without_new_version_is_unknown(self):
        drone = SimulatedDrone(M4T, CURRENT, image_version=TARGET, install=False,
                               boot_attempts=0)
        with self.assertRaisesRegex(FlashOutcomeUnknown, f"completed.*{CURRENT}"):
            self.run_flash(drone)

    def test_unexpected_version_after_upgrade_is_unknown(self):
        drone = SimulatedDrone(M4T, CURRENT, image_version="17.00.0001", boot_attempts=0)
        with self.assertRaisesRegex(FlashOutcomeUnknown, "17.00.0001"):
            self.run_flash(drone)

    def test_device_never_returns_times_out_as_unknown(self):
        drone = SimulatedDrone(M4T, CURRENT, image_version=TARGET, drop_link_at=25,
                               boot_attempts=10**9)
        with self.assertRaisesRegex(FlashOutcomeUnknown, "unavailable"):
            self.run_flash(drone, timeout=0.3)
        self.assert_no_write_repeated(drone)

    def test_silent_device_after_start_times_out_as_unknown(self):
        drone = SimulatedDrone(M4T, CURRENT)
        drone._upgrade = lambda link: None
        with self.assertRaisesRegex(FlashOutcomeUnknown, f"not confirmed.*{CURRENT}"):
            self.run_flash(drone, timeout=0.3)

    # -- regressions found by independent review ---------------------------------

    def test_refresh_without_completion_is_never_reported_as_success(self):
        same = FirmwareVersion.parse(TARGET)
        drone = SimulatedDrone(M4T, TARGET, image_version=TARGET, install=False,
                               drop_link_at=0, boot_attempts=0)
        with self.assertRaisesRegex(FlashOutcomeUnknown, "Same-version"):
            self.run_flash(drone, expected_current=same, allow_same_version=True)
        silent = SimulatedDrone(M4T, TARGET, silent=frozenset({0x0A}))
        with self.assertRaises(FlashOutcomeUnknown):
            self.run_flash(silent, expected_current=same, allow_same_version=True)

    def test_failure_received_just_before_link_loss_is_reported_at_once(self):
        drone = SimulatedDrone(M4T, CURRENT, image_version=TARGET, fail_result=9,
                               drop_after_complete=True, boot_attempts=10**9)
        with self.assertRaisesRegex(FlashFailed, "IllegalDegrade"):
            self.run_flash(drone, timeout=30)

    def test_failure_pushed_with_size_ack_prevents_start(self):
        for read_size in (None, 5):  # 5: the push is still arriving after the size ack
            with self.subTest(read_size=read_size):
                drone = SimulatedDrone(M4T, CURRENT, image_version=TARGET,
                                       push_with_size_ack=bytes([4, 8, 1]), read_size=read_size)
                with self.assertRaisesRegex(FlashAborted, "FirmNotMatch.*not started"):
                    self.run_flash(drone)
                self.assertNotIn(commands.UPGRADE_VERIFY, self.sent(drone))
                self.assertEqual(drone.firmware, FirmwareVersion.parse(CURRENT))

    def test_stale_success_push_is_not_taken_as_completion(self):
        same = FirmwareVersion.parse(TARGET)
        for read_size in (None, 5):
            with self.subTest(read_size=read_size):
                drone = SimulatedDrone(M4T, CURRENT, push_with_size_ack=bytes([4, 1, 1]),
                                       boot_attempts=0, read_size=read_size)
                drone._upgrade = lambda link: None
                with self.assertRaisesRegex(FlashOutcomeUnknown, "not confirmed"):
                    self.run_flash(drone, timeout=0.2)
                refresh = SimulatedDrone(M4T, TARGET, push_with_size_ack=bytes([4, 1, 1]),
                                         boot_attempts=0, read_size=read_size)
                refresh._upgrade = lambda link: None
                with self.assertRaisesRegex(FlashOutcomeUnknown, "Same-version"):
                    self.run_flash(refresh, expected_current=same, allow_same_version=True,
                                   timeout=0.2)

    def test_success_sent_before_the_start_reply_is_never_the_verdict(self):
        same = FirmwareVersion.parse(TARGET)
        stale_success = {commands.UPGRADE_VERIFY: bytes([4, 1, 1])}
        path = Path(self.directory.name) / "journal.jsonl"
        refresh = SimulatedDrone(M4T, TARGET, boot_attempts=0, push_before_reply=stale_success)
        refresh._upgrade = lambda link: None
        with Journal(path) as journal, self.assertRaisesRegex(FlashOutcomeUnknown, "Same-version"):
            self.run_flash(refresh, expected_current=same, allow_same_version=True, timeout=0.2,
                           journal=journal)
        self.assertIn('"status-before-reply"', path.read_text())

        # Without a reply the push shows the device is alive, nothing more.
        unacknowledged = SimulatedDrone(M4T, TARGET, silent=frozenset({0x0A}), boot_attempts=0,
                                        push_before_reply=stale_success)
        with self.assertRaisesRegex(FlashOutcomeUnknown, "Same-version"):
            self.run_flash(unacknowledged, expected_current=same, allow_same_version=True,
                           timeout=0.2)
        self.assertEqual(self.sent(unacknowledged).count(commands.UPGRADE_VERIFY), 1)

    def test_failure_before_the_start_reply_needs_a_later_success_to_be_overridden(self):
        early_failure = {commands.UPGRADE_VERIFY: bytes([4, 8, 1])}
        overridden = SimulatedDrone(M4T, CURRENT, image_version=TARGET,
                                    push_before_reply=early_failure)
        result = self.run_flash(overridden)
        self.assertEqual(str(result.installed), TARGET)
        self.assertTrue(result.completion_observed)

        # Nothing follows: unknown at once, not after the whole --timeout.
        silent = SimulatedDrone(M4T, CURRENT, push_before_reply=early_failure)
        silent._upgrade = lambda link: None
        with self.assertRaisesRegex(FlashOutcomeUnknown, "FirmNotMatch around the start"):
            self.run_flash(silent, timeout=30)

        # The main version changes but no Complete/Success came: the read-back
        # must not turn the reported failure into success.
        installed = SimulatedDrone(M4T, CURRENT, image_version=TARGET, drop_link_at=50,
                                   boot_attempts=0, push_before_reply=early_failure)
        with self.assertRaisesRegex(FlashOutcomeUnknown, "FirmNotMatch around the start"):
            self.run_flash(installed)
        self.assertEqual(installed.firmware, FirmwareVersion.parse(TARGET))

    def test_lost_start_reply_while_the_device_upgrades(self):
        # Everything the device sends lands in the request window: progress
        # proves it is alive, so the version read-back decides.
        lost = SimulatedDrone(M4T, CURRENT, image_version=TARGET,
                              lose_reply=frozenset({commands.UPGRADE_VERIFY}))
        result = self.run_flash(lost, timeout=0.3)
        self.assertEqual(str(result.installed), TARGET)
        self.assertFalse(result.completion_observed)

        failed = SimulatedDrone(M4T, CURRENT, image_version=TARGET, fail_result=9,
                                lose_reply=frozenset({commands.UPGRADE_VERIFY}))
        with self.assertRaisesRegex(FlashOutcomeUnknown, "IllegalDegrade"):
            self.run_flash(failed, timeout=30)

    def test_status_from_another_module_is_not_the_verdict(self):
        def push(payload, sender=0x0E, receiver=M4T.host):
            return Frame(sender, receiver, 9, commands.GENERAL, commands.UPGRADE_STATUS,
                         payload, ack=0).encode()

        same = FirmwareVersion.parse(TARGET)
        path = Path(self.directory.name) / "journal.jsonl"
        drone = SimulatedDrone(M4T, TARGET, boot_attempts=0)
        drone._upgrade = lambda link: link.out.extend(push(bytes([4, 1, 1])))
        with Journal(path) as journal, self.assertRaisesRegex(FlashOutcomeUnknown, "Same-version"):
            self.run_flash(drone, expected_current=same, allow_same_version=True, timeout=0.2,
                           journal=journal)
        self.assertIn('"status-ignored"', path.read_text())

        drone = SimulatedDrone(M4T, CURRENT, image_version=TARGET)
        genuine = drone._upgrade

        def foreign_failure_then_genuine(link):
            link.out.extend(push(bytes([4, 8, 1])))
            genuine(link)

        drone._upgrade = foreign_failure_then_genuine
        result = self.run_flash(drone)
        self.assertEqual(str(result.installed), TARGET)
        self.assertTrue(result.completion_observed)

        # Only foreign pushes after a lost reply: the message says so.
        lonely = SimulatedDrone(M4T, CURRENT, silent=frozenset({0x0A}))
        handle = lonely.handle

        def handle_then_foreign(link, frame):
            handle(link, frame)
            if frame.cmd_id == commands.UPGRADE_VERIFY:
                link.out.extend(push(bytes([3, 10, 0])))

        lonely.handle = handle_then_foreign
        with self.assertRaisesRegex(FlashOutcomeUnknown, r"\(1 from other modules"):
            self.run_flash(lonely)

    def test_flashed_module_may_address_any_host_index(self):
        # Only the sender identifies the flashed module; the M4T's receiver for
        # status pushes is not confirmed.
        failing = SimulatedDrone(M4T, CURRENT, image_version=TARGET, fail_result=9,
                                 push_receiver=0x0A)
        with self.assertRaisesRegex(FlashFailed, "IllegalDegrade"):
            self.run_flash(failing)
        refresh = SimulatedDrone(M4T, TARGET, image_version=TARGET, push_receiver=0x0A)
        result = self.run_flash(refresh, expected_current=FirmwareVersion.parse(TARGET),
                                allow_same_version=True)
        self.assertTrue(result.completion_observed)

    def test_rejected_start_still_logs_what_came_before_the_reply(self):
        path = Path(self.directory.name) / "journal.jsonl"
        drone = SimulatedDrone(M4T, CURRENT, reject={0x0A: 0xE2},
                               push_before_reply={commands.UPGRADE_VERIFY: bytes([4, 8, 1])})
        with Journal(path) as journal, self.assertRaisesRegex(FlashFailed, "refused"):
            self.run_flash(drone, journal=journal)
        self.assertIn('"status-before-reply"', path.read_text())

    def test_drain_before_start_ends_on_a_chatty_link(self):
        heartbeat = Frame(M4T.target, M4T.host, 1, commands.GENERAL, 0x0E, ack=0)

        class Chatty:
            parser = type("Parser", (), {"pending": 0})()

            def poll(self, timeout):
                return [heartbeat]

        flasher = Flasher(lambda: None, M4T, poll_interval=0.001, command_timeout=0.05)
        import time
        started = time.monotonic()
        flasher._settle_before_start(Chatty())
        self.assertLess(time.monotonic() - started, 1.0)

    def test_slow_transfer_does_not_eat_the_upgrade_budget(self):
        drone = SimulatedDrone(M4T, CURRENT, image_version=TARGET)

        def slow(host, source, on_bytes):
            import time
            time.sleep(0.3)
            return drone.upload(host, source, on_bytes)

        result = self.run_flash(drone, upload=slow, timeout=0.2)
        self.assertEqual(str(result.installed), TARGET)

    def test_any_uploader_exception_aborts_before_start(self):
        def odd(host, source, on_bytes):
            raise UnicodeDecodeError("utf-8", b"\xe9", 0, 1, "invalid continuation byte")
        drone = SimulatedDrone(M4T, CURRENT)
        with self.assertRaisesRegex(FlashAborted, "UnicodeDecodeError.*not started"):
            self.run_flash(drone, upload=odd)
        self.assertNotIn(commands.UPGRADE_VERIFY, self.sent(drone))

    def test_package_removed_during_transfer_aborts(self):
        drone = SimulatedDrone(M4T, CURRENT)

        def remove_after(host, source, on_bytes):
            digest = drone.upload(host, source, on_bytes)
            Path(source).unlink()
            return digest

        with self.assertRaisesRegex(FlashAborted, "differ"):
            self.run_flash(drone, upload=remove_after)
        self.assertNotIn(commands.UPGRADE_VERIFY, self.sent(drone))

    def test_oversize_image_is_refused_before_usb(self):
        from dataclasses import replace
        self.package = replace(self.package, size=1 << 32)
        drone = SimulatedDrone(M4T, CURRENT)
        with self.assertRaisesRegex(FlashRefused, "32-bit"):
            self.run_flash(drone)
        self.assertEqual(self.sent(drone), [])

    def test_reconnect_errors_of_any_type_only_delay_the_readback(self):
        drone = SimulatedDrone(M4T, CURRENT, image_version=TARGET, boot_attempts=0)
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if 1 < calls["n"] < 5:
                raise OSError(5, "Input/Output Error")
            return drone.client()

        flasher = Flasher(flaky, M4T, upload=drone.upload, reconnect_interval=0.001,
                          settle_timeout=0.05)
        result = flasher.run(self.package, target=FirmwareVersion.parse(TARGET),
                             expected_current=FirmwareVersion.parse(CURRENT), confirm=True,
                             accept_unverified=True, procedure=LEGACY_FTP)
        self.assertEqual(str(result.installed), TARGET)

    def test_unexpected_error_after_start_is_unknown_not_a_raw_exception(self):
        drone = SimulatedDrone(M4T, CURRENT, image_version=TARGET)
        flasher = self.flasher(drone)
        original = flasher._monitor

        def broken(*args):
            original(*args)
            raise RuntimeError("bug")

        flasher._monitor = broken
        with self.assertRaisesRegex(FlashOutcomeUnknown, "RuntimeError: bug"):
            flasher.run(self.package, target=FirmwareVersion.parse(TARGET),
                        expected_current=FirmwareVersion.parse(CURRENT), confirm=True,
                        accept_unverified=True, procedure=LEGACY_FTP)

    def test_journal_failure_refuses_at_begin_but_never_breaks_a_running_flash(self):
        class FullDisk(Journal):
            def __init__(self, fail_after):
                super().__init__()
                self.left = fail_after

            def event(self, kind, *, strict=False, **fields):
                self.left -= 1
                if self.left < 0:
                    self.error = OSError(28, "No space left on device")
                    if strict:
                        raise self.error

        drone = SimulatedDrone(M4T, CURRENT, image_version=TARGET)
        with self.assertRaisesRegex(FlashRefused, "journal"):
            self.run_flash(drone, journal=FullDisk(0))
        self.assertEqual(self.sent(drone), [])
        result = self.run_flash(drone, journal=FullDisk(6))
        self.assertEqual(str(result.installed), TARGET)

    def test_unusable_lock_file_is_a_refusal(self):
        lock = DeviceLock(M4T.key)
        lock.path = Path(self.directory.name) / "missing" / "dir" / "x.lock"
        with self.assertRaises(FlashRefused):
            lock.__enter__()

    # -- dry run ----------------------------------------------------------------

    def test_plan_frames_decode_to_the_documented_sequence(self):
        lines = plan(M4T, self.package, LEGACY_FTP)
        frames = [Frame.decode(bytes.fromhex(line.split("  ")[-1].strip().replace(" ", "")))
                  for line in lines if line.startswith(("read", "write"))]
        self.assertEqual([frame.cmd_id for frame in frames], [0x01, 0x07, 0x0C, 0x08, 0x0A])
        self.assertTrue(all((frame.sender, frame.receiver) == (0x2A, 0x1F) for frame in frames))
        self.assertEqual(frames[-1].payload[1:], self.package.md5)


if __name__ == "__main__":
    unittest.main()
