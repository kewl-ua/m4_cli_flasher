import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from dji_duml.cli import main
from dji_duml.errors import TransportError
from dji_duml.profiles import M4T
from duml_fixtures import (
    CURRENT, TARGET, VERSION_BODY, make_tar, usbpcap_file, usbpcap_record, version_request,
)

try:
    import usb.core
    from dji_duml import transport
except ImportError:  # pyusb is optional for everything except real USB access
    usb = None


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.image = str(make_tar(self.directory.name))
        self.journal = str(Path(self.directory.name) / "journal.jsonl")

    def flash(self, *extra, current=CURRENT):
        return run("--simulate", current, "--journal", self.journal, "flash", self.image,
                   "--target", TARGET, "--expected-current", CURRENT, *extra)

    def test_version_on_simulated_drone(self):
        code, out, _ = run("--simulate", CURRENT, "version")
        self.assertEqual(code, 0)
        self.assertIn(f"firmware  {CURRENT}", out)

    def test_flash_needs_yes_and_an_accepted_procedure(self):
        code, _, err = self.flash()
        self.assertEqual(code, 2)
        self.assertIn("requires --yes", err)
        code, _, err = self.flash("--yes", "--procedure", "legacy-ftp")
        self.assertEqual(code, 2)
        self.assertIn("not verified for Matrice 4T", err)

    def test_simulated_flash_succeeds_and_writes_journal(self):
        code, out, _ = self.flash("--yes", "--accept-unverified")
        self.assertEqual(code, 0)
        self.assertIn(f"Installed {TARGET} (was {CURRENT})", out)
        self.assertIn('"flash-end", "ok": true', Path(self.journal).read_text())

    def test_wrong_current_version_has_refusal_exit_code(self):
        code, _, err = self.flash("--yes", "--accept-unverified", current="17.00.0001")
        self.assertEqual(code, 2)
        self.assertIn("Nothing was changed", err)

    def test_interrupt_message_depends_on_stage(self):
        for procedure, during, before in (("legacy-ftp", "_monitor", "_transfer"),
                                          ("upgrade-center", "_center_watch", "_send_files")):
            with self.subTest(procedure=procedure):
                with patch(f"dji_duml.flasher.Flasher.{during}", side_effect=KeyboardInterrupt):
                    code, out, _ = self.flash("--yes", "--accept-unverified",
                                              "--procedure", procedure)
                self.assertEqual(code, 130)
                self.assertIn("do NOT unplug", out)
                with patch(f"dji_duml.flasher.Flasher.{before}", side_effect=KeyboardInterrupt):
                    code, out, _ = self.flash("--yes", "--accept-unverified",
                                              "--procedure", procedure)
                self.assertEqual(code, 130)
                self.assertIn("was not started", out)
                with patch("dji_duml.flasher.Flasher._preflight", side_effect=KeyboardInterrupt):
                    code, out, _ = self.flash("--yes", "--accept-unverified",
                                              "--procedure", procedure)
                self.assertEqual(code, 130)
                self.assertIn("before anything was written", out)

    def test_plan_and_inspect_do_not_need_usb(self):
        code, out, _ = run("plan", self.image)
        self.assertEqual(code, 0)
        self.assertIn("Procedure upgrade-center for Matrice 4T: verified", out)
        self.assertIn("Upgrade Install", out)
        code, out, _ = run("plan", self.image, "--procedure", "legacy-ftp")
        self.assertEqual(code, 0)
        self.assertIn("Upgrade Verify", out)
        code, out, _ = run("inspect", self.image)
        self.assertEqual(code, 0)
        self.assertIn("product   wa345t", out)

    def test_plan_refuses_a_package_that_flash_would_refuse(self):
        from duml_fixtures import make_zip
        bare = str(make_zip(self.directory.name))
        code, out, err = run("plan", bare)
        self.assertEqual(code, 2)
        self.assertIn("no readable manifest", err)
        code, out, err = run("plan", bare, "--procedure", "legacy-ftp")
        self.assertEqual(code, 2)
        self.assertIn("Only the dji_system.bin", err)

    def test_decode_summary(self):
        request = version_request()
        capture = usbpcap_file(Path(self.directory.name) / "capture.pcap", [
            usbpcap_record(0x04, request.encode(), False),
            usbpcap_record(0x85, request.make_reply(VERSION_BODY).encode(), True),
        ])
        code, out, err = run("decode", str(capture), "--summary")
        self.assertEqual(code, 0)
        self.assertIn("OUT ep=04 1001>3100 req set=00 id=01  Version Inquiry", out)
        self.assertIn("2 frames", err)
        code, out, _ = run("decode", str(capture), "--upgrade-only")
        self.assertEqual((code, out), (0, ""))

    def test_scan_shows_why_a_device_is_unusable(self):
        from dji_duml.transport import UsbCandidate
        found = [UsbCandidate("libusb1", 1, 47, None, False, "[Errno 2] Entity not found")]
        with patch("dji_duml.transport.scan", return_value=found):
            code, out, _ = run("scan")
        self.assertEqual(code, 0)
        self.assertIn("duml-interface=no  ([Errno 2] Entity not found)", out)

    def test_usb_location_selects_only_the_first_connection(self):
        # The drone gets a new USB address on every reboot during a flash.
        from dji_duml.cli import _opener, build_parser
        args = build_parser().parse_args(["--usb-location", "0:2", "version"])
        with patch("dji_duml.transport.UsbBulkTransport.open") as opened:
            open_client = _opener(args, M4T)
            open_client()
            open_client()
        self.assertEqual([call.kwargs["location"] for call in opened.call_args_list],
                         ["0:2", None])

    def test_missing_file_is_an_error_not_a_traceback(self):
        code, _, err = run("inspect", str(Path(self.directory.name) / "absent.bin"))
        self.assertEqual(code, 1)
        self.assertIn("Error", err)


@unittest.skipIf(usb is None, "pyusb is not installed")
class UsbOpenTests(unittest.TestCase):
    """libusb-win32 lists one node per vendor interface; only one owns the pipe."""

    def node(self, read_error=None, data=b""):
        device = MagicMock()
        device.bus, device.address = 0, id(device) % 250
        device.read.side_effect = read_error
        device.read.return_value = data
        return device

    def open(self, nodes, **options):
        with patch.object(transport, "_enumerate", return_value=[("libusb0", nodes)]), \
                patch.object(transport, "_interface", return_value=object()), \
                patch.object(transport, "_serial", return_value=None), \
                patch("usb.util.claim_interface"), patch("usb.util.release_interface"), \
                patch("usb.util.dispose_resources"), patch("sys.platform", "win32"):
            return transport.UsbBulkTransport.open(M4T, **options)

    def test_node_without_the_pipe_is_skipped_and_probe_data_is_kept(self):
        wrong = self.node(read_error=usb.core.USBError("invalid endpoint", -22))
        right = self.node(data=b"\x55\x0d")
        link = self.open([wrong, right])
        self.assertIs(link._device, right)
        self.assertEqual(link.read(0.1), b"\x55\x0d")
        right.set_configuration.assert_not_called()
        right.reset.assert_not_called()

    def test_timeout_spellings_count_as_an_idle_pipe(self):
        for error in (usb.core.USBTimeoutError("timeout"),
                      usb.core.USBError("libusb0-dll:err [_usb_reap_async] timeout error", -116)):
            with self.subTest(error=str(error)):
                node = self.node(read_error=error)
                self.assertIs(self.open([node])._device, node)

    def test_two_usable_devices_are_ambiguous(self):
        with self.assertRaisesRegex(TransportError, "2 usable devices"):
            self.open([self.node(), self.node()])

    def test_no_usable_node_reports_every_problem(self):
        with self.assertRaisesRegex(TransportError, "busy.*close DJI Assistant"):
            self.open([self.node(read_error=usb.core.USBError("busy", -16))])

    def test_zero_timeout_never_reaches_libusb(self):
        node = self.node()
        link = self.open([node])
        link.read(0)
        self.assertEqual(node.read.call_args.args[2], 1)

    def test_same_device_through_second_backend_is_not_a_second_drone(self):
        first, second = self.node(), self.node()
        with patch.object(transport, "_enumerate",
                          return_value=[("libusb0", [first]), ("libusb1", [second])]), \
                patch.object(transport, "_interface", return_value=object()), \
                patch.object(transport, "_serial", return_value=None), \
                patch("usb.util.claim_interface"), patch("usb.util.dispose_resources"):
            link = transport.UsbBulkTransport.open(M4T)
        self.assertIs(link._device, first)
        second.read.assert_not_called()

    def test_descriptor_errors_are_reported_not_swallowed(self):
        node = self.node()
        with patch.object(transport, "_enumerate", return_value=[("libusb0", [node])]), \
                patch.object(transport, "_interface",
                             side_effect=usb.core.USBError("Access denied", -13)), \
                patch.object(transport, "_serial", return_value=None), \
                patch("usb.util.dispose_resources"):
            with self.assertRaisesRegex(TransportError, "Access denied"):
                transport.UsbBulkTransport.open(M4T)
            self.assertIn("Access denied", transport.scan(M4T)[0].error)

    def test_enumeration_and_io_errors_become_transport_errors(self):
        with patch("usb.core.find", side_effect=usb.core.USBError("Input/Output Error", -5)):
            with self.assertRaisesRegex(TransportError, "enumeration failed"):
                transport.UsbBulkTransport.open(M4T, backend="libusb1")
        node = self.node()
        link = self.open([node])
        node.read.side_effect = NotImplementedError("no backend call")
        with self.assertRaises(TransportError):
            link.read(0.1)
        node.read.side_effect = usb.core.USBError(
            "The semaphore timeout period has expired", -5)
        with self.assertRaises(TransportError):
            link.read(0.1)

    def test_missing_libusb_win32_is_named_as_the_cause(self):
        node = self.node()
        with patch.object(transport, "_enumerate", return_value=[("libusb1", [node])]), \
                patch.object(transport, "_interface",
                             side_effect=usb.core.USBError("Entity not found", -5)), \
                patch.object(transport, "_serial", return_value=None), \
                patch("usb.util.dispose_resources"), patch("sys.platform", "win32"):
            with self.assertRaisesRegex(TransportError, "Entity not found.*libusb-win32 DLL"):
                transport.UsbBulkTransport.open(M4T)

    def test_short_write_is_an_error(self):
        node = self.node()
        node.write.return_value = 3
        with self.assertRaisesRegex(TransportError, "short write"):
            self.open([node]).write(b"\x55" * 13)


if __name__ == "__main__":
    unittest.main()
