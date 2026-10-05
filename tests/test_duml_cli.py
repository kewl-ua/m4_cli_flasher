import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from dji_duml.cli import main
from dji_duml.errors import TransportError
from dji_duml.package import inspect_package
from dji_duml.profiles import M4T
from duml_fixtures import (
    CURRENT, TARGET, VERSION_BODY, make_tar, usbpcap_file, usbpcap_record, version_request,
)
from store_fixtures import A, B, C, OLD, StoreCase, age, config, image, release_list

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


class FirmwareStoreCliTests(StoreCase):
    """dji-duml fw and flash --from-store; the store comes from --store."""

    def setUp(self):
        super().setUp()
        self.version = self.folder(TARGET, (A, B), start="2026/05/29")
        self.partial = self.folder(OLD, (A, C))
        (self.partial / C[0]).unlink()
        self.journal = self.tmp / "journal.jsonl"

    def fw(self, *argv):
        return run("--store", str(self.root), "fw", *argv)

    def filled(self):
        self.assertEqual(self.fw("add", str(self.version), str(self.partial))[0], 0)

    def flash(self, *extra, current=CURRENT, target=TARGET):
        return run("--store", str(self.root), "--simulate", current, "--journal",
                   str(self.journal), "flash", "--from-store", "--target", target,
                   "--expected-current", CURRENT, "--yes", *extra)

    def status(self, drone_config, current):
        with patch("dji_duml.sim._config_for", return_value=drone_config):
            plain = run("--store", str(self.root), "--simulate", current, "fw", "status")
            js = run("--store", str(self.root), "--simulate", current, "fw", "status", "--json")
        return plain, js

    def test_status(self):
        self.filled()  # store holds TARGET (ready 2/2) and OLD (PARTIAL 1/2, missing C)
        # (1) the drone runs exactly the stored, complete TARGET configuration
        (code, out, _), (_, js, _) = self.status(config(TARGET, (A, B), start="2026/05/29"), TARGET)
        self.assertEqual(code, 0, out)
        self.assertIn("installed ready in the store", out)
        obj = json.loads(js)
        self.assertEqual(obj["installed"]["state"], "ready")
        self.assertFalse(obj["store_damaged"])
        self.assertIn(TARGET, [version["version"] for version in obj["ready"]])
        # (2) the drone runs a configuration the store does not hold (modules are present)
        (code, out, _), _ = self.status(config(CURRENT, (A, B)), CURRENT)
        self.assertEqual(code, 0, out)
        self.assertIn("installed not in the store", out)
        self.assertIn(TARGET, out)  # offered as a version to move to
        # (3) the drone's configuration is held but incomplete -> report the bad module, not "0"
        (code, out, _), _ = self.status(config(OLD, (A, C)), OLD)
        self.assertEqual(code, 0, out)
        self.assertIn("PARTIAL", out)
        self.assertIn("not ready", out)
        self.assertIn(C[0], out)

    def test_add_list_show_orphans_check(self):
        code, out, err = self.fw("list")
        self.assertEqual(code, 1)
        self.assertIn("No firmware store", err)
        code, out, _ = self.fw("add", str(self.version))
        self.assertEqual(code, 0)
        self.assertIn(f"store     {self.root.resolve()} (created)", out)  # /var on macOS
        self.assertIn(f"versions  {TARGET}  not held -> ready 2/2", out)
        self.assertIn(f"next      dji-duml flash --from-store --target {TARGET}", out)
        self.fw("add", str(self.partial))
        cache = self.src / "cache"
        age(self.write(f"{1:032x}.cache", release_list((TARGET, "2026-05-29"),
                                                       ("16.01.0006", "2025-12-22")), cache))
        age(self.write(f"{2:032x}.cache", image(42), cache))
        with patch.dict(os.environ, {"DJI_DUML_ASSISTANT_CACHE": str(cache)}):
            code, listed, _ = self.fw("list")
            self.assertIn("assistant firm_cache: 2 files, 2 not in the store", listed)
            self.assertIn("next      dji-duml fw harvest", listed)
            self.assertEqual(self.fw("harvest")[0], 0)
            code, listed, _ = self.fw("list")
            self.assertEqual(listed, self.fw()[1])  # bare fw is fw list
        self.assertEqual(code, 0)
        self.assertIn("assistant firm_cache: 2 files, all in the store", listed)
        self.assertRegex(listed, rf"  {TARGET}  2026-05-29  ready      2/2  .*  folder\n")
        self.assertRegex(listed, rf"  16.01.0006  2025-12-22  not held .*DJI release list only")
        self.assertRegex(listed, rf"  {OLD} .* PARTIAL    1/2 .* missing 1 \({C[0]}, .*\): "
                                 rf"fw show {OLD}")
        self.assertIn("orphans   1 modules", listed)
        self.assertIn("next      dji-duml flash --from-store --target <version>", listed)
        code, out, _ = self.fw("show", "17.02.05.01")
        self.assertEqual(code, 0)
        self.assertIn(f"version   wa345t {TARGET}, released 2026-05-29 (formal)", out)
        self.assertIn("release   from 2026/05/29, expire 2027/01/01, antirollback 0, enforce 0",
                      out)
        self.assertIn(f"note      Note for {TARGET}.", out)
        code, out, _ = self.fw("show", OLD)
        self.assertEqual(code, 1)
        self.assertIn(f"md5 {hashlib.md5(C[1]).hexdigest()}", out)
        self.assertIn("not in the store", out)
        code, out, _ = self.fw("orphans")
        self.assertEqual(code, 0)
        self.assertIn("orphans   1 modules", out)
        self.assertIn(f"{hashlib.sha256(image(42)).hexdigest()[:12]}", out)
        code, out, _ = self.fw("check", "--full")
        self.assertEqual(code, 0)
        self.assertIn("checked   5 objects (0.0 MB rehashed), 2 configurations, 1 release lists: "
                      "no problems", out)
        stray = self.root / "objects" / "stray"
        stray.write_bytes(b"x")
        self.assertEqual(self.fw("check")[0], 2)
        code, out, _ = self.fw("check", "--fix")
        self.assertEqual(code, 0)
        self.assertIn("fixed     stray file", out)

    def test_export(self):
        self.filled()
        out = self.tmp / "out.bin"
        code, text, _ = self.fw("export", TARGET, "-o", str(out))
        self.assertEqual(code, 0)
        self.assertIn("files     3,", text)
        self.assertEqual(inspect_package(out).config_name, "wa345t.cfg.sig")
        code, _, err = self.fw("export", TARGET, "-o", str(out))
        self.assertEqual(code, 1)
        self.assertIn("already exists", err)
        code, _, err = self.fw("export", OLD, "-o", str(self.tmp / "old.bin"))
        self.assertEqual(code, 1)
        self.assertIn("PARTIAL 1/2", err)
        code, _, err = self.fw("export", TARGET, "-o", str(self.root / "in.bin"))
        self.assertEqual(code, 1)
        self.assertIn("inside the store", err)

    def test_flash_from_store(self):
        self.filled()
        code, out, _ = self.flash()
        self.assertEqual(code, 0, out)
        self.assertIn("build     written and read back", out)
        self.assertIn(f"Installed {TARGET} (was {CURRENT})", out)
        self.assertEqual(list((self.root / "tmp").iterdir()), [])
        events = [json.loads(line) for line in self.journal.read_text().splitlines()]
        (event,) = [event for event in events if event["event"] == "store-package"]
        config_sha = hashlib.sha256((self.version / "wa345t.cfg.sig").read_bytes()).hexdigest()
        self.assertEqual((event["version"], event["config_sha256"]), (TARGET, config_sha))

    def test_temporary_package_is_removed_however_the_flash_ends(self):
        self.filled()
        code, _, err = self.flash(current="17.00.0001")
        self.assertEqual(code, 2)
        self.assertIn("Nothing was changed", err)
        self.assertEqual(list((self.root / "tmp").iterdir()), [])
        with patch("dji_duml.cli.Flasher.run", side_effect=KeyboardInterrupt):
            code, out, _ = self.flash()
        self.assertEqual(code, 130)
        self.assertEqual(list((self.root / "tmp").iterdir()), [])

    def test_store_problems_are_refusals_before_anything_is_sent(self):
        self.filled()
        with patch("dji_duml.sim.SimulatedM4T") as drone:
            for target, error in ((OLD, "PARTIAL 1/2"), ("16.01.0006", "is not held")):
                code, _, err = self.flash(target=target)
                self.assertEqual(code, 2)
                self.assertIn(error, err)
                self.assertIn("Nothing was sent.", err)
        drone.assert_not_called()

    def test_package_or_from_store(self):
        for argv in (["flash", "x.bin", "--from-store"], ["flash"],
                     ["flash", "x.bin", "--config", "0" * 8], ["flash", "x.bin", "--config", ""]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as exit_:
                run(*argv, "--target", TARGET, "--expected-current", CURRENT, "--yes")
            self.assertEqual(exit_.exception.code, 2)

    def test_a_cleanup_failure_does_not_replace_the_flash_result(self):
        self.filled()
        real = Path.unlink

        def held(path, missing_ok=False):
            if path.name.startswith("flash-") and path.exists():
                raise PermissionError(13, "held by a virus scanner")
            return real(path, missing_ok=missing_ok)

        with patch.object(Path, "unlink", held):
            code, out, err = self.flash()
        self.assertEqual(code, 0, err)
        self.assertIn(f"Installed {TARGET} (was {CURRENT})", out)
        self.assertRegex(out, r"note: could not delete .*flash-.*held by a virus scanner.*"
                              "fw check --fix deletes it after 24 h")

    def test_a_non_ascii_store_path_on_an_ascii_console(self):
        self.root = self.tmp / "Артём" / "store"
        self.filled()
        raw = io.BytesIO()
        out = io.TextIOWrapper(raw, encoding="ascii")  # errors="strict", like cp1252 pipes
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()) as err:
            code = main(["--store", str(self.root), "--simulate", CURRENT, "--journal",
                         str(self.tmp / "Артём" / "journal.jsonl"), "flash", "--from-store",
                         "--target", TARGET, "--expected-current", CURRENT, "--yes"])
        out.flush()
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn(b"\\u0410\\u0440\\u0442\\u0451\\u043c", raw.getvalue())
        self.assertIn(f"Installed {TARGET}".encode(), raw.getvalue())

    def test_an_os_error_of_the_store_is_a_refusal(self):
        self.filled()
        for target, error in (("dji_duml.cli.Store.open", PermissionError(13, "held")),
                              ("dji_duml.cli.Store.select", ValueError("bad version 1.x"))):
            with self.subTest(target=target), patch(target, side_effect=error), \
                    patch("dji_duml.sim.SimulatedM4T") as drone:
                code, _, err = self.flash()
            self.assertEqual(code, 2)
            self.assertIn("Nothing was sent.", err)
            drone.assert_not_called()

    def test_next_names_the_configuration_when_a_version_has_two(self):
        other = self.folder(TARGET, (A, C))
        code, out, _ = self.fw("add", str(self.version), str(other))
        self.assertEqual(code, 0)
        self.assertIn(f"versions  {TARGET}  not held -> ready x2", out)
        self.assertIn(f"next      dji-duml fw show {TARGET}   (2 complete configurations: "
                      "choose one with --config)", out)
        shas = sorted(hashlib.sha256((folder / "wa345t.cfg.sig").read_bytes()).hexdigest()[:8]
                      for folder in (self.version, other))
        code, out, _ = self.fw("show", TARGET)
        self.assertIn(f"--target {TARGET} --config <{shas[0]} or {shas[1]}>", out)
        code, out, _ = self.fw("show", TARGET, "--config", shas[1])
        self.assertIn(f"--target {TARGET} --config {shas[1]} --expected-current", out)
        code, out, _ = self.fw("export", TARGET, "--config", shas[0], "-o",
                               str(self.tmp / "out.bin"))
        self.assertEqual(code, 0)
        self.assertIn(f"next      dji-duml flash --from-store --target {TARGET} --config "
                      f"{shas[0]} --expected-current", out)
        code, _, err = self.flash("--config", shas[0])
        self.assertEqual(code, 0, err)

    def test_an_unreadable_configuration_is_shown(self):
        self.filled()
        data = (self.version / "wa345t.cfg.sig").read_bytes()
        path = self.root / "objects" / hashlib.sha256(data).hexdigest()
        os.chmod(path, 0o600)
        path.write_bytes(data[:4] + bytes(len(data) - 4))  # same size: only the bytes differ
        code, out, _ = self.fw("list")
        self.assertIn(f"DAMAGED   unreadable config {path.name[:12]}: ", out)
        self.assertIn("STORE DAMAGED: dji-duml fw check", out)
        code, out, _ = self.fw("show", TARGET)
        self.assertIn(f"DAMAGED   unreadable config {path.name[:12]}: ", out)

    def test_store_help_names_the_default_off_windows(self):
        from dji_duml.cli import build_parser
        self.assertIn("~/.dji-duml/store", " ".join(build_parser().format_help().split()))


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
