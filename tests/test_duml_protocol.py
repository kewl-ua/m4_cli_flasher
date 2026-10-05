import tempfile
import unittest
from pathlib import Path

from dji_duml import commands, pcap
from dji_duml.errors import CommandRejected, NoReply, PackageError, UnexpectedReply
from dji_duml.frame import Frame
from dji_duml.journal import Journal
from dji_duml.package import inspect_package
from dji_duml.profiles import M4T
from dji_duml.sim import SimulatedDrone
from duml_fixtures import (
    CURRENT, TARGET, VERSION_BODY, make_tar, make_zip, manifest, usbpcap_file, usbpcap_record,
    version_request,
)


class CommandTests(unittest.TestCase):
    def test_version_reply_with_bytes_observed_on_m4t(self):
        info = commands.parse_version_reply(VERSION_BODY)
        self.assertEqual((info.hardware, str(info.firmware)), ("WA345T AC Ver.A", "17.02.0501"))
        self.assertTrue(M4T.matches_hardware(info.hardware))

    def test_version_reply_read_from_a_real_m4t(self):
        # `dji-duml version` on 2026-10-04: 0x1F -> 0x2A, same seq as the
        # request; DJI Assistant showed Current 17.02.0501 for this drone.
        payload = bytes.fromhex("00 12 57 41 33 34 35 54 20 41 43 20 56 65 72 2e 41 00 00 00 00 00"
                                " f5 01 02 11 01 00 00 c0 00")
        info = commands.parse_version_reply(payload)
        self.assertEqual((info.hardware, str(info.loader), str(info.firmware)),
                         ("WA345T AC Ver.A", "00.00.0000", "17.02.0501"))

    def test_bad_version_replies_are_not_guessed(self):
        with self.assertRaises(UnexpectedReply):
            commands.parse_version_reply(VERSION_BODY[:20])
        with self.assertRaises(UnexpectedReply):
            commands.parse_version_reply(bytes(2) + b"\xff" * 16 + bytes(16))
        with self.assertRaises(CommandRejected):
            commands.parse_version_reply(b"\xe0")

    def test_upgrade_payloads_match_public_packets(self):
        # pyduml: 55 16 04 FC ... 07 | 00*9 and 55 1A 04 B1 ... 08 | 00 size 00*6 02 04
        self.assertEqual(commands.enter_upgrade_payload(), bytes(9))
        self.assertEqual(commands.upgrade_size_payload(665835520).hex(),
                         "0000d8af270000000000000204")
        self.assertEqual(commands.upgrade_verify_payload(bytes(range(16))),
                         b"\x00" + bytes(range(16)))
        for size in (0, -1, 1 << 32):
            with self.assertRaises(ValueError):
                commands.upgrade_size_payload(size)

    def test_upgrade_status_push(self):
        status = commands.parse_upgrade_status(bytes([3, 42, 0x21]))
        self.assertEqual((status.state, status.percent), (commands.UpgradeState.UPGRADING, 42))
        self.assertEqual(commands.parse_upgrade_status(bytes([4, 9, 1])).result_name,
                         "IllegalDegrade")
        for payload in (b"", bytes([9]), bytes([3]), bytes([3, 101, 0])):
            with self.subTest(payload=payload), self.assertRaises(UnexpectedReply):
                commands.parse_upgrade_status(payload)


class ClientTests(unittest.TestCase):
    def test_request_reply_and_unsolicited_frames_are_separated(self):
        drone = SimulatedDrone(M4T, CURRENT)
        with drone.client() as client:
            link = client.transport
            link.out += Frame(0x1F, 0x2A, 1, 0, 0x42, bytes([1, 0, 0]), ack=0).encode()
            info = commands.get_version(client, M4T.target)
            self.assertEqual(str(info.firmware), CURRENT)
            self.assertEqual([frame.cmd_id for frame in client.poll(0.01)], [0x42])

    def test_read_is_retried_but_reports_no_reply(self):
        drone = SimulatedDrone(M4T, CURRENT, silent=frozenset({commands.VERSION_INQUIRY}))
        with drone.client() as client, self.assertRaises(NoReply):
            commands.get_version(client, M4T.target, timeout=0.02, retries=2)
        self.assertEqual(len(drone.received), 3)
        self.assertEqual(len({frame.seq for frame in drone.received}), 3)

    def test_noise_that_looks_like_a_long_header_does_not_block_the_reply(self):
        from dji_duml.crc import crc8
        fake = bytes([0x55, 0xFF, 0x07])           # version 1, length 1023
        fake += bytes([crc8(fake)])
        drone = SimulatedDrone(M4T, CURRENT)
        with drone.client() as client:
            client.stall_timeout = 0.02
            client.transport.out += fake
            info = commands.get_version(client, M4T.target, timeout=1.0, retries=0)
        self.assertEqual(str(info.firmware), CURRENT)
        self.assertEqual(len(drone.received), 1)

    def test_noise_header_is_dropped_while_telemetry_keeps_arriving(self):
        # On the M4T bytes never stop; progress must be judged by frames.
        from dji_duml.client import DumlClient
        from dji_duml.crc import crc8
        import time
        fake = bytes([0x55, 0xFF, 0x07])
        fake += bytes([crc8(fake)])
        request = version_request(0x1000)

        class Busy:
            def __init__(self):
                self.first = True

            def write(self, data):
                pass

            def read(self, timeout):
                time.sleep(0.02)
                if self.first:
                    self.first = False
                    return fake + request.make_reply(VERSION_BODY).encode()
                return Frame(0x04, 0x2A, 1, 4, 5, ack=0).encode()  # 13 bytes of telemetry

            def close(self):
                pass

        client = DumlClient(Busy(), host=0x2A)
        client._seq = 0x0FFF
        started = time.monotonic()
        reply = client.request(0x1F, 0, 1, timeout=1.0)
        self.assertEqual(reply.payload, VERSION_BODY)
        self.assertLess(time.monotonic() - started, 0.8)

    def test_a_failed_write_never_loses_what_the_same_read_returned(self):
        # Answering a device request (or the keepalive) can fail in the read
        # that also carried the verdict; the verdict must still come out.
        from dji_duml.client import DumlClient
        from dji_duml.errors import TransportError
        verdict = Frame(0x48, 0x2A, 3, 0, 0x42, bytes([4, 9, 0]), ack=0)
        question = Frame(0x48, 0x2A, 4, 0, 0x81, bytes(64))

        class Dying:
            def __init__(self):
                self.chunks = [question.encode() + verdict.encode()]

            def write(self, data):
                raise TransportError("device gone")

            def read(self, timeout):
                return self.chunks.pop(0) if self.chunks else b""

            def close(self):
                pass

        client = DumlClient(Dying(), host=0x2A)
        client.responders[(0, 0x81)] = b"\x00"
        frames = client.poll(0.01)
        self.assertEqual([frame.cmd_id for frame in frames], [0x42])
        with self.assertRaisesRegex(TransportError, "device gone"):
            client.poll(0.01)

    def test_journal_records_general_frames_and_counts_telemetry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log" / "journal.jsonl"
            with Journal(path) as journal, SimulatedDrone(M4T, CURRENT).client(journal) as client:
                client.transport.out += Frame(0x04, 0x2A, 1, 4, 5, ack=0).encode() * 3
                commands.get_version(client, M4T.target)
            lines = path.read_text().splitlines()
        self.assertEqual([('"tx"' in line, '"rx"' in line) for line in lines[:2]],
                         [(True, False), (False, True)])
        self.assertIn('"rx-counted"', lines[-1])
        self.assertIn('"0x04>0x2a 04/05": 3', lines[-1])


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def test_tar_image_and_offline_zip(self):
        image = inspect_package(make_tar(self.directory.name))
        self.assertEqual((image.kind, image.product_code, str(image.version)),
                         ("tar", "wa345t", TARGET))
        offline = inspect_package(make_zip(self.directory.name))
        self.assertEqual((offline.kind, offline.product_code, str(offline.version)),
                         ("zip", "wa345t", "17.02.0501"))
        self.assertTrue(image.unchanged())

    def test_tar_version_comes_from_the_manifest_not_the_file_name(self):
        # The real image V17.00.0001_wa345t_dji_system.bin has a bare
        # wa345t.cfg.sig: only the manifest inside it states the version.
        image = inspect_package(make_tar(self.directory.name, "V17.02.0501_dji_system.bin",
                                         version="17.00.0001"))
        self.assertEqual(str(image.version), "17.00.0001")
        unreadable = inspect_package(make_tar(self.directory.name, "sealed.bin",
                                              content=b"IM*H" + bytes(4000)))
        self.assertIsNone(unreadable.version)

    def test_files_follow_the_manifest_and_are_verified(self):
        from dji_duml.package import open_file, verify_files
        from duml_fixtures import MODULE_DATA, module_name
        import hashlib
        for path in (make_tar(self.directory.name),
                     make_zip(self.directory.name, "with.zip", content=manifest())):
            with self.subTest(path=path.name):
                package = inspect_package(path)
                self.assertEqual([item.name for item in package.files],
                                 [package.config_name, module_name()])
                self.assertIsNone(package.files[0].md5)
                self.assertEqual(package.files[1].md5, hashlib.md5(MODULE_DATA).digest())
                self.assertEqual(package.files_size, package.files[0].size + len(MODULE_DATA))
                with open_file(package, module_name()) as handle:
                    self.assertEqual(handle.read(), MODULE_DATA)
                seen = []
                verify_files(package, seen.append)
                self.assertEqual(sum(seen), package.files_size)
        self.assertEqual(inspect_package(make_tar(self.directory.name, "bare.bin",
                                                  version=None)).files, ())

    def test_manifest_and_files_must_agree(self):
        from dji_duml.package import verify_files
        from duml_fixtures import MODULE_DATA, module_name
        name = module_name()
        cases = {
            "missing.bin": manifest(modules=[("absent.fw.sig", MODULE_DATA)]),
            "size.bin": manifest(modules=[(name, MODULE_DATA + b"x")]),
            "twice.bin": manifest(modules=[(name, MODULE_DATA), (name, MODULE_DATA)]),
            "md5.bin": manifest().replace(b'md5="', b'md5="x'),
        }
        for file_name, content in cases.items():
            with self.subTest(file_name), self.assertRaises(PackageError):
                inspect_package(make_tar(self.directory.name, file_name, content=content))
        corrupt = inspect_package(make_tar(self.directory.name, "corrupt.bin", content=manifest(
            modules=[(name, bytes(len(MODULE_DATA)))])))
        with self.assertRaisesRegex(PackageError, "does not match the MD5"):
            verify_files(corrupt)

    def test_zip_name_and_manifest_must_agree(self):
        same = inspect_package(make_zip(self.directory.name, "same.zip", content=manifest()))
        self.assertEqual(str(same.version), TARGET)
        with self.assertRaisesRegex(PackageError, "says 17.02.0501, its manifest says 17.00.0001"):
            inspect_package(make_zip(self.directory.name, "mixed.zip",
                                     content=manifest("17.00.0001")))

    def test_inconsistent_manifests_are_package_errors(self):
        cases = {
            "device.bin": manifest(device="wm220"),
            "formal.bin": manifest(formal="17.00.0001"),
            "broken.bin": manifest().replace(b"</device>", b""),
            "spelling.bin": manifest("seventeen"),
            "huge.bin": manifest() + bytes(1 << 20),
        }
        for name, content in cases.items():
            with self.subTest(name), self.assertRaises(PackageError):
                inspect_package(make_tar(self.directory.name, name, content=content))
        # A declared encoding is ignored: manifests are read as UTF-8.
        for encoding in (b"gbk", b"x-nope"):
            content = manifest().replace(b'encoding="utf-8"', b'encoding="' + encoding + b'"')
            image = inspect_package(make_tar(self.directory.name, f"{encoding.decode()}.bin",
                                             content=content))
            self.assertEqual(str(image.version), TARGET)

    def test_change_after_inspection_is_detected(self):
        path = make_tar(self.directory.name)
        package = inspect_package(path)
        with open(path, "ab") as handle:
            handle.write(b"x")
        self.assertFalse(package.unchanged())

    def test_damaged_zip_and_bad_version_are_package_errors(self):
        good = make_zip(self.directory.name)
        data = bytearray(good.read_bytes())
        start = data.rfind(b"PK\x01\x02")
        data[start + 4:start + 30] = b"\xff" * 26
        damaged = Path(self.directory.name) / "damaged.zip"
        damaged.write_bytes(bytes(data))
        huge = make_zip(self.directory.name, "huge.zip",
                        config="wa345t_0000_v999.02.0501_20260529.pro.cfg.sig")
        for path in (damaged, huge):
            with self.subTest(path=path.name), self.assertRaises(PackageError):
                inspect_package(path)

    def test_malformed_packages(self):
        bad = Path(self.directory.name) / "random.bin"
        bad.write_bytes(b"not an archive" * 100)
        cases = [bad, make_tar(self.directory.name, "none.bin", config="readme.txt"),
                 make_tar(self.directory.name, "two.bin", extra=("other.cfg.sig",)),
                 make_tar(self.directory.name, "escape.bin", extra=("../etc/passwd",)),
                 make_tar(self.directory.name, "name.bin", config="strange name.cfg.sig")]
        for path in cases:
            with self.subTest(path=path.name), self.assertRaises(PackageError):
                inspect_package(path)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        request = version_request()
        self.request = request.encode()
        self.reply = request.make_reply(VERSION_BODY).encode()
        self.push = Frame(0x1F, 0x2A, 7, 0, 0x42, bytes([3, 40, 0]), ack=0).encode()

    def capture(self, records):
        return usbpcap_file(Path(self.directory.name) / "capture.pcap", records)

    def test_usbpcap_reassembly_direction_and_filters(self):
        path = self.capture([
            usbpcap_record(0x04, self.request[:5], False),
            usbpcap_record(0x04, b"", True),                      # OUT completion: no data
            usbpcap_record(0x04, self.request[5:], False),
            usbpcap_record(0x85, b"", False),                     # IN request: no data
            usbpcap_record(0x85, b"\x99" + self.reply + self.push, True),
            usbpcap_record(0x81, self.push, True, transfer=1),    # interrupt, ignored
            usbpcap_record(0x85, self.reply, True, device=9),     # another device
        ])
        entries, stats = pcap.decode(path, device=47)
        self.assertEqual([(entry.direction.strip(), entry.frame.cmd_id, entry.frame.response)
                          for entry in entries],
                         [("OUT", 1, False), ("IN", 1, True), ("IN", 0x42, False)])
        self.assertTrue(entries[1].frame.answers(entries[0].frame))
        self.assertEqual((stats.frames, stats.discarded), (3, 1))
        only_out, _ = pcap.decode(path, endpoints={0x04})
        self.assertEqual(len(only_out), 1)

    def test_frames_behind_a_fake_long_header_are_recovered(self):
        from dji_duml.crc import crc8
        fake = bytes([0x55, 0xFF, 0x07])
        fake += bytes([crc8(fake)])
        path = self.capture([
            usbpcap_record(0x85, fake + self.reply, True, seconds=10),
            usbpcap_record(0x85, self.push, True, seconds=11),
            usbpcap_record(0x04, self.request, False, seconds=12),
        ])
        entries, stats = pcap.decode(path)
        self.assertEqual([(entry.time, entry.frame.cmd_id) for entry in entries],
                         [(10.0, 1), (11.0, 0x42), (12.0, 1)])
        self.assertEqual(stats.discarded, 4)

    def test_truncated_capture_keeps_complete_records(self):
        path = self.capture([usbpcap_record(0x04, self.request, False),
                             usbpcap_record(0x85, self.reply, True)])
        path.write_bytes(path.read_bytes()[:-10])
        entries, _ = pcap.decode(path)
        self.assertEqual(len(entries), 1)

    def test_usbmon_pcapng(self):
        import struct

        def urb(event, endpoint, data):
            return struct.pack("<QBBBBHbbqiiII8sIIII", 1, ord(event), 3, endpoint, 5, 2, 0, 0,
                               0, 0, 0, len(data), len(data), bytes(8), 0, 0, 0, 0) + data

        def block(kind, body):
            body += bytes(-len(body) % 4)
            total = len(body) + 12
            return struct.pack("<II", kind, total) + body + struct.pack("<I", total)

        def packet(data):
            return block(6, struct.pack("<IIIII", 0, 0, 1_000_000, len(data), len(data)) + data)

        path = Path(self.directory.name) / "capture.pcapng"
        path.write_bytes(
            block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
            + block(1, struct.pack("<HHI", 220, 0, 65535))
            + packet(urb("S", 0x04, self.request)) + packet(urb("C", 0x04, b""))
            + packet(urb("S", 0x85, b"")) + packet(urb("C", 0x85, self.reply)))
        entries, _ = pcap.decode(path)
        self.assertEqual([(entry.endpoint, entry.device, entry.frame.response)
                          for entry in entries], [(0x04, 5, False), (0x85, 5, True)])
        self.assertAlmostEqual(entries[0].time, 1.0)

    def test_pcapng_with_a_network_interface_too(self):
        import struct

        def urb(event, endpoint, data):
            return struct.pack("<QBBBBHbbqiiII8sIIII", 1, ord(event), 3, endpoint, 5, 2, 0, 0,
                               0, 0, 0, len(data), len(data), bytes(8), 0, 0, 0, 0) + data

        def block(kind, body):
            body += bytes(-len(body) % 4)
            total = len(body) + 12
            return struct.pack("<II", kind, total) + body + struct.pack("<I", total)

        def packet(interface, data):
            return block(6, struct.pack("<IIIII", interface, 0, 1_000_000, len(data), len(data))
                         + data)

        header = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        ethernet = block(1, struct.pack("<HHI", 1, 0, 65535))
        path = Path(self.directory.name) / "mixed.pcapng"
        path.write_bytes(header + ethernet + block(1, struct.pack("<HHI", 220, 0, 65535))
                         + packet(0, bytes(60)) + packet(1, urb("S", 0x04, self.request))
                         + packet(0, bytes(60)) + packet(1, urb("C", 0x85, self.reply)))
        entries, _ = pcap.decode(path)
        self.assertEqual([entry.frame.response for entry in entries], [False, True])
        path.write_bytes(header + ethernet + packet(0, bytes(60)))
        with self.assertRaisesRegex(pcap.CaptureError, "link type 1"):
            pcap.decode(path)

    def test_classic_pcap_of_another_link_type(self):
        import struct

        path = Path(self.directory.name) / "net.pcap"
        path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        with self.assertRaisesRegex(pcap.CaptureError, "link type 1"):
            pcap.decode(path)

    def test_stats_when_the_reader_stops_early(self):
        path = self.capture([usbpcap_record(0x85, b"\x99" + self.reply, True),
                             usbpcap_record(0x85, self.push, True)])
        stats = pcap.TraceStats()
        frames = pcap.iter_frames(path, stats=stats)
        next(frames)
        frames.close()
        self.assertEqual(stats.discarded, 1)

    def test_truncated_pcapng_option_does_not_crash(self):
        import struct

        def block(kind, body):
            total = len(body) + 12
            return struct.pack("<II", kind, total) + body + struct.pack("<I", total)

        path = Path(self.directory.name) / "odd.pcapng"
        path.write_bytes(
            block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
            + block(1, struct.pack("<HHI", 220, 0, 65535) + struct.pack("<HH", 9, 1)))
        with self.assertRaises(pcap.CaptureError):
            pcap.decode(path)  # no packets, but no IndexError either

    def test_unknown_files_are_refused(self):
        path = Path(self.directory.name) / "junk.pcap"
        path.write_bytes(b"\x00" * 64)
        with self.assertRaises(pcap.CaptureError):
            pcap.decode(path)


if __name__ == "__main__":
    unittest.main()
