"""dji-duml fw add and harvest: every kind of source, what is kept and what is refused.

The real-data checks at the end run only when their sources are named:

    DJI_DUML_FW_DIR=C:\\dev\\fw_list\\m4t
    DJI_DUML_FIRM_CACHE=...\\DJIEngine\\DJIData\\firm_cache
    DJI_DUML_STORE_CAPTURE=C:\\dev\\captures\\upgrade_17_usb.pcap
"""
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from dji_duml import store as store_module
from dji_duml.extract import extract
from dji_duml.flasher import plan
from dji_duml.ingest import BUSY, add, harvest
from dji_duml.package import IMAGE_MAGIC, inspect_package
from dji_duml.profiles import M4T
from dji_duml.store import Store, StoreError
from store_fixtures import (
    A, B, C, CURRENT, OLD, TARGET, StoreCase, age, config, image, release_list,
)
from test_duml_extract import Upload, interleave

FW_DIR = os.environ.get("DJI_DUML_FW_DIR")
FIRM_CACHE = os.environ.get("DJI_DUML_FIRM_CACHE")
CAPTURE = os.environ.get("DJI_DUML_STORE_CAPTURE")


def make_zip(path, version=TARGET, modules=(A, B), listed=None):
    """An offline download: the configuration under DJI's long name."""
    name = f"wa345t_0000_v{version}_20260529.pro.cfg.sig"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(name, config(version, listed or modules))
        for item, data in modules:
            archive.writestr(item, data)
    return Path(path)


def make_tar(path, version=TARGET, modules=(A, B), extra=()):
    with tarfile.open(path, "w") as archive:
        for name, data in [("wa345t.cfg.sig", config(version, modules)), *modules, *extra]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return Path(path)


@contextmanager
def opened_files():
    """Names of the files the store and the ingest open."""
    real, real_source, names = open, store_module.open_source, []

    def spy(path, *args, **kwargs):
        names.append(Path(path).name)
        return real(path, *args, **kwargs)

    def source_spy(path):
        names.append(Path(path).name)
        return real_source(path)

    with patch("dji_duml.store.open", spy, create=True), \
            patch("dji_duml.ingest.open", spy, create=True), \
            patch("dji_duml.store.open_source", source_spy), \
            patch("dji_duml.ingest.open_source", source_spy):
        yield names


def snapshot(*paths):
    """Size, mtime and SHA-256 of every file below ``paths``."""
    files = [file for path in paths for file in
             ([Path(path)] if Path(path).is_file() else sorted(Path(path).rglob("*")))
             if file.is_file()]
    return {str(file): (file.stat().st_size, file.stat().st_mtime_ns,
                        hashlib.sha256(file.read_bytes()).hexdigest()) for file in files}


class IngestCase(StoreCase):
    def add(self, *paths, force=False):
        store = self.store()
        report = add(store, list(paths), force)
        return store, report

    def summary(self, store):
        return [(str(version.version), version.summary) for version in store.versions("wa345t")
                if version.configs]


class PackageTests(IngestCase):
    def test_zip_gives_a_ready_version_and_is_not_read_twice(self):
        archive = make_zip(self.src / "M4T.zip")
        before = snapshot(archive)
        store, report = self.add(archive)
        self.assertEqual((report.code, self.summary(store)), (0, [(TARGET, "ready 2/2")]))
        self.assertRegex(report.lines[0], r"^zip\s+M4T.zip: config \w{12} \(wa345t 17.02.0501\) "
                                          r"\+ 2 modules: 3 new, 0 held$")
        with patch("dji_duml.ingest.inspect_package") as inspect, \
                patch("dji_duml.ingest.open_file") as opened:
            store, report = self.add(archive)
        inspect.assert_not_called()
        opened.assert_not_called()
        self.assertIn("unchanged since", report.lines[0])
        self.assertIn("nothing new", report.lines[0])
        self.assertEqual(snapshot(archive), before)
        _, report = self.add(archive, force=True)
        self.assertIn("0 new, 3 held", report.lines[0])

    def test_tar_and_zip_of_one_version_share_the_objects(self):
        store, report = self.add(make_zip(self.src / "M4T.zip"),
                                 make_tar(self.src / "dji_system.bin"))
        self.assertIn("0 new, 3 held", report.lines[1])
        (config_object,) = [record for record in store.index["objects"].values()
                            if record["kind"] == "config"]
        self.assertEqual([(source["from"], source["name"]) for source in config_object["sources"]],
                         [("zip", f"wa345t_0000_v{TARGET}_20260529.pro.cfg.sig"),
                          ("tar", "wa345t.cfg.sig")])

    def test_member_that_differs_from_the_manifest_is_rejected(self):
        bad = (B[0], image(77))
        store, report = self.add(make_zip(self.src / "bad.zip", modules=(A, bad),
                                          listed=(A, B)))
        self.assertEqual(report.code, 2)
        self.assertTrue(any(f"rejected {B[0]}: size or MD5 differs" in line
                            for line in report.lines))
        self.assertEqual(self.summary(store), [(TARGET, "PARTIAL 1/2")])

    def test_an_interrupted_zip_is_read_again(self):
        archive = make_zip(self.src / "M4T.zip", modules=(A, B, C))
        real, calls = Store.put, []

        def interrupted(store, *args, **kwargs):
            calls.append(1)
            if len(calls) == 3:
                raise KeyboardInterrupt
            return real(store, *args, **kwargs)

        with patch.object(Store, "put", interrupted), self.assertRaises(KeyboardInterrupt):
            self.add(archive)
        store = self.store()
        self.assertEqual(self.summary(store), [(TARGET, "PARTIAL 1/3")])
        store, report = self.add(archive)
        self.assertNotIn("unchanged since", report.lines[0])
        self.assertEqual(self.summary(store), [(TARGET, "ready 3/3")])
        store, report = self.add(archive)
        self.assertIn("unchanged since", report.lines[0])

    def test_a_skipped_member_leaves_the_zip_unfinished(self):
        archive = make_zip(self.src / "M4T.zip")
        real, calls = Store.put, []

        def changed(store, source, *args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise store_module.Changed("changed while reading")
            return real(store, source, *args, **kwargs)

        with patch.object(Store, "put", changed):
            store, report = self.add(archive)
        self.assertEqual(report.code, 2)
        store, report = self.add(archive)
        self.assertEqual((report.code, self.summary(store)), (0, [(TARGET, "ready 2/2")]))

    def test_unlisted_members_are_named_not_stored(self):
        store, report = self.add(make_tar(self.src / "x.bin", extra=[C]))
        self.assertTrue(any(f"not in the manifest, not stored: {C[0]}" in line
                            for line in report.lines))
        self.assertEqual(len(store.index["objects"]), 3)


class CaptureTests(IngestCase):
    def capture(self, upload, name="capture.pcap"):
        return upload.write(self.src / name)

    def test_complete_session(self):
        upload = Upload()
        upload.session(modules=[A, B])
        capture = self.capture(upload)
        before = snapshot(capture)
        store, report = self.add(capture)
        self.assertEqual(report.code, 0)
        self.assertEqual(report.lines[0],
                         "capture   capture.pcap: 3 transfers, 3 passed every check")
        self.assertEqual(self.summary(store), [(CURRENT, "ready 2/2")])
        self.assertEqual(list((self.root / "tmp").iterdir()), [])
        self.assertEqual(snapshot(capture), before)
        sources = [source for record in store.index["objects"].values()
                   for source in record["sources"]]
        self.assertEqual({source["from"] for source in sources}, {"capture"})
        self.assertNotIn("usb", json.dumps(store.index).lower())

    def test_an_interrupted_capture_is_read_again(self):
        upload = Upload()
        upload.session(modules=[A, B])
        capture = self.capture(upload)
        real, calls = Store.put, []

        def full_disk(store, *args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise OSError(28, "No space left on device")
            return real(store, *args, **kwargs)

        with patch.object(Store, "put", full_disk), self.assertRaises(OSError):
            self.add(capture)
        store, report = self.add(capture)
        self.assertEqual(self.summary(store), [(CURRENT, "ready 2/2")])
        store, report = self.add(capture)
        self.assertIn("unchanged since", report.lines[0])

    def test_two_drones_give_two_configurations(self):
        first, second = Upload(device=47), Upload(device=48)
        first.session(modules=[A, B])
        second.session(modules=[A, C])
        store, report = self.add(self.capture(interleave(first, second)))
        (version,) = store.versions("wa345t")
        self.assertEqual(version.summary, "ready x2")

    def test_capture_without_a_configuration_gives_orphans(self):
        upload = Upload()
        upload.send(A[0], A[1])
        store, report = self.add(self.capture(upload))
        self.assertEqual(report.orphans, (0, 1))
        self.assertEqual(store.versions("wa345t"), [])

    def test_corrupted_chunk_leaves_the_version_partial(self):
        upload = Upload()
        upload.send("wa345t.cfg.sig", config(CURRENT, (A, B)))
        upload.send(A[0], A[1])
        upload.send(B[0], B[1], skip={1})
        store, report = self.add(self.capture(upload))
        self.assertEqual(report.code, 2)
        self.assertIn("1 failed extraction, not stored", report.lines[1])
        with self.assertRaisesRegex(StoreError, f"missing: {B[0]}"):
            store.select("wa345t", CURRENT)

    def test_tmp_is_empty_after_a_failure_inside_extract(self):
        upload = Upload()
        upload.session(modules=[A, B])
        capture = self.capture(upload)
        with patch("dji_duml.ingest.extract", side_effect=lambda capture, out: (
                Path(out).mkdir(), (Path(out) / "x").write_bytes(b"x"), 1 / 0)):
            with self.assertRaises(ZeroDivisionError):
                self.add(capture)
        self.assertEqual(list((self.root / "tmp").iterdir()), [])

    def test_a_file_that_is_not_a_capture_is_rejected_unread(self):
        store, report = self.add(self.write("notes.pcap", b"hello"))
        self.assertEqual(report.code, 2)
        self.assertIn("not a pcap or pcapng file", report.lines[0])


class ExtractFolderTests(IngestCase):
    def extracted(self, upload, name="extracted"):
        out = self.src / name
        extract(upload.write(self.tmp / f"{name}.pcap"), out)
        return out

    def test_extract_output(self):
        upload = Upload()
        upload.session(modules=[A, B])
        upload.send(C[0], C[1], skip={0}, reply=None)  # fails: .incomplete
        upload.send("wa345t.cfg.sig", config(OLD, (A, C)))  # a second session in one capture
        upload.send(A[0], A[1])
        upload.send(C[0], C[1])
        folder = self.extracted(upload)
        self.assertTrue(any(path.name.endswith(".incomplete") for path in folder.iterdir()))
        before = snapshot(folder)
        store, report = self.add(folder)
        self.assertEqual(self.summary(store), [(CURRENT, "ready 2/2"), (OLD, "ready 2/2")])
        self.assertFalse(any(record["size"] == (folder / "report.json").stat().st_size
                             for record in store.index["objects"].values()))
        self.assertEqual(snapshot(folder), before)

    def test_a_file_changed_after_extraction_is_rejected(self):
        upload = Upload()
        upload.session(modules=[A, B])
        folder = self.extracted(upload)
        (folder / B[0]).write_bytes(image(55))
        store, report = self.add(folder)
        self.assertEqual(report.code, 2)
        self.assertTrue(any("changed after extraction" in line for line in report.lines))
        self.assertEqual(self.summary(store), [(CURRENT, "PARTIAL 1/2")])


class CacheTests(IngestCase):
    def cache(self, *items, folder="cache"):
        for number, data in enumerate(items):
            age(self.write(f"{number:032x}.cache", data, self.src / folder))
        return self.src / folder

    def test_harvest(self):
        cache = self.cache(A[1], A[1], B[1], release_list((CURRENT, "2026-04-29")))
        before = snapshot(cache)
        store = self.store()
        report = harvest(store, cache)
        self.assertEqual(report.code, 0)
        self.assertEqual(len(store.index["objects"]), 2)  # a duplicate under another name
        self.assertEqual(len(store.index["releases"]), 1)
        self.assertIn("4 files: 3 modules (2 distinct), 1 release lists; 0 busy, 0 locked, "
                      "0 rejected", report.lines[1])
        self.assertEqual(report.orphans, (0, 2))
        self.assertEqual(snapshot(cache), before)
        with opened_files() as opened:
            report = harvest(store, cache)
        self.assertEqual([name for name in opened if name.endswith(".cache")], [])
        self.assertIn("0 modules new (0.0 MB), 4 already held", report.lines[2])

    def test_junk_busy_and_locked_files(self):
        cache = self.cache(A[1], b"PK junk", b"[1, 2]")
        young = self.write(f"{9:032x}.cache", B[1], cache)
        os.utime(young, None)
        store = self.store()
        report = harvest(store, cache)
        self.assertEqual(report.code, 2)
        self.assertIn("1 busy, 0 locked, 2 rejected", report.lines[1])
        self.assertEqual(len(store.index["objects"]), 1)
        age(young, BUSY + 1)
        real = store_module.open_source

        def locked(path):
            if Path(path).name == young.name:
                raise PermissionError(13, "in use")
            return real(path)

        with patch("dji_duml.ingest.open_source", locked):
            report = harvest(store, cache)
        self.assertIn("0 busy, 1 locked", report.lines[1])

    def test_a_file_rewritten_while_it_is_copied_is_discarded(self):
        cache = self.cache(A[1])
        store = self.store()
        real, calls = store_module.file_stat, []

        def rewritten(path):
            calls.append(path)
            size, mtime = real(path)
            return size, mtime + len(calls)  # a new mtime at every look

        with patch("dji_duml.store.file_stat", rewritten):
            report = harvest(store, cache)
        self.assertEqual(report.code, 2)
        self.assertTrue(any("changed while reading" in line for line in report.lines))
        self.assertEqual(store.index["objects"], {})

    def test_a_cache_file_rewritten_under_its_name_is_read_once(self):
        cache = self.cache(A[1], B[1])
        store = self.store()
        harvest(store, cache)
        rewritten = cache / f"{1:032x}.cache"
        rewritten.write_bytes(C[1])  # Assistant reused the name for other content
        age(rewritten, 7200)
        report = harvest(store, cache)
        self.assertIn("1 modules new", report.lines[2])
        with opened_files() as opened:
            report = harvest(store, cache)
        self.assertEqual([name for name in opened if name.endswith(".cache")], [])
        self.assertIn("0 modules new (0.0 MB), 2 already held", report.lines[2])
        self.assertEqual(store.unseen_cache(cache), (2, 0))

    def test_harvest_refuses_a_folder_that_is_not_a_cache(self):
        folder = self.src / "other"
        self.write("readme.txt", b"x", folder)
        with self.assertRaisesRegex(StoreError, "not a DJI Assistant firm_cache"):
            harvest(self.store(), folder)


class FolderTests(IngestCase):
    def test_configuration_with_its_modules(self):
        folder = self.folder(CURRENT, (A, B))
        self.write("notes.txt", b"x", folder)
        before = snapshot(folder)
        with opened_files() as opened:
            store, report = self.add(folder)
        self.assertEqual(self.summary(store), [(CURRENT, "ready 2/2")])
        self.assertNotIn("notes.txt", opened)
        self.assertIn("skipped   notes.txt: not a firmware file name", report.lines)
        self.assertEqual(report.code, 0)
        self.assertEqual(snapshot(folder), before)

    def test_unlisted_module_needs_a_held_configuration(self):
        folder = self.folder(CURRENT, (A,))
        self.write(*C, folder)
        store, report = self.add(folder)
        self.assertEqual(report.code, 2)
        self.assertTrue(any("listed by no held configuration" in line for line in report.lines))
        other = self.folder(OLD, (C,))
        (other / "wa345t.cfg.sig").rename(self.src / "loose.cfg.sig")
        add(store, [self.src / "loose.cfg.sig"])
        report = add(store, [folder / C[0]])
        self.assertEqual(report.code, 0)
        self.assertEqual(self.summary(store), [(CURRENT, "ready 1/1"), (OLD, "ready 1/1")])

    def test_a_listed_module_must_match_its_manifest(self):
        folder = self.folder(CURRENT, (A, B))
        (folder / B[0]).write_bytes(image(66))
        store, report = self.add(folder)
        self.assertTrue(any("differs from the manifest next to it" in line
                            for line in report.lines))

    def test_subfolders_one_level_deep(self):
        top = self.src / "top"
        self.folder(CURRENT, (A,), name="top/one")
        self.folder(OLD, (B,), name="top/one/two")
        store, report = self.add(top)
        self.assertEqual(self.summary(store), [(CURRENT, "ready 1/1")])

    def test_loose_configuration_name_must_agree_with_its_manifest(self):
        path = self.write(f"wa345t_0000_v{TARGET}_20260529.pro.cfg.sig", config(CURRENT))
        store, report = self.add(path)
        self.assertEqual(report.code, 2)
        self.assertIn(f"its name says {TARGET}", "\n".join(report.lines))

    def test_names_that_are_not_firmware_are_skipped(self):
        store, report = self.add(self.write("photo.jpg", b"x"))
        self.assertEqual((report.code, report.lines), (0, ["skipped   photo.jpg: not a "
                                                           "firmware file name"]))


class ScopeTests(IngestCase):
    def test_assistant_data_outside_firm_cache_is_refused_unopened(self):
        data = self.src / "DJIEngine" / "DJIData"
        cache = data / "firm_cache"
        age(self.write(f"{1:032x}.cache", A[1], cache))
        self.write("auth.ini", b"secret", data)
        (data / "data_security").mkdir()
        (cache / "sub").mkdir()
        store = self.store()
        with opened_files() as opened:
            for path in (data, data / "auth.ini", data / "data_security", self.src / "auth.ini",
                         data / "data_security" / "x.fw.sig", cache / "sub", data / "other.json"):
                with self.subTest(path=path), self.assertRaisesRegex(
                        StoreError, "never opened|only the files in firm_cache"):
                    add(store, [path])
        self.assertEqual(opened, [])
        self.assertEqual(harvest(store, cache).code, 0)
        self.assertEqual(len(store.index["objects"]), 1)

    def test_every_file_is_guarded_before_it_is_opened(self):
        upload = Upload()
        upload.session(modules=[A, B])
        extracted = self.src / "extracted"
        extract(upload.write(self.tmp / "x.pcap"), extracted)
        cache = self.src / "cache"
        age(self.write(f"{1:032x}.cache", C[1], cache))
        folder = self.folder(OLD, (A, C))
        guarded = []

        def spy(path):
            guarded.append(Path(path).name)

        with opened_files() as opened, patch("dji_duml.ingest.scope_guard", spy):
            self.add(extracted, cache, folder)
        sources = [name for name in opened  # not the store's own tmp, index and lock
                   if not name.endswith(".part") and not name.startswith("index.json")
                   and name != "lock"]
        self.assertGreaterEqual(len(set(sources)), 5)  # extracted, cache and folder files
        for name in sources:
            self.assertIn(name, guarded)

    def test_a_link_out_of_the_folder_is_refused_unopened(self):
        outside = self.write("secret.fw.sig", A[1], self.tmp / "elsewhere")
        folder = self.folder(CURRENT, (B,))
        link = folder / A[0]
        try:
            os.symlink(outside, link)
        except (OSError, NotImplementedError) as exc:  # no privilege on Windows
            self.skipTest(f"cannot make a symbolic link here: {exc}")
        with opened_files() as opened:
            store, report = self.add(folder)
        self.assertNotIn("secret.fw.sig", opened)
        self.assertNotIn(A[0], opened)
        self.assertTrue(any("a link out of" in line for line in report.lines))
        self.assertEqual(report.code, 2)

    @unittest.skipUnless(os.name == "nt", "a directory junction")
    def test_a_junction_out_of_the_folder_is_refused(self):
        import _winapi
        target = self.folder(OLD, (A,), name="elsewhere")
        top = self.src / "top"
        top.mkdir()
        _winapi.CreateJunction(str(target), str(top / "linked"))
        store, report = self.add(top)
        self.assertTrue(any("a link out of" in line for line in report.lines))
        self.assertEqual(store.index["objects"], {})

    def test_missing_path_is_fatal(self):
        with self.assertRaisesRegex(StoreError, "does not exist"):
            add(self.store(), [self.src / "absent.zip"])


class FreeSpaceTests(IngestCase):
    def test_not_enough_free_space_skips_the_source(self):
        archive = make_zip(self.src / "M4T.zip")
        with patch("dji_duml.ingest.shutil.disk_usage") as usage:
            usage.return_value.free = 1 << 20
            store, report = self.add(archive)
        self.assertEqual(report.code, 2)
        self.assertIn("skipped", report.lines[0])
        self.assertEqual(list((self.root / "objects").iterdir()), [])

    def test_a_zip_is_measured_unpacked(self):
        big = (A[0], IMAGE_MAGIC + bytes(1 << 20))  # deflates to a few kB
        archive = self.src / "M4T.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
            handle.writestr(f"wa345t_0000_v{TARGET}_20260529.pro.cfg.sig",
                            config(TARGET, (big,)))
            handle.writestr(*big)
        self.assertLess(archive.stat().st_size, 1 << 19)
        with patch("dji_duml.ingest.shutil.disk_usage") as usage:
            usage.return_value.free = store_module.SPARE + (1 << 19)
            store, report = self.add(archive)
        self.assertEqual(report.code, 2)
        self.assertRegex(report.lines[0], "skipped, .* it needs 1.0 MB")
        self.assertEqual(list((self.root / "objects").iterdir()), [])

    def test_folders_and_loose_files_are_measured(self):
        folder = self.folder(CURRENT, (A, B))
        loose = self.write("x.cfg.sig", config(OLD, (C,)))
        with patch("dji_duml.ingest.shutil.disk_usage") as usage:
            usage.return_value.free = store_module.SPARE + 100
            store, report = self.add(folder, loose)
        self.assertEqual(report.code, 2)
        self.assertEqual(sum(": skipped, " in line for line in report.lines), 2)
        self.assertEqual(list((self.root / "objects").iterdir()), [])


@unittest.skipUnless(FW_DIR, "set DJI_DUML_FW_DIR")
class RealPackagesTest(unittest.TestCase):
    def test_packages_give_ready_versions_and_the_flashed_bytes(self):
        folder = Path(FW_DIR)
        with tempfile.TemporaryDirectory() as tmp:
            store = Store.open(Path(tmp) / "store", create=True)
            add(store, [folder / "14.01.0012_dji_system.bin",
                        folder / "M4T_UAV_17.02.05.01_pro.zip",
                        folder / "V17.00.0001_wa345t_dji_system.bin"])
            states = {str(version.version): version.state for version in store.versions("wa345t")}
            self.assertEqual(states, {"14.01.0012": "ready", "17.00.0001": "ready",
                                      "17.02.0501": "ready"})
            out = Path(tmp) / "14.bin"
            store.export(store.select("wa345t", "14.01.0012")[0], out)
            self.assertEqual(hashlib.md5(out.read_bytes()).hexdigest(),
                             "b23b8d431db7bc001381db9fd8128584")
            out = Path(tmp) / "17.bin"
            store.export(store.select("wa345t", "17.02.0501")[0], out)
            self.assertEqual(plan(M4T, inspect_package(out)),
                             plan(M4T, inspect_package(folder / "M4T_UAV_17.02.05.01_pro.zip")))


@unittest.skipUnless(FIRM_CACHE, "set DJI_DUML_FIRM_CACHE")
class RealCacheTest(unittest.TestCase):
    def test_harvest_leaves_the_cache_unchanged(self):
        cache = Path(FIRM_CACHE)
        def state():
            return {path.name: (path.stat().st_size, path.stat().st_mtime_ns)
                    for path in cache.iterdir()}

        before = state()
        with tempfile.TemporaryDirectory() as tmp:
            store = Store.open(Path(tmp) / "store", create=True)
            harvest(store, cache)
            self.assertEqual(len(store.index["releases"]), 3)
            self.assertEqual(len(store.orphans()), 59)  # no configuration: all are orphans
        self.assertEqual(state(), before)


@unittest.skipUnless(CAPTURE, "set DJI_DUML_STORE_CAPTURE")
class RealCaptureTest(unittest.TestCase):
    def test_the_captured_version_becomes_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store.open(Path(tmp) / "store", create=True)
            add(store, [CAPTURE])
            self.assertTrue(any(version.state == "ready" for version in store.versions("wa345t")))


if __name__ == "__main__":
    unittest.main()
