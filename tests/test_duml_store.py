"""dji-duml fw: the firmware store, its derived versions, export and check."""
import hashlib
import io
import itertools
import json
import os
import shutil
import stat
import tarfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dji_duml import store as store_module
from dji_duml.errors import PackageError
from dji_duml.ingest import add, harvest
from dji_duml.pack import PackError, pack
from dji_duml.package import ConfigInfo, read_config
from dji_duml.store import FORMAT, Source, Store, StoreError
from store_fixtures import (
    A, B, C, CURRENT, OLD, TARGET, StoreCase, age, config, image, module, release_list,
)


class ReadConfigTests(StoreCase):
    def test_product_version_modules_and_release_fields(self):
        info = read_config(config(OLD, start="2025/06/14"))
        self.assertIsInstance(info, ConfigInfo)
        self.assertEqual((info.product, str(info.version)), ("wa345t", OLD))
        self.assertEqual([item.name for item in info.modules], [A[0], B[0]])
        self.assertEqual(dict(info.release), {"from": "2025/06/14", "expire": "2027/01/01",
                                              "antirollback": "0", "enforce": "0"})

    def test_refusals(self):
        for data, error in ((b"MZ" + config()[2:], "IM\\*H"), (image(1), "No readable manifest"),
                            (config() + bytes(1 << 20), "too large")):
            with self.subTest(error=error), self.assertRaisesRegex(PackageError, error):
                read_config(data)


class PutTests(StoreCase):
    def put(self, store, name, data, kind="file"):
        path = self.write(name, data)
        return store.put(Source.of(kind, path))

    def test_one_content_under_two_names_is_one_read_only_object(self):
        store = self.store()
        with store.writer():
            first = self.put(store, "one.fw.sig", A[1])
            second = self.put(store, "two.fw.sig", A[1])
        self.assertEqual(first, (hashlib.sha256(A[1]).hexdigest(), True))
        self.assertEqual(second, (first[0], False))
        path = self.root / "objects" / first[0]
        self.assertEqual(path.read_bytes(), A[1])
        self.assertFalse(stat.S_IMODE(path.stat().st_mode) & 0o222)  # access() lies for root
        record = store.index["objects"][first[0]]
        self.assertEqual(record["kind"], "module")
        self.assertEqual([source["name"] for source in record["sources"]],
                         ["one.fw.sig", "two.fw.sig"])
        self.assertEqual(record["md5"], hashlib.md5(A[1]).hexdigest())

    def test_index_is_sorted_format_1(self):
        store = self.store()
        with store.writer():
            self.put(store, "b.fw.sig", B[1])
            self.put(store, "a.fw.sig", A[1])
        text = (self.root / "index.json").read_text(encoding="utf-8")
        index = json.loads(text)
        self.assertEqual(index["format"], 1)
        self.assertEqual(text, json.dumps(index, ensure_ascii=True, indent=1, sort_keys=True)
                         + "\n")
        self.assertEqual((self.root / "FORMAT").read_text(encoding="utf-8"), FORMAT)
        self.assertTrue((self.root / "index.json.bak").exists())

    def test_failure_in_the_middle_of_a_copy_leaves_nothing(self):
        store = self.store()
        with store.writer():
            self.put(store, "a.fw.sig", A[1])
        before = (self.root / "index.json").read_bytes()

        class Broken(io.BytesIO):
            def read(self, size=-1):
                if self.tell():
                    raise OSError("device removed")
                return super().read(4)

        source = Source.of("file", self.write("b.fw.sig", B[1]))
        with store.writer(), self.assertRaises(OSError):
            store.put(source, lambda: Broken(B[1]))
        self.assertEqual(len(list((self.root / "objects").iterdir())), 1)
        self.assertEqual(list((self.root / "tmp").iterdir()), [])
        self.assertEqual((self.root / "index.json").read_bytes(), before)

    def test_failed_index_replace_leaves_a_stray_that_is_adopted(self):
        store = self.store()
        real = os.replace

        def no_index(source, target):
            if str(target).endswith("index.json"):
                raise OSError("disk full")
            return real(source, target)

        with store.writer(), patch("dji_duml.store.os.replace", no_index), \
                self.assertRaisesRegex(StoreError, "is stored, but the index could not be saved"):
            self.put(store, "a.fw.sig", A[1])
        digest = hashlib.sha256(A[1]).hexdigest()
        store = self.store()
        self.assertNotIn(digest, store.index["objects"])
        problems = store.check()
        self.assertEqual([problem.text for problem in problems],
                         [f"stray file objects{os.sep}{digest}"])
        with store.writer():
            fixed = store.check(fix=True)
        self.assertTrue(fixed[0].fixed)
        self.assertEqual(store.index["objects"][digest]["sources"][0]["from"], "recovered")
        self.assertEqual(store.check(), [])
        # A re-run of the ingest records it as well.
        with store.writer():
            self.assertEqual(self.put(store, "a.fw.sig", A[1]), (digest, False))

    def test_permission_error_on_the_index_replace_is_retried(self):
        store = self.store()
        real, calls = os.replace, itertools.count()

        def busy(source, target):
            if str(target).endswith("index.json") and next(calls) < 3:
                raise PermissionError("in use")
            return real(source, target)

        with store.writer(), patch("dji_duml.store.os.replace", busy), \
                patch("dji_duml.store.time.sleep"):
            digest, _ = self.put(store, "a.fw.sig", A[1])
        self.assertIn(digest, Store.open(self.root).index["objects"])

    def test_second_writer_is_refused(self):
        store = self.store()
        with store.writer():
            with self.assertRaisesRegex(StoreError, "in use by another dji-duml"):
                with Store.open(self.root).writer():
                    pass

    def test_a_wrong_existing_record_is_corrected_from_the_bytes(self):
        store = self.store()
        with store.writer():
            digest, _ = self.put(store, "a.fw.sig", A[1])
            store.index["objects"][digest].update(md5="0" * 32, size=1, kind="config")
            store.save()
        store = Store.open(self.root)
        with store.writer():
            self.assertEqual(self.put(store, "b.fw.sig", A[1]), (digest, False))
        record = Store.open(self.root).index["objects"][digest]
        self.assertEqual((record["md5"], record["size"], record["kind"]),
                         (hashlib.md5(A[1]).hexdigest(), len(A[1]), "module"))

    def test_a_size_outside_the_allowed_ones_is_rejected_unread(self):
        store = self.store()
        source = Source.of("file", self.write("a.fw.sig", A[1]))
        with store.writer(), patch("dji_duml.store.open_source") as opened:
            with self.assertRaisesRegex(StoreError, "not listed"):
                store.put(source, allowed={(len(A[1]) + 1, bytes(16))}, reason="not listed")
        opened.assert_not_called()
        self.assertEqual(list((self.root / "tmp").iterdir()), [])

    def test_backup_copy_is_retried_and_its_failure_names_the_index(self):
        store = self.store()
        real, calls = shutil.copyfile, itertools.count()

        def busy(source, target):
            if str(target).endswith(".bak") and next(calls) < 3:
                raise PermissionError(13, "in use")
            return real(source, target)

        with store.writer(), patch("dji_duml.store.shutil.copyfile", busy), \
                patch("dji_duml.store.time.sleep"):
            self.put(store, "a.fw.sig", A[1])
            digest, _ = self.put(store, "b.fw.sig", B[1])
        self.assertIn(digest, Store.open(self.root).index["objects"])

        def locked(source, target):
            raise PermissionError(13, "in use")

        with store.writer(), patch("dji_duml.store.shutil.copyfile", locked), \
                patch("dji_duml.store.time.sleep"), self.assertRaisesRegex(
                    StoreError, r"is stored, but the index could not be saved: Cannot update "
                                r".*index\.json\.bak"):
            self.put(store, "c.fw.sig", C[1])

    def test_a_source_renamed_while_it_is_read_is_changed_not_stored(self):
        store = self.store()
        path = self.write("a.fw.sig", A[1])
        source = Source.of("cache", path)

        def read():
            handle = store_module.open_source(path)
            os.replace(path, path.with_name("renamed"))  # Assistant, meanwhile
            return handle

        with store.writer(), self.assertRaisesRegex(StoreError, "gone while reading"):
            store.put(source, read)
        self.assertEqual(store.index["objects"], {})

    def test_a_lock_that_cannot_be_opened_is_not_called_in_use(self):
        store = self.store()
        with store.writer():
            pass
        os.chmod(self.root / "lock", 0o444)
        self.addCleanup(os.chmod, self.root / "lock", 0o666)
        if os.name == "nt":
            with self.assertRaisesRegex(StoreError, "Cannot open the store's lock"):
                with store.writer():
                    pass
        else:  # flock needs no write access: the flasher's _open_lock_file
            with store.writer():
                pass

    def test_non_images_and_unlisted_sizes_are_rejected(self):
        store = self.store()
        with store.writer():
            with self.assertRaisesRegex(StoreError, "IM\\*H"):
                self.put(store, "x.fw.sig", b"MZ" + A[1])
            source = Source.of("file", self.write("a.fw.sig", A[1]))
            with self.assertRaisesRegex(StoreError, "differs"):
                store.put(source, allowed={(len(A[1]), bytes(16))})
        self.assertEqual(store.index["objects"], {})
        self.assertEqual(list((self.root / "tmp").iterdir()), [])


class RootTests(StoreCase):
    def test_root_guards(self):
        (self.tmp / "repo" / ".git").mkdir(parents=True)
        with self.assertRaisesRegex(StoreError, "git work tree"):
            Store.open(self.tmp / "repo" / "store", create=True)
        (self.tmp / "busy").mkdir()
        (self.tmp / "busy" / "file.txt").write_text("x")
        with self.assertRaisesRegex(StoreError, "not empty"):
            Store.open(self.tmp / "busy", create=True)
        # Built from the limit, not from TEMP: /tmp on Linux is short.
        base = str(self.tmp.resolve())
        with self.assertRaisesRegex(StoreError, "longer than"):
            Store.open(self.tmp / ("x" * max(1, store_module.ROOT_LIMIT - len(base))), create=True)
        with self.assertRaisesRegex(StoreError, "No firmware store"):
            Store.open(self.tmp / "absent")

    def test_paths_inside_the_store_are_refused(self):
        store = self.store()
        with self.assertRaisesRegex(StoreError, "inside the store"):
            add(store, [self.root / "FORMAT"])
        with self.assertRaisesRegex(StoreError, "inside the store"):
            store.export(None, self.root / "out.bin")

    @unittest.skipUnless(os.name == "nt", "Windows path spellings")
    def test_inside_sees_through_other_spellings_of_the_store(self):
        store = self.store()
        root = str(self.root.resolve())
        spellings = ["\\\\?\\" + root + "\\x.bin", "\\\\?\\" + root + "\\objects\\x.bin"]
        share = f"\\\\localhost\\{root[0]}$" + root[2:]
        if os.path.isdir(share):  # admin shares may be off
            spellings.append(share + "\\x.bin")
        for spelling in spellings:
            with self.subTest(spelling=spelling):
                self.assertTrue(store_module.inside(Path(spelling), self.root))
                with self.assertRaisesRegex(StoreError, "inside the store"):
                    store.export(None, spelling)
        self.assertFalse(store_module.inside(self.tmp / "out.bin", self.root))

    def test_missing_index_is_refused_until_check_fix_restores_the_backup(self):
        add(self.store(), [self.folder(CURRENT, (A, B))])
        add(self.store(), [self.folder(OLD, (A, C))])
        backup = (self.root / "index.json.bak").read_bytes()
        (self.root / "index.json").unlink()
        store = Store.open(self.root)
        self.assertTrue(store.lost_index)
        with self.assertRaisesRegex(StoreError, "index.json is missing.*fw check --fix "
                                                "restores it from the backup"):
            add(store, [self.folder(TARGET, (B,))])
        with self.assertRaisesRegex(StoreError, "index.json is missing"):
            store.select("wa345t", CURRENT)
        self.assertEqual((self.root / "index.json.bak").read_bytes(), backup)
        self.assertRegex(store.check()[0].text, "index.json is missing")
        with store.writer(repair=True):
            problems = store.check(fix=True)
        self.assertEqual(problems[0].text, "index.json was missing: restored from "
                                           "index.json.bak; objects added after it are adopted")
        self.assertTrue(all(problem.fixed for problem in problems))
        store = Store.open(self.root)
        self.assertEqual({str(version.version): version.summary
                          for version in store.versions("wa345t")},
                         {CURRENT: "ready 2/2", OLD: "ready 2/2"})

    def test_missing_index_without_a_backup_adopts_the_objects(self):
        add(self.store(), [self.folder(CURRENT, (A, B))])
        (self.root / "index.json").unlink()
        (self.root / "index.json.bak").unlink(missing_ok=True)
        store = Store.open(self.root)
        self.assertTrue(store.lost_index)
        with store.writer(repair=True):
            store.check(fix=True)
        store = Store.open(self.root)
        self.assertFalse(store.lost_index)
        self.assertEqual(store.versions("wa345t")[0].summary, "ready 2/2")

    def test_defaults_off_windows(self):
        kept = {key: value for key, value in os.environ.items() if key not in
                ("LOCALAPPDATA", "DJI_DUML_STORE", "DJI_DUML_ASSISTANT_CACHE")}
        store = self.store()
        with patch.dict(os.environ, kept, clear=True):
            self.assertEqual(store_module.default_root(), Path.home() / ".dji-duml" / "store")
            # Only os.name for the call: pathlib picks its class by it.
            with patch.object(store_module.os, "name", "posix"):
                cache = store_module.assistant_cache()
            self.assertIsNone(cache)
            with patch("dji_duml.ingest.assistant_cache", return_value=None), \
                    self.assertRaisesRegex(StoreError, "name the folder"):
                harvest(store)

    def test_unreadable_index_points_to_the_backup(self):
        self.store()
        (self.root / "index.json").write_text("{", encoding="utf-8")
        with self.assertRaisesRegex(StoreError, "index.json.bak"):
            Store.open(self.root)


class ModelTests(StoreCase):
    def test_orphans_attach_when_their_configuration_arrives(self):
        folder = self.folder(CURRENT, (A, B))
        store = self.store()
        add(store, [folder / A[0], folder / B[0]])  # loose modules: rejected, nothing vouches
        self.assertEqual(store.index["objects"], {})
        cache = self.src / "cache"
        for number, (_, data) in enumerate((A, B)):
            age(self.write(f"{number:032x}.cache", data, cache))
        add(store, [cache])
        self.assertEqual(len(store.orphans()), 2)
        self.assertEqual(store.versions("wa345t"), [])
        mtimes = {path.name: path.stat().st_mtime_ns for path in (self.root / "objects").iterdir()}
        add(store, [folder / "wa345t.cfg.sig"])
        (version,) = store.versions("wa345t")
        self.assertEqual((str(version.version), version.summary), (CURRENT, "ready 2/2"))
        self.assertEqual(store.orphans(), [])
        for name, mtime in mtimes.items():
            self.assertEqual((self.root / "objects" / name).stat().st_mtime_ns, mtime)

    def test_add_order_does_not_matter(self):
        folders = [self.folder(CURRENT, (A, B)), self.folder(TARGET, (B, C)),
                   self.folder(OLD, (A, C))]
        results = set()
        for number, order in enumerate(itertools.permutations(folders)):
            store = Store.open(self.tmp / f"s{number}", create=True)
            for folder in order:
                add(store, [folder])
            results.add(tuple((str(version.version), version.summary)
                              for version in store.versions("wa345t")))
        self.assertEqual(results, {((TARGET, "ready 2/2"), (CURRENT, "ready 2/2"),
                                    (OLD, "ready 2/2"))})

    def test_partial_and_damaged(self):
        folder = self.folder(CURRENT, (A, B))
        (folder / B[0]).unlink()
        store = self.store()
        add(store, [folder])
        (version,) = store.versions("wa345t")
        self.assertEqual(version.summary, "PARTIAL 1/2")
        with self.assertRaisesRegex(StoreError, f"PARTIAL 1/2; missing: {B[0]} \\(5000 bytes, "
                                                f"md5 {hashlib.md5(B[1]).hexdigest()}\\)"):
            store.select("wa345t", CURRENT)
        digest = hashlib.sha256(A[1]).hexdigest()
        path = self.root / "objects" / digest
        os.chmod(path, 0o600)
        path.unlink()
        store = Store.open(self.root)
        self.assertEqual(store.versions("wa345t")[0].best.entries[0].state, "damaged")
        problems = store.check()
        self.assertEqual(problems[0].text, f"object {digest[:12]} (module, 5000 bytes) is missing")
        self.assertIn("dji-duml fw add", problems[0].hint)

    def test_md5_conflict(self):
        add(self.store(), [self.folder(CURRENT, (A, B))])
        other = image(99)
        store = self.store()
        with store.writer():
            digest, _ = store.put(Source.of("file", self.write("x.fw.sig", other)))
            store.index["objects"][digest]["md5"] = hashlib.md5(A[1]).hexdigest()
            store.index["objects"][digest]["size"] = len(A[1])
            store.save()
        store = Store.open(self.root)
        self.assertEqual(store.versions("wa345t")[0].state, "CONFLICT")
        with self.assertRaisesRegex(StoreError, "CONFLICT"):
            store.select("wa345t", CURRENT)
        self.assertTrue(any(problem.text.startswith("CONFLICT") for problem in store.check()))


class SelectTests(StoreCase):
    def test_selection(self):
        store = self.store()
        add(store, [self.folder(CURRENT, (A, B)), self.folder(CURRENT, (A, C))])
        configs = store.versions("wa345t")[0].configs
        with self.assertRaisesRegex(StoreError, "2 complete configurations; choose one"):
            store.select("wa345t", CURRENT)
        chosen, notes = store.select("wa345t", "17.01.05.16", configs[1].sha[:8])
        self.assertEqual((chosen, notes), (configs[1], []))
        for prefix in ("abc", "0" * 8, ""):
            with self.subTest(prefix=prefix), self.assertRaises(StoreError):
                store.select("wa345t", CURRENT, prefix)
        with self.assertRaisesRegex(StoreError, "not held"):
            store.select("wa345t", TARGET)
        with self.assertRaisesRegex(StoreError, "not held"):
            store.select("ab123", CURRENT)

    def test_one_complete_and_one_partial(self):
        store = self.store()
        partial = self.folder(CURRENT, (A, module(400)))
        (partial / module(400)[0]).unlink()
        add(store, [self.folder(CURRENT, (A, B)), partial])
        chosen, notes = store.select("wa345t", "v17.01.0516")
        self.assertTrue(chosen.complete)
        self.assertRegex(notes[0], "is PARTIAL 1/2; not used")

    def test_another_products_configuration_is_never_selected(self):
        store = self.store()
        rc = self.src / "rc"
        self.write("rc123.cfg.sig", config(CURRENT, [module(5, device="rc123")], device="rc123"),
                   rc)
        self.write(module(5, device="rc123")[0], module(5, device="rc123")[1], rc)
        add(store, [rc])
        self.assertEqual(store.products(), ["rc123"])
        with self.assertRaisesRegex(StoreError, "wa345t 17.01.0516 is not held"):
            store.select("wa345t", CURRENT)


class ExportTests(StoreCase):
    def setUp(self):
        super().setUp()
        self.files = self.folder(CURRENT, (A, B, (A[0].replace("0100", "0101"), A[1])))
        self.store_ = self.store()
        add(self.store_, [self.files])
        self.config, _ = self.store_.select("wa345t", CURRENT)

    def test_export_is_deterministic_and_equals_pack(self):
        first, second, packed = self.tmp / "1.bin", self.tmp / "2.bin", self.tmp / "p.bin"
        package = self.store_.export(self.config, first)
        self.store_.export(self.config, second)
        pack(self.files, packed)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first.read_bytes(), packed.read_bytes())
        self.assertEqual(str(package.version), CURRENT)
        with tarfile.open(first) as archive:
            self.assertEqual(archive.getnames()[0], "wa345t.cfg.sig")
            self.assertEqual(len(archive.getnames()), 4)  # one object, two members

    def test_damaged_module_is_refused_and_nothing_is_left(self):
        digest = hashlib.sha256(B[1]).hexdigest()
        path = self.root / "objects" / digest
        os.chmod(path, 0o600)
        path.write_bytes(B[1][:-1] + bytes([B[1][-1] ^ 1]))
        out = self.tmp / "out.bin"
        with self.assertRaisesRegex(PackError, "does not match the MD5"):
            self.store_.export(self.config, out)
        self.assertFalse(out.exists())
        self.assertFalse((self.tmp / "out.bin.part").exists())

    def test_existing_output_is_refused(self):
        out = self.tmp / "out.bin"
        out.write_bytes(b"old")
        with self.assertRaisesRegex(PackError, "already exists"):
            self.store_.export(self.config, out)
        self.assertEqual(out.read_bytes(), b"old")

    def test_an_unrelated_part_file_is_left_alone(self):
        folder = self.tmp / "downloads"
        folder.mkdir()
        part = folder / "out.bin.part"
        part.write_bytes(b"a browser's download")
        package = self.store_.export(self.config, folder / "out.bin")
        self.assertEqual(part.read_bytes(), b"a browser's download")
        self.assertEqual(sorted(path.name for path in folder.iterdir()),
                         ["out.bin", "out.bin.part"])
        self.assertEqual(package.path, (folder / "out.bin").resolve())

    def test_output_that_appears_meanwhile_is_not_replaced(self):
        out = self.tmp / "out.bin"
        real = store_module.write_package

        def racing(*args):
            package = real(*args)
            out.write_bytes(b"someone else's")
            return package

        with patch("dji_duml.store.write_package", racing), \
                self.assertRaisesRegex(PackError, "already exists"):
            self.store_.export(self.config, out)
        self.assertEqual(out.read_bytes(), b"someone else's")
        self.assertEqual(sorted(path.name for path in self.tmp.iterdir()
                                if path.name.startswith("out.bin")), ["out.bin"])


class CheckTests(StoreCase):
    def setUp(self):
        super().setUp()
        add(self.store(), [self.folder(CURRENT, (A, B))])
        self.objects = self.root / "objects"
        self.a = self.objects / hashlib.sha256(A[1]).hexdigest()

    def problems(self, **options):
        return [problem.text for problem in Store.open(self.root).check(**options)]

    def test_clean_store(self):
        self.assertEqual(self.problems(full=True), [])

    def test_quick_problems(self):
        os.chmod(self.a, 0o600)
        self.assertRegex(self.problems()[0], "is not read-only")
        self.a.write_bytes(A[1] + b"x")
        self.assertRegex(self.problems()[0], "has 5001 bytes")
        self.a.write_bytes(A[1])
        (self.objects / "stray").write_bytes(b"x")
        self.assertEqual(self.problems()[-1], f"stray file objects{os.sep}stray")
        (self.objects / "stray").unlink()
        config_object = next(path for path in self.objects.iterdir() if path.stat().st_size != 5000)
        os.chmod(config_object, 0o600)
        config_object.write_bytes(b"IM*H" + bytes(config_object.stat().st_size - 4))
        self.assertTrue(any("no longer reads as a configuration" in text
                            for text in self.problems()))

    def test_full_check_finds_a_flipped_byte_and_fix_quarantines_it(self):
        os.chmod(self.a, 0o600)
        self.a.write_bytes(bytes([A[1][0] ^ 1]) + A[1][1:])
        os.chmod(self.a, 0o400)
        self.assertEqual(self.problems(), [])
        self.assertRegex(self.problems(full=True)[0], "does not match its SHA-256")
        store = Store.open(self.root)
        with store.writer():
            problems = store.check(full=True, fix=True)
        self.assertIn("moved to", problems[0].text)
        self.assertEqual(len(list((self.root / "quarantine").iterdir())), 1)
        self.assertEqual(Store.open(self.root).versions("wa345t")[0].summary, "PARTIAL 1/2")
        self.assertRegex(self.problems()[0], "is missing")
        add(Store.open(self.root), [self.src / "folder1"])
        self.assertEqual(self.problems(full=True), [])

    def test_a_wrong_record_is_corrected_and_the_object_kept(self):
        store = Store.open(self.root)
        digest = self.a.name
        with store.writer():
            store.index["objects"][digest]["md5"] = "0" * 32
            store.index["objects"][digest]["size"] = 4999
            store.save()
        for options in ({}, {"full": True}):
            with self.subTest(**options):
                (text,) = self.problems(**options)
                self.assertIn("is intact, but its index record is wrong: size 4999 (the object: "
                              "5000), md5 " + "0" * 32, text)
        store = Store.open(self.root)
        with store.writer():
            (problem,) = store.check(full=True, fix=True)
        self.assertTrue(problem.fixed)
        self.assertFalse((self.root / "quarantine").exists())
        self.assertEqual(self.problems(full=True), [])
        self.assertEqual(Store.open(self.root).versions("wa345t")[0].summary, "ready 2/2")

    def test_a_read_that_fails_is_not_damage(self):
        store = Store.open(self.root)
        real = open

        def flaky(path, *args, **kwargs):
            if Path(path) == self.a:
                raise PermissionError(13, "held by a virus scanner")
            return real(path, *args, **kwargs)

        with store.writer(), patch("dji_duml.store.open", flaky, create=True):
            problems = store.check(full=True, fix=True)
        self.assertEqual(len(problems), 1)
        self.assertRegex(problems[0].text, "could not be read .*held by a virus scanner")
        self.assertFalse(problems[0].fixed)
        self.assertTrue(self.a.exists())
        self.assertFalse((self.root / "quarantine").exists())

    def test_read_only_is_the_mode_bits_also_for_root(self):
        # access(2) grants W_OK to root whatever the mode bits say.
        with patch("dji_duml.store.os.access", return_value=True):
            self.assertEqual(self.problems(), [])
        os.chmod(self.a, 0o600)
        with patch("dji_duml.store.os.access", return_value=False):
            self.assertRegex(self.problems()[0], "is not read-only")

    def test_quarantine_names_never_collide(self):
        store = Store.open(self.root)
        with store.writer(), patch("dji_duml.store.time.strftime", return_value="20260101T000000Z"):
            for _ in range(2):
                (self.objects / "junk").write_bytes(b"x")
                store.check(fix=True)
        self.assertEqual(sorted(path.name for path in (self.root / "quarantine").iterdir()),
                         ["junk-20260101T000000Z", "junk-20260101T000000Z-2"])

    def test_stale_tmp_entries_are_reported_and_swept(self):
        stale = age(self.write("old.part", b"x", self.root / "tmp"), 2 * 24 * 3600)
        self.assertRegex(self.problems()[0], "older than 24 h")
        store = Store.open(self.root)
        with store.writer():  # every writer sweeps them
            pass
        self.assertFalse(stale.exists())


class ReleaseListTests(StoreCase):
    def harvest(self, *lists):
        cache = self.src / "cache"
        for number, data in enumerate(lists):
            age(self.write(f"{number:032x}.cache", data, cache))
        store = self.store()
        add(store, [cache])
        return store

    def test_attribution_union_and_not_held(self):
        add(self.store(), [self.folder(OLD, (A, B), start="2025/06/14")])
        store = self.harvest(
            release_list(("13.01.0010", "2025-04-11"), (OLD, "2025-06-14")),
            release_list((OLD, "2025-06-14"), (CURRENT, "2026-04-29")),
            release_list(("01.41.0208", "2024-12-24")),
            release_list((OLD, "2020-01-01"), ("99.00.0001", "2030-01-01")))
        rows = [(str(version.version), version.state, version.release.date)
                for version in store.versions("wa345t")]
        self.assertEqual(rows, [(CURRENT, "not held", "2026-04-29"),
                                (OLD, "ready", "2025-06-14"),
                                ("13.01.0010", "not held", "2025-04-11")])
        self.assertEqual(len(store.unassigned()), 2)  # 01.x, and a list with the wrong date
        self.assertEqual(store.versions("wa345t")[1].release.note, f"Note for {OLD}.")
        text = (self.root / "index.json").read_text(encoding="utf-8")
        self.assertNotIn("roles", text)
        self.assertNotIn("sub_product_types", text)

    def test_version_alone_decides_without_a_from_date(self):
        add(self.store(), [self.folder(OLD, (A, B))])
        store = self.harvest(release_list((OLD, "2020-01-01")))
        self.assertEqual(store.versions("wa345t")[0].release.date, "2020-01-01")


if __name__ == "__main__":
    import unittest
    unittest.main()
