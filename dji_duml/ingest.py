"""Put firmware into the store: packages, captures, extract output, folders
and DJI Assistant's download cache (``fw add`` and ``fw harvest``).

A file is opened only when its name matches a rule below; anything else is
skipped unread. Inside DJI Assistant's DJIData only the files directly in
firm_cache are read: auth.ini, data_security and everything else there are
refused before anything is opened. That check runs on every file before it
is opened, also inside a folder, and a link that leads out of the folder
being read is refused. Sources are only read, never changed or moved. Cache
files, folder files and extract output are opened shared for delete on
Windows, so DJI Assistant can still rename or delete them meanwhile; a ZIP,
tar or capture cannot be renamed or deleted while it is being read. Of a
capture only the files it shows being sent, and only those that passed every
check, are kept; the capture itself, report.json, journals, USB addresses and
serial numbers never enter the store.

Modules arrive vouched for by a manifest (a package, a folder with its
.cfg.sig) or as orphans (Assistant's cache, a capture), which become usable
when a configuration that lists them arrives.
"""
from __future__ import annotations

import itertools
import json
import os
import re
import shutil
import tarfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .errors import DumlError, PackageError
from .extract import INCOMPLETE, REPORT, extract
from .package import CONFIG_LIMIT, IMAGE_MAGIC, PackageInfo, inspect_package, open_file, read_config
from .store import (
    CACHE_NAME, SPARE, Changed, Rejected, Source, Store, StoreError, assistant_cache, file_stat,
    inside, open_source, size_text,
)
from .version import FirmwareVersion

PACKAGES = (".zip", ".bin", ".tar")
CAPTURES = (".pcap", ".pcapng")
#: pcap in both byte orders, with micro- and nanosecond times, and pcapng.
CAPTURE_MAGIC = {bytes.fromhex(magic) for magic in
                 ("d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d", "0a0d0d0a")}
#: Seconds a cache file must be left alone before it is taken: younger, it
#: may still be downloading.
BUSY = 120
_NAMED = re.compile(r".*_v(?P<version>\d+\.\d+\.\d+)_\d{8}(?:\.pro)?\.cfg\.sig")
_extracts = itertools.count(1)


def scope_guard(path: str | Path) -> None:
    """Refuse, before anything is opened, the parts of DJI Assistant's data
    that are not firmware."""
    resolved = Path(path).resolve()
    parts = [part.lower() for part in resolved.parts]
    if "data_security" in parts:
        raise StoreError(f"{path}: data_security is out of scope and never opened.")
    if parts[-1] == "auth.ini":
        raise StoreError(f"{path}: auth.ini is out of scope and never opened.")
    if "djidata" in parts:
        below = parts[parts.index("djidata") + 1:]
        if not below or below[0] != "firm_cache" or len(below) > 2 \
                or (len(below) == 2 and resolved.is_dir()):
            raise StoreError(f"{path}: inside DJI Assistant's DJIData only the files in "
                             "firm_cache are read.")


def _within(file: Path, folder: Path) -> None:
    """Refuse a file of ``folder`` that is a link leading out of it."""
    if not inside(file, folder):
        raise StoreError(f"{file}: a link out of {folder}; not opened.")


def detect(path: Path) -> str | None:
    """What ``path`` is, by its name (and, for a folder, the names in it);
    None for a name that matches no rule."""
    if path.is_dir():
        if (path / REPORT).is_file():
            return "extract"
        files = [entry for entry in path.iterdir() if entry.is_file()]
        if files and all(CACHE_NAME.fullmatch(entry.name) for entry in files):
            return "cache"
        return "folder"
    name = path.name.lower()
    if name.endswith(PACKAGES):
        return "package"
    if name.endswith(CAPTURES):
        return "capture"
    if name.endswith(".cfg.sig"):
        return "config"
    if name.endswith(".fw.sig"):
        return "module"
    if CACHE_NAME.fullmatch(path.name):
        return "cache_file"
    return None


@dataclass
class _Tally:
    """What one source gave."""
    new: int = 0
    held: int = 0
    rejected: int = 0
    skipped: int = 0
    new_bytes: int = 0
    configs: list[str] = field(default_factory=list)  # "7735d79121fc (14.01.0012)"
    problems: list[str] = field(default_factory=list)

    def counts(self) -> str:
        return ", ".join([f"{self.new} new", f"{self.held} held"]
                         + ([f"{self.rejected} rejected"] if self.rejected else [])
                         + ([f"{self.skipped} skipped"] if self.skipped else []))


@dataclass
class AddReport:
    lines: list[str] = field(default_factory=list)
    rejected: int = 0
    skipped: int = 0
    #: (product, version, state before, state after) of every version that changed.
    changes: list[tuple[str, str, str, str]] = field(default_factory=list)
    orphans: tuple[int, int] = (0, 0)

    @property
    def code(self) -> int:
        return 2 if self.rejected or self.skipped else 0

    def say(self, label: str, text: str) -> None:
        self.lines.append(f"{label:9} {text}")


def _states(store: Store) -> dict[tuple[str, str], str]:
    return {(product, str(version.version)): version.summary
            for product in store.products() for version in store.versions(product)
            if version.configs}


def add(store: Store, paths, force: bool = False) -> AddReport:
    """``fw add``: every path is checked before anything is read."""
    targets = []
    for given in paths:
        scope_guard(given)
        path = Path(given)
        if not path.exists():
            raise StoreError(f"{path} does not exist.")
        if inside(path, store.root):
            raise StoreError(f"{path} is inside the store.")
        targets.append(path.resolve())
    report = AddReport()
    with store.writer():
        before, orphans = _states(store), len(store.orphans())
        ingest = _Ingest(store, report, force)
        for path in targets:
            ingest.item(path, 0)
        after = _states(store)
        report.orphans = (orphans, len(store.orphans()))
    report.changes = [(product, version, before.get((product, version), "not held"), state)
                      for (product, version), state in sorted(after.items())
                      if before.get((product, version)) != state]
    return report


def harvest(store: Store, directory: str | Path | None = None) -> AddReport:
    """``fw harvest``: ``fw add`` of DJI Assistant's firm_cache."""
    folder = Path(directory) if directory else assistant_cache()
    if folder is None:
        raise StoreError("DJI Assistant runs only on Windows; name the folder that holds a copy "
                         "of its firm_cache: dji-duml fw harvest DIR.")
    scope_guard(folder)
    if not folder.is_dir():
        raise StoreError(f"No DJI Assistant cache at {folder}; name it: dji-duml fw harvest DIR.")
    if detect(folder) != "cache" and any(folder.iterdir()):
        raise StoreError(f"{folder} is not a DJI Assistant firm_cache folder "
                         "(it holds more than <32 hex digits>.cache files).")
    return add(store, [folder])


class _Ingest:
    def __init__(self, store: Store, report: AddReport, force: bool):
        self.store, self.report, self.force = store, report, force

    def item(self, path: Path, depth: int) -> None:
        try:
            scope_guard(path)
            if depth:
                _within(path, path.parent)
        except StoreError as exc:
            self.report.say("refused", str(exc))
            self.report.rejected += 1
            return
        if path.is_dir() and depth > 1:
            return  # folders are read one level deep
        kind = detect(path)
        if kind is None:
            self.report.say("skipped", f"{path.name}: not a firmware file name")
            return
        getattr(self, "_" + kind)(path, depth)

    def _finish(self, label: str, text: str, tally: _Tally) -> None:
        self.report.say(label, text)
        for problem in tally.problems:
            self.report.say("", problem)
        self.report.rejected += tally.rejected
        self.report.skipped += tally.skipped

    def _unchanged(self, label: str, path: Path, container: bool = False) -> bool:
        added = None if self.force else self.store.unchanged(path, container)
        if added:
            self.report.say(label, f"{path.name}: unchanged since {added[:16].replace('T', ' ')}"
                            ", nothing new (--force reads it again)")
        return added is not None

    def _room(self, label: str, path: Path, need: int, tally: _Tally | None = None) -> bool:
        """Whether ``need`` bytes fit with 1 GB to spare; else the source is
        skipped (``tally``: one file of a folder)."""
        free = shutil.disk_usage(self.store.root).free
        if free >= need + SPARE:
            return True
        text = f"{path.name}: skipped, {size_text(free)} free; it needs {size_text(need)} " \
               "and 1 GB to spare"
        if tally is None:
            self.report.say(label, text)
            self.report.skipped += 1
        else:
            tally.problems.append(text)
            tally.skipped += 1
        return False

    def _known(self, path: Path) -> bool:
        return not self.force and self.store.unchanged(path) is not None

    @staticmethod
    def _guard(file: Path, folder: Path | None, tally: _Tally) -> bool:
        """scope_guard for one file of a folder, before it is opened."""
        try:
            scope_guard(file)
            if folder is not None:
                _within(file, folder)
        except StoreError as exc:
            tally.rejected += 1
            tally.problems.append(f"refused {exc}")
            return False
        return True

    def _stored_config(self, digest: str, tally: _Tally):
        """The ConfigInfo of a configuration object, or None (reported) when
        the stored object no longer reads as one."""
        try:
            return read_config((self.store.objects / digest).read_bytes())
        except (PackageError, OSError) as exc:
            tally.problems.append(f"configuration object {digest[:12]} in the store does not "
                                  f"read ({exc}): dji-duml fw check")
            return None

    def _put(self, source: Source, tally: _Tally, read=None, **options) -> str | None:
        """Store one item, counting the outcome; the SHA-256, or None."""
        try:
            digest, new = self.store.put(source, read, **options)
        except Changed as exc:
            tally.skipped += 1
            tally.problems.append(f"skipped {source.name}: {exc}")
            return None
        except PermissionError as exc:  # opening or reading the source
            tally.skipped += 1
            tally.problems.append(f"skipped {source.name}: locked ({exc.strerror})")
            return None
        except (Rejected, PackageError) as exc:
            tally.rejected += 1
            tally.problems.append(f"rejected {source.name}: {exc}")
            return None
        record = self.store.index["objects"][digest]
        if new:
            tally.new += 1
            tally.new_bytes += record["size"]
        else:
            tally.held += 1
        if record["kind"] == "config":
            info = self._stored_config(digest, tally)
            if info is not None:
                tally.configs.append(f"{digest[:12]} ({info.product} {info.version})")
        return digest

    @staticmethod
    def _configs(tally: _Tally) -> str:
        return "".join(f"config {config} + " for config in tally.configs)

    # Packages ------------------------------------------------------------

    def _package(self, path: Path, depth: int) -> None:
        label = "zip" if path.suffix.lower() == ".zip" else "tar"
        if self._unchanged(label, path, container=True):
            return
        tally = _Tally()
        try:
            package = inspect_package(path)
            if not package.files:
                raise PackageError("no readable manifest listing its files")
        except PackageError as exc:
            tally.rejected += 1
            self._finish(label, f"{path.name}: rejected: {exc}", tally)
            return
        # What it unpacks to, not its compressed size.
        if not self._room(label, path, package.files_size):
            return
        label, stat = package.kind, (package.size, package.mtime_ns)
        for position, item in enumerate(package.files):
            source = Source(package.kind, package.path, item.name, stat)
            digest = self._put(
                source, tally, lambda name=item.name: open_file(package, name),
                allowed=None if position == 0 else {(item.size, item.md5)}, config=position == 0)
            if position == 0 and digest is None:
                break  # without its configuration nothing vouches for the modules
        unlisted = sorted(set(_member_names(package)) - {item.name for item in package.files})
        if unlisted:
            tally.problems.append("note: not in the manifest, not stored: " + ", ".join(unlisted))
        if not tally.skipped:
            self.store.finished(Source(package.kind, package.path, package.path.name, stat))
        self._finish(label, f"{path.name}: {self._configs(tally)}{len(package.files) - 1} "
                     f"modules: {tally.counts()}", tally)

    # Captures and extract output --------------------------------------------

    def _capture(self, path: Path, depth: int) -> None:
        with open(path, "rb") as handle:
            magic = handle.read(4)
        tally = _Tally()
        if magic not in CAPTURE_MAGIC:
            tally.rejected += 1
            self._finish("capture", f"{path.name}: rejected: not a pcap or pcapng file", tally)
            return
        # The files it holds are no larger than the capture itself.
        if self._unchanged("capture", path, container=True) \
                or not self._room("capture", path, path.stat().st_size):
            return
        stat = file_stat(path)
        work = self.store.tmp / f"extract-{os.getpid()}-{next(_extracts)}"
        try:
            try:
                result = extract(path, work)
            except DumlError as exc:
                tally.rejected += 1
                self._finish("capture", f"{path.name}: rejected: {exc}", tally)
                return
            if file_stat(path) != stat:
                tally.skipped += 1
                self._finish("capture", f"{path.name}: skipped, changed while reading", tally)
                return
            passed = [item for item in result.files if item.ok]
            # Configurations first, so the line names them before their modules.
            for item in sorted(passed, key=lambda item: not item.name.endswith(".cfg.sig")):
                self._put(Source("capture", path, item.name, stat), tally,
                          own=work / item.saved_as, allowed={(item.size, item.md5)},
                          config=item.name.endswith(".cfg.sig"))
            failed = len(result.files) - len(passed)
            tally.rejected += failed
            if not tally.skipped:
                self.store.finished(Source("capture", path.resolve(), path.name, stat))
            text = f"{path.name}: {len(result.files)} transfers, {len(passed)} passed every check"
            self.report.say("capture", text)
            self._finish("", f"{self._configs(tally)}{len(passed)} files: {tally.counts()}"
                         + (f"; {failed} failed extraction, not stored" if failed else ""), tally)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def _extract(self, path: Path, depth: int) -> None:
        """extract's output: only the files report.json shows as intact, and
        only while they still have the size and MD5 it states."""
        tally = _Tally()
        if not self._guard(path / REPORT, path, tally):
            self._finish("extract", f"{path.name}: rejected: {REPORT} not opened", tally)
            return
        try:
            report = json.loads((path / REPORT).read_text(encoding="utf-8"))
            passed = [entry for entry in report["files"] if entry.get("ok") is True]
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            tally.rejected += 1
            self._finish("extract", f"{path.name}: rejected: unreadable {REPORT}: {exc}", tally)
            return
        passed.sort(key=lambda entry: not str(entry.get("name", "")).endswith(".cfg.sig"))
        todo = []
        for entry in passed:
            try:
                saved, name = str(entry["saved_as"]), str(entry["name"])
                expected = (int(entry["size"]), bytes.fromhex(entry["md5"]))
            except (KeyError, TypeError, ValueError):
                tally.rejected += 1
                tally.problems.append(f"rejected a malformed {REPORT} entry")
                continue
            file = path / saved
            if Path(saved).name != saved or saved in ("", ".", "..", REPORT) \
                    or saved.endswith(INCOMPLETE) or not file.is_file():
                tally.rejected += 1
                tally.problems.append(f"rejected {saved}: not a file of this folder")
                continue
            if not self._guard(file, path, tally):
                continue
            if self._known(file):
                tally.held += 1
                continue
            todo.append((file, name, expected))
        if self._room("extract", path, sum(file.stat().st_size for file, _, _ in todo), tally):
            for file, name, expected in todo:
                self._put(Source.of("extract", file, name), tally, allowed={expected},
                          reason="changed after extraction: size or MD5 differs from "
                                 f"{REPORT}", config=name.endswith(".cfg.sig"))
        self._finish("extract", f"{path.name}: {self._configs(tally)}{len(passed)} files passed "
                     f"extraction: {tally.counts()}", tally)

    # DJI Assistant's cache ----------------------------------------------------

    def _cache(self, path: Path, depth: int) -> None:
        files = sorted(entry for entry in path.iterdir()
                       if entry.is_file() and CACHE_NAME.fullmatch(entry.name))
        todo = [file for file in files if not self._known(file)]
        if not self._room("cache", path, sum(file.stat().st_size for file in todo)):
            return
        tally, counts = _Tally(), {"modules": 0, "lists": 0, "busy": 0, "locked": 0}
        distinct, lists_new = set(), 0
        for file in files:
            kind, digest = self._cache_item(file, tally, counts, path)
            if kind == "module":
                distinct.add(digest)
            lists_new += kind == "list-new"
        self.report.say("cache", str(path))
        self.report.say("", f"{len(files)} files: {counts['modules']} modules "
                        f"({len(distinct)} distinct), {counts['lists']} release lists; "
                        f"{counts['busy']} busy, {counts['locked']} locked, "
                        f"{tally.rejected} rejected")
        self._finish("added", f"{tally.new} modules new ({size_text(tally.new_bytes)}), "
                     f"{tally.held} already held; {counts['lists']} release lists, "
                     f"{lists_new} new", tally)

    def _cache_file(self, path: Path, depth: int) -> None:
        tally, counts = _Tally(), {"modules": 0, "lists": 0, "busy": 0, "locked": 0}
        kind, _ = self._cache_item(path, tally, counts)
        self._finish("cache", f"{path.name}: {kind or 'not stored'}: {tally.counts()}", tally)

    def _cache_item(self, file: Path, tally: _Tally, counts: dict,
                    folder: Path | None = None) -> tuple[str | None, str | None]:
        """One cache file of ``folder``: a module, a DJI release list, or neither."""
        if not self._guard(file, folder, tally):
            return None, None
        if self._known(file):
            tally.held += 1
            hits = self.store.recorded(file)
            if hits[0][2]:
                counts["lists"] += 1
                return "list", hits[0][1]
            counts["modules"] += 1
            return "module", hits[0][1]
        source = Source.of("cache", file)
        if time.time() - source.stat[1] / 1e9 < BUSY:
            counts["busy"] += 1
            tally.skipped += 1
            return None, None
        try:
            with open_source(file) as handle:
                head = handle.read(4)
                data = head + handle.read() if head[:1] == b"[" \
                    and source.stat[0] <= CONFIG_LIMIT else b""
        except PermissionError:
            counts["locked"] += 1
            tally.skipped += 1
            return None, None
        if head == IMAGE_MAGIC:
            digest = self._put(source, tally)
            if digest is not None:
                counts["modules"] += 1
            return ("module", digest) if digest else (None, None)
        if data:
            if file_stat(file) != source.stat:
                tally.skipped += 1
                tally.problems.append(f"skipped {file.name}: changed while reading")
                return None, None
            try:
                digest, new = self.store.add_release(data, source)
            except Rejected as exc:
                tally.rejected += 1
                tally.problems.append(f"rejected {file.name}: {exc}")
                return None, None
            counts["lists"] += 1
            return ("list-new" if new else "list"), digest
        tally.rejected += 1
        tally.problems.append(f"rejected {file.name}: neither a firmware image nor a release list")
        return None, None

    # Folders and loose files --------------------------------------------------

    def _folder(self, path: Path, depth: int) -> None:
        """Top-level files, configurations first; a .fw.sig named by one of
        them must match it, any other .fw.sig a held configuration. Subfolders
        are read one level deep."""
        entries = sorted(path.iterdir(), key=lambda entry: entry.name)
        files = [entry for entry in entries if entry.is_file()]
        configs = [file for file in files if file.name.lower().endswith(".cfg.sig")]
        modules = [file for file in files if file.name.lower().endswith(".fw.sig")]
        tally, listed = _Tally(), {}
        need = sum(file.stat().st_size for file in configs + modules if not self._known(file))
        if self._room("folder", path, need, tally):
            for file in configs:
                info = self._config_file(file, "folder", tally, path)
                if info is not None:
                    listed.update({module.name: (module.size, module.md5)
                                   for module in info.modules})
            for file in modules:
                self._module_file(file, "folder", tally, listed.get(file.name), path)
        if configs or modules:
            self._finish("folder", f"{path.name}: {self._configs(tally)}"
                         f"{len(configs) + len(modules)} files: {tally.counts()}", tally)
        for entry in entries:
            if entry not in configs and entry not in modules and (entry.is_file() or depth == 0):
                self.item(entry, depth + 1)

    def _config(self, path: Path, depth: int) -> None:
        tally = _Tally()
        if self._known(path) or self._room("file", path, path.stat().st_size, tally):
            self._config_file(path, "file", tally)
        self._finish("file", f"{path.name}: {self._configs(tally) or 'config: '}{tally.counts()}",
                     tally)

    def _module(self, path: Path, depth: int) -> None:
        tally = _Tally()
        if self._known(path) or self._room("file", path, path.stat().st_size, tally):
            self._module_file(path, "file", tally, None)
        self._finish("file", f"{path.name}: module: {tally.counts()}", tally)

    def _config_file(self, path: Path, kind: str, tally: _Tally, folder: Path | None = None):
        """A loose .cfg.sig of ``folder``; its ConfigInfo, or None when it is
        not stored."""
        if not self._guard(path, folder, tally):
            return None
        if self._known(path):
            tally.held += 1
            return self._stored_config(self.store.recorded(path)[0][1], tally)
        source = Source.of(kind, path)
        try:
            if source.stat[0] > CONFIG_LIMIT:
                raise PackageError("too large for a configuration")
            with open_source(path) as handle:
                info = read_config(handle.read(CONFIG_LIMIT + 1))
            named = _NAMED.fullmatch(path.name)
            if named and FirmwareVersion.parse(named.group("version")) != info.version:
                raise PackageError(f"its name says {named.group('version')}, its manifest "
                                   f"says {info.version}")
        except PackageError as exc:
            tally.rejected += 1
            tally.problems.append(f"rejected {path.name}: {exc}")
            return None
        return info if self._put(source, tally, config=True) else None

    def _module_file(self, path: Path, kind: str, tally: _Tally, expected,
                     folder: Path | None = None) -> None:
        if not self._guard(path, folder, tally):
            return
        if self._known(path):
            tally.held += 1
            return
        if expected is not None:
            allowed, reason = {expected}, "size or MD5 differs from the manifest next to it"
        else:
            allowed = self.store.module_keys()
            reason = "listed by no held configuration (add its configuration first)"
        self._put(Source.of(kind, path), tally, allowed=allowed, reason=reason)


def _member_names(package: PackageInfo) -> list[str]:
    if package.kind == "zip":
        with zipfile.ZipFile(package.path) as archive:
            return [entry.filename for entry in archive.infolist() if not entry.is_dir()]
    with tarfile.open(package.path, "r:") as archive:
        return archive.getnames()
