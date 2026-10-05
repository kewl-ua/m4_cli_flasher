"""A local store of DJI firmware files, used by version.

Every configuration and module is kept once, as ``objects/<sha256>``: a
read-only file that never changes. ``index.json`` records where each one was
seen and the few fields kept from DJI's release lists; nothing else is
stored. Versions, completeness and orphans are derived on every command from
the configurations' signed manifests, which name each module with its size
and MD5: a module is found by (MD5, size), never by its name. ``export``
writes the same uncompressed tar as ``pack``, which is what ``flash
--from-store`` sends.

An object is written before the index names it, so the index never names a
file that does not exist; a crash leaves at most one unrecorded object, which
the next ingest or ``check --fix`` records.
"""
from __future__ import annotations

import dataclasses
import errno
import hashlib
import itertools
import json
import os
import re
import shutil
import stat as stat_mode
import subprocess
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import BinaryIO

from .errors import DumlError, PackageError
from .flasher import _open_lock_file
from .pack import PackError, write_package
from .package import (
    CONFIG_LIMIT, IMAGE_MAGIC, ConfigInfo, PackageFile, PackageInfo, read_config,
)
from .version import FirmwareVersion

FORMAT = "dji-duml firmware store 1\n"
INDEX = "index.json"
#: The longest path in the store is the root plus 93 characters (quarantine\
#: <sha256>-<utc>): this keeps every one under Windows' MAX_PATH of 260.
ROOT_LIMIT = 160
#: Free space left over after an ingest writes everything it may write.
SPARE = 1 << 30
#: Seconds after which an entry in tmp is a leftover of a crash.
STALE = 24 * 3600
ASSISTANT_CACHE = Path("DJI Product", "DJI Assistant 2 (Enterprise Series)", "DJIEngine",
                       "DJIData", "firm_cache")
CACHE_NAME = re.compile(r"[0-9a-f]{32}\.cache")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_parts = itertools.count(1)


class StoreError(DumlError):
    pass


class Rejected(StoreError):
    """The item failed a check; nothing was stored."""


class Changed(StoreError):
    """The source changed while it was read; nothing was stored."""


def default_root() -> Path:
    """%DJI_DUML_STORE%, else %LOCALAPPDATA%\\dji-duml\\store on Windows and
    ~/.dji-duml/store elsewhere. Under sudo, HOME is root's: pass --store."""
    if os.environ.get("DJI_DUML_STORE"):
        return Path(os.environ["DJI_DUML_STORE"])
    base = os.environ.get("LOCALAPPDATA")
    return Path(base, "dji-duml", "store") if base else Path.home() / ".dji-duml" / "store"


def assistant_cache() -> Path | None:
    """DJI Assistant's download cache: the only folder of its DJIData we read.
    None off Windows, where Assistant does not run, unless it is named."""
    if os.environ.get("DJI_DUML_ASSISTANT_CACHE"):
        return Path(os.environ["DJI_DUML_ASSISTANT_CACHE"])
    if os.name != "nt":
        return None
    return Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / ASSISTANT_CACHE


def file_stat(path: Path) -> tuple[int, int]:
    stat = path.stat()
    return stat.st_size, stat.st_mtime_ns


def writable(path: Path) -> bool:
    """Whether a write bit is set. Not os.access: that is always true for
    root on Linux. On Windows the read-only attribute clears the bits."""
    return bool(stat_mode.S_IMODE(path.stat().st_mode) & 0o222)


def inside(path: Path, root: Path) -> bool:
    """Whether ``path`` is ``root`` or below it, however either is spelled
    (\\\\?\\, an admin share, a link): by name, then by file identity."""
    path, root = Path(path).resolve(), Path(root).resolve()
    name, base = os.path.normcase(path), os.path.normcase(root)
    if name == base or name.startswith(base.rstrip(os.sep) + os.sep):
        return True
    try:
        identity = os.stat(root)
    except OSError:
        return False
    for folder in (path, *path.parents):
        try:
            if os.path.samestat(os.stat(folder), identity):
                return True
        except OSError:
            continue
    return False


def open_source(path: Path) -> BinaryIO:
    """Open a source file for reading. On Windows it is shared for delete,
    so DJI Assistant can still rename or delete it while it is read (put()
    then sees it changed and keeps nothing); Python's open() would block it."""
    if os.name != "nt":
        return open(path, "rb")
    import ctypes
    import msvcrt
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateFileW
    create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    create.restype = wintypes.HANDLE
    # GENERIC_READ; FILE_SHARE_READ | WRITE | DELETE; OPEN_EXISTING; FILE_ATTRIBUTE_NORMAL
    handle = create(str(path), 0x80000000, 7, None, 3, 0x80, None)
    if handle is None or handle == wintypes.HANDLE(-1).value:
        error = ctypes.get_last_error()
        raise OSError(None, ctypes.FormatError(error), str(path), error)
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except OSError:
        kernel32.CloseHandle(wintypes.HANDLE(handle))
        raise
    return os.fdopen(descriptor, "rb")


def _place(work: Path, out: Path) -> None:
    """Move ``work`` to ``out``; FileExistsError, never a replace, when
    ``out`` exists by then."""
    if os.name == "nt":
        os.rename(work, out)  # refuses an existing target on Windows
        return
    try:
        os.link(work, out)  # refuses an existing target; rename would replace it
    except FileExistsError:
        raise
    except OSError:  # no hard links on this file system (FAT, some shares)
        if os.path.lexists(out):
            raise FileExistsError(errno.EEXIST, "File exists", str(out)) from None
        os.rename(work, out)


def quote(path: Path | str) -> str:
    return subprocess.list2cmdline([str(path)])


def size_text(size: int) -> str:
    return f"{size / 1e9:.1f} GB" if size >= 1e9 else f"{size / 1e6:.1f} MB"


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _retry(action: Callable[[], None], what: str) -> None:
    """An editor or a virus scanner may hold a file for a moment on Windows."""
    for attempt in range(20):
        try:
            return action()
        except PermissionError as exc:
            if attempt == 19:
                raise StoreError(f"Cannot {what} ({exc}); close whatever holds it and "
                                 "run the command again.") from exc
            time.sleep(0.1)


@dataclass(frozen=True)
class Source:
    """Where an object was seen. ``path`` is the file whose stat is recorded:
    the container for a ZIP, tar or capture member."""
    kind: str  # zip, tar, capture, extract, cache, folder, file or recovered
    path: Path
    name: str
    stat: tuple[int, int]

    @classmethod
    def of(cls, kind: str, path: Path, name: str | None = None) -> "Source":
        path = Path(path).resolve()
        return cls(kind, path, name or path.name, file_stat(path))

    def record(self) -> dict:
        return {"from": self.kind, "path": str(self.path), "name": self.name,
                "stat": list(self.stat), "added": _now()}


def _source_key(record: dict) -> tuple[str, str, str]:
    return record["from"], os.path.normcase(record["path"]), record["name"]


def _add_source(sources: list[dict], source: Source) -> None:
    record = source.record()
    for position, old in enumerate(sources):
        if _source_key(old) == _source_key(record):
            record["added"] = old["added"]
            sources[position] = record
            return
    sources.append(record)


def release_entries(data: bytes) -> list[dict]:
    """The fields kept from a DJI release list (a JSON list in Assistant's
    cache): version, date, flow and the English note. ``roles``,
    ``sub_product_types`` and everything else are dropped."""
    if not data.startswith(b"[") or len(data) > CONFIG_LIMIT:
        raise Rejected("not a DJI release list")
    try:
        items = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise Rejected(f"not a DJI release list: {exc}") from exc
    if not isinstance(items, list) or not items or not all(
            isinstance(item, dict) and isinstance(item.get("product_version"), str)
            and isinstance(item.get("released_time"), str) for item in items):
        raise Rejected("a JSON list, but not of DJI releases")
    entries = []
    for item in items:
        note = item.get("release_note")
        note = note.get("en") if isinstance(note, dict) else note
        try:
            version = FirmwareVersion.parse(item["product_version"])
        except ValueError as exc:
            raise Rejected(f"release list with {exc}") from exc
        if not _DATE.match(item["released_time"]):
            raise Rejected(f"release list with date {item['released_time']!r}")
        entries.append({"version": str(version), "date": item["released_time"][:10],
                        "flow": item["flow"] if isinstance(item.get("flow"), str) else None,
                        "note": note if isinstance(note, str) else ""})
    return entries


@dataclass(frozen=True)
class Release:
    """One version as a DJI release list states it."""
    version: FirmwareVersion
    date: str  # YYYY-MM-DD
    flow: str | None
    note: str


@dataclass(frozen=True)
class Entry:
    """One module of a manifest and the objects with its (MD5, size)."""
    file: PackageFile
    state: str  # ok, missing, damaged (its object is gone or resized) or conflict
    objects: tuple[str, ...]


@dataclass(frozen=True)
class Config:
    sha: str
    size: int
    info: ConfigInfo
    entries: tuple[Entry, ...]

    @property
    def held(self) -> int:
        return sum(entry.state == "ok" for entry in self.entries)

    @property
    def complete(self) -> bool:
        return self.held == len(self.entries)

    @property
    def state(self) -> str:
        if self.complete:
            return "complete"
        if any(entry.state == "conflict" for entry in self.entries):
            return "CONFLICT"
        return f"PARTIAL {self.held}/{len(self.entries)}"

    @property
    def files_size(self) -> int:
        return self.size + sum(entry.file.size for entry in self.entries)


@dataclass(frozen=True)
class Version:
    product: str
    version: FirmwareVersion
    configs: tuple[Config, ...]  # empty: known only from a DJI release list
    release: Release | None

    @property
    def complete(self) -> list[Config]:
        return [config for config in self.configs if config.complete]

    @property
    def best(self) -> Config | None:
        """The configuration a row describes: the complete one, else the
        one with most modules held."""
        if not self.configs:
            return None
        return max(self.configs, key=lambda config: (config.complete, config.held))

    @property
    def state(self) -> str:
        if not self.configs:
            return "not held"
        complete = len(self.complete)
        if complete:
            return "ready" if complete == 1 else f"ready x{complete}"
        if all(config.state == "CONFLICT" for config in self.configs):
            return "CONFLICT"
        return "PARTIAL"

    @property
    def summary(self) -> str:
        """State with module counts, e.g. ``ready 16/16``."""
        best = self.best
        if best is None or self.state == "CONFLICT" or self.state.startswith("ready x"):
            return self.state
        return f"{self.state} {best.held}/{len(best.entries)}"


@dataclass(frozen=True)
class Problem:
    text: str
    hint: str = ""
    fixed: bool = False


@dataclass
class Model:
    """Everything derived from the index and the objects on disk."""
    present: dict[str, dict]  # sha -> index record; the file is there with its size
    absent: dict[str, dict]   # recorded, but the file is missing or resized
    configs: list[Config]
    unreadable: dict[str, str]  # config objects that no longer read as one
    lists: dict[str, set[str]]  # release list -> products it is attributed to


class _Lock:
    """Writer lock, released by the OS when the process dies (the flasher's
    DeviceLock pattern; os.kill(pid, 0) would kill the process on Windows)."""

    def __init__(self, path: Path):
        self.path = path
        self._handle = None

    def __enter__(self):
        try:
            self._handle = open(self.path, "a+b") if os.name == "nt" \
                else _open_lock_file(self.path)
        except OSError as exc:
            owner = ""
            try:
                owner = f", owner uid {self.path.stat().st_uid}" if os.name != "nt" else ""
            except OSError:
                pass
            raise StoreError(f"Cannot open the store's lock {self.path} ({exc}{owner}): the "
                             "store may belong to another user, or the file is read-only.") \
                from exc
        try:
            if os.name == "nt":
                import msvcrt
                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if self._handle is not None:
                self._handle.close()
                self._handle = None
            raise StoreError(f"The store is in use by another dji-duml (lock {self.path}: "
                             f"{exc}).") from exc
        return self

    def __exit__(self, *exc):
        if self._handle is not None:
            self._handle.close()  # closing releases the lock on both platforms
            self._handle = None
        return False


class Store:
    def __init__(self, root: Path):
        self.root = root
        self.objects = root / "objects"
        self.tmp = root / "tmp"
        self.quarantine = root / "quarantine"
        self.index: dict = {"format": 1, "objects": {}, "releases": {}}
        self.created = False
        #: index.json is gone although the store held something: writers
        #: refuse until check --fix restores it from index.json.bak.
        self.lost_index = False
        self.restored: str | None = None  # how writer(repair=True) restored a lost index
        self._model: Model | None = None
        self._paths: dict[str, list[tuple[tuple[int, int], str, bool]]] | None = None
        self._writing = False

    @classmethod
    def open(cls, root: str | Path | None = None, create: bool = False) -> "Store":
        """Open the store at ``root``; ``create`` makes it when the folder is
        missing or empty. Readers take no lock: objects never change and the
        index is read in one go."""
        root = Path(root or default_root()).expanduser().resolve()
        if len(str(root)) > ROOT_LIMIT:
            raise StoreError(f"Store path {root} is longer than {ROOT_LIMIT} characters.")
        for folder in (root, *root.parents):
            if (folder / ".git").exists():
                raise StoreError(f"Store {root} is inside the git work tree {folder}; "
                                 "firmware must stay out of git.")
        store = cls(root)
        marker = root / "FORMAT"
        if marker.exists():
            if marker.read_text(encoding="utf-8") != FORMAT:
                raise StoreError(f"{root} is a store of an unknown format.")
        elif root.exists() and (not root.is_dir() or any(root.iterdir())):
            raise StoreError(f"{root} is not empty and is not a firmware store (no FORMAT file).")
        elif not create:
            raise StoreError(f"No firmware store at {root}. Fill it with: dji-duml fw add "
                             "<package, capture or folder>, or dji-duml fw harvest.")
        else:
            root.mkdir(parents=True, exist_ok=True)
            marker.write_text(FORMAT, encoding="utf-8", newline="\n")
            (root / ".gitignore").write_text("*\n", encoding="utf-8", newline="\n")
            store.created = True
        if create:
            store.objects.mkdir(exist_ok=True)
            store.tmp.mkdir(exist_ok=True)
        store._load()
        return store

    @staticmethod
    def _parse(path: Path, text: str) -> dict:
        try:
            index = json.loads(text)
            if not isinstance(index, dict) or index.get("format") != 1 or not all(
                    isinstance(index.get(key), dict) for key in ("objects", "releases")):
                raise ValueError("not a format 1 index")
        except ValueError as exc:
            raise StoreError(f"Unreadable {path}: {exc}. It is not repaired automatically; "
                             f"the previous generation is {path}.bak.") from exc
        return index

    def _load(self) -> None:
        path = self.root / INDEX
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            self.index = {"format": 1, "objects": {}, "releases": {}}
            # Not a new store: an empty index would hide what it holds, and
            # the next two saves would overwrite index.json.bak with it. One
            # object alone is what a crash before the first save leaves.
            self.lost_index = (self.root / (INDEX + ".bak")).exists() or (
                self.objects.is_dir() and len(list(itertools.islice(self.objects.iterdir(), 2)))
                > 1)
        else:
            self.index = self._parse(path, text)
            self.lost_index = False
        self._model = self._paths = None

    def lost_text(self) -> str:
        backup = self.root / (INDEX + ".bak")
        return (f"{self.root / INDEX} is missing, but the store holds objects"
                + (f" and {backup.name}" if backup.exists() else "") + "; nothing is written "
                "until dji-duml fw check --fix " + ("restores it from the backup"
                                                   if backup.exists() else "adopts the objects")
                + ".")

    def _restore(self) -> None:
        """check --fix of a lost index: index.json.bak, if it reads, becomes
        index.json again (the backup is kept); strays are adopted after."""
        backup = self.root / (INDEX + ".bak")
        if backup.exists():
            text = backup.read_text(encoding="utf-8")
            self._parse(backup, text)
            shutil.copyfile(backup, self.root / INDEX)
            self.restored = f"restored from {backup.name}; objects added after it are adopted"
        else:
            self.restored = "no backup: the objects are adopted as recovered"
        self._load()
        self.lost_index = False
        if not backup.exists():
            self.save()  # an empty index, which the adoption below fills

    def save(self) -> None:
        path = self.root / INDEX
        part = self.root / (INDEX + ".tmp")
        try:
            with open(part, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(self.index, handle, ensure_ascii=True, indent=1, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            if path.exists():
                _retry(lambda: shutil.copyfile(path, self.root / (INDEX + ".bak")),
                       f"update {path}.bak")
            _retry(lambda: os.replace(part, path), f"replace {path}")
        except OSError as exc:
            raise StoreError(f"Cannot save {path} ({exc}).") from exc
        self._model = self._paths = None

    @contextmanager
    def writer(self, repair: bool = False) -> Iterator["Store"]:
        """Hold the writer lock: reload the index, sweep stale tmp entries.
        ``repair`` (check --fix) restores a lost index instead of refusing."""
        with _Lock(self.root / "lock"):
            self._load()
            if self.lost_index:
                if not repair:
                    raise StoreError(self.lost_text())
                self._restore()
            self.objects.mkdir(exist_ok=True)
            self.tmp.mkdir(exist_ok=True)
            self.sweep()
            self._writing = True
            try:
                yield self
            finally:
                self._writing = False

    def stale(self) -> list[Path]:
        if not self.tmp.is_dir():
            return []
        limit = time.time() - STALE
        return [entry for entry in self.tmp.iterdir() if entry.lstat().st_mtime < limit]

    def sweep(self) -> int:
        """Delete tmp entries older than a day, skipping files still open."""
        removed = 0
        for entry in self.stale():
            try:
                if entry.is_dir():
                    shutil.rmtree(entry)
                else:
                    entry.unlink()
                removed += 1
            except OSError:
                pass
        return removed

    # Ingest ------------------------------------------------------------

    def put(self, source: Source,
            read: Callable[[], AbstractContextManager[BinaryIO]] | None = None,
            *, allowed: set[tuple[int, bytes]] | None = None, reason: str = "",
            config: bool = False, own: Path | None = None) -> tuple[str, bool]:
        """Store one file and record ``source``; returns its SHA-256 and
        whether the object is new.

        ``read`` opens the bytes (the source file by default). ``own`` is a
        file in our tmp that is moved into place instead of copied. Raises
        Rejected when the bytes are not an IM*H image, when ``config`` is set
        and they do not read as a configuration, or when their (size, MD5) is
        not in ``allowed``; Changed when ``source.path`` changed meanwhile.
        """
        assert self._writing, "put needs the writer lock"
        if allowed is not None and read is None:
            # The size is known before anything is read or copied.
            known = (own.stat().st_size if own else source.stat[0])
            if known not in {size for size, _ in allowed}:
                raise Rejected(reason or "size or MD5 differs from the manifest")
        sha, md5, size, head = hashlib.sha256(), hashlib.md5(), 0, bytearray()
        part = own or self.tmp / f"{os.getpid()}-{next(_parts)}.part"
        try:
            with ExitStack() as stack:
                handle = stack.enter_context(
                    read() if read else open(own, "rb") if own else open_source(source.path))
                out = None if own else stack.enter_context(open(part, "xb"))
                while block := handle.read(1 << 20):
                    sha.update(block)
                    md5.update(block)
                    size += len(block)
                    if len(head) <= CONFIG_LIMIT:
                        head += block
                    if out is not None:
                        out.write(block)
                if out is not None:
                    out.flush()
                    os.fsync(out.fileno())
            if not head.startswith(IMAGE_MAGIC):
                raise Rejected("not a signed DJI image (no IM*H header)")
            kind = "module"
            if size <= CONFIG_LIMIT:
                try:
                    read_config(bytes(head))
                    kind = "config"
                except PackageError as exc:
                    if config:
                        raise Rejected(f"not a readable configuration: {exc}") from exc
            elif config:
                raise Rejected("too large for a configuration")
            if allowed is not None and (size, md5.digest()) not in allowed:
                raise Rejected(reason or "size or MD5 differs from the manifest")
            try:
                current = file_stat(source.path)
            except OSError as exc:  # renamed or deleted (pending) meanwhile
                raise Changed(f"gone while reading ({exc.strerror or exc})") from exc
            if current != source.stat:
                raise Changed("changed while reading")
            digest = sha.hexdigest()
            target = self.objects / digest
            new = not target.exists()
            if not new:
                # Byte-level damage is check --full's job.
                if target.stat().st_size != size:
                    raise StoreError(f"{target} has the wrong size; run dji-duml fw check --fix.")
            else:
                os.replace(part, target)
                os.chmod(target, stat_mode.S_IREAD)
        finally:
            if own is None:
                part.unlink(missing_ok=True)
        # The bytes just read hash to ``digest``: they, not an existing
        # record that a hand edit or a bug made wrong, decide its fields.
        fields = {"kind": kind, "size": size, "md5": md5.hexdigest()}
        record = self.index["objects"].setdefault(digest, {**fields, "sources": []})
        record.update(fields)
        _add_source(record["sources"], source)
        try:
            self.save()
        except StoreError as exc:
            raise StoreError(f"Object {digest[:12]} is stored, but the index could not be "
                             f"saved: {exc} Run dji-duml fw check --fix, then the command "
                             "again.") from exc
        return digest, new

    def add_release(self, data: bytes, source: Source) -> tuple[str, bool]:
        """Record the kept fields of a DJI release list; returns its key (the
        SHA-256 of the list) and whether it is new."""
        assert self._writing, "add_release needs the writer lock"
        entries = release_entries(data)
        digest = hashlib.sha256(data).hexdigest()
        new = digest not in self.index["releases"]
        record = self.index["releases"].setdefault(digest, {"entries": entries, "sources": []})
        _add_source(record["sources"], source)
        self.save()
        return digest, new

    def _by_path(self) -> dict[str, list[tuple[tuple[int, int], str, bool, str]]]:
        """Recorded sources by file: (stat, object or list, is a list, added)."""
        if self._paths is None:
            self._paths = {}
            for table, release in (("objects", False), ("releases", True)):
                for digest, record in self.index[table].items():
                    for source in record["sources"]:
                        self._paths.setdefault(os.path.normcase(source["path"]), []).append(
                            (tuple(source["stat"]), digest, release, source["added"]))
        return self._paths

    def recorded(self, path: Path) -> list[tuple[tuple[int, int], str, bool, str]]:
        """The sources recorded for ``path`` with its current stat: records of
        content it held before (Assistant rewrites a cache file under the same
        name) do not count."""
        path = Path(path).resolve()
        hits = self._by_path().get(os.path.normcase(str(path)))
        if not hits:
            return []
        current = file_stat(path)
        return [hit for hit in hits if hit[0] == current]

    def unchanged(self, path: Path, container: bool = False) -> str | None:
        """When ``path`` was first added, if it has the stat recorded then and
        every object recorded from it is present: then reading it again would
        add nothing. A ZIP, tar or capture (``container``) counts only once it
        was read to the end (``finished``): an interrupted ingest records some
        of its members and must be resumed."""
        hits = self.recorded(path)
        if container:
            mark = self.index.get("containers", {}).get(os.path.normcase(str(Path(path).resolve())))
            if mark is None or tuple(mark["stat"]) != file_stat(Path(path).resolve()):
                return None
            added = [mark["added"]]
        elif not hits:
            return None
        else:
            added = []
        if not all(release or self.has(digest) for _, digest, release, _ in hits):
            return None
        return min(added + [added_ for *_, added_ in hits])

    def finished(self, source: Source) -> None:
        """Record that the ZIP, tar or capture ``source.path`` was read to the
        end with nothing skipped (rejected members count: they are rejected
        again on every read)."""
        assert self._writing, "finished needs the writer lock"
        containers = self.index.setdefault("containers", {})
        key = os.path.normcase(str(source.path))
        old = containers.get(key)
        containers[key] = {"from": source.kind, "stat": list(source.stat),
                           "added": old["added"] if old and tuple(old["stat"]) == source.stat
                           else _now()}
        if old != containers[key]:
            self.save()

    def has(self, digest: str) -> bool:
        record = self.index["objects"].get(digest)
        try:
            return record is not None and (self.objects / digest).stat().st_size == record["size"]
        except OSError:
            return False

    # Derived views -------------------------------------------------------

    def model(self) -> Model:
        if self._model is None:
            self._model = self._derive()
        return self._model

    def _derive(self) -> Model:
        present, absent = {}, {}
        for digest, record in self.index["objects"].items():
            (present if self.has(digest) else absent)[digest] = record
        by_key: dict[tuple[str, int], list[str]] = {}
        for digest, record in present.items():
            by_key.setdefault((record["md5"], record["size"]), []).append(digest)
        lost = {(record["md5"], record["size"]) for record in absent.values()}
        configs, unreadable = [], {}
        for digest, record in sorted(present.items()):
            if record["kind"] != "config":
                continue
            try:
                info = read_config((self.objects / digest).read_bytes())
            except (PackageError, OSError) as exc:
                unreadable[digest] = str(exc)
                continue
            entries = []
            for module in info.modules:
                key = (module.md5.hex(), module.size)
                found = tuple(sorted(by_key.get(key, ())))
                state = "ok" if len(found) == 1 else "conflict" if found \
                    else "damaged" if key in lost else "missing"
                entries.append(Entry(module, state, found))
            configs.append(Config(digest, record["size"], info, tuple(entries)))
        # A list belongs to a product when it states one of that product's
        # versions with the date in the configuration's <release from>.
        lists = {}
        for digest, record in self.index["releases"].items():
            lists[digest] = {
                config.info.product for entry in record["entries"] for config in configs
                if str(config.info.version) == entry["version"]
                and dict(config.info.release).get("from", entry["date"]).replace("/", "-")
                == entry["date"]}
        return Model(present, absent, configs, unreadable, lists)

    def configs(self) -> list[Config]:
        return self.model().configs

    def products(self) -> list[str]:
        return sorted({config.info.product for config in self.configs()})

    def release_info(self, product: str) -> dict[FirmwareVersion, Release]:
        """The union of the lists attributed to ``product``; where lists
        differ, the one added last wins. A version missing from a list proves
        nothing: lists are partial views."""
        model = self.model()
        records = sorted(
            (record for digest, record in self.index["releases"].items()
             if product in model.lists[digest]),
            key=lambda record: max(source["added"] for source in record["sources"]))
        known = {}
        for record in records:
            for entry in record["entries"]:
                version = FirmwareVersion.parse(entry["version"])
                known[version] = Release(version, entry["date"], entry["flow"], entry["note"])
        return known

    def unassigned(self) -> list[tuple[str, list[dict]]]:
        model = self.model()
        return [(digest, record["entries"])
                for digest, record in sorted(self.index["releases"].items())
                if not model.lists[digest]]

    def versions(self, product: str) -> list[Version]:
        held: dict[FirmwareVersion, list[Config]] = {}
        for config in self.configs():
            if config.info.product == product:
                held.setdefault(config.info.version, []).append(config)
        known = self.release_info(product)
        return [Version(product, version, tuple(held.get(version, ())), known.get(version))
                for version in sorted(set(held) | set(known), reverse=True)]

    def orphans(self) -> list[tuple[str, dict]]:
        """Present modules that no held configuration lists."""
        listed = {(module.md5.hex(), module.size)
                  for config in self.configs() for module in config.info.modules}
        return [(digest, record) for digest, record in sorted(self.model().present.items())
                if record["kind"] == "module" and (record["md5"], record["size"]) not in listed]

    def module_keys(self) -> set[tuple[int, bytes]]:
        """(size, MD5) of every module a held configuration lists."""
        return {(module.size, module.md5)
                for config in self.configs() for module in config.info.modules}

    def kinds(self, digests) -> str:
        """Where these objects came from, e.g. ``tar, extract, cache``, in the
        order the kinds were first added."""
        first: dict[str, str] = {}
        for digest in digests:
            for source in self.index["objects"].get(digest, {}).get("sources", ()):
                if source["from"] not in first or source["added"] < first[source["from"]]:
                    first[source["from"]] = source["added"]
        return ", ".join(sorted(first, key=lambda kind: (first[kind], kind)))

    def hint(self, record: dict) -> str:
        """How to get a lost object back: re-add its first source that still exists."""
        for source in record["sources"]:
            path = Path(source["path"])
            if source["from"] == "recovered" or not path.exists() or inside(path, self.root):
                continue
            if source["from"] == "cache":
                cache = assistant_cache()
                if cache is not None and os.path.normcase(path.parent) == os.path.normcase(cache):
                    return "dji-duml fw harvest"
                return f"dji-duml fw add {quote(path.parent)}"
            if source["from"] == "extract":
                return f"dji-duml fw add {quote(path.parent)}"
            return f"dji-duml fw add {quote(path)}"
        return "no source of it is left: add a package, capture or cache that holds it"

    def unseen_cache(self, directory: Path | None) -> tuple[int, int] | None:
        """(cache files, files not in the store) in DJI Assistant's cache, by
        one stat each; nothing is read. None when there is no such folder."""
        if directory is None:
            return None
        try:
            directory = Path(directory).resolve()
            files = [entry for entry in os.scandir(directory)
                     if entry.is_file() and CACHE_NAME.fullmatch(entry.name)]
        except OSError:
            return None
        recorded = {(os.path.normcase(source["path"]), tuple(source["stat"]))
                    for table in ("objects", "releases") for record in self.index[table].values()
                    for source in record["sources"] if source["from"] == "cache"}
        unseen = 0
        for entry in files:
            stat = entry.stat()
            unseen += (os.path.normcase(str(directory / entry.name)),
                       (stat.st_size, stat.st_mtime_ns)) not in recorded
        return len(files), unseen

    # Selection and export ----------------------------------------------

    def incomplete(self, config: Config) -> str:
        """Why a configuration cannot be exported, with what is missing."""
        what = f"{config.info.product} {config.info.version} configuration {config.sha[:12]}"
        conflicts = [entry for entry in config.entries if entry.state == "conflict"]
        if conflicts:
            return (f"{what} has a CONFLICT: " + "; ".join(
                f"{entry.file.name} matches {len(entry.objects)} different objects "
                f"({', '.join(digest[:12] for digest in entry.objects)})" for entry in conflicts)
                + ". See dji-duml fw check.")
        missing = [entry for entry in config.entries if entry.state != "ok"]
        return (f"{what} is PARTIAL {config.held}/{len(config.entries)}; missing: " + "; ".join(
            f"{entry.file.name} ({entry.file.size} bytes, md5 {entry.file.md5.hex()}"
            + (", damaged: dji-duml fw check" if entry.state == "damaged" else "") + ")"
            for entry in missing) + ".")

    def select(self, product: str, version: FirmwareVersion | str, config: str | None = None
               ) -> tuple[Config, list[str]]:
        """The one complete configuration of ``product`` ``version``, with
        notes; ``config`` is a SHA-256 prefix of at least 8 hex digits."""
        if self.lost_index:
            raise StoreError(self.lost_text())
        if isinstance(version, str):
            version = FirmwareVersion.parse(version)
        versions = self.versions(product)
        found = next((item for item in versions if item.version == version), None)
        if found is None or not found.configs:
            held = [str(item.version) for item in versions if item.configs]
            listed = f" (DJI's list: released {found.release.date})" if found else ""
            raise StoreError(f"{product} {version} is not held{listed}. "
                             f"Held: {', '.join(held) or 'nothing'}.")
        if config is not None:
            prefix = config.strip().lower()
            if not re.fullmatch(r"[0-9a-f]{8,64}", prefix):
                raise StoreError("--config needs at least 8 hex digits of a configuration's "
                                 "SHA-256.")
            matches = [item for item in found.configs if item.sha.startswith(prefix)]
            if len(matches) != 1:
                raise StoreError(f"--config {config} matches {len(matches)} configurations of "
                                 f"{product} {version}; they are: "
                                 f"{self._candidates(found.configs)}.")
            if not matches[0].complete:
                raise StoreError(self.incomplete(matches[0]))
            return matches[0], []
        complete = found.complete
        if len(complete) > 1:
            raise StoreError(f"{product} {version} has {len(complete)} complete configurations; "
                             f"choose one with --config: {self._candidates(complete)}.")
        if not complete:
            raise StoreError(" ".join(self.incomplete(item) for item in found.configs))
        notes = [f"configuration {item.sha[:12]} of this version is {item.state}; not used"
                 for item in found.configs if item is not complete[0]]
        return complete[0], notes

    def _candidates(self, configs) -> str:
        return "; ".join(f"{config.sha[:12]} {config.state}, seen in "
                         + ", ".join(sorted({source["name"] for source in
                                             self.index["objects"][config.sha]["sources"]}))
                         for config in configs)

    def export(self, config: Config, output: str | Path, *, temporary: bool = False
               ) -> PackageInfo:
        """Write ``config`` and its modules as a package at ``output``, a new
        file outside the store (``temporary``: in the store's tmp), read back
        the way flash reads it. It is written under a name of its own next to
        ``output`` and then moved there, so an existing ``<output>.part``, or
        any other file, is never overwritten or deleted."""
        out = Path(output)
        if not temporary and inside(out, self.root):
            raise StoreError(f"{out} is inside the store; export to a file outside it.")
        if not config.complete:
            raise StoreError(self.incomplete(config))
        if out.exists():
            raise PackError(f"{out} already exists.")
        data = (self.objects / config.sha).read_bytes()
        if hashlib.sha256(data).hexdigest() != config.sha:
            raise StoreError(f"Configuration object {config.sha[:12]} is damaged; "
                             "run dji-duml fw check --full.")
        members = [(f"{config.info.product}.cfg.sig", self.objects / config.sha)]
        members += [(entry.file.name, self.objects / entry.objects[0]) for entry in config.entries]
        if temporary:  # a name of our own in tmp already
            return write_package(out, members, config.info.version, data)
        while True:
            work = out.with_name(f"{out.name}.dji-duml-{os.getpid()}-{next(_parts)}")
            if not work.exists() and not work.with_name(work.name + ".part").exists():
                break
        package = write_package(work, members, config.info.version, data)
        try:
            _place(work, out)
        except FileExistsError as exc:
            raise PackError(f"{out} already exists.") from exc
        finally:
            work.unlink(missing_ok=True)
        return dataclasses.replace(package, path=out.resolve())

    # Verification ----------------------------------------------------------

    def _quarantine(self, path: Path) -> Path:
        """Move ``path`` to quarantine under a name no earlier move took."""
        self.quarantine.mkdir(exist_ok=True)
        stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        target = self.quarantine / f"{path.name}-{stamp}"
        for number in itertools.count(2):
            if not os.path.lexists(target):
                break
            target = self.quarantine / f"{path.name}-{stamp}-{number}"
        os.rename(path, target)  # a read-only file can still be renamed
        self._model = None
        return target

    @staticmethod
    def _hash(path: Path, on_bytes: Callable[[int], None] | None = None) -> tuple[str, str]:
        sha, md5 = hashlib.sha256(), hashlib.md5()
        with open(path, "rb") as handle:
            while block := handle.read(1 << 20):
                sha.update(block)
                md5.update(block)
                if on_bytes is not None:
                    on_bytes(len(block))
        return sha.hexdigest(), md5.hexdigest()

    @staticmethod
    def _kind(data: bytes) -> str:
        if len(data) <= CONFIG_LIMIT:
            try:
                read_config(data)
                return "config"
            except PackageError:
                pass
        return "module"

    def _object_problem(self, digest: str, record: dict, full: bool, fix: bool,
                        on_bytes) -> tuple[Problem | None, bool]:
        """One recorded object: (its problem or None, whether --fix rewrote
        its record). The SHA-256 decides: bytes that hash to the object's name
        are intact, and then a wrong size, MD5 or kind is the record's fault,
        not the object's. A read that fails is never taken for damage."""
        path = self.objects / digest
        label = f"object {digest[:12]} ({record['kind']}, {record['size']} bytes)"
        if not os.path.lexists(path):
            return Problem(f"{label} is missing", self.hint(record)), False
        try:
            size = path.stat().st_size
            suspect = None
            if size != record["size"]:
                suspect = f"has {size} bytes"
            elif record["kind"] == "config":
                try:
                    read_config(path.read_bytes())
                except PackageError as exc:
                    suspect = f"no longer reads as a configuration ({exc})"
            if suspect is None and not full:
                if not writable(path):
                    return None, False
                if fix:
                    os.chmod(path, stat_mode.S_IREAD)
                return Problem(f"{label} is not read-only", "dji-duml fw check --fix sets it "
                               "again", fixed=fix), False
            sha, md5 = self._hash(path, on_bytes)
            kind = self._kind(path.read_bytes()) if size <= CONFIG_LIMIT else "module"
        except OSError as exc:
            return Problem(f"{label} could not be read ({exc})",
                           "nothing was changed; close whatever holds it and run the check "
                           "again"), False
        if sha != digest:
            damage = suspect or "does not match its SHA-256"
            try:
                moved = f"; moved to {self._quarantine(path)}" if fix else ""
            except OSError as exc:
                moved = f"; could not be moved to quarantine ({exc})"
            return Problem(f"{label} {damage}{moved}", self.hint(record)), False
        actual = {"kind": kind, "size": size, "md5": md5}
        wrong = [f"{key} {record[key]} (the object: {value})"
                 for key, value in actual.items() if record[key] != value]
        if wrong:
            if fix:
                record.update(actual)
            return Problem(f"{label} is intact, but its index record is wrong: "
                           + ", ".join(wrong), "dji-duml fw check --fix corrects the record",
                           fixed=fix), fix
        if writable(path):
            if fix:
                os.chmod(path, stat_mode.S_IREAD)
            return Problem(f"{label} is not read-only", "dji-duml fw check --fix sets it again",
                           fixed=fix), False
        return None, False

    def check(self, full: bool = False, fix: bool = False,
              on_bytes: Callable[[int], None] | None = None) -> list[Problem]:
        """Problems of the store. ``full`` rehashes every object; ``fix``
        (under the writer lock) quarantines damaged objects, adopts or
        quarantines strays, sets read-only again and sweeps stale tmp
        entries. Nothing is ever deleted except stale tmp entries."""
        assert not fix or self._writing, "check --fix needs the writer lock"
        problems = []
        if self.lost_index:  # under --fix, writer() has restored it already
            problems.append(Problem(self.lost_text()))
        elif fix and self.restored:
            problems.append(Problem(f"{INDEX} was missing: {self.restored}", fixed=True))
        objects = self.index["objects"]
        rewritten = False
        for digest, record in sorted(objects.items()):
            problem, fixed = self._object_problem(digest, record, full, fix, on_bytes)
            if problem is not None:
                problems.append(problem)
            rewritten |= fixed
        if rewritten:
            self.save()
        keys: dict[tuple[str, int], list[str]] = {}
        for digest, record in objects.items():
            keys.setdefault((record["md5"], record["size"]), []).append(digest)
        for (md5, size), digests in sorted(keys.items()):
            if len(digests) > 1:
                problems.append(Problem(
                    f"CONFLICT: {len(digests)} different objects have MD5 {md5} and {size} bytes: "
                    + ", ".join(sorted(digest[:12] for digest in digests)),
                    "versions that list this module cannot be exported or flashed"))
        if self.objects.is_dir():
            for path in sorted(self.objects.iterdir()):
                if path.name not in objects:
                    problems.append(self._stray(path, fix))
        for entry in self.stale():
            removed = False
            if fix:
                try:
                    shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
                    removed = True
                except OSError:
                    pass
            problems.append(Problem(f"tmp entry {entry.name} is older than 24 h",
                                    "dji-duml fw check --fix deletes it", fixed=removed))
        return problems

    def _stray(self, path: Path, fix: bool) -> Problem:
        """A file in objects that the index does not name: an object written
        just before a crash, or something put there by hand."""
        text = f"stray file objects{os.sep}{path.name}"
        if not fix:
            return Problem(text, "dji-duml fw check --fix adopts it if its name is its SHA-256")
        sha = None
        try:
            if path.is_file() and not path.is_symlink() and _SHA256.fullmatch(path.name):
                sha, _ = self._hash(path)
            if sha == path.name:
                try:
                    self.put(Source.of("recovered", path), own=path)
                    if writable(path):
                        os.chmod(path, stat_mode.S_IREAD)
                    return Problem(f"{text}: adopted as recovered", fixed=True)
                except Rejected:
                    pass
            target = self._quarantine(path)
        except (OSError, Changed) as exc:
            return Problem(f"{text} could not be read ({exc})",
                           "nothing was changed; run dji-duml fw check --fix again")
        return Problem(f"{text}: moved to {target}", fixed=True)
