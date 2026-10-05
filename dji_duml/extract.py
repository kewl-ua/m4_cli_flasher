"""Recover the files a host sent to the M4T's upgrade center from a USB capture.

DJI Assistant and dji-duml send every package file as a 00/2A transfer: open
(u32 size, name), data chunks addressed by index, end (MD5 of the file). This
rebuilds each transfer from the host's frames, streaming the capture and
writing chunks straight to disk, and passes a file only when it checks out:

* every chunk is present, a repeated chunk is identical (by BLAKE2b), and
  every chunk but the last has one size: the one the device asked for in its
  open reply when the capture has that reply;
* the length equals the size announced in the open frame;
* the MD5 equals the one in the end frame;
* the device did not reject the open or the end;
* when the capture carries a .cfg.sig for that USB device, the file was sent
  after it, is listed in its signed manifest, and has the size and MD5 the
  manifest states.

A file that fails a check is kept as ``<name>.incomplete`` with the reasons in
``report.json``, never under its own name. The DJI signature itself is not
checked: the device does that.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import commands
from .errors import DumlError, PackageError
from .package import CONFIG_LIMIT, manifest_files
from .pcap import TraceStats, iter_frames

REPORT = "report.json"
INCOMPLETE = ".incomplete"
#: Chunks held in memory while the chunk size is unknown (no open reply yet).
_PENDING_LIMIT = 256
#: Files open at once on one USB device; the host sends one at a time.
_ACTIVE_LIMIT = 16
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,199}")
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{n}" for n in range(1, 10)),
             *(f"LPT{n}" for n in range(1, 10))}


class ExtractError(DumlError):
    pass


def _safe_name(name: str) -> bool:
    """A plain file name that is safe to create on Windows and POSIX and does
    not pass for the mark of a failed file."""
    return bool(_NAME.fullmatch(name)) and not name.endswith(".") \
        and name.split(".")[0].upper() not in _RESERVED \
        and not name.lower().endswith(INCOMPLETE)


def _signature(data: bytes) -> bytes:
    """Length and digest of a chunk: enough to tell a repeat from a conflict."""
    return len(data).to_bytes(2, "little") + hashlib.blake2b(data, digest_size=16).digest()


class _Disk:
    """Bytes the assembled files may still take: every byte of a real file is
    in the capture, so all of them together never need more than its size."""

    def __init__(self, allowed: int):
        self.remaining = allowed


@dataclass(eq=False)
class Transfer:
    """One file the host sent: open, data chunks by index, end."""
    number: int
    name: str
    size: int
    usb: tuple[int, int]  # bus, device address
    sender: int
    receiver: int
    started: float
    part: Path
    disk: _Disk
    chunk_size: int | None = None
    offered_chunk: int | None = None  # from the device's open reply
    open_status: int | None = None
    end_status: int | None = None
    end_md5: bytes | None = None
    finished: float | None = None
    chunks: dict[int, bytes] = field(default_factory=dict)  # index -> _signature
    pending: list[tuple[int, bytes]] = field(default_factory=list)
    chunk_count: int = 0
    duplicates: int = 0
    conflicts: int = 0
    extent: int = 0    # end of the furthest chunk written
    refused: int = 0   # chunks not written: more data than the capture holds
    length: int = 0
    md5: bytes | None = None
    closed: bool = False
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    manifest: str = "no manifest in the capture"
    saved_as: str = ""
    _handle: object = None

    @property
    def ok(self) -> bool:
        return self.closed and not self.problems

    def add(self, index: int, data: bytes) -> None:
        signature = _signature(data)
        known = self.chunks.get(index)
        if known is not None:
            if known == signature:
                self.duplicates += 1
            else:
                self.conflicts += 1
            return
        self.chunks[index] = signature
        if self.chunk_size is not None:
            self._write(index, data)
            return
        self.pending.append((index, data))
        if len(self.pending) > _PENDING_LIMIT:
            self._chunk_size_from_data()

    def open_reply(self, payload: bytes) -> None:
        self.open_status = payload[0]
        if payload[0] == 0 and len(payload) == 7:
            self.offered_chunk = int.from_bytes(payload[1:3], "little")
            if self.chunk_size is None and not self.closed and self.offered_chunk:
                self._set_chunk_size(self.offered_chunk)

    def _chunk_size_from_data(self) -> None:
        # Every chunk but the last is full-size, so of two or more chunks the
        # largest has the chunk size.
        self._set_chunk_size(max(len(data) for _, data in self.pending))

    def _set_chunk_size(self, size: int) -> None:
        self.chunk_size = size
        for index, data in self.pending:
            self._write(index, data)
        self.pending.clear()

    def _file(self):
        if self._handle is None:
            self._handle = open(self.part, "w+b")
        return self._handle

    def _write(self, index: int, data: bytes) -> None:
        # Nothing lands past the announced size, and the files never grow
        # beyond the capture, so a stray index cannot fill the disk; close()
        # reports such chunks.
        offset = index * self.chunk_size
        if offset >= self.size:
            return
        growth = max(0, offset + len(data) - self.extent)
        if growth > self.disk.remaining:
            self.refused += 1
            return
        self.disk.remaining -= growth
        self.extent += growth
        handle = self._file()
        handle.seek(offset)
        handle.write(data)

    def close(self) -> None:
        """Assemble what arrived and check it against the open and end frames."""
        if self.closed:
            return
        if self.chunk_size is None and self.pending:
            self._chunk_size_from_data()
        self.closed = True
        self.chunk_count = len(self.chunks)
        if self.finished is None:
            self.problems.append("no end frame for this file")
        if self.conflicts:
            self.problems.append(f"{self.conflicts} chunk(s) repeated with different data")
        if self.refused:
            self.problems.append(f"{self.refused} chunk(s) lie beyond the data in the capture")
        if self.chunk_size:
            count = -(-self.size // self.chunk_size)
            last = self.size - self.chunk_size * (count - 1)
            missing = count - sum(1 for index in self.chunks if index < count)
            beyond = len(self.chunks) - (count - missing)
            wrong = [index for index, signature in self.chunks.items() if index < count
                     and int.from_bytes(signature[:2], "little")
                     != (self.chunk_size if index < count - 1 else last)]
            if missing:
                self.problems.append(f"{missing} of {count} chunk(s) missing")
            if beyond:
                self.problems.append(f"{beyond} chunk(s) beyond the announced size")
            if wrong:
                self.problems.append(
                    f"{len(wrong)} chunk(s) of the wrong length, the first at index {min(wrong)}")
        elif self.size:
            self.problems.append("no data")
        self.chunks.clear()
        handle = self._file()
        handle.seek(0)
        digest = hashlib.md5()
        while block := handle.read(1 << 20):
            digest.update(block)
            self.length += len(block)
        handle.close()
        self.md5 = digest.digest()
        if self.length != self.size and not self.problems:
            self.problems.append(f"assembled {self.length} bytes, announced {self.size}")
        if self.end_md5 is not None and self.md5 != self.end_md5:
            self.problems.append("MD5 differs from the end frame")

    def verdict(self) -> None:
        """Checks on the device's replies, which may follow the end frame."""
        if self.open_status is None:
            self.notes.append("no open reply in the capture; chunk size taken from the data")
        elif self.open_status:
            self.problems.append(f"the device rejected the open: status {self.open_status:#04x}")
        elif self.chunk_count and self.offered_chunk != self.chunk_size \
                and self.size > min(self.chunk_size, self.offered_chunk):
            # A file within one chunk lays out the same with either size.
            self.problems.append(f"chunks are {self.chunk_size} bytes, "
                                 f"the device asked for {self.offered_chunk}")
        if self.finished is not None:
            if self.end_status is None:
                self.notes.append("no reply to the end frame in the capture")
            elif self.end_status:
                self.problems.append(f"the device rejected the file: status {self.end_status:#04x}")

    def discard(self) -> None:
        if self._handle is not None:
            self._handle.close()
        self.part.unlink(missing_ok=True)

    def report(self) -> dict:
        return {
            "number": self.number, "name": self.name, "saved_as": self.saved_as,
            "ok": self.ok, "size": self.size, "length": self.length,
            "md5": self.md5.hex() if self.md5 else None,
            "end_md5": self.end_md5.hex() if self.end_md5 else None,
            "manifest": self.manifest, "problems": self.problems, "notes": self.notes,
            "chunk_size": self.chunk_size, "chunks": self.chunk_count,
            "duplicates": self.duplicates, "conflicts": self.conflicts,
            "usb": f"{self.usb[0]}:{self.usb[1]}",
            "sender": f"{self.sender:#04x}", "receiver": f"{self.receiver:#04x}",
            "seconds": round(self.finished - self.started, 3) if self.finished else None,
        }


@dataclass
class Extraction:
    files: list[Transfer]
    sessions: list[dict]
    stray_frames: int
    stats: TraceStats

    @property
    def ok(self) -> bool:
        return bool(self.files) and all(item.ok for item in self.files) and all(
            session["error"] is None and not session["missing"] for session in self.sessions)


def _parse_open(payload: bytes) -> tuple[str, int] | None:
    if len(payload) < 7:
        return None
    raw = payload[6:6 + payload[5]]
    if not raw or len(raw) != payload[5]:
        return None
    # Bytes outside printable ASCII become visible escapes, which _safe_name
    # rejects, so a name steers neither the terminal nor the file system.
    name = "".join(chr(byte) if 0x20 <= byte < 0x7F else f"\\x{byte:02x}"
                   for byte in raw.split(b"\0", 1)[0])
    return name, int.from_bytes(payload[1:5], "little")


def extract(capture: str | Path, output: str | Path, *, device: int | None = None) -> Extraction:
    """Rebuild every 00/2A file transfer in ``capture`` into ``output``, a new
    or empty directory, and write ``report.json`` there."""
    out = Path(output)
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise ExtractError(f"{out} must be a new or empty directory.")
    with open(capture, "rb") as handle:  # an unreadable capture leaves no directory behind
        disk = _Disk(handle.seek(0, 2))
    out.mkdir(parents=True, exist_ok=True)
    stats = TraceStats()
    transfers: list[Transfer] = []
    active: dict[tuple, Transfer] = {}  # (bus, device, sender, receiver), in open order
    awaiting: dict[tuple, tuple[str, Transfer]] = {}  # request (bus, device, sender, receiver, seq)
    numbers = itertools.count(1)
    stray = 0
    try:
        for entry in iter_frames(capture, device=device, stats=stats):
            frame, payload = entry.frame, entry.frame.payload
            if (frame.cmd_set, frame.cmd_id) != (commands.GENERAL, commands.FILE_TRANSFER) \
                    or not payload:
                continue
            if frame.response:
                # A reply returns the request's seq to its sender. Progress
                # reports (5 bytes, status 00) answer nothing tracked here;
                # any reply with a non-zero status is a rejection.
                key = (entry.bus, entry.device, frame.receiver, frame.sender, frame.seq)
                kind, transfer = awaiting.get(key, (None, None))
                if kind == "open" and (len(payload) == 7 or payload[0]):
                    transfer.open_reply(payload)
                    del awaiting[key]
                elif kind == "end" and (len(payload) == 1 or payload[0]):
                    transfer.end_status = payload[0]
                    del awaiting[key]
                continue
            usb = (entry.bus, entry.device)
            pair = (*usb, frame.sender, frame.receiver)
            current = active.get(pair)
            if payload[0] == commands.FT_OPEN and (opened := _parse_open(payload)):
                name, size = opened
                if current is not None and (current.name, current.size) == opened \
                        and not current.chunks:
                    # The host repeated the open, e.g. after a lost reply.
                    awaiting[pair + (frame.seq,)] = ("open", current)
                    continue
                if current is not None:
                    current.problems.append("the host opened the next file before ending this one")
                    current.close()
                    del active[pair]
                same_device = [key for key in active if key[:2] == usb]
                if len(same_device) >= _ACTIVE_LIMIT:
                    oldest = active.pop(same_device[0])
                    oldest.problems.append("too many files open at once on this device")
                    oldest.close()
                number = next(numbers)
                transfer = Transfer(number, name, size, usb, frame.sender, frame.receiver,
                                    entry.time, out / f".transfer-{number:03d}.part", disk)
                transfers.append(transfer)
                active[pair] = transfer
                awaiting[pair + (frame.seq,)] = ("open", transfer)
            elif payload[0] == commands.FT_DATA and len(payload) >= 5 and current is not None:
                current.add(int.from_bytes(payload[1:5], "little"), payload[5:])
            elif payload[0] == commands.FT_END and len(payload) == 17 and current is not None:
                del active[pair]
                current.end_md5, current.finished = payload[1:], entry.time
                current.close()
                awaiting[pair + (frame.seq,)] = ("end", current)
            else:
                stray += 1
        for transfer in transfers:
            transfer.close()
            transfer.verdict()
        sessions = _check_manifests(transfers)
        _save(transfers, out)
        result = Extraction(transfers, sessions, stray, stats)
        (out / REPORT).write_text(json.dumps({
            "capture": str(capture), "ok": result.ok, "frames": stats.frames,
            "not_duml_bytes": stats.discarded, "stray_frames": stray,
            "sessions": sessions, "files": [item.report() for item in transfers],
        }, indent=1), encoding="utf-8")
    except BaseException:
        # Leave the directory as empty as it was, so the run can be repeated.
        for transfer in transfers:
            transfer.discard()
        (out / REPORT).unlink(missing_ok=True)
        raise
    return result


def _check_manifests(transfers: list[Transfer]) -> list[dict]:
    """A .cfg.sig starts a session on its USB device: the files that device
    received after it must be modules its signed manifest lists, with the
    same size and MD5. Files a device received before its first .cfg.sig
    cannot be checked and fail."""
    sessions: list[dict] = []
    current: dict[tuple[int, int], tuple[dict, dict | None]] = {}  # usb -> session, modules
    with_manifest = {item.usb for item in transfers if item.name.endswith(".cfg.sig")}
    for item in transfers:
        if item.name.endswith(".cfg.sig"):
            item.manifest = "this is the manifest"
            session = {"config": item.name, "usb": f"{item.usb[0]}:{item.usb[1]}",
                       "version": None, "error": None, "missing": [], "unlisted": []}
            sessions.append(session)
            current[item.usb] = (session, _read_manifest(item, session))
            continue
        if item.usb not in current:
            if item.usb in with_manifest:
                item.manifest = "sent before the manifest"
                item.problems.append("sent before the .cfg.sig, so not checked against it")
            continue
        session, modules = current[item.usb]
        if modules is None:
            item.manifest = "not checked: the manifest is unusable"
            item.problems.append("not checked: the manifest before it is unusable")
            continue
        module = modules.get(item.name)
        if module is None:
            item.manifest = "not listed in the manifest"
            item.problems.append("not listed in the signed manifest")
            session["unlisted"].append(item.name)
            continue
        if item.name in session["missing"]:
            session["missing"].remove(item.name)
        if not item.ok:
            item.manifest = "not checked: the file failed its own checks"
        elif (item.size, item.md5) != (module.size, module.md5):
            item.manifest = "differs from the manifest"
            item.problems.append("size or MD5 differs from the signed manifest")
        else:
            item.manifest = "matches the manifest"
    return sessions


def _read_manifest(item: Transfer, session: dict) -> dict | None:
    """Modules by name from a received .cfg.sig, or None with the reason in
    the session."""
    if not item.ok:
        session["error"] = "the configuration did not arrive intact"
        return None
    if item.size > CONFIG_LIMIT:  # it is read whole below
        session["error"] = f"{item.size} bytes is too large for a configuration"
        return None
    try:
        version, listed = manifest_files(item.name, item.part.read_bytes())
    except PackageError as exc:
        session["error"] = str(exc)
        return None
    if version is None:
        session["error"] = "no readable manifest in the configuration"
        return None
    session["version"] = str(version)
    session["missing"] = [module.name for module in listed]
    return {module.name: module for module in listed}


def _save(transfers: list[Transfer], out: Path) -> None:
    taken = {REPORT}

    def free(base: str, mark: str) -> str:
        candidate, copy = base + mark, 1
        while candidate.lower() in taken:  # Windows names ignore case
            copy += 1
            candidate = f"{base}.{copy}{mark}"
        taken.add(candidate.lower())
        return candidate

    for item in transfers:
        mark = "" if item.ok else INCOMPLETE
        generic = f"transfer-{item.number:03d}.bin"
        if not _safe_name(item.name):
            item.notes.append("the announced name is not a safe file name")
            candidate = free(generic, mark)
        else:
            candidate = free(item.name, mark)
        try:
            item.part = item.part.replace(out / candidate)
        except OSError:
            if candidate.startswith(generic):
                raise
            # E.g. a long name in a deep directory without long path support.
            item.notes.append("the announced name could not be created here")
            candidate = free(generic, mark)
            item.part = item.part.replace(out / candidate)
        item.saved_as = candidate
