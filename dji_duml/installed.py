"""The signed configuration (.cfg.sig) of the firmware installed on the drone.

DJI Assistant reads it from the upgrade center on every connect (idle.pcap,
2026-10-04): 00/4F ``01 | u32 offset | u32 1000``, answered by ``status |
u32 length | u32 bytes left after this chunk | length bytes``, 256 bytes at a
time on the M4T (101 requests for the 25632 bytes of 17.02.0501). It is the
package's .cfg.sig byte for byte, so it names the version and the size and
MD5 of every installed module. The modules themselves cannot be read this
way, and nothing here changes the drone.
"""
from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterable
from dataclasses import dataclass

from . import commands
from .client import DumlClient
from .errors import CommandRejected, PackageError, UnexpectedReply
from .frame import Frame
from .package import CONFIG_LIMIT, PackageFile, PackageInfo, manifest_files, open_file
from .version import FirmwareVersion

CONFIG_FILE = 0x01
#: What Assistant asks for per request; the M4T answers with 256 bytes.
REQUEST_SIZE = 1000


@dataclass(frozen=True)
class InstalledConfig:
    data: bytes
    version: FirmwareVersion | None
    modules: tuple[PackageFile, ...]

    @property
    def md5(self) -> bytes:
        return hashlib.md5(self.data).digest()


def config_request(offset: int, size: int = REQUEST_SIZE) -> bytes:
    return bytes([CONFIG_FILE]) + struct.pack("<II", offset, size)


def parse_config_chunk(payload: bytes) -> tuple[bytes, int]:
    """(chunk, bytes left after it)."""
    if payload and payload[0] != 0:
        raise CommandRejected("Get Cfg File", payload[0])
    if len(payload) < 9:
        raise UnexpectedReply(f"Get Cfg File reply is too short: {payload.hex()}")
    size, left = struct.unpack_from("<II", payload, 1)
    if len(payload) != 9 + size:
        raise UnexpectedReply(f"Get Cfg File reply says {size} bytes and has {len(payload) - 9}.")
    return payload[9:], left


def read_config(client: DumlClient, center: int, *, timeout: float = 2.0) -> bytes:
    """Read the whole configuration; it only reads, so requests are retried."""
    data, total = bytearray(), None
    while True:
        reply = client.request(center, commands.GENERAL, commands.UPGRADE_RESULT,
                               config_request(len(data)), timeout=timeout, retries=2)
        chunk, left = parse_config_chunk(reply.payload)
        data += chunk
        if total is None:
            total = len(data) + left
            if total > CONFIG_LIMIT:
                raise UnexpectedReply(f"A configuration of {total} bytes is too large.")
        elif len(data) + left != total:
            raise UnexpectedReply(f"The configuration's size changed while it was read: "
                                  f"{total}, then {len(data) + left} bytes.")
        if not left:
            return bytes(data)
        if not chunk:
            raise UnexpectedReply(f"Empty chunk at offset {len(data)} with {left} bytes left.")


def config_from_frames(frames: Iterable[Frame], center: int) -> bytes | None:
    """The last configuration a capture shows being read from start to end.
    A read restarts at offset 0; chunks of different reads are never mixed,
    so a capture across a flash cannot splice two configurations."""
    pending: dict[tuple[int, int], int] = {}  # (seq, host) -> offset asked for
    current: bytearray | None = None
    total = None
    found = None
    for frame in frames:
        if frame.cmd_set != commands.GENERAL or frame.cmd_id != commands.UPGRADE_RESULT:
            continue
        if not frame.response:
            if frame.receiver != center:
                continue
            offset = None  # other 00/4F types (04 after an install) are not chunks
            if len(frame.payload) == 9 and frame.payload[0] == CONFIG_FILE:
                offset = struct.unpack_from("<I", frame.payload, 1)[0]
                if offset == 0:
                    current = None  # a new read starts, even if its reply is lost
            pending[(frame.seq, frame.sender)] = offset
            continue
        offset = pending.pop((frame.seq, frame.receiver), None)
        if offset is None or frame.sender != center:
            continue
        try:
            chunk, left = parse_config_chunk(frame.payload)
        except (CommandRejected, UnexpectedReply):
            current = None
            continue
        if offset == 0:
            if not chunk.startswith(b"IM*H"):
                current = None
                continue
            current, total = bytearray(), len(chunk) + left
        if current is None or offset != len(current) or offset + len(chunk) + left != total \
                or total > CONFIG_LIMIT:
            current = None
            continue
        current += chunk
        if not left:
            found, current = bytes(current), None
    return found


def describe(data: bytes, product_code: str) -> InstalledConfig:
    if not data.startswith(b"IM*H"):
        raise PackageError("The configuration read from the drone has no IM*H header.")
    version, modules = manifest_files(f"{product_code}.cfg.sig", data)
    return InstalledConfig(data, version, tuple(modules))


def compare(installed: InstalledConfig, package: PackageInfo) -> list[str]:
    """How the drone's configuration differs from a package's; empty when the
    package's .cfg.sig is the drone's, byte for byte."""
    with open_file(package, package.config_name) as handle:
        config = handle.read(CONFIG_LIMIT + 1)
    if hashlib.md5(config).digest() == installed.md5:
        return []
    differences = [f"configuration: package {hashlib.md5(config).hexdigest()}, "
                   f"drone {installed.md5.hex()}"]
    if package.version != installed.version:
        differences.append(f"version: package {package.version}, drone {installed.version}")
    ours = {item.name: item for item in package.files[1:]}
    theirs = {item.name: item for item in installed.modules}
    differences += [f"only on the drone: {name}" for name in sorted(theirs.keys() - ours.keys())]
    differences += [f"only in the package: {name}" for name in sorted(ours.keys() - theirs.keys())]
    differences += [f"different: {name}" for name in sorted(ours.keys() & theirs.keys())
                    if (ours[name].size, ours[name].md5) != (theirs[name].size, theirs[name].md5)]
    return differences
