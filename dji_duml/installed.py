"""The signed configuration (.cfg.sig) of the firmware installed on the drone.

DJI Assistant reads it on connect from the upgrade center with 00/4F type 01
(idle capture of an M4T, 2026-10-05): request 01, offset u32, 1000 u32;
reply status, length u32, bytes left after this chunk u32, then ``length``
bytes (256 on the M4T), until nothing is left. 25632 bytes on 17.02.0501,
byte for byte a package's .cfg.sig: the manifest of every module installed.
The modules themselves cannot be read this way.
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
#: What Assistant asks for per request; the M4T answers 256 bytes.
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
        raise UnexpectedReply(f"Get Cfg File reply says {size} bytes, has {len(payload) - 9}.")
    return payload[9:], left


def read_config(client: DumlClient, center: int, *, timeout: float = 2.0) -> bytes:
    """Only reads, so each request is retried."""
    data = bytearray()
    while True:
        reply = client.request(center, commands.GENERAL, commands.UPGRADE_RESULT,
                               config_request(len(data)), timeout=timeout, retries=2)
        chunk, left = parse_config_chunk(reply.payload)
        data += chunk
        if len(data) + left > CONFIG_LIMIT:
            raise UnexpectedReply(f"Configuration of {len(data) + left} bytes is too large.")
        if not left:
            return bytes(data)
        if not chunk:
            raise UnexpectedReply(f"Empty chunk at offset {len(data)} with {left} bytes left.")


def config_from_frames(frames: Iterable[Frame], center: int) -> bytes | None:
    """The configuration a capture shows being read, if every byte of it is
    there; the last read of each offset wins."""
    pending: dict[tuple[int, int], Frame] = {}
    chunks: dict[int, bytes] = {}
    total = None
    for frame in frames:
        if frame.cmd_set != commands.GENERAL or frame.cmd_id != commands.UPGRADE_RESULT:
            continue
        if not frame.response:
            if frame.receiver == center and len(frame.payload) == 9 \
                    and frame.payload[0] == CONFIG_FILE:
                pending[(frame.seq, frame.sender)] = frame
            continue
        request = pending.pop((frame.seq, frame.receiver), None)
        if request is None or not frame.answers(request):
            continue
        try:
            chunk, left = parse_config_chunk(frame.payload)
        except (CommandRejected, UnexpectedReply):
            continue
        offset = struct.unpack_from("<I", request.payload, 1)[0]
        chunks[offset] = chunk
        total = offset + len(chunk) + left
    if total is None or total > CONFIG_LIMIT:
        return None
    data = bytearray()
    while len(data) < total:
        chunk = chunks.get(len(data))
        if not chunk:
            return None
        data += chunk
    return bytes(data[:total])


def describe(data: bytes, product_code: str) -> InstalledConfig:
    if not data.startswith(b"IM*H"):
        raise PackageError("The configuration read from the drone has no IM*H header.")
    version, modules = manifest_files(f"{product_code}.cfg.sig", data)
    return InstalledConfig(data, version, tuple(modules))


def compare(installed: InstalledConfig, package: PackageInfo) -> list[str]:
    """Differences between what the drone has and what a package installs;
    empty when the package's .cfg.sig is the drone's, byte for byte."""
    with open_file(package, package.config_name) as handle:
        config = handle.read(CONFIG_LIMIT + 1)
    if hashlib.md5(config).digest() == installed.md5:
        return []
    differences = [f"configuration differs: package {package.config_name} "
                   f"md5 {hashlib.md5(config).hexdigest()}, drone {installed.md5.hex()}"]
    if package.version != installed.version:
        differences.append(f"version: package {package.version}, drone {installed.version}")
    ours = {item.name: item for item in package.files[1:]}
    theirs = {item.name: item for item in installed.modules}
    for name in sorted(theirs.keys() - ours.keys()):
        differences.append(f"only on the drone: {name}")
    for name in sorted(ours.keys() - theirs.keys()):
        differences.append(f"only in the package: {name}")
    for name in sorted(ours.keys() & theirs.keys()):
        if (ours[name].size, ours[name].md5) != (theirs[name].size, theirs[name].md5):
            differences.append(f"different: {name}")
    return differences
