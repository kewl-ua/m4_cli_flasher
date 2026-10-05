"""Firmware package inspection: structure, names and the version stated in the
configuration manifest. The DJI signature is verified by the device, not here."""
from __future__ import annotations

import hashlib
import re
import tarfile
import zipfile
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from xml.etree import ElementTree

from .errors import PackageError
from .version import FirmwareVersion

_CONFIG = re.compile(
    r"(?P<code>[a-z]+\d+[a-z]?)(?:_\d{4}_v(?P<version>\d+\.\d+\.\d+)_\d{8})?(?:\.pro)?\.cfg\.sig"
)
_MD5 = re.compile(r"[0-9a-fA-F]{32}")
_SIZE = re.compile(r"[0-9]{1,12}")  # str.isdigit() also takes "²", which int() rejects
#: Real M4T configurations are about 25 KiB.
CONFIG_LIMIT = 1 << 20
#: Every signed DJI image starts with this: configurations and modules alike.
IMAGE_MAGIC = b"IM*H"
#: <release> attributes worth showing; none of them is enforced here.
RELEASE_FIELDS = ("from", "expire", "antirollback", "enforce")


@dataclass(frozen=True)
class PackageFile:
    """One file the device receives: the configuration, then each module."""
    name: str
    size: int
    md5: bytes | None  # from the manifest; None for the configuration itself


@dataclass(frozen=True)
class PackageInfo:
    path: Path
    kind: str  # "tar" (dji_system.bin) or "zip" (offline download)
    product_code: str
    version: FirmwareVersion | None
    config_name: str
    members: int
    size: int
    mtime_ns: int
    md5: bytes
    sha256: str
    #: Configuration first, then the manifest's modules in manifest order: the
    #: order DJI Assistant sends them in. Empty without a readable manifest.
    files: tuple[PackageFile, ...] = ()

    @property
    def files_size(self) -> int:
        return sum(item.size for item in self.files)

    def unchanged(self) -> bool:
        try:
            stat = self.path.stat()
        except OSError:
            return False
        return (stat.st_size, stat.st_mtime_ns) == (self.size, self.mtime_ns)


def _safe(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts \
        and "\\" not in name and ":" not in name


def _is_config(name: str, size: int) -> bool:
    if not name.endswith(".cfg.sig"):
        return False
    if size > CONFIG_LIMIT:
        raise PackageError(f"Configuration {name!r} is {size} bytes, too large for a manifest.")
    return True


def _names(path: Path) -> tuple[str, list[str], dict[str, int], dict[str, bytes]]:
    """Package kind, member names, member sizes and the .cfg.sig contents."""
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as archive:
                entries = archive.infolist()
                if any(entry.flag_bits & 1 for entry in entries):
                    raise PackageError("Encrypted ZIP is not a DJI firmware package.")
                bad = archive.testzip()
                if bad is not None:
                    raise PackageError(f"ZIP CRC failed for {bad}.")
                files = [entry for entry in entries if not entry.is_dir()]
                configs = {entry.filename: archive.read(entry) for entry in files
                           if _is_config(entry.filename, entry.file_size)}
                return ("zip", [entry.filename for entry in files],
                        {entry.filename: entry.file_size for entry in files}, configs)
        except (zipfile.BadZipFile, NotImplementedError, EOFError) as exc:
            raise PackageError(f"Damaged or unsupported ZIP: {exc}") from exc
    try:
        with tarfile.open(path, "r:") as archive:
            members = archive.getmembers()
            if any(not member.isfile() for member in members):
                raise PackageError("Package contains links, devices or directories.")
            configs = {member.name: archive.extractfile(member).read() for member in members
                       if _is_config(member.name, member.size)}
    except (tarfile.TarError, EOFError) as exc:
        raise PackageError(f"Not a ZIP or an uncompressed tar package: {exc}") from exc
    return ("tar", [member.name for member in members],
            {member.name: member.size for member in members}, configs)


def _manifest(data: bytes, code: str, name: str
              ) -> tuple[FirmwareVersion | None, list[PackageFile]]:
    """Release version and module files from the XML manifest of a signed
    configuration.

    DJI keeps the manifest readable after the IM*H header, for example
    ``<device id="wa345t"><firmware formal="17.00.0001"><release version="17.00.0001"``
    with one ``<module size=".." md5="..">file name</module>`` per module.
    This is the only version a dji_system.bin states: its configuration name
    has none. Returns (None, []) when there is no readable manifest.
    """
    start = data.find(b"<?xml")
    end = data.find(b"</dji>", start)
    if start < 0 or end < 0:
        return None, []
    try:
        # DJI manifests are UTF-8; a declared exotic encoding must not escape as
        # a LookupError instead of a package error.
        root = ElementTree.fromstring(data[start:end + len(b"</dji>")],
                                      parser=ElementTree.XMLParser(encoding="utf-8"))
    except (ElementTree.ParseError, ValueError, LookupError) as exc:
        raise PackageError(f"Unreadable manifest in {name!r}: {exc}") from exc
    devices = [device for device in root.findall("device")
               if device.get("id", "").lower() == code.lower()]
    if len(devices) != 1:
        raise PackageError(f"Manifest in {name!r} does not describe one {code!r} device.")
    firmware = devices[0].findall("firmware")
    releases = [release for item in firmware for release in item.findall("release")]
    if len(firmware) != 1 or len(releases) != 1:
        raise PackageError(f"Manifest in {name!r} does not have exactly one release.")
    spellings = {firmware[0].get("formal"), releases[0].get("version")} - {None}
    try:
        versions = {FirmwareVersion.parse(text) for text in spellings}
    except ValueError as exc:
        raise PackageError(f"Invalid version in the manifest of {name!r}.") from exc
    if len(versions) != 1:
        raise PackageError(
            f"Manifest in {name!r} states {len(versions)} versions: {sorted(spellings)}."
        )
    modules = []
    for module in releases[0].findall("module"):
        file_name = (module.text or "").strip()
        size, md5 = module.get("size", ""), module.get("md5", "")
        if not _safe(file_name) or not _SIZE.fullmatch(size) or not _MD5.fullmatch(md5):
            raise PackageError(f"Malformed module entry {file_name!r} in the manifest of {name!r}.")
        modules.append(PackageFile(file_name, int(size), bytes.fromhex(md5)))
    return versions.pop(), modules


def manifest_files(config_name: str, data: bytes
                   ) -> tuple[FirmwareVersion | None, list[PackageFile]]:
    """Version and module files stated by the manifest of a .cfg.sig."""
    match = _CONFIG.fullmatch(PurePosixPath(config_name).name)
    if not match:
        raise PackageError(f"Unrecognised configuration name: {config_name!r}.")
    version, modules = _manifest(data, match.group("code"), config_name)
    names = [module.name for module in modules]
    if len(set(names)) != len(names):
        raise PackageError(f"The manifest in {config_name!r} lists a module file twice.")
    return version, modules


@dataclass(frozen=True)
class ConfigInfo:
    """What a .cfg.sig states, read from its bytes alone (its name is not used)."""
    product: str  # <device id>, e.g. wa345t
    version: FirmwareVersion
    modules: tuple[PackageFile, ...]
    release: tuple[tuple[str, str], ...]  # RELEASE_FIELDS present, e.g. ("from", "2025/06/14")


def read_config(data: bytes) -> ConfigInfo:
    """Product, version and module files of a signed configuration, or a
    PackageError when the bytes are not one."""
    if not data.startswith(IMAGE_MAGIC):
        raise PackageError("Not a signed DJI image: no IM*H header.")
    if len(data) > CONFIG_LIMIT:
        raise PackageError(f"{len(data)} bytes is too large for a configuration.")
    start = data.find(b"<?xml")
    end = data.find(b"</dji>", start)
    if start < 0 or end < 0:
        raise PackageError("No readable manifest in the configuration.")
    try:
        root = ElementTree.fromstring(data[start:end + len(b"</dji>")],
                                      parser=ElementTree.XMLParser(encoding="utf-8"))
    except (ElementTree.ParseError, ValueError, LookupError) as exc:
        raise PackageError(f"Unreadable manifest: {exc}") from exc
    products = {device.get("id", "").lower() for device in root.findall("device")}
    if len(products) != 1:
        raise PackageError(f"The manifest describes {len(products)} devices, not one.")
    product = products.pop()
    version, modules = manifest_files(f"{product}.cfg.sig", data)
    if version is None or not modules:
        raise PackageError("The manifest lists no version or no module files.")
    release = root.find("device/firmware/release")
    return ConfigInfo(product, version, tuple(modules), tuple(
        (key, release.get(key)) for key in RELEASE_FIELDS if release.get(key) is not None))


def _files(config: str, sizes: dict[str, int], modules: list[PackageFile]
           ) -> tuple[PackageFile, ...]:
    """What the device receives, checked against the archive."""
    names = [module.name for module in modules]
    if len(set(names)) != len(names) or config in names:
        raise PackageError("The manifest lists a module file twice.")
    for module in modules:
        if module.name not in sizes:
            raise PackageError(f"The manifest lists {module.name!r}, which is not in the package.")
        if sizes[module.name] != module.size:
            raise PackageError(
                f"{module.name!r} is {sizes[module.name]} bytes, the manifest says {module.size}."
            )
    return (PackageFile(config, sizes[config], None), *modules)


def inspect_package(path: str | Path) -> PackageInfo:
    package = Path(path).expanduser().resolve(strict=True)
    if not package.is_file():
        raise PackageError("Firmware package must be a regular file.")
    before = package.stat()
    kind, names, sizes, contents = _names(package)
    if not names:
        raise PackageError("Package is empty.")
    if len(set(names)) != len(names) or not all(_safe(name) for name in names):
        raise PackageError("Package has duplicate or unsafe member names.")
    configs = [name for name in names if name.endswith(".cfg.sig")]
    if len(configs) != 1:
        raise PackageError(f"Expected exactly one .cfg.sig, found {len(configs)}.")
    match = _CONFIG.fullmatch(PurePosixPath(configs[0]).name)
    if not match:
        raise PackageError(f"Unrecognised configuration name: {configs[0]!r}.")
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    with open(package, "rb") as handle:
        while block := handle.read(1 << 20):
            md5.update(block)
            sha256.update(block)
    after = package.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise PackageError("Package changed while it was being inspected.")
    named = match.group("version")
    try:
        named = FirmwareVersion.parse(named) if named else None
    except ValueError as exc:
        raise PackageError(f"Invalid version in configuration name {configs[0]!r}.") from exc
    stated, modules = _manifest(contents[configs[0]], match.group("code"), configs[0])
    if named is not None and stated is not None and named != stated:
        raise PackageError(
            f"Configuration name {configs[0]!r} says {named}, its manifest says {stated}."
        )
    return PackageInfo(
        path=package, kind=kind, product_code=match.group("code"),
        version=stated if stated is not None else named,
        config_name=configs[0], members=len(names), size=after.st_size,
        mtime_ns=after.st_mtime_ns, md5=md5.digest(), sha256=sha256.hexdigest(),
        files=_files(configs[0], sizes, modules) if stated is not None else (),
    )


_READ_ERRORS = (KeyError, zipfile.BadZipFile, tarfile.TarError, EOFError)


@contextmanager
def open_file(package: PackageInfo, name: str) -> Iterator[BinaryIO]:
    """Read one file of the package."""
    with ExitStack() as stack:
        try:
            if package.kind == "zip":
                archive = stack.enter_context(zipfile.ZipFile(package.path))
                handle = stack.enter_context(archive.open(name))
            else:
                archive = stack.enter_context(tarfile.open(package.path, "r:"))
                handle = archive.extractfile(name)
                if handle is None:
                    raise PackageError(f"{name!r} is not a regular file.")
                stack.enter_context(handle)
        except _READ_ERRORS as exc:
            raise PackageError(f"Cannot read {name!r} from the package: {exc}") from exc
        yield handle


def verify_files(package: PackageInfo, on_bytes: Callable[[int], None] | None = None
                 ) -> dict[str, bytes]:
    """Check every module file against the size and MD5 in the manifest.
    Returns the MD5 of every file, the configuration included."""
    if not package.files:
        raise PackageError("The package has no readable manifest listing its files.")
    digests = {}
    for item in package.files:
        digest, size = hashlib.md5(), 0
        with open_file(package, item.name) as handle:
            try:
                while block := handle.read(1 << 20):
                    digest.update(block)
                    size += len(block)
                    if on_bytes is not None:
                        on_bytes(len(block))
            except _READ_ERRORS as exc:
                raise PackageError(f"Cannot read {item.name!r} from the package: {exc}") from exc
        if size != item.size:
            raise PackageError(f"{item.name!r} reads as {size} bytes, expected {item.size}.")
        if item.md5 is not None and digest.digest() != item.md5:
            raise PackageError(f"{item.name!r} does not match the MD5 in the manifest.")
        digests[item.name] = digest.digest()
    if not package.unchanged():
        raise PackageError("Package changed while its files were being verified.")
    return digests
