"""Build a firmware package from the files a capture showed being sent.

``dji-duml extract`` recovers what the host sent to the upgrade center: the
.cfg.sig and the modules its signed manifest lists. ``pack`` puts them into an
uncompressed tar that ``inspect``, ``plan`` and ``flash`` accept, like DJI's
dji_system.bin: configuration first, then the modules in manifest order (the
order Assistant sends them; DJI's own tar sorts them by name, which flash does
not depend on). It refuses unless every listed module is there with the size
and MD5 the manifest states, and reads the result back the way ``flash``
will. The DJI signature is not checked here: the device does that.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path

from .errors import DumlError, PackageError
from .extract import INCOMPLETE, REPORT
from .package import CONFIG_LIMIT, PackageInfo, inspect_package, manifest_files, verify_files


_COPY = re.compile(r".+\.cfg\.sig(\.\d+)?")


class PackError(DumlError):
    pass


@dataclass(frozen=True)
class Packed:
    package: PackageInfo
    ignored: tuple[str, ...]  # files in the directory that are not in the package
    notes: tuple[str, ...]


def _md5(path: Path) -> bytes:
    digest = hashlib.md5()
    with open(path, "rb") as handle:
        while block := handle.read(1 << 20):
            digest.update(block)
    return digest.digest()


def _vouched(source: Path, config: str, data: bytes) -> bool:
    """Whether report.json says ``config`` arrived intact with these bytes."""
    try:
        report = json.loads((source / REPORT).read_text(encoding="utf-8"))
        entries = [item for item in report["files"] if item["saved_as"] == config]
        sessions = len(report.get("sessions", []))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise PackError(f"Unreadable {REPORT} in {source}: {exc}") from exc
    if sessions > 1:
        raise PackError(f"{REPORT} lists {sessions} flashing sessions; extract one session "
                        "per directory.")
    return len(entries) == 1 and entries[0].get("ok") is True \
        and entries[0].get("md5") == hashlib.md5(data).hexdigest()


def pack(directory: str | Path, output: str | Path) -> Packed:
    """Write the package for the files in ``directory`` to ``output``, a path
    that must not exist yet."""
    source, out = Path(directory), Path(output)
    if not source.is_dir():
        raise PackError(f"{source} is not a directory.")
    if out.exists():
        raise PackError(f"{out} already exists.")
    names = sorted(entry.name for entry in source.iterdir() if entry.is_file())
    # extract numbers the .cfg.sig of a second session in one capture .2, .3...
    configs = [name for name in names if _COPY.fullmatch(name)]
    if len(configs) != 1:
        failed = [name for name in names if name.endswith(".cfg.sig" + INCOMPLETE)]
        raise PackError(f"Expected one .cfg.sig in {source}, found {len(configs)}"
                        + (f" and {len(failed)} that failed extraction" if failed else "")
                        + (": extract one flashing session per directory"
                           if len(configs) > 1 else "") + ".")
    config = configs[0]
    if not config.endswith(".cfg.sig"):
        raise PackError(f"{config} is a second session's configuration; extract one "
                        "flashing session per directory.")
    if (source / config).stat().st_size > CONFIG_LIMIT:
        raise PackError(f"{config} is too large for a configuration.")
    data = (source / config).read_bytes()
    version, modules = manifest_files(config, data)
    if version is None or not modules:
        raise PackError(f"{config} has no readable manifest listing module files.")
    notes = []
    if (source / REPORT).exists():
        if not _vouched(source, config, data):
            raise PackError(f"{REPORT} does not show {config} as extracted intact with these bytes.")
    else:
        notes.append(f"no {REPORT}: {config} is taken as it is; the device checks its signature")
    for module in modules:
        path = source / module.name
        if not path.is_file():
            failed = (source / (module.name + INCOMPLETE)).exists()
            raise PackError(f"{module.name} is missing"
                            + (", only a copy that failed extraction is there" if failed else "")
                            + ".")
        if path.stat().st_size != module.size or _md5(path) != module.md5:
            raise PackError(f"{module.name} differs from the size or MD5 in the manifest.")
    members = [config, *(module.name for module in modules)]
    used = {os.path.normcase(name) for name in [*members, REPORT]}  # Windows ignores case
    ignored = tuple(name for name in names if os.path.normcase(name) not in used)
    part = out.with_name(out.name + ".part")
    try:
        # Fixed metadata: the same files always give the same package.
        with tarfile.open(part, "w", format=tarfile.GNU_FORMAT) as archive:
            for name in members:
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = (source / name).stat().st_size, 0o644, 0
                with open(source / name, "rb") as handle:
                    archive.addfile(info, handle)
        with open(part, "rb+") as handle:
            os.fsync(handle.fileno())
        os.replace(part, out)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    try:
        package = _read_back(out, version, members, data)
    except BaseException:
        out.unlink(missing_ok=True)
        raise
    return Packed(package, ignored, tuple(notes))


def _read_back(out: Path, version, members: list[str], data: bytes) -> PackageInfo:
    """Open the package as flash will and check it holds exactly what was
    checked above, so nothing changed while it was written."""
    try:
        package = inspect_package(out)
        digests = verify_files(package)
    except PackageError as exc:
        raise PackError(f"The written package does not read back: {exc}") from exc
    if package.version != version or [item.name for item in package.files] != members \
            or digests[members[0]] != hashlib.md5(data).digest():
        raise PackError("The written package does not hold the files that were checked.")
    return package
