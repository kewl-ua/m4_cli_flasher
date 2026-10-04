import hashlib
import io
import struct
import tarfile
import zipfile
from pathlib import Path

from dji_duml.frame import Frame

CURRENT = "17.01.0516"
TARGET = "17.02.0501"
VERSION_BODY = (bytes(2) + b"WA345T AC Ver.A\0" + bytes.fromhex("01000001")
                + bytes.fromhex("f5010211") + bytes(8))


MODULE_DATA = bytes(range(256)) * 80  # 20480 bytes


def module_name(device="wa345t"):
    return f"{device}_0802_v10.00.21.17_20260529.ar0.pro.fw.sig"


def manifest(version=TARGET, device="wa345t", formal=None, modules=None):
    """A .cfg.sig laid out like DJI's: IM*H header, then the readable XML that
    lists each module file with its size and MD5."""
    if modules is None:
        modules = [(module_name(device), MODULE_DATA)]
    entries = "".join(
        f'                <module id="0802" version="10.00.21.17" group="ac" size="{len(data)}" '
        f'md5="{hashlib.md5(data).hexdigest()}">{name}</module>\n'
        for name, data in modules
    )
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n<dji>\n'
        f'    <device id="{device}">\n'
        f'        <firmware formal="{formal or version}">\n'
        f'            <release version="{version}" antirollback="0" enforce="0">\n'
        f'{entries}'
        '            </release>\n        </firmware>\n    </device>\n</dji>\n'
    )
    return b"IM*H" + bytes(604) + xml.encode() + bytes(256)


def make_tar(directory, name="dji_system.bin", config="wa345t.cfg.sig", extra=(),
             version=TARGET, content=None):
    """dji_system.bin as DJI ships it: the version is only in the manifest."""
    device = config.split("_")[0].split(".")[0]
    if content is None:
        content = manifest(version, device) if version else b""
    path = Path(directory) / name
    with tarfile.open(path, "w") as archive:
        for member in (config, module_name(device), *extra):
            data = content if member == config else (
                MODULE_DATA if member == module_name(device) else bytes(20000))
            info = tarfile.TarInfo(member)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def make_zip(directory, name="M4T_UAV_17.02.05.01_pro.zip",
             config="wa345t_0000_v17.02.0501_20260529.pro.cfg.sig", content=b"config"):
    path = Path(directory) / name
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(config, content)
        archive.writestr(module_name(), MODULE_DATA)
    return path


def usbpcap_record(endpoint, data, completion, *, transfer=3, device=47, seconds=10):
    header = struct.pack("<HQIHBHHBBI", 27, 1, 0, 9, int(completion), 1, device,
                         endpoint, transfer, len(data))
    packet = header + data
    return struct.pack("<IIII", seconds, 0, len(packet), len(packet)) + packet


def usbpcap_file(path, records):
    Path(path).write_bytes(
        struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 249) + b"".join(records))
    return Path(path)


def version_request(seq=0x2710):
    return Frame(0x2A, 0x1F, seq, 0, 1)
