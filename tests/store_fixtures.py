"""Firmware for store tests: modules are IM*H images, as DJI's are."""
import itertools
import json
import os
import random
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from dji_duml.package import IMAGE_MAGIC
from dji_duml.store import Store
from duml_fixtures import CURRENT, TARGET, manifest

OLD = "14.01.0012"


def image(seed, size=5000):
    return IMAGE_MAGIC + random.Random(seed).randbytes(size - len(IMAGE_MAGIC))


def module(number, seed=None, size=5000, device="wa345t"):
    name = f"{device}_{number:04d}_v01.00.00.{number % 100:02d}_20260101.pro.fw.sig"
    return name, image(number if seed is None else seed, size)


A, B, C = module(100), module(200), module(300)


def config(version=CURRENT, modules=(A, B), device="wa345t", start=None):
    data = manifest(version, device=device, modules=list(modules))
    if start:
        data = data.replace(b'enforce="0">', f'enforce="0" from="{start}" expire="2027/01/01">'
                            .encode())
    return data


def release_list(*versions, extra=None):
    """A DJI release list as Assistant caches it, roles and all."""
    return json.dumps([{"flow": "formal", "product_version": version, "released_time": date,
                        "release_note": {"en": f"Note for {version}."}, "roles": ["pilot"],
                        "sub_product_types": [7]} for version, date in versions]
                      + (extra or [])).encode()


def age(path, seconds=3600):
    """Make a file look older, as Assistant's finished downloads are."""
    stamp = time.time() - seconds
    os.utime(path, (stamp, stamp))
    return path


class StoreCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name)
        self.root = self.tmp / "store"
        self.src = self.tmp / "src"
        self.src.mkdir()
        self.counter = itertools.count(1)
        env = patch.dict(os.environ, {"DJI_DUML_ASSISTANT_CACHE": str(self.tmp / "no-cache"),
                                      "DJI_DUML_STORE": str(self.root)})
        env.start()
        self.addCleanup(env.stop)

    def store(self):
        return Store.open(self.root, create=True)

    def write(self, name, data, folder=None):
        folder = Path(folder or self.src)
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / name
        path.write_bytes(data)
        return path

    def folder(self, version=CURRENT, modules=(A, B), name=None, start=None):
        """A .cfg.sig with its modules, as an unpacked offline download."""
        folder = self.src / (name or f"folder{next(self.counter)}")
        self.write("wa345t.cfg.sig", config(version, modules, start=start), folder)
        for item, data in modules:
            self.write(item, data, folder)
        return folder


__all__ = ["A", "B", "C", "CURRENT", "OLD", "TARGET", "StoreCase", "age", "config", "image",
           "module", "release_list"]
