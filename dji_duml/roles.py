"""What each firmware module is for, inferred from its file name.

A module file name encodes a DUML target as two decimal fields, ``TTII``: the
device type ``TT`` -- the same 0..31 type a DUML address carries, so
``frame.address()`` packs ``0802`` as ``0x48`` = type 8, index 2 -- and a
sub-module index ``II``. The type gives the component. For the M4T a few types
are reassigned from the classic DUML table (type 24 is "RC battery" there but
the aircraft uses it for perception units), and several names carry a
supplier/role suffix, so a per-id table refines the type-only guess.

Everything here is reverse-engineered, not read from the drone: roles are
flagged ``approximate`` wherever they rest on a filename suffix or a reassigned
type rather than the DUML type table. Sources: the dji-firmware-tools DUML
device-type enum (dji-dumlv1-proto.lua), this project's own
``frame.address()`` / profiles, and firmware filename suffixes (BA = battery,
mc = motor controller, IA640 = 640x512 thermal, ld = laser distance,
RD = radar/ranging, ar0 = Ambarella SoC).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

_ID = re.compile(r"_(\d{4})_v")

#: Canonical DUML device types (the 0..31 enum a DUML address uses).
DEVICE_TYPES = {
    0: "configuration", 1: "camera", 3: "flight controller", 4: "gimbal",
    5: "center board", 6: "remote controller", 7: "Wi-Fi (air side)",
    8: "camera / video SoC", 9: "HD video link (air side)", 10: "PC / host",
    11: "battery", 12: "ESC / motor controller", 17: "monocular vision",
    18: "binocular vision", 23: "onboard computer", 24: "RC battery",
    25: "IMU", 26: "GPS / RTK", 29: "power management (PMU)",
}
#: Types in DEVICE_TYPES that the newer M4T / WA platform reassigns, so a role
#: taken from the type alone is unreliable and is flagged approximate. (Type 15
#: is reassigned too, but is absent from DEVICE_TYPES, so it already falls to
#: the "unknown" branch; its only M4T use, 1502, is in M4T_MODULES.)
REASSIGNED = frozenset({10, 24})

#: M4T-specific roles keyed by the 4-digit ``TTII`` id, from firmware suffixes
#: and known M4T hardware: (role, description, approximate).
M4T_MODULES = {
    "0103": ("thermal camera", "640x512 infrared imager (IA640 / HK sensor builds)", False),
    "0105": ("camera", "visible-light camera / ISP unit", True),
    "0106": ("camera", "visible-light camera / ISP unit", True),
    "0501": ("center board", "power and connector hub to the flight controller", True),
    "0802": ("camera / video SoC", "primary Ambarella imaging SoC; also the upgrade center (0x48)",
             False),
    "1005": ("peripheral", "type-10 module, role unconfirmed (GB95)", True),
    "1006": ("peripheral", "type-10 module, role unconfirmed (PA02, possibly an RF power amp)",
             True),
    "1100": ("battery", "intelligent flight battery (BA03; PTL / GY0 cell variants)", False),
    "1200": ("ESC / motor controller", "motor controller (mc firmware)", False),
    "1202": ("ESC / motor controller", "second motor-controller group (mc firmware)", False),
    "1502": ("camera / vision SoC", "second Ambarella SoC, companion to 0802", True),
    "2400": ("vision / perception", "obstacle-sensing unit (RD03); one of four", True),
    "2401": ("vision / perception", "obstacle-sensing unit (RD03); one of four", True),
    "2402": ("vision / perception", "obstacle-sensing unit (RD03); one of four", True),
    "2403": ("vision / perception", "obstacle-sensing unit (RD03); one of four", True),
    "2405": ("laser rangefinder", "1800 m laser rangefinder (ld04)", True),
    "2506": ("IMU", "inertial measurement unit", True),
}


@dataclass(frozen=True)
class ModuleRole:
    module_type: int | None   # TT, decimal; None when the name does not parse
    index: int | None         # II
    role: str
    description: str
    approximate: bool         # the role is inferred, not from the DUML type table


def describe_module(name: str) -> ModuleRole:
    """The component a module file serves, from its name alone."""
    match = _ID.search(PurePosixPath(name).name)
    if not match:
        return ModuleRole(None, None, "unknown", "unrecognised module name", True)
    code = match.group(1)
    module_type, index = int(code[:2]), int(code[2:])
    if code in M4T_MODULES:
        role, description, approximate = M4T_MODULES[code]
        return ModuleRole(module_type, index, role, description, approximate)
    base = DEVICE_TYPES.get(module_type)
    if base is None:
        return ModuleRole(module_type, index, "unknown",
                          f"DUML device type {module_type}, no known role", True)
    return ModuleRole(module_type, index, base, f"DUML device type {module_type}",
                      module_type in REASSIGNED)
