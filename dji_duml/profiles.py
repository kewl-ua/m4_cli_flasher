"""Device profiles: every device-specific constant lives here, with its evidence."""
from __future__ import annotations

from dataclasses import dataclass

from .errors import DumlError
from .frame import address

PC = 10


@dataclass(frozen=True)
class DeviceProfile:
    key: str
    name: str
    product_code: str
    vid: int
    pid: int
    interface: int
    ep_out: int
    ep_in: int
    host: int
    target: int
    #: Flash procedures confirmed on this model. Empty means none is confirmed
    #: and ``flash`` refuses unless the caller explicitly accepts the risk.
    verified_procedures: tuple[str, ...] = ()
    ftp_host: str = "192.168.42.2"
    #: Module that receives the package and reports progress ("upgrade
    #: center"); None when the model has none known.
    upgrade_center: int | None = None
    #: Procedure `flash` and `plan` use unless told otherwise.
    default_procedure: str = "legacy-ftp"

    def matches_hardware(self, hardware: str) -> bool:
        return hardware.strip().lower().startswith(self.product_code.lower())


# Evidence (README, 2026-10-04, one M4T on firmware 17.02.0501):
#   * VID 2CA3 / PID 0020, interface 4 (MI04), bulk OUT 0x04 / IN 0x85:
#     configuration descriptor plus a captured Assistant exchange.
#   * host 0x2A (PC, index 1) -> target 0x1F, command set 0 id 1 answered with
#     "WA345T AC Ver.A" and bytes f5 01 02 11 (= 17.02.0501): captured, then
#     confirmed by our own request (dji-duml version, 2026-10-04): firmware at
#     reply bytes 22..25 matches Current in DJI Assistant.
#   * Upgrade center 0x48 (type 8 index 2, module 0802): captures of DJI
#     Assistant flashing this M4T (online refresh of 17.01.0516 and offline
#     upgrade to 17.02.0501, 2026-10-04). Assistant sends 00/83, 00/84, every
#     package file as 00/2A, 00/85, 00/4F and 00/41 there, and 0x48 sends the
#     00/42 statuses. No FTP is used.
#   * Our own upgrade-center runs, 2026-10-04, both from the offline ZIP:
#     same-version refresh of 17.02.0501 (one reboot, 205 s) and the version
#     change 17.01.0516 -> 17.02.0501 (two reboots, 357 s). Both ended with
#     Complete/Success from 0x48 and 00/4F = 17.02.0501; the capture of the
#     first matched Assistant's byte for byte from the device's side.
M4T = DeviceProfile(
    key="m4t", name="Matrice 4T", product_code="wa345t",
    vid=0x2CA3, pid=0x0020, interface=4, ep_out=0x04, ep_in=0x85,
    host=address(PC, 1), target=0x1F, upgrade_center=address(8, 2),
    default_procedure="upgrade-center", verified_procedures=("upgrade-center",),
)

PROFILES = {profile.key: profile for profile in (M4T,)}


def get_profile(key: str) -> DeviceProfile:
    try:
        return PROFILES[key.lower()]
    except KeyError:
        raise DumlError(f"Unknown profile {key!r}; known: {', '.join(sorted(PROFILES))}.") from None
