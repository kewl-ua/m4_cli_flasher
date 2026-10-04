"""USB bulk transport through pyusb.

Works with the libusb-win32 driver that DJI Assistant installs (libusb0
backend) and with libusb-1.0 (Linux, macOS, WinUSB). A stock libusb0.dll goes
through pyusb; DJI's own copy, libusb0_device.dll, has a different structure
layout and goes through :mod:`dji_duml.libusb_win32` instead.

The transport never sends SET_CONFIGURATION, SET_INTERFACE or a reset: the
device also runs RNDIS and mass storage on the same configuration.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass

from . import libusb_win32
from .errors import TransportError
from .profiles import DeviceProfile

_READ_SIZE = 16 * 512


# DJI Assistant installs libusb-win32 1.2.6 as libusb0_device.dll. pyusb must
# never load it: pyusb's libusb0 backend crashed Python with an access
# violation on it (2026-10-04, M4T attached), because that DLL's usb_device
# is laid out differently. libusb_win32 binds it with the right layout.
def _backends(name: str):
    import usb.backend.libusb0
    import usb.backend.libusb1

    available = {"libusb0": usb.backend.libusb0, "libusb1": usb.backend.libusb1}
    if name == "auto":
        order = ["libusb0", "libusb1"] if sys.platform == "win32" else ["libusb1", "libusb0"]
    elif name in available:
        order = [name]
    else:
        raise TransportError(f"Unknown USB backend {name!r}; use auto, libusb0 or libusb1.")
    for key in order:
        backend = available[key].get_backend()
        if backend is None and key == "libusb0" and sys.platform == "win32":
            try:
                backend = libusb_win32.load()
            except OSError:
                backend = None
        if backend is not None:
            yield key, backend


def _is_timeout(error) -> bool:
    import usb.core

    if isinstance(error, usb.core.USBTimeoutError):
        return True
    if "reaping request failed" in str(error).lower():
        return False  # libusb-win32: a failed transfer, even when it reports -116
    # libusb-win32 reports -116, which is not Python's ETIMEDOUT on Windows.
    # A code decides on its own: libusb-win32's message is a static buffer that
    # can still hold an earlier "timeout error".
    code = getattr(error, "backend_error_code", None)
    if code is not None:
        return code in (-116, -110, -7)
    # Deliberately narrow: Windows reports a vanished device as "The semaphore
    # timeout period has expired", which must count as a lost link.
    text = str(error).lower()
    return "timeout error" in text or "timed out" in text


@dataclass(frozen=True)
class UsbCandidate:
    backend: str
    bus: int | None
    address: int | None
    serial: str | None
    has_interface: bool
    error: str | None = None

    @property
    def location(self) -> str:
        return f"{self.bus}:{self.address}"


def _interface(device, profile: DeviceProfile):
    """Return the DUML interface descriptor or None; USB errors propagate."""
    import usb.util

    configuration = device.get_active_configuration()
    interface = usb.util.find_descriptor(
        configuration, bInterfaceNumber=profile.interface, bAlternateSetting=0,
    )
    if interface is None:
        return None
    bulk = {
        endpoint.bEndpointAddress for endpoint in interface
        if usb.util.endpoint_type(endpoint.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK
    }
    return interface if {profile.ep_out, profile.ep_in} <= bulk else None


def _serial(device) -> str | None:
    import usb.util

    try:
        if isinstance(device, libusb_win32.Device):
            return device.serial()
        return usb.util.get_string(device, device.iSerialNumber) if device.iSerialNumber else None
    except Exception:
        return None


def _claim(device, number: int) -> None:
    import usb.util

    if isinstance(device, libusb_win32.Device):
        device.claim_interface(number)
    else:
        usb.util.claim_interface(device, number)


def _release(device, number: int) -> None:
    import usb.util

    if isinstance(device, libusb_win32.Device):
        device.release_interface(number)
    else:
        usb.util.release_interface(device, number)


def _dispose(device) -> None:
    import usb.util

    if isinstance(device, libusb_win32.Device):
        device.dispose()
    else:
        usb.util.dispose_resources(device)


_USB_ERRORS: tuple = ()


def _usb_errors() -> tuple:
    global _USB_ERRORS
    if not _USB_ERRORS:
        import usb.core
        _USB_ERRORS = (usb.core.USBError, NotImplementedError, ValueError)
    return _USB_ERRORS


def _enumerate(profile: DeviceProfile, backend: str):
    """Yield (backend name, [devices]) per loadable backend, in preference order."""
    import usb.core

    seen = False
    for name, handle in _backends(backend):
        seen = True
        try:
            if isinstance(handle, libusb_win32.Library):
                devices = handle.find(profile.vid, profile.pid)
            else:
                devices = list(usb.core.find(
                    find_all=True, idVendor=profile.vid, idProduct=profile.pid, backend=handle,
                ))
        except _usb_errors() as exc:
            raise TransportError(f"USB enumeration failed ({name}): {exc}") from exc
        yield name, devices
    if not seen:
        raise TransportError(
            "No libusb backend could be loaded. Install libusb-1.0, or on Windows keep "
            "the libusb-win32 driver that DJI Assistant installs."
        )


def scan(profile: DeviceProfile, backend: str = "auto") -> list[UsbCandidate]:
    """List matching devices. Sends only standard descriptor requests."""
    found = []
    for name, devices in _enumerate(profile, backend):
        for device in devices:
            try:
                usable, error = _interface(device, profile) is not None, None
            except _usb_errors() as exc:
                usable, error = False, str(exc)
            found.append(UsbCandidate(name, getattr(device, "bus", None),
                                      getattr(device, "address", None),
                                      _serial(device), usable, error))
            try:
                _dispose(device)
            except _usb_errors():
                pass
    return found


class UsbBulkTransport:
    def __init__(self, device, profile: DeviceProfile, backend: str, pending: bytes = b""):
        self._device = device
        self._profile = profile
        self._pending = pending
        self.backend = backend
        self.location = f"{getattr(device, 'bus', None)}:{getattr(device, 'address', None)}"

    @classmethod
    def open(cls, profile: DeviceProfile, *, backend: str = "auto",
             location: str | None = None, serial: str | None = None) -> "UsbBulkTransport":
        """Claim the DUML interface of exactly one device.

        libusb-win32 exposes every vendor interface of the composite device as
        its own node with the same IDs and the same configuration descriptor,
        so descriptors alone cannot tell which node owns the DUML endpoints.
        Each node is therefore claimed and probed with one short bulk IN read
        (which sends nothing); nodes where that pipe does not exist are skipped.
        With several drones attached, ``location`` ("bus:address" as printed by
        scan) or ``serial`` must select one; an ambiguous match is refused.
        """
        import usb.core
        import usb.util

        working: list[UsbBulkTransport] = []
        problems: list[str] = []
        tried: list[str] = []
        for name, devices in _enumerate(profile, backend):
            tried.append(name)
            for device in devices:
                where = f"{getattr(device, 'bus', None)}:{getattr(device, 'address', None)}"
                if (location and where != location) or (serial and _serial(device) != serial):
                    _dispose(device)
                    continue
                try:
                    if _interface(device, profile) is None:
                        _dispose(device)
                        continue
                    if (sys.platform.startswith("linux")
                            and device.is_kernel_driver_active(profile.interface)):
                        device.detach_kernel_driver(profile.interface)
                    _claim(device, profile.interface)
                    try:
                        pending = bytes(device.read(profile.ep_in, _READ_SIZE, 20))
                    except usb.core.USBError as exc:
                        if not _is_timeout(exc):
                            raise
                        pending = b""
                except _usb_errors() as exc:
                    problems.append(f"{name} {where}: {exc}")
                    _dispose(device)
                    continue
                working.append(cls(device, profile, name, pending))
            if working:
                break  # the same device seen through a second backend is not a second drone
        if len(working) > 1:
            for transport in working:
                transport.close()
            raise TransportError(
                f"{len(working)} usable devices; select one with --usb-location or --serial."
            )
        if not working:
            detail = f" Tried: {'; '.join(problems)}." if problems else ""
            if sys.platform == "win32" and "libusb0" not in tried:
                raise TransportError(
                    f"No usable {profile.name} DUML interface.{detail} No libusb-win32 DLL "
                    "(libusb0.dll or DJI's libusb0_device.dll) was loaded, and libusb-1.0 "
                    "cannot open a device bound to the libusb-win32 driver."
                )
            raise TransportError(
                f"No usable {profile.name} DUML interface {profile.interface} "
                f"(VID {profile.vid:04X} PID {profile.pid:04X}).{detail} Check cable and "
                "power, and close DJI Assistant with its services: only one program can "
                "own the interface."
            )
        return working[0]

    def write(self, data: bytes) -> None:
        try:
            sent = self._device.write(self._profile.ep_out, data, 2000)
        except _usb_errors() as exc:
            raise TransportError(f"USB write failed: {exc}") from exc
        if sent != len(data):
            raise TransportError(f"USB short write: {sent} of {len(data)} bytes.")

    def read(self, timeout: float) -> bytes:
        if self._pending:
            pending, self._pending = self._pending, b""
            return pending
        try:
            # A timeout of 0 means "wait forever" in libusb, so clamp to 1 ms.
            return bytes(self._device.read(
                self._profile.ep_in, _READ_SIZE, max(1, int(timeout * 1000)),
            ))
        except _usb_errors() as exc:
            if _is_timeout(exc):
                return b""
            raise TransportError(f"USB read failed: {exc}") from exc

    def close(self) -> None:
        try:
            _release(self._device, self._profile.interface)
        except Exception:
            pass
        _dispose(self._device)
