"""libusb-win32 through the DLL that DJI Assistant installs, without pyusb.

DJI's ``libusb0_device.dll`` is libusb-win32 1.2.6.0 (OriginalFilename
libusb0.dll), but its ``struct usb_device`` has a 1024-byte filename: it is
allocated as 0x444 bytes, with bus at 0x410, descriptor at 0x418, config at
0x42a and devnum at 0x43a (usb_find_devices and usb_open in that DLL, read
from its code on 2026-10-04). The public header and pyusb use 512 bytes, so
pyusb reads pointers out of the filename and crashes Python. ``struct
usb_bus`` is the standard 0x224 bytes.

Only what the transport needs is bound. Every device descriptor must read as
a device descriptor before any other field is used, and the configuration is
fetched with a standard GET_DESCRIPTOR instead of walking the descriptor tree
the DLL builds.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import sys
from ctypes import (
    POINTER, Structure, c_char, c_char_p, c_int, c_size_t, c_uint8, c_uint16, c_uint32, c_void_p,
)
from dataclasses import dataclass, field

DLL_NAME = "libusb0_device"
_TIMEOUT = -116  # -ETIMEDOUT as libusb-win32 reports it
LINK_LOST = -5   # -EIO: what a failed transfer is reported as instead
_DT_CONFIG, _DT_INTERFACE, _DT_ENDPOINT = 2, 4, 5


class _DeviceDescriptor(Structure):
    _pack_ = 1
    _layout_ = "ms"
    _fields_ = [
        ("bLength", c_uint8), ("bDescriptorType", c_uint8), ("bcdUSB", c_uint16),
        ("bDeviceClass", c_uint8), ("bDeviceSubClass", c_uint8), ("bDeviceProtocol", c_uint8),
        ("bMaxPacketSize0", c_uint8), ("idVendor", c_uint16), ("idProduct", c_uint16),
        ("bcdDevice", c_uint16), ("iManufacturer", c_uint8), ("iProduct", c_uint8),
        ("iSerialNumber", c_uint8), ("bNumConfigurations", c_uint8),
    ]


class _Device(Structure):
    _pack_ = 1
    _layout_ = "ms"


class _Bus(Structure):
    _pack_ = 1
    _layout_ = "ms"


_Device._fields_ = [
    ("next", POINTER(_Device)), ("prev", POINTER(_Device)), ("filename", c_char * 1024),
    ("bus", POINTER(_Bus)), ("descriptor", _DeviceDescriptor), ("config", c_void_p),
    ("dev", c_void_p), ("devnum", c_uint8), ("num_children", c_uint8), ("children", c_void_p),
]
_Bus._fields_ = [
    ("next", POINTER(_Bus)), ("prev", POINTER(_Bus)), ("dirname", c_char * 512),
    ("devices", POINTER(_Device)), ("location", c_uint32), ("root_dev", POINTER(_Device)),
]


def _prototypes(lib) -> None:
    for name, args, result in (
        ("usb_init", [], None),
        ("usb_find_busses", [], c_int),
        ("usb_find_devices", [], c_int),
        ("usb_get_busses", [], POINTER(_Bus)),
        ("usb_open", [POINTER(_Device)], c_void_p),
        ("usb_close", [c_void_p], c_int),
        ("usb_claim_interface", [c_void_p, c_int], c_int),
        ("usb_release_interface", [c_void_p, c_int], c_int),
        ("usb_bulk_write", [c_void_p, c_int, c_char_p, c_int, c_int], c_int),
        ("usb_bulk_read", [c_void_p, c_int, c_void_p, c_int, c_int], c_int),
        ("usb_get_descriptor", [c_void_p, c_uint8, c_uint8, c_void_p, c_int], c_int),
        ("usb_get_string_simple", [c_void_p, c_int, c_void_p, c_size_t], c_int),
        ("usb_strerror", [], c_char_p),
    ):
        function = getattr(lib, name)
        function.argtypes, function.restype = args, result


_loaded = None


def load(path: str | None = None) -> "Library | None":
    """DJI's libusb-win32 DLL, loaded once; None when it is not installed."""
    global _loaded
    if _loaded is None:
        if sys.platform != "win32":
            return None
        found = path or ctypes.util.find_library(DLL_NAME)
        if not found:
            return None
        lib = ctypes.CDLL(found)
        _prototypes(lib)
        lib.usb_init()
        _loaded = Library(lib)
    return _loaded


def _usb_error(text: str, code: int | None = None):
    import usb.core

    if code == _TIMEOUT:
        # The DLL returns -116 both for a real timeout ("timeout error") and for
        # a transfer that failed with ERROR_SEM_TIMEOUT or ERROR_OPERATION_ABORTED
        # ("reaping request failed"), which is how a vanished device shows up.
        if "reaping request failed" in text.lower():
            return usb.core.USBError(text, LINK_LOST)
        return usb.core.USBTimeoutError(text, code)
    return usb.core.USBError(text, code)


class Library:
    def __init__(self, lib):
        self.lib = lib

    def error(self) -> str:
        text = self.lib.usb_strerror()
        return text.decode(errors="replace") if text else "unknown error"

    def find(self, vid: int, pid: int) -> list["Device"]:
        """Devices with these IDs. Raises if any descriptor does not read as
        one: the structure layout would not match the loaded DLL."""
        if self.lib.usb_find_busses() < 0 or self.lib.usb_find_devices() < 0:
            raise _usb_error(f"enumeration failed: {self.error()}")
        found = []
        bus = self.lib.usb_get_busses()
        while bus:
            device = bus.contents.devices
            while device:
                record = device.contents
                descriptor = record.descriptor
                if (descriptor.bLength, descriptor.bDescriptorType) != (18, 1):
                    raise _usb_error(
                        f"{DLL_NAME} device list does not match the expected layout "
                        f"(descriptor header {descriptor.bLength}/{descriptor.bDescriptorType}); "
                        "refusing to use it."
                    )
                if (descriptor.idVendor, descriptor.idProduct) == (vid, pid):
                    found.append(Device(self, device, bus.contents.location, record.devnum,
                                        descriptor.iSerialNumber))
                device = record.next
            bus = bus.contents.next
        return found


@dataclass
class Endpoint:
    bEndpointAddress: int
    bmAttributes: int
    wMaxPacketSize: int


@dataclass
class Interface:
    bInterfaceNumber: int
    bAlternateSetting: int
    bInterfaceClass: int
    bInterfaceSubClass: int
    bInterfaceProtocol: int
    endpoints: list[Endpoint] = field(default_factory=list)

    def __iter__(self):
        return iter(self.endpoints)


@dataclass
class Configuration:
    bConfigurationValue: int
    interfaces: list[Interface] = field(default_factory=list)

    def __iter__(self):
        return iter(self.interfaces)


def parse_configuration(raw: bytes) -> Configuration:
    """Standard configuration descriptor with its interfaces and endpoints."""
    if len(raw) < 9 or raw[1] != _DT_CONFIG:
        raise ValueError(f"Not a configuration descriptor: {raw[:9].hex()}")
    total = int.from_bytes(raw[2:4], "little")
    if total > len(raw):
        raise ValueError(f"Configuration descriptor truncated: {len(raw)} of {total} bytes.")
    configuration = Configuration(raw[5])
    offset = 0
    while offset < total:
        length = raw[offset]
        if length < 2 or offset + length > total:
            raise ValueError(f"Malformed descriptor at byte {offset} of the configuration.")
        body = raw[offset:offset + length]
        kind = body[1]
        if kind == _DT_INTERFACE and length >= 9:
            configuration.interfaces.append(Interface(*body[2:4], *body[5:8]))
        elif kind == _DT_ENDPOINT and length >= 7:
            if not configuration.interfaces:
                raise ValueError("Endpoint descriptor before any interface descriptor.")
            configuration.interfaces[-1].endpoints.append(
                Endpoint(body[2], body[3], int.from_bytes(body[4:6], "little")))
        offset += length
    return configuration


class Device:
    """The part of a pyusb Device that the transport uses."""

    def __init__(self, library: Library, record, bus: int, address: int, serial_index: int):
        self._library = library
        self._record = record
        self._handle = None
        self._disposed = False
        self.bus = bus
        self.address = address
        self.iSerialNumber = serial_index

    def _open(self):
        if self._disposed:
            # Its usb_device record may have been freed by a later enumeration.
            raise _usb_error("device was disposed; enumerate again")
        if self._handle is None:
            handle = self._library.lib.usb_open(self._record)
            if not handle:
                raise _usb_error(f"usb_open failed: {self._library.error()}")
            self._handle = handle
        return self._handle

    def _check(self, result: int, action: str) -> int:
        if result < 0:
            raise _usb_error(f"{action} failed: {self._library.error()}", result)
        return result

    def get_active_configuration(self) -> Configuration:
        handle = self._open()
        header = ctypes.create_string_buffer(9)
        self._check(self._library.lib.usb_get_descriptor(handle, _DT_CONFIG, 0, header, 9),
                    "GET_DESCRIPTOR")
        total = int.from_bytes(header.raw[2:4], "little")
        buffer = ctypes.create_string_buffer(max(total, 9))
        size = self._check(self._library.lib.usb_get_descriptor(
            handle, _DT_CONFIG, 0, buffer, len(buffer)), "GET_DESCRIPTOR")
        return parse_configuration(buffer.raw[:size])

    def serial(self) -> str | None:
        if not self.iSerialNumber:
            return None
        buffer = ctypes.create_string_buffer(256)
        size = self._check(self._library.lib.usb_get_string_simple(
            self._open(), self.iSerialNumber, buffer, len(buffer)), "GET_DESCRIPTOR string")
        return buffer.raw[:size].decode(errors="replace")

    def claim_interface(self, number: int) -> None:
        self._check(self._library.lib.usb_claim_interface(self._open(), number),
                    f"claim interface {number}")

    def release_interface(self, number: int) -> None:
        if self._handle is not None:
            self._check(self._library.lib.usb_release_interface(self._handle, number),
                        f"release interface {number}")

    def read(self, endpoint: int, size: int, timeout: int) -> bytes:
        buffer = ctypes.create_string_buffer(size)
        count = self._check(self._library.lib.usb_bulk_read(
            self._open(), endpoint, buffer, size, timeout), f"bulk read {endpoint:#04x}")
        return buffer.raw[:count]

    def write(self, endpoint: int, data: bytes, timeout: int) -> int:
        return self._check(self._library.lib.usb_bulk_write(
            self._open(), endpoint, bytes(data), len(data), timeout), f"bulk write {endpoint:#04x}")

    def dispose(self) -> None:
        self._disposed = True
        if self._handle is not None:
            handle, self._handle = self._handle, None
            self._library.lib.usb_close(handle)
