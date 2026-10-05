import ctypes
import unittest
from unittest.mock import patch

from dji_duml import libusb_win32
from dji_duml.errors import TransportError
from dji_duml.libusb_win32 import _Bus, _Device, Library, parse_configuration
from dji_duml.profiles import M4T

try:
    import usb.core
    from dji_duml import transport
except ImportError:  # pyusb is optional for everything except real USB access
    usb = None


def configuration() -> bytes:
    """Configuration shaped like the M4T one in README: vendor interfaces 3-7
    (class FF/43/01) with bulk pairs 03/84 .. 07/88; MI04 owns 04/85."""
    body = b""
    for number in range(8):
        vendor = number >= 3
        endpoints = [(number, 0x80 | (number + 1))] if vendor else []
        body += bytes([9, 4, number, 0, 2 * len(endpoints),
                       0xFF if vendor else 0x08, 0x43 if vendor else 0x06,
                       0x01 if vendor else 0x50, 0])
        for out, inp in endpoints:
            body += bytes([7, 5, out, 2, 0, 2, 0]) + bytes([7, 5, inp, 2, 0, 2, 0])
    return bytes([9, 2, *(9 + len(body)).to_bytes(2, "little"), 8, 1, 0, 0x80, 250]) + body


class FakeDll:
    """Stands in for libusb0_device.dll; the device list is real ctypes memory
    in the DLL's own layout."""

    def __init__(self, nodes=1, pipe_on=0, descriptor=(18, 1), ids=(0x2CA3, 0x0020)):
        self.bus = _Bus(location=1)
        self.records = [_Device() for _ in range(nodes)]
        for index, record in enumerate(self.records):
            record.descriptor.bLength, record.descriptor.bDescriptorType = descriptor
            record.descriptor.idVendor, record.descriptor.idProduct = ids
            record.descriptor.iSerialNumber = 3
            record.devnum = 47 + index
            if index + 1 < nodes:
                record.next = ctypes.pointer(self.records[index + 1])
        if nodes:
            self.bus.devices = ctypes.pointer(self.records[0])
        self.pipe_on = pipe_on
        self.reads = []
        self.written = []
        self.claimed = []
        self.closed = []

    def _node(self, handle):
        return handle - 1

    def usb_find_busses(self):
        return 0

    usb_find_devices = usb_find_busses

    def usb_get_busses(self):
        return ctypes.pointer(self.bus)

    def usb_open(self, record):
        address = ctypes.addressof(record.contents)
        return 1 + [ctypes.addressof(item) for item in self.records].index(address)

    def usb_close(self, handle):
        self.closed.append(self._node(handle))
        return 0

    def usb_get_descriptor(self, handle, kind, index, buffer, size):
        data = configuration()[:size]
        ctypes.memmove(buffer, data, len(data))
        return len(data)

    def usb_get_string_simple(self, handle, index, buffer, size):
        ctypes.memmove(buffer, b"SERIAL", 6)
        return 6

    def usb_claim_interface(self, handle, number):
        self.claimed.append((self._node(handle), number))
        return 0

    def usb_release_interface(self, handle, number):
        return 0

    def usb_bulk_read(self, handle, endpoint, buffer, size, timeout):
        if self._node(handle) != self.pipe_on:
            return -22  # libusb-win32: invalid endpoint on a node without the pipe
        if not self.reads:
            return -116
        data = self.reads.pop(0)
        ctypes.memmove(buffer, data, len(data))
        return len(data)

    def usb_bulk_write(self, handle, endpoint, data, size, timeout):
        self.written.append((endpoint, data[:size]))
        return size

    def usb_strerror(self):
        return b"libusb0-dll:err [_usb_reap_async] timeout error"


class LayoutTests(unittest.TestCase):
    def test_layout_is_the_one_djis_dll_allocates_and_addresses(self):
        # usb_find_devices: malloc(0x444), descriptor at 0x418, config 0x42a,
        # devnum 0x43a, children 0x43c; usb_open reads bus at 0x410;
        # usb_find_busses: malloc(0x224); bus->devices 0x210, root_dev 0x21c.
        self.assertEqual(ctypes.sizeof(_Device), 0x444)
        self.assertEqual([getattr(_Device, name).offset for name in
                          ("bus", "descriptor", "config", "devnum", "num_children", "children")],
                         [0x410, 0x418, 0x42A, 0x43A, 0x43B, 0x43C])
        self.assertEqual(ctypes.sizeof(_Bus), 0x224)
        self.assertEqual((_Bus.devices.offset, _Bus.location.offset, _Bus.root_dev.offset),
                         (0x210, 0x218, 0x21C))

    def test_configuration_parser(self):
        parsed = parse_configuration(configuration())
        self.assertEqual(len(parsed.interfaces), 8)
        mi04 = parsed.interfaces[4]
        self.assertEqual((mi04.bInterfaceNumber, mi04.bInterfaceClass, mi04.bInterfaceSubClass),
                         (4, 0xFF, 0x43))
        self.assertEqual([(e.bEndpointAddress, e.bmAttributes, e.wMaxPacketSize) for e in mi04],
                         [(0x04, 2, 512), (0x85, 2, 512)])
        for broken in (b"", configuration()[:20], bytes([9, 2, 12, 0, 1, 1, 0, 0x80, 250, 1, 4, 0]),
                       bytes([9, 2, 16, 0, 1, 1, 0, 0x80, 250, 7, 5, 0x85, 2, 0, 2, 0])):
            with self.subTest(raw=broken.hex()), self.assertRaises(ValueError):
                parse_configuration(broken)


@unittest.skipIf(usb is None, "pyusb is not installed")
class DjiDllTests(unittest.TestCase):
    def test_walk_finds_the_device_in_the_dlls_layout(self):
        dll = FakeDll(nodes=3)
        devices = Library(dll).find(0x2CA3, 0x0020)
        self.assertEqual([(d.bus, d.address) for d in devices], [(1, 47), (1, 48), (1, 49)])
        self.assertEqual(devices[0].serial(), "SERIAL")
        self.assertEqual(Library(FakeDll(ids=(0x1234, 1))).find(0x2CA3, 0x0020), [])

    def test_a_list_that_does_not_read_as_descriptors_is_refused(self):
        with self.assertRaisesRegex(usb.core.USBError, "does not match the expected layout"):
            Library(FakeDll(descriptor=(0, 0))).find(0x2CA3, 0x0020)

    def test_timeouts_and_errors_keep_their_meaning(self):
        dll = FakeDll()
        device = Library(dll).find(0x2CA3, 0x0020)[0]
        with self.assertRaises(usb.core.USBTimeoutError) as caught:
            device.read(0x85, 512, 20)
        self.assertTrue(transport._is_timeout(caught.exception))
        dll.pipe_on = 5
        with self.assertRaises(usb.core.USBError) as caught:
            device.read(0x85, 512, 20)
        self.assertFalse(transport._is_timeout(caught.exception))

    def test_a_failed_transfer_is_a_lost_link_not_silence(self):
        # The DLL reports both with -116; only the message tells them apart.
        dll = FakeDll(nodes=1, pipe_on=0)
        with patch.object(transport, "_backends", return_value=iter([("libusb0", Library(dll))])):
            link = transport.UsbBulkTransport.open(M4T)
        self.assertEqual(link.read(0.1), b"")  # "timeout error": an idle pipe
        dll.usb_strerror = lambda: (b"libusb0-dll:err [_usb_reap_async] reaping request "
                                    b"failed, win error: The semaphore timeout period has expired.")
        with self.assertRaisesRegex(TransportError, "reaping request failed"):
            link.read(0.1)
        self.assertFalse(transport._is_timeout(
            usb.core.USBError("reaping request failed, win error: aborted", -116)))

    def test_a_disposed_device_is_never_reopened(self):
        dll = FakeDll()
        device = Library(dll).find(0x2CA3, 0x0020)[0]
        device.get_active_configuration()
        device.dispose()
        with self.assertRaisesRegex(usb.core.USBError, "disposed"):
            device.read(0x85, 512, 20)
        self.assertEqual(dll.closed, [0])

    def test_skipped_nodes_are_closed(self):
        dll = FakeDll(nodes=3, pipe_on=2)
        dll.reads = [b"\x55"]
        no_pipe = dll.usb_get_descriptor

        def only_last_has_the_interface(handle, kind, index, buffer, size):
            if handle - 1 == 2:
                return no_pipe(handle, kind, index, buffer, size)
            header = bytes([9, 2, 9, 0, 0, 1, 0, 0x80, 250])
            ctypes.memmove(buffer, header[:size], min(size, 9))
            return min(size, 9)

        dll.usb_get_descriptor = only_last_has_the_interface
        with patch.object(transport, "_backends", return_value=iter([("libusb0", Library(dll))])):
            link = transport.UsbBulkTransport.open(M4T)
        self.assertEqual(sorted(dll.closed), [0, 1])
        link.close()

    def test_transport_opens_the_node_that_owns_the_pipe(self):
        dll = FakeDll(nodes=5, pipe_on=1)
        dll.reads = [b"\x55\x0d"]
        with patch.object(transport, "_backends", return_value=iter([("libusb0", Library(dll))])):
            link = transport.UsbBulkTransport.open(M4T)
        self.assertEqual(link.read(0.1), b"\x55\x0d")
        link.write(b"\x55" * 13)
        self.assertEqual(dll.written, [(0x04, b"\x55" * 13)])
        self.assertIn((1, 4), dll.claimed)
        link.close()
        self.assertEqual(sorted(set(dll.closed)), [0, 1, 2, 3, 4])

    def test_the_dll_binding_has_no_kernel_driver_to_detach(self):
        # The same tests run on Linux, where transport detaches kernel
        # drivers from pyusb devices; DJI's binding has none.
        dll = FakeDll(nodes=2, pipe_on=1)
        with patch.object(transport, "_backends", return_value=iter([("libusb0", Library(dll))])), \
                patch.object(transport.sys, "platform", "linux"):
            link = transport.UsbBulkTransport.open(M4T)
        self.assertIn((1, 4), dll.claimed)
        link.close()

    def test_scan_lists_and_closes_every_node(self):
        dll = FakeDll(nodes=2)
        with patch.object(transport, "_backends", return_value=iter([("libusb0", Library(dll))])):
            found = transport.scan(M4T)
        self.assertEqual([(c.backend, c.location, c.serial, c.has_interface) for c in found],
                         [("libusb0", "1:47", "SERIAL", True), ("libusb0", "1:48", "SERIAL", True)])
        self.assertEqual(sorted(dll.closed), [0, 1])

    def test_pyusb_never_gets_djis_dll_and_the_binding_is_the_fallback(self):
        with patch("sys.platform", "win32"), \
                patch("usb.backend.libusb0.get_backend", return_value=None) as pyusb0, \
                patch("usb.backend.libusb1.get_backend", return_value="b1"), \
                patch.object(libusb_win32, "load", return_value="dji") as load:
            self.assertEqual(list(transport._backends("auto")),
                             [("libusb0", "dji"), ("libusb1", "b1")])
        pyusb0.assert_called_once_with()
        load.assert_called_once_with()

    def test_no_backend_at_all_is_reported(self):
        with patch.object(transport, "_backends", return_value=iter([])), \
                patch("sys.platform", "win32"):
            with self.assertRaisesRegex(TransportError, "No libusb backend"):
                transport.UsbBulkTransport.open(M4T)


if __name__ == "__main__":
    unittest.main()
