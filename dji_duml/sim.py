"""In-memory drone used by the tests and by ``dji-duml --simulate``.

SimulatedDrone speaks the frames of the public legacy procedure. SimulatedM4T
adds the upgrade center (0x48) as two captures of DJI Assistant flashing an
M4T show it. Both prove the code is consistent with that evidence, not that a
real device behaves this way in every case.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path

from . import commands
from .client import DumlClient
from .errors import TransportError
from .frame import AckType, Frame, StreamParser
from .profiles import DeviceProfile
from .version import FirmwareVersion


class _Link:
    def __init__(self, drone: "SimulatedDrone"):
        self.drone = drone
        self.parser = StreamParser()
        self.out = bytearray()
        self.alive = True
        #: Drop off the bus once the host has read everything queued.
        self.die_after_drain = False

    def _check(self) -> None:
        if not self.alive:
            raise TransportError("simulated device disconnected")

    def write(self, data: bytes) -> None:
        self._check()
        for frame in self.parser.feed(data):
            self.drone.handle(self, frame)

    def read(self, timeout: float) -> bytes:
        if self.alive:
            self.drone.on_read(self)
        if not self.out:
            self._check()
            time.sleep(min(timeout, 0.001))
        size = self.drone.read_size or len(self.out)
        data, self.out = bytes(self.out[:size]), self.out[size:]
        if self.die_after_drain and not self.out:
            self.drone._reboot(self)
        return data

    def close(self) -> None:
        self.alive = False


class SimulatedDrone:
    def __init__(self, profile: DeviceProfile, firmware: str = "17.01.0516", *,
                 hardware: str = "WA345T AC Ver.A", image_version: str | None = None,
                 fail_result: int | None = None, silent: frozenset[int] = frozenset(),
                 reject: dict[int, int] | None = None, drop_link_at: int | None = None,
                 boot_attempts: int = 2, install: bool = True,
                 push_with_size_ack: bytes | None = None, drop_after_complete: bool = False,
                 push_before_reply: dict[int, bytes] | None = None,
                 read_size: int | None = None, lose_reply: frozenset[int] = frozenset(),
                 push_receiver: int | None = None):
        self.profile = profile
        self.firmware = FirmwareVersion.parse(firmware)
        self.hardware = hardware
        self.image_version = FirmwareVersion.parse(image_version) if image_version else None
        self.fail_result = fail_result
        self.silent = silent
        self.reject = reject or {}
        self.drop_link_at = drop_link_at
        self.boot_attempts = boot_attempts
        self.install = install
        self.push_with_size_ack = push_with_size_ack
        self.drop_after_complete = drop_after_complete
        #: Status push queued when a command arrives, ahead of its reply.
        self.push_before_reply = push_before_reply or {}
        #: Bytes per host read; real USB delivers about one frame per transfer.
        self.read_size = read_size
        #: Commands that are executed but whose reply never reaches the host.
        self.lose_reply = lose_reply
        #: Receiver of status pushes; the host by default.
        self.push_receiver = profile.host if push_receiver is None else push_receiver
        self.upgrade_mode = False
        self.uploaded: bytes | None = None
        self.announced_size: int | None = None
        self.received: list[Frame] = []
        self.uploads = 0
        self._booting = 0
        self._link: _Link | None = None
        self._seq = 0x4000

    # -- host side ------------------------------------------------------------

    def on_read(self, link: _Link) -> None:
        """Called when the host reads: where a real device's timers would fire."""

    def connect(self) -> _Link:
        if self._booting > 0:
            self._booting -= 1
            raise TransportError("simulated device is rebooting")
        self._link = _Link(self)
        return self._link

    def client(self, journal=None) -> DumlClient:
        return DumlClient(self.connect(), host=self.profile.host, journal=journal)

    def upload(self, host: str, source: Path, on_bytes) -> bytes:
        if not self.upgrade_mode:
            raise OSError("FTP refused: device is not in upgrade mode")
        self.uploads += 1
        data = Path(source).read_bytes()
        for offset in range(0, len(data), 4096):
            on_bytes(len(data[offset:offset + 4096]))
        self.uploaded = data
        return hashlib.md5(data).digest()

    # -- device side ----------------------------------------------------------

    def _push(self, link: _Link, payload: bytes) -> None:
        self._seq += 1
        link.out += Frame(self.profile.target, self.push_receiver, self._seq, commands.GENERAL,
                          commands.UPGRADE_STATUS, payload, ack=AckType.NONE).encode()

    def _answer(self, link: _Link, frame: Frame, payload: bytes) -> None:
        if frame.cmd_id not in self.lose_reply:
            link.out += frame.make_reply(payload).encode()

    def _reboot(self, link: _Link) -> None:
        link.alive = False
        self.upgrade_mode = False
        self._booting = self.boot_attempts

    def handle(self, link: _Link, frame: Frame) -> None:
        self.received.append(frame)
        if frame.receiver != self.profile.target or frame.cmd_set != commands.GENERAL:
            return
        cmd = frame.cmd_id
        if cmd in self.push_before_reply:
            self._push(link, self.push_before_reply[cmd])
        if cmd in self.silent:
            return
        if cmd in self.reject:
            self._answer(link, frame, bytes([self.reject[cmd]]))
            return
        if cmd == commands.VERSION_INQUIRY:
            body = (bytes(2) + self.hardware.encode().ljust(16, b"\0")[:16]
                    + bytes.fromhex("01000001") + self.firmware.to_wire() + bytes(8))
            self._answer(link, frame, body)
        elif cmd == commands.ENTER_UPGRADE:
            self.upgrade_mode, self.uploaded, self.announced_size = True, None, None
            self._answer(link, frame, b"\x00")
        elif cmd == commands.UPGRADE_REPORT:
            self._answer(link, frame, bytes(6))
        elif cmd == commands.UPGRADE_DATA_SIZE:
            self.announced_size = int.from_bytes(frame.payload[1:5], "little")
            self._answer(link, frame, b"\x00")
            if self.push_with_size_ack is not None:
                self._push(link, self.push_with_size_ack)
        elif cmd == commands.UPGRADE_VERIFY:
            good = (self.upgrade_mode and self.uploaded is not None
                    and len(self.uploaded) == self.announced_size
                    and hashlib.md5(self.uploaded).digest() == frame.payload[1:17])
            self._answer(link, frame, b"\x00" if good else b"\xE2")
            if good:
                self._upgrade(link)

    def _upgrade(self, link: _Link) -> None:
        self._push(link, bytes([commands.UpgradeState.VERIFY, 0, 0]))
        for percent in (0, 25, 50, 75, 100):
            if self.drop_link_at is not None and percent >= self.drop_link_at:
                if self.install and self.image_version:
                    self.firmware = self.image_version
                self._reboot(link)
                return
            self._push(link, bytes([commands.UpgradeState.UPGRADING, percent, 0]))
        if self.fail_result is not None:
            self._push(link, bytes([commands.UpgradeState.COMPLETE, self.fail_result, 1]))
            self.upgrade_mode = False
            if self.drop_after_complete:
                self._reboot(link)
            return
        self._push(link, bytes([commands.UpgradeState.COMPLETE, 1, 1]))
        if self.install and self.image_version:
            self.firmware = self.image_version
        self._booting = self.boot_attempts
        self.upgrade_mode = False


def _center_version(version: FirmwareVersion) -> bytes:
    """Version bytes of the 00/4F reply: one decimal field per byte, low first."""
    return bytes([version.build % 100, version.build // 100, version.minor, version.major])


#: Replies to Assistant's reconnect routine, as captured (serial number zeroed).
GREETING_REPLIES = {
    (0x03, commands.VERSION_INQUIRY): bytes(31),
    (0x28, 0x51): b"\xd6",
    (0x68, 0x51): b"\x00\x18" + bytes(5) + b"0" * 20,
    (0x28, 0x4A): b"\x00",
}


class SimulatedM4T(SimulatedDrone):
    """The M4T upgrade center (0x48) as DJI Assistant's captures show it.

    83 -> 00 07 00; 84 -> 00; 2A open -> 00 d403 8813 0101; data gets no
    reply, but a progress report every ``progress_every`` chunks and at the
    end of a file, sent when the host reads (the device reports on a ~100 ms
    timer, not per chunk); the last report of a file is repeated between the
    end request and its reply, as captured; end -> 00 when length and MD5
    match; 85 -> 06, then status
    pushes, ``reboots`` reboots, and after the last one 03 57 00, 03 64 00 and
    04 01 00 (or 04 <fail_result> 00). After a reboot the pushes resume only
    once the host has greeted the aircraft (00/4A to 0x28), as in all six
    captured reconnects. After that the main controller reports
    firmware 00000000 for ``zero_version_reads`` inquiries. The device asks
    the host 00/81 and 00/82 on 83 and after each reconnect.
    """

    def __init__(self, profile: DeviceProfile, firmware: str = "17.01.0516", *,
                 reboots: int = 1, zero_version_reads: int = 2, progress_every: int = 1250,
                 end_status: dict[str, int] | None = None, stop_after_files: int | None = None,
                 mute_progress: bool = False, **options):
        super().__init__(profile, firmware, **options)
        self.center = profile.upgrade_center
        self.reboots = reboots
        self.zero_version_reads = zero_version_reads
        self.progress_every = progress_every
        self.end_status = end_status or {}
        self.stop_after_files = stop_after_files
        self.mute_progress = mute_progress
        #: Largest distance between a received chunk and the last progress report.
        self.max_ahead = 0
        self.prepared = False
        self.announced_total: int | None = None
        self.files: dict[str, bytes] = {}
        self.host_answers: dict[int, bytes] = {}
        self.finished = False
        self.errors: list[str] = []
        self._open: list | None = None
        self._boots_left = 0
        self._zero_left = 0
        self._center_seq = 0
        self.greeted = 0
        self._after_greeting = None

    # -- host side ------------------------------------------------------------

    def connect(self) -> _Link:
        link = super().connect()
        if self._boots_left > 0:
            self._boots_left -= 1
            self._ask_host(link)
            self._after_greeting = (self._resume_after_reboot if self._boots_left > 0
                                    else self._finish_install)
        return link

    def _resume_after_reboot(self, link: _Link) -> None:
        self._center_push(link, bytes([commands.UpgradeState.UPGRADING, 73, 0]))
        link.die_after_drain = True

    # -- device side ----------------------------------------------------------

    def _center_push(self, link: _Link, payload: bytes) -> None:
        self._seq += 1
        link.out += Frame(self.center, self.push_receiver, self._seq, commands.GENERAL,
                          commands.UPGRADE_STATUS, payload, ack=AckType.NONE).encode()

    def _ask_host(self, link: _Link) -> None:
        block = b"WA345T".ljust(32, b"\0") + b"\x02\x08" + bytes(6) + b"\x02\x08" + bytes(22)
        for cmd_id in (commands.CENTER_INFO, commands.CENTER_STATE):
            self._seq += 1
            link.out += Frame(self.center, self.profile.host, self._seq, commands.GENERAL,
                              cmd_id, block, ack=AckType.AFTER_EXEC).encode()

    def _progress(self, link: _Link, index: int) -> None:
        self._center_seq += 1
        link.out += Frame(self.center, self.profile.host, self._center_seq, commands.GENERAL,
                          commands.FILE_TRANSFER, b"\x00" + index.to_bytes(4, "little"),
                          response=True, ack=AckType.NONE).encode()

    def handle(self, link: _Link, frame: Frame) -> None:
        if frame.receiver == self.center and frame.cmd_set == commands.GENERAL:
            self.received.append(frame)
            if frame.response:
                self.host_answers[frame.cmd_id] = frame.payload
            elif frame.cmd_id not in self.silent:
                self._center_command(link, frame)
            return
        greeting = GREETING_REPLIES.get((frame.receiver, frame.cmd_id))
        if greeting is not None and frame.cmd_set == commands.GENERAL and not frame.response:
            self.received.append(frame)
            self.greeted += 1
            self._answer(link, frame, greeting)
            if frame.cmd_id == 0x4A and self._after_greeting is not None:
                resume, self._after_greeting = self._after_greeting, None
                resume(link)
            return
        if (frame.receiver == self.profile.target and frame.cmd_set == commands.GENERAL
                and frame.cmd_id == commands.VERSION_INQUIRY and self._zero_left > 0):
            self.received.append(frame)
            self._zero_left -= 1
            body = bytes(2) + self.hardware.encode().ljust(16, b"\0")[:16] + bytes(14)
            self._answer(link, frame, body)
            return
        super().handle(link, frame)

    def _center_command(self, link: _Link, frame: Frame) -> None:
        cmd, payload = frame.cmd_id, frame.payload
        if cmd in self.reject:
            self._answer(link, frame, bytes([self.reject[cmd]]))
        elif cmd == commands.UPGRADE_PREPARE:
            self.prepared = True
            self._ask_host(link)
            self._answer(link, frame, b"\x00\x07\x00")
        elif cmd == commands.UPGRADE_ANNOUNCE:
            if not self.prepared:
                self.errors.append("84 before 83")
            self.announced_total = int.from_bytes(payload[1:5], "little")
            self._answer(link, frame, b"\x00")
        elif cmd == commands.FILE_TRANSFER:
            self._file_transfer(link, frame)
        elif cmd == commands.UPGRADE_INSTALL:
            self._answer(link, frame, b"\x06")
            self._install(link)
        elif cmd == commands.UPGRADE_RESULT:
            self._answer(link, frame, b"\x00\x04" + bytes(7) + _center_version(self.firmware))
        elif cmd == commands.PUSH_CONTROL:
            self.finished = True
            self._answer(link, frame, b"\x00")

    def _file_transfer(self, link: _Link, frame: Frame) -> None:
        payload = frame.payload
        if payload[0] == commands.FT_OPEN:
            if self.announced_total is None or self._open is not None:
                self.errors.append("open out of order")
            size = int.from_bytes(payload[1:5], "little")
            name = payload[6:5 + payload[5]].decode("ascii")
            self._open = [name, size, bytearray(), -1, -1]
            self._answer(link, frame, bytes.fromhex("00d40388130101"))
        elif payload[0] == commands.FT_DATA:
            if self._open is None:
                self.errors.append("data without an open file")
                return
            name, size, data, highest, reported = self._open
            index = int.from_bytes(payload[1:5], "little")
            if index != highest + 1:
                self.errors.append(f"{name}: chunk {index} after {highest}")
                return
            data += payload[5:]
            self._open[3] = index
            self.max_ahead = max(self.max_ahead, index - reported)
        elif payload[0] == commands.FT_END:
            if self._open is None:
                self.errors.append("end without an open file")
                return
            name, size, data, highest = self._open[:4]
            if not self.mute_progress:
                self._progress(link, highest)  # stale by the time the host reads it
            good = len(data) == size and hashlib.md5(data).digest() == payload[1:17]
            status = self.end_status.get(name, 0 if good else 0xE1)
            self._answer(link, frame, bytes([status]))
            self._open = None
            if status == 0:
                self.files[name] = bytes(data)
                if self.stop_after_files is not None and len(self.files) >= self.stop_after_files:
                    link.alive = False

    def on_read(self, link: _Link) -> None:
        if self._open is None or self.mute_progress:
            return
        _, size, data, highest, reported = self._open
        if highest > reported and (highest - reported >= self.progress_every
                                   or len(data) >= size):
            self._open[4] = highest
            self._progress(link, highest)

    def _install(self, link: _Link) -> None:
        sent = sum(len(data) for data in self.files.values())
        if sent != self.announced_total:
            self.errors.append(f"announced {self.announced_total}, received {sent}")
        entries = bytes([0, 1, 0, 0, 0, 0, 0x31, 0]) + bytes([0x48, 0, 0, 0, 0, 0, 0x31, 0])
        for percent in (0, 7, 43, 87):
            self._center_push(link, bytes([commands.UpgradeState.UPGRADING, percent, 2]) + entries)
        if self.reboots <= 0:
            self._finish_install(link)
            return
        self._boots_left = self.reboots
        link.die_after_drain = True

    def _finish_install(self, link: _Link) -> None:
        self._center_push(link, bytes([commands.UpgradeState.UPGRADING, 87, 0]))
        self._center_push(link, bytes([commands.UpgradeState.UPGRADING, 100, 0]))
        if self.fail_result is not None:
            self._center_push(link, bytes([commands.UpgradeState.COMPLETE, self.fail_result, 0]))
            return
        if self.install and self.image_version:
            self.firmware = self.image_version
        self._zero_left = self.zero_version_reads
        self._center_push(link, bytes([commands.UpgradeState.COMPLETE, 1, 0]))
