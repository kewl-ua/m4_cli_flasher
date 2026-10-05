"""In-memory drone used by the tests and by ``dji-duml --simulate``.

SimulatedDrone speaks the frames of the public legacy procedure. SimulatedM4T
adds the upgrade center (0x48) as two captures of DJI Assistant flashing an
M4T show it. Both prove the code is consistent with that evidence, not that a
real device behaves this way in every case.
"""
from __future__ import annotations

import hashlib
import struct
import time
from collections import Counter
from pathlib import Path

from . import battery, commands
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


FLIGHT_CONTROLLER = 0x03

#: A small config table 0 in the M4T's layout: (index, type id, default,
#: minimum, maximum, name, value bytes).
SIM_PARAMS = [
    (1, 0, 0, 0, 18, "sweep_test_flag", b"\x00"),
    (2, 8, 180.0, 0.0, 1000.0, "sweep_total_t_A__PRBS_period", struct.pack("<f", 180.0)),
    (4, 5, 100, 20, 150, "basic_gain_roll_usr", struct.pack("<h", 120)),
    (5, 2, 0, 0, 0xFFFFFFFF, "set_motor_auto_start_1", struct.pack("<I", 0)),
]


def _battery_block(voltage_mv=16600, current_ma=-300, full=6690, remaining=6356,
                   temp_dc=250, cells=4, soc=95, status=0, tail=None) -> bytes:
    """A 45-byte 0D/02 reply in the M4T's field order, SoC consistent with
    remaining/full by default."""
    if tail is None:
        tail = b"\x01" + bytes(10) + bytes([0x03, 0, 0, 0])  # version byte, then opaque
    block = (b"\x00\x00" + struct.pack("<IiII", voltage_mv, current_ma, full, remaining)
             + struct.pack("<H", temp_dc) + bytes([cells, soc]) + struct.pack("<Q", status) + tail)
    return block


#: Default smart-battery data the simulator returns for 0D/02.
SIM_BATTERY = _battery_block()

#: Default device-info string the simulator returns for 00/FF (NUL-terminated).
SIM_DEVICE_INFO = b"NAVI wa345 20260101|000000\x00"


def _config_for(version: FirmwareVersion, product: str = "wa345t") -> bytes:
    """A configuration as DJI lays it out (IM*H header, readable manifest),
    listing no modules."""
    xml = (f'<?xml version="1.0" encoding="utf-8"?>\n<dji><device id="{product}">'
           f'<firmware formal="{version}"><release version="{version}"></release>'
           '</firmware></device></dji>\n')
    return b"IM*H" + bytes(604) + xml.encode()


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
    once the host has greeted the aircraft (00/4A to 0x28). That is stricter
    than the real M4T, which in our second run sent them before the greeting,
    so a test passes only if the greeting is sent. After that 0x1F reports
    firmware 00000000 for ``zero_version_reads`` inquiries. The device asks
    the host 00/81 and 00/82 on 83 and after each reconnect.
    """

    def __init__(self, profile: DeviceProfile, firmware: str = "17.01.0516", *,
                 reboots: int = 1, zero_version_reads: int = 2, progress_every: int = 1250,
                 end_status: dict[str, int] | None = None, stop_after_files: int | None = None,
                 mute_progress: bool = False, lose=(), repeat_reports: int = 1,
                 tick: float | None = None, installed_config: bytes | None = None,
                 params: list[tuple] | None = None, require_unlock: bool = False,
                 ignore_writes=(), battery_data: bytes | None = None,
                 device_info: bytes | None = None, **options):
        super().__init__(profile, firmware, **options)
        self.center = profile.upgrade_center
        #: What 00/4F type 01 returns; by default a manifest of ``firmware``.
        self.installed_config = installed_config
        #: Flight controller config table 0: (index, type id, default, minimum,
        #: maximum, name, value bytes); indexes in between have no item.
        self.params = SIM_PARAMS if params is None else params
        #: Whether 03/DF Assistant Unlock has been received this session.
        self.unlocked = False
        #: When True, E3 writes are rejected (status 9) until an unlock arrives.
        self.require_unlock = require_unlock
        #: Indexes whose E3 reply is a success that does not persist -- the value
        #: silently reverts -- to exercise the read-back confirmation.
        self.ignore_writes = set(ignore_writes)
        #: Every accepted write, as (index, value bytes), in order.
        self.writes: list[tuple[int, bytes]] = []
        #: The 45-byte block returned for a 0D/02 battery read.
        self.battery_data = SIM_BATTERY if battery_data is None else battery_data
        #: The string returned for a 00/FF device-info read.
        self.device_info = SIM_DEVICE_INFO if device_info is None else device_info
        self.reboots = reboots
        self.zero_version_reads = zero_version_reads
        self.progress_every = progress_every
        self.end_status = end_status or {}
        self.stop_after_files = stop_after_files
        self.mute_progress = mute_progress
        #: (file number, chunk) pairs lost on the way, once each, or as many
        #: times as a mapping says. The device never sees a lost chunk: it
        #: learns of the gap when a later chunk arrives, and then reports the
        #: gap instead of progress, as in Assistant's capture.
        self.lose = Counter(lose)
        self.lost: list[tuple[int, int]] = []
        self.resent: list[tuple[int, int]] = []
        self.duplicates: list[tuple[int, int]] = []
        #: Reports per read: the device's timer keeps reporting while the host
        #: writes, so several can wait to be read at once.
        self.repeat_reports = repeat_reports
        #: Seconds between reports even when nothing changed, like the real
        #: device's ~100 ms timer; None reports only on change.
        self.tick = tick
        self._reported_at = 0.0
        self._opened = -1
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

    def _progress(self, link: _Link, index: int, gap: tuple[int, int] | None = None) -> None:
        """A progress report, or with ``gap`` (first missing, count) the gap
        report the device sends in its place."""
        self._center_seq += 1
        body = b"\x00" + index.to_bytes(4, "little")
        if gap is not None:
            body += gap[0].to_bytes(4, "little") + gap[1].to_bytes(4, "little")
        link.out += Frame(self.center, self.profile.host, self._center_seq, commands.GENERAL,
                          commands.FILE_TRANSFER, body, response=True,
                          ack=AckType.NONE).encode()

    def _gap(self) -> tuple[int, int] | None:
        missing = self._open[5]
        if not missing:
            return None
        first = min(missing)
        count = 1
        while first + count in missing:
            count += 1
        return first, count

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
        if frame.receiver == FLIGHT_CONTROLLER and frame.cmd_set == commands.FLYC \
                and not frame.response:
            self.received.append(frame)
            self._flight_controller(link, frame)
            return
        if (frame.receiver == battery.BATTERY_ADDRESS and frame.cmd_set == commands.BATTERY
                and frame.cmd_id == battery.DYNAMIC_DATA and not frame.response):
            self.received.append(frame)
            self._answer(link, frame, self.battery_data)
            return
        if (frame.receiver == FLIGHT_CONTROLLER and frame.cmd_set == commands.GENERAL
                and frame.cmd_id == commands.QUERY_DEVICE_INFO and not frame.response):
            self.received.append(frame)
            self._answer(link, frame, self.device_info)
            return
        super().handle(link, frame)

    def _flight_controller(self, link: _Link, frame: Frame) -> None:
        """Config table 0 reads as idle.pcap shows them; anything else gets
        status 9, as the M4T gave for table 1."""
        payload, items = frame.payload, {item[0]: item for item in self.params}
        count = max(items, default=-1) + 2  # one empty index after the last item
        if frame.cmd_id == 0xE0 and payload == b"\x00\x00":
            self._answer(link, frame, struct.pack("<HHII", 0, 0, 0xDDB5B586, count))
        elif frame.cmd_id == 0xE1 and len(payload) == 4 and payload[:2] == b"\x00\x00":
            item = items.get(struct.unpack_from("<H", payload, 2)[0])
            if item is None:
                self._answer(link, frame, b"\x0e\x00")
                return
            index, type_id, default, minimum, maximum, name, value = item
            limit = "<f" if type_id in (8, 9) else ("<i" if type_id in (4, 5, 6, 7) else "<I")
            self._answer(link, frame, struct.pack("<HHHHH", 0, 0, index, type_id, len(value))
                         + b"".join(struct.pack(limit, number)
                                    for number in (default, minimum, maximum))
                         + name.encode() + b"\0")
        elif frame.cmd_id == 0xE2 and len(payload) == 6 and payload[:4] == b"\x00\x00\x01\x00":
            index = struct.unpack_from("<H", payload, 4)[0]
            item = items.get(index)
            self._answer(link, frame, b"\x0e\x00" if item is None
                         else struct.pack("<HHH", 0, 0, index) + item[6])
        elif frame.cmd_id == 0xDF and len(payload) == 4:
            if struct.unpack_from("<I", payload)[0]:
                self.unlocked = True
            self._answer(link, frame, b"\x00")  # unlock status is a single byte
        elif frame.cmd_id == 0xE3 and len(payload) >= 6 and payload[:4] == b"\x00\x00\x01\x00":
            index = struct.unpack_from("<H", payload, 4)[0]
            value, item = payload[6:], items.get(index)
            if item is None or len(value) != len(item[6]) \
                    or (self.require_unlock and not self.unlocked):
                self._answer(link, frame, b"\x09\x00")
                return
            self.writes.append((index, value))
            if index not in self.ignore_writes:  # otherwise accepted but not stored
                self.params = [(*item[:6], value) if entry[0] == index else entry
                               for entry in self.params]
            # success echo of the requested value (not re-read from storage, so
            # with ignore_writes it differs from what is stored -- a reverting device)
            self._answer(link, frame, struct.pack("<HHH", 0, 0, index) + value)
        else:
            self._answer(link, frame, b"\x09\x00")

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
        elif cmd == commands.UPGRADE_RESULT and payload[:1] == b"\x01":
            # The installed configuration, 256 bytes per request as the M4T sends it.
            config = self.installed_config or _config_for(self.firmware)
            offset = int.from_bytes(payload[1:5], "little")
            chunk = config[offset:offset + 256]
            left = max(0, len(config) - offset - len(chunk))
            self._answer(link, frame, b"\x00" + len(chunk).to_bytes(4, "little")
                         + left.to_bytes(4, "little") + chunk)
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
            # name, size, chunks by index, highest, last reported, missing,
            # a report due because a gap opened or a missing chunk arrived
            self._open = [name, size, {}, -1, -1, set(), False]
            self._opened += 1
            self._answer(link, frame, bytes.fromhex("00d40388130101"))
        elif payload[0] == commands.FT_DATA:
            if self._open is None:
                self.errors.append("data without an open file")
                return
            name, size, chunks, highest, reported, missing = self._open[:6]
            index = int.from_bytes(payload[1:5], "little")
            key = (self._opened, index)
            if self.lose[key] > 0:
                self.lose[key] -= 1
                self.lost.append(key)
                return
            if index in missing:
                missing.discard(index)
                chunks[index] = payload[5:]
                self.resent.append(key)
                self._open[6] = True  # the next timer report tells what is still missing
                return
            if index <= highest:
                self.duplicates.append(key)
                self.errors.append(f"{name}: chunk {index} again after {highest}")
                return
            if index > highest + 1:
                missing.update(range(highest + 1, index))
                self._open[6] = True
            self._open[3] = index
            self.max_ahead = max(self.max_ahead, index - reported)
            chunks[index] = payload[5:]
        elif payload[0] == commands.FT_END:
            if self._open is None:
                self.errors.append("end without an open file")
                return
            name, size, chunks, highest = self._open[:4]
            if not self.mute_progress:
                # Stale by the time the host reads it.
                self._progress(link, highest, self._gap())
            data = b"".join(chunks[index] for index in sorted(chunks))
            good = (not self._open[5] and len(data) == size
                    and hashlib.md5(data).digest() == payload[1:17])
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
        _, size, _, highest, reported, missing, changed = self._open
        if highest < 0:
            return  # no chunk yet, nothing to report
        sent_all = (highest + 1) * 980 >= size
        now = time.monotonic()
        timer = self.tick is not None and now - self._reported_at >= self.tick
        if changed or missing or timer or highest - reported >= self.progress_every \
                or (sent_all and highest > reported):
            # While chunks are missing a gap report takes the place of the
            # progress report; a new gap or a chunk sent again gets a report
            # on the device's next ~100 ms tick.
            self._open[4], self._open[6], self._reported_at = highest, False, now
            for _ in range(self.repeat_reports):
                self._progress(link, highest, self._gap())

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
