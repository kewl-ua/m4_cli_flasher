"""Firmware upgrade state machine for the public "legacy FTP" procedure.

    preflight   read version, check model / current version / package
    enter       0x07 Enter Upgrade Mode, 0x0C enable reporting
    transfer    FTP STOR /upgrade/dji_system.bin over the RNDIS interface
    start       0x08 size, 0x0A MD5 (the device starts flashing here); statuses
                received ahead of the 0x0A reply, or without one, are never the
                verdict, and a failure among them makes the outcome unknown
                unless a later Complete/Success from the flashed module follows
    monitor     0x42 status pushes from the flashed module; read errors are
                tolerated, nothing is sent
    confirm     reconnect after reboot and read the installed version
                (a same-version reflash is confirmed by the Complete push,
                because the version cannot tell it apart from no flash)

The sequence is the one published in pyduml for Mavic-era devices. It is NOT
confirmed for the Matrice 4T: profiles list the procedures verified per model
and anything else is refused unless the caller opts in explicitly.

Failure classes tell the operator what is safe to do next:
    FlashRefused         nothing device-changing was sent; fix and rerun
    FlashAborted         upgrade mode was entered, flashing was not started
    FlashFailed          the device reported a failure
    FlashOutcomeUnknown  start may have been delivered; never retry blindly
"""
from __future__ import annotations

import hashlib
import math
import os
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from ftplib import FTP
from pathlib import Path

from . import commands
from .client import DumlClient
from .errors import (
    CommandRejected, DumlError, FlashAborted, FlashFailed, FlashOutcomeUnknown,
    FlashRefused, NoReply, PackageError, TransportError, UnexpectedReply,
)
from .frame import AckType, Frame, address
from .journal import Journal
from .package import PackageInfo, open_file, verify_files
from .profiles import PC, DeviceProfile
from .version import FirmwareVersion

LEGACY_FTP = "legacy-ftp"
#: DJI Assistant's procedure for the M4T, from two USB captures: every package
#: file goes to the upgrade center (0x48) as 00/2A, no FTP. See docs/duml.md.
UPGRADE_CENTER = "upgrade-center"
PROCEDURES = (LEGACY_FTP, UPGRADE_CENTER)
REMOTE_PATH = "/upgrade/dji_system.bin"
#: Data chunks Assistant keeps in flight beyond the device's last progress report.
WINDOW = 1250
#: Data chunks per send_batch call (about 64 KB).
BATCH = 64
#: Chunks kept in memory to send again when the device reports a gap (about
#: 5 MB); older ones are read from the package again.
RESEND_BUFFER = 4 * WINDOW
#: Chunks one file may need again before the transfer is given up.
RESEND_LIMIT = 4096
#: Seconds before a chunk sent again and still reported missing goes once more,
#: when no later chunk shows that the device got past it (a stall of 0.95 s
#: was captured).
RESEND_RETRY = 1.0
#: The device cannot report a lost last chunk: nothing follows it. When its
#: reports (on its ~100 ms timer, at least two) stay this many seconds within
#: TAIL_LIMIT chunks of the end of the file, those chunks go again, in order.
TAIL_WAIT = 2.0
TAIL_LIMIT = 8
#: Module 0x1F still starting after a reboot reports firmware 00.00.0000.
NOT_READY = FirmwareVersion(0, 0, 0)


class Stage(str, Enum):
    PREFLIGHT = "preflight"
    ENTER = "enter"
    TRANSFER = "transfer"
    START = "start"
    VERIFY = "verify"
    USER_CONFIRM = "user-confirm"
    UPGRADING = "upgrading"
    REBOOT = "reboot"
    CONFIRM = "confirm"  # the device reported completion; reading its version
    DONE = "done"


@dataclass(frozen=True)
class Progress:
    stage: Stage
    percent: int | None = None
    detail: str = ""


@dataclass
class _Early:
    """What the flashed module reported ahead of the start reply, or with no
    reply at all. The pipe is drained just before the request, so this is most
    likely the device's first reaction to it, but a stale push cannot be ruled
    out: it shows the device is alive and is never the verdict by itself."""
    heard: bool = False
    failure: commands.UpgradeStatus | None = None
    foreign: int = 0  # statuses from other modules


class _Resend:
    """The data chunks of the open file sent most recently, to send again when
    the device reports them missing; older ones are read from the package."""

    def __init__(self, package: PackageInfo, member: str, name: str, chunk: int):
        self.package, self.member, self.name, self.chunk = package, member, name, chunk
        self.count = 0  # chunks sent again so far
        self._kept: dict[int, bytes] = {}
        self._order: deque[int] = deque()
        #: chunk -> (last chunk sent before it went again, when), until a
        #: plain report shows nothing is missing
        self._again: dict[int, tuple[int, float]] = {}

    def keep(self, index: int, payload: bytes) -> None:
        self._kept[index] = payload
        self._order.append(index)
        if len(self._order) > RESEND_BUFFER:
            del self._kept[self._order.popleft()]

    def due(self, first: int, count: int, highest: int, now: float) -> list[int]:
        """Chunks of a gap report to send now. One already sent again counts
        only once the device got past it (``highest`` beyond the chunk sent
        before it) or RESEND_RETRY passed: reports read in a burst, or made
        before the device reached the resend, still name it."""
        due = []
        for index in range(first, first + count):
            mark, at = self._again.get(index, (None, 0.0))
            if mark is None or highest > mark or now - at >= RESEND_RETRY:
                due.append(index)
        return due

    def sent(self, indexes: list[int], last_sent: int, now: float) -> None:
        self.count += len(indexes)
        for index in indexes:
            self._again[index] = (last_sent, now)

    def settled(self) -> None:
        """A plain report: the device is missing nothing."""
        self._again.clear()

    def payloads(self, indexes: list[int]) -> tuple[list[bytes], bool]:
        """Data payloads of these chunks, and whether any had to be read from
        the package again."""
        reread = {index: None for index in indexes if index not in self._kept}
        if reread:
            with open_file(self.package, self.member) as handle:
                for index in reread:
                    handle.seek(index * self.chunk)
                    block = handle.read(self.chunk)
                    if not block:
                        raise FlashAborted(f"Chunk {index} of {self.name} is past its end. "
                                           "Flashing was not started.")
                    reread[index] = commands.file_data_payload(index, block)
        return [self._kept.get(index) or reread[index] for index in indexes], bool(reread)


@dataclass(frozen=True)
class FlashResult:
    previous: FirmwareVersion
    installed: FirmwareVersion
    completion_observed: bool
    seconds: float


Uploader = Callable[[str, Path, Callable[[int], None]], bytes]


def ftp_upload(host: str, source: Path, on_bytes: Callable[[int], None]) -> bytes:
    """Upload the image and return the MD5 of the bytes that were actually sent."""
    digest = hashlib.md5()

    def sent(block: bytes) -> None:
        digest.update(block)
        on_bytes(len(block))

    with FTP() as ftp:
        ftp.connect(host, 21, timeout=30)
        ftp.login()
        ftp.set_pasv(True)
        with open(source, "rb") as handle:
            ftp.storbinary(f"STOR {REMOTE_PATH}", handle, blocksize=1 << 16, callback=sent)
        remote = ftp.size(REMOTE_PATH)
    if remote != source.stat().st_size:
        raise OSError(f"Remote size {remote} differs from local {source.stat().st_size}.")
    return digest.digest()


class DeviceLock:
    """Cross-process lock so two flashers never drive the same model at once."""

    def __init__(self, key: str):
        self.path = Path(tempfile.gettempdir()) / f"dji-duml-{key}.lock"
        self._handle = None

    def __enter__(self):
        try:
            self._handle = open(self.path, "a+b")
            if os.name == "nt":
                import msvcrt
                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if self._handle is not None:
                self._handle.close()
                self._handle = None
            raise FlashRefused(
                f"Cannot take the flash lock {self.path} ({exc}); another flash operation "
                "may be running. Nothing was sent."
            ) from exc
        return self

    def __exit__(self, *exc):
        if self._handle is not None:
            self._handle.close()  # closing releases the lock on both platforms
            self._handle = None
        return False


def check_package(profile: DeviceProfile, package: PackageInfo) -> None:
    if package.kind != "tar":
        raise FlashRefused(
            "Only the dji_system.bin tar image can be transferred. How Assistant sends "
            "an offline ZIP to the device is not known."
        )
    if not 0 < package.size <= 0xFFFFFFFF:
        raise FlashRefused("Image size does not fit the 32-bit size field of the protocol.")
    if package.product_code.lower() != profile.product_code.lower():
        raise FlashRefused(
            f"Package is for {package.product_code!r}, device profile is "
            f"{profile.product_code!r}."
        )


def check_center_package(profile: DeviceProfile, package: PackageInfo) -> None:
    if profile.upgrade_center is None:
        raise FlashRefused(f"No upgrade center is known for {profile.name}.")
    if package.product_code.lower() != profile.product_code.lower():
        raise FlashRefused(
            f"Package is for {package.product_code!r}, device profile is "
            f"{profile.product_code!r}."
        )
    if not package.files:
        raise FlashRefused(
            "The package has no readable manifest listing its files, so they cannot be "
            "sent one by one."
        )
    if not 0 < package.files_size <= 0xFFFFFFFF:
        raise FlashRefused("Package files do not fit the 32-bit size field of the protocol.")
    for position, item in enumerate(package.files):
        name = sent_name(package, position)
        if not name.isascii() or len(name) + 1 > 0xFF or item.size <= 0:
            raise FlashRefused(f"Package file {name!r} ({item.size} bytes) cannot be announced.")


def sent_name(package: PackageInfo, position: int) -> str:
    """Name a file is announced under: Assistant sends the configuration as
    <product>.cfg.sig whatever it is called in the package."""
    if position == 0:
        return f"{package.product_code}.cfg.sig"
    return package.files[position].name


def plan(profile: DeviceProfile, package: PackageInfo, procedure: str | None = None
         ) -> list[str]:
    """Human-readable dry run with the exact frames (sequence numbers zeroed)."""
    procedure = procedure or profile.default_procedure
    if procedure == UPGRADE_CENTER:
        return _center_plan(profile, package)
    check_package(profile, package)
    def frame(cmd_id: int, payload: bytes) -> str:
        raw = Frame(profile.host, profile.target, 0, commands.GENERAL, cmd_id, payload).encode()
        return f"{commands.command_name(commands.GENERAL, cmd_id):<20} {raw.hex(' ')}"

    return [
        "read    " + frame(commands.VERSION_INQUIRY, b""),
        "write   " + frame(commands.ENTER_UPGRADE, commands.enter_upgrade_payload()),
        "write   " + frame(commands.UPGRADE_REPORT, commands.upgrade_report_payload()),
        f"ftp     STOR {REMOTE_PATH} to {profile.ftp_host} ({package.size} bytes)",
        "write   " + frame(commands.UPGRADE_DATA_SIZE, commands.upgrade_size_payload(package.size)),
        "write   " + frame(commands.UPGRADE_VERIFY, commands.upgrade_verify_payload(package.md5)),
        "listen  Fw Upgrade Push Status (set 00 id 42) until Complete, then re-read version",
    ]


def _center_plan(profile: DeviceProfile, package: PackageInfo) -> list[str]:
    check_center_package(profile, package)
    center = profile.upgrade_center

    def frame(receiver: int, cmd_id: int, payload: bytes) -> str:
        raw = Frame(profile.host, receiver, 0, commands.GENERAL, cmd_id, payload).encode()
        return f"{commands.command_name(commands.GENERAL, cmd_id):<20} {raw.hex(' ')}"

    lines = [
        "read    " + frame(profile.target, commands.VERSION_INQUIRY, b""),
        "write   " + frame(center, commands.UPGRADE_PREPARE, commands.prepare_payload()),
        "write   " + frame(center, commands.UPGRADE_ANNOUNCE,
                           commands.announce_payload(package.files_size)),
    ]
    for position, item in enumerate(package.files):
        md5 = item.md5
        if md5 is None:
            with open_file(package, item.name) as handle:
                md5 = hashlib.md5(handle.read()).digest()
        lines += [
            "write   " + frame(center, commands.FILE_TRANSFER,
                               commands.file_open_payload(sent_name(package, position), item.size)),
            f"stream  {-(-item.size // 980)} data chunks of 980 bytes, at most {WINDOW} ahead "
            "of the device's progress report",
            "write   " + frame(center, commands.FILE_TRANSFER, commands.file_end_payload(md5)),
        ]
    return lines + [
        "write   " + frame(center, commands.UPGRADE_INSTALL, commands.install_payload()),
        f"listen  Fw Upgrade Push Status from {center:#04x} through the reboots until Complete",
        "write   " + frame(center, commands.UPGRADE_RESULT, commands.result_query_payload()),
        "write   " + frame(center, commands.PUSH_CONTROL, commands.push_control_payload()),
        f"read    version from {profile.target:#04x} until it is not 00.00.0000",
    ]


class Flasher:
    def __init__(
        self, open_client: Callable[[], DumlClient], profile: DeviceProfile, *,
        journal: Journal | None = None, upload: Uploader = ftp_upload,
        on_progress: Callable[[Progress], None] | None = None,
        poll_interval: float = 0.25, reconnect_interval: float = 2.0,
        command_timeout: float = 5.0, start_timeout: float = 30.0,
        settle_timeout: float = 180.0, upload_stop_timeout: float = 35.0,
        greet_delay: float = 3.0, sleep: Callable[[float], None] = time.sleep,
    ):
        self.open_client = open_client
        self.profile = profile
        self.journal = journal or Journal()
        self.upload = upload
        self.on_progress = on_progress
        self.poll_interval = poll_interval
        self.reconnect_interval = reconnect_interval
        self.command_timeout = command_timeout
        self.start_timeout = start_timeout
        #: How long the old version may keep answering after the device said
        #: Complete (or after an unacknowledged start) before giving up.
        self.settle_timeout = settle_timeout
        self.upload_stop_timeout = upload_stop_timeout
        #: Assistant greets a reconnected aircraft 3-4 s after it reappears; at
        #: 0.3 s module 0x68 did not answer yet.
        self.greet_delay = greet_delay
        self.sleep = sleep
        self._last: Progress | None = None
        self._procedure = LEGACY_FTP
        #: Module whose status pushes count: the version target (0x1F) for the legacy
        #: procedure, the upgrade center for UPGRADE_CENTER.
        self._sender = profile.target
        self._digests: dict[str, bytes] = {}
        self._result_version: FirmwareVersion | None = None

    @property
    def stage(self) -> Stage | None:
        return self._last.stage if self._last else None

    def _report(self, stage: Stage, percent: int | None = None, detail: str = "") -> None:
        progress = Progress(stage, percent, detail)
        if progress == self._last:
            return
        self._last = progress
        self.journal.event("progress", stage=stage.value, percent=percent, detail=detail)
        if self.on_progress is not None:
            try:
                self.on_progress(progress)
            except Exception as exc:
                # A broken console (a closed pipe, say) must not stop a flash.
                self.journal.event("progress-display-failed", text=repr(exc))
                self.on_progress = None

    def check(self, package: PackageInfo, target: FirmwareVersion, *, procedure: str,
              accept_unverified: bool) -> None:
        """Offline preconditions; raises FlashRefused before any USB access."""
        if procedure not in PROCEDURES:
            raise FlashRefused(f"Unknown procedure {procedure!r}; known: {', '.join(PROCEDURES)}.")
        if procedure not in self.profile.verified_procedures and not accept_unverified:
            raise FlashRefused(
                f"Procedure {procedure!r} is not verified for {self.profile.name}. Compare "
                "`plan` with a decoded capture of DJI Assistant flashing this model first; "
                "pass accept_unverified only if you accept the risk to the device."
            )
        if procedure == UPGRADE_CENTER:
            check_center_package(self.profile, package)
        else:
            check_package(self.profile, package)
        if package.version is None:
            raise FlashRefused(
                f"The package states no firmware version (no readable manifest in "
                f"{package.config_name}), so it cannot be checked against target {target}."
            )
        if package.version != target:
            raise FlashRefused(f"Package is {package.version}, requested target is {target}.")
        if procedure == UPGRADE_CENTER:
            try:
                self._digests = verify_files(package)
            except PackageError as exc:
                raise FlashRefused(f"{exc} Nothing was sent.") from exc

    def run(
        self, package: PackageInfo, *, target: FirmwareVersion,
        expected_current: FirmwareVersion, confirm: bool = False,
        procedure: str | None = None, accept_unverified: bool = False,
        allow_same_version: bool = False, timeout: float = 1800,
    ) -> FlashResult:
        """``timeout`` is the budget for the upgrade itself, counted from the
        start request; the steps before it have their own short timeouts.
        ``procedure`` defaults to the profile's."""
        if confirm is not True:
            raise FlashRefused("Firmware writes require confirm=True and prepared hardware.")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be finite and positive.")
        procedure = procedure or self.profile.default_procedure
        self.check(package, target, procedure=procedure, accept_unverified=accept_unverified)
        self._procedure = procedure
        self._sender = (self.profile.upgrade_center if procedure == UPGRADE_CENTER
                        else self.profile.target)
        self._result_version = None
        with DeviceLock(self.profile.key):
            started = time.monotonic()
            try:
                self.journal.event(
                    "flash-begin", strict=True, profile=self.profile.key, procedure=procedure,
                    package=str(package.path), sha256=package.sha256, size=package.size,
                    target=str(target), expected_current=str(expected_current),
                    verified=procedure in self.profile.verified_procedures,
                )
            except OSError as exc:
                raise FlashRefused(f"Cannot write the journal: {exc} Nothing was sent.") from exc
            try:
                result = self._run(package, target, expected_current, allow_same_version,
                                   started, timeout)
            except BaseException as exc:
                # Includes Ctrl+C: the device keeps going on its own.
                self.journal.event("flash-end", ok=False, error=type(exc).__name__, text=str(exc))
                raise
            self.journal.event("flash-end", ok=True, installed=str(result.installed),
                               seconds=round(result.seconds, 1))
            return result

    # -- phases ---------------------------------------------------------------

    def _run(self, package, target, expected_current, allow_same_version, started, timeout):
        self._report(Stage.PREFLIGHT)
        try:
            client = self.open_client()
        except TransportError as exc:
            raise FlashRefused(f"{exc} Nothing was sent.") from exc
        center = self._procedure == UPGRADE_CENTER
        # The upgrade may outlive several USB connections; session[0] is the
        # current one and is closed whatever happens.
        session = [client]
        try:
            if center:
                self._center_session(client)
            previous = self._preflight(client, package, target, expected_current,
                                       allow_same_version)
            if center:
                # Assistant greets the aircraft on every connection; the first
                # one was not captured, so do the same as after a reboot.
                self._greet(client)
                acknowledged, early = self._center_start(client, package)
            else:
                self._enter(client)
                self._transfer(client, package)
                acknowledged, early = self._start(client, package)
            # The start request is out. From here the flasher only observes, and
            # nothing may be reported as "safe to retry".
            deadline = time.monotonic() + timeout
            try:
                if center:
                    completion = self._center_watch(session, deadline, acknowledged, early)
                else:
                    completion = self._monitor(client, deadline, acknowledged, early)
            except DumlError:
                raise
            except Exception as exc:
                raise self._unknown(exc) from exc
        finally:
            if session[0] is not None:
                try:
                    session[0].close()
                except Exception:
                    pass
        if early.failure is not None and not completion:
            # A version read-back must not turn a reported failure into success:
            # another module may have failed while the main firmware changed.
            raise FlashOutcomeUnknown(self._early_failure_text(early))
        if center and not completion:
            # The version 0x1F reports cannot vouch for the other modules.
            raise FlashOutcomeUnknown(
                "The upgrade center's verdict (Complete) was not received. Do not retry "
                "automatically; read the device version and check it in DJI Assistant."
            )
        if completion and self._result_version not in (None, target):
            raise FlashOutcomeUnknown(
                f"The device reported Complete/Success but its upgrade center reports "
                f"{self._result_version} installed, not {target}. Do not retry automatically; "
                "inspect the device."
            )
        try:
            installed = self._confirm(target, previous, completion, acknowledged, deadline)
        except DumlError:
            raise
        except Exception as exc:
            raise self._unknown(exc) from exc
        self._report(Stage.DONE, 100, str(installed))
        return FlashResult(previous, installed, completion, time.monotonic() - started)

    @staticmethod
    def _early_failure_text(early: _Early) -> str:
        return (
            f"The device reported {early.failure.result_name} around the start request and "
            "no Complete/Success followed; whether it refers to this request cannot be "
            "proven. Do not retry and do not power off; inspect the device."
        )

    @staticmethod
    def _unknown(exc: Exception) -> FlashOutcomeUnknown:
        return FlashOutcomeUnknown(
            f"Unexpected error after the start request ({type(exc).__name__}: {exc}). "
            "Do not retry and do not power off; read the device version when it is idle."
        )

    def _preflight(self, client, package, target, expected_current, allow_same_version):
        try:
            info = commands.get_version(client, self.profile.target,
                                        timeout=min(2.0, self.command_timeout))
        except (NoReply, TransportError, CommandRejected, UnexpectedReply) as exc:
            raise FlashRefused(f"Cannot read the device version: {exc} Nothing was changed.") from exc
        self.journal.event("device", hardware=info.hardware, firmware=str(info.firmware),
                           loader=str(info.loader), raw=info.raw.hex())
        if not self.profile.matches_hardware(info.hardware):
            raise FlashRefused(
                f"Device reports hardware {info.hardware!r}, expected {self.profile.product_code!r}."
            )
        if info.firmware != expected_current:
            raise FlashRefused(
                f"Device is on {info.firmware}, expected {expected_current}. Nothing was changed."
            )
        if info.firmware == target and not allow_same_version:
            raise FlashRefused(f"Device already runs {target}; pass allow_same_version to reflash.")
        if not package.unchanged():
            raise FlashRefused("Firmware package changed after inspection.")
        return info.firmware

    def _command(self, client, cmd_id: int, payload: bytes, *,
                 timeout: float | None = None, preceding: list[Frame] | None = None) -> None:
        """Send one device-changing command exactly once; never retried."""
        name = commands.command_name(commands.GENERAL, cmd_id)
        reply = client.request(self.profile.target, commands.GENERAL, cmd_id, payload,
                               timeout=timeout or self.command_timeout, retries=0,
                               preceding=preceding)
        commands.require_ok(reply, name)

    def _enter(self, client) -> None:
        self._report(Stage.ENTER)
        try:
            self._command(client, commands.ENTER_UPGRADE, commands.enter_upgrade_payload())
            self._command(client, commands.UPGRADE_REPORT, commands.upgrade_report_payload())
        except (NoReply, CommandRejected, TransportError) as exc:
            raise FlashAborted(
                f"Upgrade mode was not confirmed: {exc} Flashing was not started. "
                "Power-cycle the device before another attempt."
            ) from exc

    def _transfer(self, client, package) -> None:
        self._report(Stage.TRANSFER, 0)
        sent = 0
        outcome: dict = {}
        cancelled = threading.Event()

        def count(size: int) -> None:
            nonlocal sent
            if cancelled.is_set():
                raise OSError("upload cancelled")
            sent += size

        def work() -> None:
            try:
                outcome["md5"] = self.upload(self.profile.ftp_host, package.path, count)
            except BaseException as exc:
                outcome["error"] = exc

        worker = threading.Thread(target=work, name="dji-duml-upload", daemon=True)
        worker.start()
        try:
            while worker.is_alive():
                # Keep draining the IN pipe so device pushes never back up.
                try:
                    for frame in client.poll(self.poll_interval):
                        self._abort_on_failure_push(frame)
                except TransportError as exc:
                    raise FlashAborted(
                        f"USB link lost during transfer: {exc} Flashing was not started."
                    ) from exc
                self._report(Stage.TRANSFER, min(99, sent * 100 // package.size))
        except BaseException:
            # Stop the upload before the lock is released. A blocked socket call
            # ends at its own timeout, hence the generous wait.
            cancelled.set()
            worker.join(self.upload_stop_timeout)
            if worker.is_alive():
                self.journal.event("upload-still-running")
            raise
        worker.join()
        error = outcome.get("error")
        if error is not None:
            if not isinstance(error, Exception):
                raise error
            raise FlashAborted(
                f"Image transfer failed ({type(error).__name__}: {error}). Flashing was not "
                f"started. Is the RNDIS network interface up and {self.profile.ftp_host} "
                "reachable? Power-cycle the device before another attempt."
            ) from error
        if outcome.get("md5") != package.md5 or not package.unchanged():
            raise FlashAborted(
                "Transferred bytes differ from the inspected package. Flashing was not started."
            )
        self._report(Stage.TRANSFER, 100)

    def _abort_on_failure_push(self, frame: Frame) -> None:
        # Before start a failure from any module is a reason not to start.
        status = self._status(frame)
        if status and status.state is commands.UpgradeState.COMPLETE and status.result != 1:
            raise FlashAborted(
                f"Device reported {status.result_name} before start was requested. "
                "Flashing was not started."
            )

    def _settle_before_start(self, client, limit: float | None = None) -> None:
        """Read until the pipe is quiet (at most ``limit`` seconds, default
        command_timeout) and judge all of it as pre-start, so a failure the
        device has already queued stops the start request."""
        deadline = time.monotonic() + (self.command_timeout if limit is None else limit)
        while True:
            try:
                frames = client.poll(self.poll_interval)
            except TransportError as exc:
                raise FlashAborted(
                    f"USB link lost before start: {exc} Flashing was not started."
                ) from exc
            for frame in frames:
                self._abort_on_failure_push(frame)
            if (not frames and not client.parser.pending) or time.monotonic() >= deadline:
                return

    def _early(self, frames: list[Frame]) -> _Early:
        early = _Early()
        for frame in frames:
            status = self._status(frame)
            if status is None:
                continue
            self.journal.event("status-before-reply", sender=f"{frame.sender:#04x}",
                               state=status.state.name, percent=status.percent,
                               result=status.result_name)
            if frame.sender != self._sender:
                early.foreign += 1
                continue
            early.heard = True
            if (early.failure is None and status.state is commands.UpgradeState.COMPLETE
                    and status.result != 1):
                early.failure = status
        return early

    def _start(self, client, package) -> tuple[bool, _Early]:
        """Request the upgrade. Returns whether the request was acknowledged
        (False: sent, but the reply was lost) and what the flashed module
        reported before the reply; from here on the flasher only observes."""
        self._report(Stage.START)
        try:
            self._command(client, commands.UPGRADE_DATA_SIZE,
                          commands.upgrade_size_payload(package.size))
        except (NoReply, CommandRejected, TransportError) as exc:
            raise FlashAborted(
                f"Image size was not accepted: {exc} Flashing was not started."
            ) from exc
        self._settle_before_start(client)
        frames: list[Frame] = []
        try:
            self._command(client, commands.UPGRADE_VERIFY,
                          commands.upgrade_verify_payload(package.md5),
                          timeout=self.start_timeout, preceding=frames)
        except CommandRejected as exc:
            self._early(frames)
            raise FlashFailed(f"Device refused to start the upgrade: {exc}") from exc
        except Exception as exc:
            # The request may or may not have reached the device.
            self.journal.event("start-unacknowledged", error=type(exc).__name__, text=str(exc))
            return False, self._early(frames)
        return True, self._early(frames)

    # -- upgrade center (M4T) --------------------------------------------------

    def _center_session(self, client) -> None:
        """What DJI Assistant keeps up on every connection: it answers the
        upgrade center's 00/81 and 00/82 requests and sends 00/0C from 0x0A to
        0x00 about once a second. Whether the device needs either is untested,
        so both are copied."""
        client.responders[(commands.GENERAL, commands.CENTER_INFO)] = commands.CENTER_INFO_REPLY
        client.responders[(commands.GENERAL, commands.CENTER_STATE)] = \
            commands.CENTER_STATE_REPLY
        client.set_keepalive(1.0, address(PC, 0), 0x00, commands.GENERAL,
                             commands.UPGRADE_REPORT, b"\x00")
        # Progress reports (~10/s) and the device's 81/82 requests (2/s) are
        # counted, not journaled one by one.
        # Gap reports are rare and the evidence for a failed end: journal each.
        client.journal_rx = lambda frame: (
            frame.cmd_set == commands.GENERAL
            and not (self._is_progress(frame) and len(frame.payload) == 5)
            and frame.cmd_id not in (commands.CENTER_INFO, commands.CENTER_STATE))

    def _greet(self, client) -> None:
        """Assistant's routine on each connection. In its five captured
        reconnects the status pushes resumed after it, but in our second run
        they came 1-2 s before it, so it is copied, not relied on. Read-only
        apart from 00/4A, which sets the aircraft clock. Best effort."""
        now = time.localtime()
        clock = (now.tm_year.to_bytes(2, "little")
                 + bytes([now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec])
                 + (-time.timezone // 60).to_bytes(2, "little", signed=True))
        for receiver, cmd_id, payload in (
            (self.profile.target, commands.VERSION_INQUIRY, b""),
            (0x03, commands.VERSION_INQUIRY, b""),
            (0x28, 0x51, b"\x01"),
            (0x68, 0x51, b"\x04"),
            (0x28, 0x4A, clock),
        ):
            try:
                client.request(receiver, commands.GENERAL, cmd_id, payload,
                               timeout=min(2.0, self.command_timeout), retries=0)
            except (NoReply, TransportError) as exc:
                self.journal.event("greet-failed", receiver=f"{receiver:#04x}",
                                   cmd=f"{cmd_id:02x}", text=str(exc))

    def _center_command(self, client, cmd_id: int, payload: bytes, *,
                        timeout: float | None = None, length: int | tuple[int, ...] | None = None,
                        preceding: list[Frame] | None = None) -> Frame:
        """One request to the upgrade center, never retried. ``length`` tells
        the reply from the file transfer progress reports (5 bytes), which also
        arrive as 00/2A responses from the same module."""
        lengths = (length,) if isinstance(length, int) else length
        accept = None if lengths is None else (lambda frame: len(frame.payload) in lengths)
        return client.request(self.profile.upgrade_center, commands.GENERAL, cmd_id, payload,
                              timeout=timeout or self.command_timeout, retries=0,
                              preceding=preceding, accept=accept)

    def _center_start(self, client, package) -> tuple[bool, _Early]:
        self._report(Stage.ENTER)
        try:
            reply = self._center_command(client, commands.UPGRADE_PREPARE,
                                         commands.prepare_payload(),
                                         timeout=max(3.0, self.command_timeout))
            commands.require_ok(reply, "Upgrade Prepare")
            reply = self._center_command(client, commands.UPGRADE_ANNOUNCE,
                                         commands.announce_payload(package.files_size))
            commands.require_ok(reply, "Upgrade Announce")
        except (NoReply, CommandRejected, TransportError) as exc:
            raise FlashAborted(
                f"The upgrade center did not accept the upgrade: {exc} Flashing was not "
                "started. Power-cycle the device before another attempt."
            ) from exc
        try:
            self._send_files(client, package)
        except (FlashAborted, FlashFailed, FlashOutcomeUnknown, FlashRefused):
            raise
        except Exception as exc:
            # Package read errors (PackageError too) and the like: upgrade mode
            # was entered, nothing was installed yet.
            raise FlashAborted(
                f"Transfer stopped ({type(exc).__name__}: {exc}). Flashing was not started. "
                "Power-cycle the device before another attempt."
            ) from exc
        return self._center_install(client)

    def _send_files(self, client, package) -> None:
        self._report(Stage.TRANSFER, 0)
        total, done = package.files_size, 0
        for position, item in enumerate(package.files):
            name = sent_name(package, position)
            started = time.monotonic()
            # Reports still queued, or arriving before the open reply, belong to
            # the previous file (one was seen between an end and its reply).
            self._drop_progress(client)
            stale: list[Frame] = []
            try:
                reply = self._center_command(client, commands.FILE_TRANSFER,
                                             commands.file_open_payload(name, item.size),
                                             length=(7, 1), preceding=stale)
                chunk = commands.parse_file_open_reply(reply.payload, f"Open of {name}")
            except (NoReply, CommandRejected, UnexpectedReply, TransportError) as exc:
                raise FlashAborted(
                    f"{exc} Flashing was not started. Power-cycle the device before "
                    "another attempt."
                ) from exc
            for frame in stale:
                self._abort_on_failure_push(frame)
            digest = hashlib.md5()
            index, progress, batch = 0, -1, []
            resend = _Resend(package, item.name, name, chunk)
            with open_file(package, item.name) as handle:
                while block := handle.read(chunk):
                    if index > progress + WINDOW:
                        self._flush(client, batch)
                        batch = []
                        progress = self._await_progress(client, progress, index - WINDOW,
                                                        index - 1, name, resend)
                    payload = commands.file_data_payload(index, block)
                    batch.append(payload)
                    resend.keep(index, payload)
                    digest.update(block)
                    index += 1
                    done += len(block)
                    if len(batch) >= BATCH:
                        self._flush(client, batch)
                        batch = []
                        self._report(Stage.TRANSFER, min(99, done * 100 // total))
            self._flush(client, batch)
            if index:
                # The device sends a gap report in place of a progress report,
                # so the end goes out only after a plain report of the last
                # chunk that came after everything sent again.
                self._await_progress(client, progress, index - 1, index - 1, name, resend)
            if digest.digest() != self._digests.get(item.name) or not package.unchanged():
                raise FlashAborted(
                    f"{item.name!r} changed after it was verified. Flashing was not started. "
                    "Power-cycle the device before another attempt."
                )
            try:
                reply = self._center_command(client, commands.FILE_TRANSFER,
                                             commands.file_end_payload(digest.digest()),
                                             length=1)
                commands.require_ok(reply, f"End of {name}")
            except (NoReply, CommandRejected, TransportError) as exc:
                raise FlashAborted(
                    f"{exc} Flashing was not started. Power-cycle the device before "
                    "another attempt."
                ) from exc
            self.journal.event("file-sent", name=name, size=item.size, chunks=index,
                               md5=digest.hexdigest(),
                               seconds=round(time.monotonic() - started, 2))
        self._report(Stage.TRANSFER, 100)

    def _flush(self, client, batch: list[bytes]) -> None:
        if not batch:
            return
        try:
            client.send_batch(self.profile.upgrade_center, commands.GENERAL,
                              commands.FILE_TRANSFER, batch, ack=AckType.AFTER_EXEC)
        except TransportError as exc:
            raise FlashAborted(
                f"USB link lost during transfer: {exc} Flashing was not started."
            ) from exc

    def _is_progress(self, frame: Frame) -> bool:
        """A progress report, or the gap report the device sends in its place."""
        return (frame.response and frame.sender == self.profile.upgrade_center
                and frame.cmd_set == commands.GENERAL
                and frame.cmd_id == commands.FILE_TRANSFER and len(frame.payload) in (5, 13))

    def _drop_progress(self, client) -> None:
        if any(self._is_progress(frame) for frame in client.inbox):
            kept = [frame for frame in client.inbox if not self._is_progress(frame)]
            client.inbox.clear()
            client.inbox.extend(kept)

    def _await_progress(self, client, progress: int, need: int, last_sent: int,
                        name: str, resend: "_Resend | None" = None) -> int:
        """Read until the device reports chunk ``need`` of the open file. The
        reports come on a ~100 ms timer; a stall of command_timeout aborts. A
        report beyond ``last_sent`` cannot be about this file and is ignored.
        A gap report gets the missing chunks sent again at once, as Assistant
        does; only a plain report counts as progress. Of the reports read
        together only the newest counts: they queue up while the host writes."""
        stalled = moved = time.monotonic()
        stalled += self.command_timeout
        last_gap, steady = None, 0  # steady: plain reports of ``progress`` since ``moved``
        while progress < need:
            now = time.monotonic()
            if now > stalled:
                raise FlashAborted(
                    f"The upgrade center stopped acknowledging {name} at chunk {progress}. "
                    "Flashing was not started. Power-cycle the device before another attempt."
                )
            if (resend is not None and need == last_sent and now - moved >= TAIL_WAIT
                    and steady >= 2 and last_sent - progress <= TAIL_LIMIT):
                self._send_tail(client, progress, last_sent, name, resend, now)
                moved, steady = now, 0
            try:
                frames = client.poll(min(self.poll_interval, 0.05))
            except TransportError as exc:
                raise FlashAborted(
                    f"USB link lost during transfer: {exc} Flashing was not started."
                ) from exc
            report = None
            for frame in frames:
                self._abort_on_failure_push(frame)
                if self._is_progress(frame):
                    report = frame.payload
            if report is None:
                continue
            now = time.monotonic()
            if len(report) == 13:
                try:
                    gap = commands.parse_file_gap(report)
                except UnexpectedReply as exc:
                    self.journal.event("gap-unparsed", text=str(exc))
                    continue
                if gap != last_gap:
                    # A new gap is the device talking; the same one again is not.
                    last_gap, moved, stalled = gap, now, now + self.command_timeout
                self._send_again(client, gap, last_sent, name, resend, now)
                continue
            try:
                reported = commands.parse_file_progress(report)
            except UnexpectedReply as exc:
                self.journal.event("progress-unparsed", text=str(exc))
                continue
            if reported > last_sent:
                self.journal.event("progress-ignored", file=name, reported=reported,
                                   sent=last_sent)
                continue
            last_gap = None
            if resend is not None:
                resend.settled()
            if reported > progress:
                progress, moved, stalled = reported, now, now + self.command_timeout
                steady = 0
            elif reported == progress:
                steady += 1
        return progress

    def _send_again(self, client, gap: tuple[int, int, int], last_sent: int, name: str,
                    resend: "_Resend | None", now: float) -> None:
        highest, first, count = gap
        if highest > last_sent:
            self.journal.event("gap-ignored", file=name, highest=highest, first=first,
                               count=count, sent=last_sent)
            return
        if resend is None or count < 1 or first + count - 1 > last_sent:
            raise FlashAborted(
                f"The upgrade center asks for chunks {first}+{count} of {name}, which "
                f"cannot be right (highest received {highest}, sent {last_sent}). Flashing "
                "was not started. Power-cycle the device before another attempt."
            )
        due = resend.due(first, count, highest, now)
        if due:
            self._resend(client, due, last_sent, name, resend, now, highest=highest)

    def _send_tail(self, client, progress: int, last_sent: int, name: str,
                   resend: "_Resend", now: float) -> None:
        """The device stays just short of the end of the file: its last
        chunks may have been lost, which it cannot see. They go again in
        order, so the device can only take them as normal data."""
        self._resend(client, list(range(progress + 1, last_sent + 1)), last_sent, name,
                     resend, now, tail=True)

    def _resend(self, client, indexes: list[int], last_sent: int, name: str,
                resend: "_Resend", now: float, **detail) -> None:
        if resend.count + len(indexes) > RESEND_LIMIT:
            raise FlashAborted(
                f"The upgrade center kept reporting chunks of {name} missing after "
                f"{resend.count} were sent again. Flashing was not started. Power-cycle "
                "the device before another attempt."
            )
        payloads, reread = resend.payloads(indexes)
        self._flush(client, payloads)
        resend.sent(indexes, last_sent, now)
        self.journal.event("chunks-resent", file=name, first=indexes[0], count=len(indexes),
                           reread=reread, **detail)

    def _center_install(self, client) -> tuple[bool, _Early]:
        """00/85 starts the installation; Assistant saw the reply 06. M4T
        telemetry never lets the pipe go quiet, and Assistant sends 00/85 within
        2 ms of the last end reply, so the drain before it is short."""
        self._settle_before_start(client, limit=0.3)
        self._report(Stage.START)
        frames: list[Frame] = []
        try:
            reply = self._center_command(client, commands.UPGRADE_INSTALL,
                                         commands.install_payload(), timeout=self.start_timeout,
                                         length=1, preceding=frames)
        except Exception as exc:
            # The request may or may not have reached the device.
            self.journal.event("start-unacknowledged", error=type(exc).__name__, text=str(exc))
            return False, self._early(frames)
        self.journal.event("install-reply", payload=reply.payload.hex())
        # 06 is the only answer seen; anything else is not proof the install began.
        return reply.payload == b"\x06", self._early(frames)

    def _center_watch(self, session: list, deadline: float, acknowledged: bool,
                      early: _Early) -> bool:
        """Watch the upgrade center's status pushes through the reboots it
        performs on its own (one for a refresh, two for a version change).
        Returns True on Complete/Success. Nothing is sent but the session
        traffic, the reconnect greeting and, after Complete, 00/4F and 00/41."""
        self._report(Stage.VERIFY)
        alive = (acknowledged or early.heard) and early.failure is None
        silence = None if alive else time.monotonic() + self.start_timeout
        ignored = early.foreign
        greet_at = lost_at = None
        while time.monotonic() < deadline:
            if greet_at is not None and time.monotonic() >= greet_at and session[0] is not None:
                greet_at = None
                self._greet(session[0])
            if silence is not None and time.monotonic() > silence:
                if early.failure is not None:
                    raise FlashOutcomeUnknown(self._early_failure_text(early))
                raise FlashOutcomeUnknown(
                    "Start request was sent but neither acknowledged nor followed by a "
                    "status push from the upgrade center"
                    + (f" ({ignored} from other modules were ignored)" if ignored else "")
                    + ". Do not retry and do not power off; read the device version when "
                    "it is idle."
                )
            client = session[0]
            if client is None:
                client = self._reconnect(deadline)
                if client is None:
                    break
                session[0] = client
                self._center_session(client)
                self.journal.event(
                    "reconnected", location=getattr(client.transport, "location", None),
                    seconds=round(time.monotonic() - lost_at, 1) if lost_at else None)
                greet_at = time.monotonic() + self.greet_delay
                continue
            try:
                frames = client.poll(self.poll_interval)
            except TransportError as exc:
                # The device reboots by itself while installing; keep listening.
                self.journal.event("link-lost", text=str(exc))
                self._report(Stage.REBOOT)
                try:
                    client.close()
                except Exception:
                    pass
                session[0] = None
                greet_at, lost_at = None, time.monotonic()
                continue
            for frame in frames:
                status = self._status(frame)
                if status is None:
                    continue
                if frame.sender != self._sender:
                    ignored += 1
                    self.journal.event("status-ignored", reason="not from the upgrade center",
                                       sender=f"{frame.sender:#04x}",
                                       receiver=f"{frame.receiver:#04x}")
                    continue
                silence = None
                if status.state is commands.UpgradeState.COMPLETE:
                    if status.result != 1:
                        raise FlashFailed(f"Device reported upgrade result {status.result_name}.")
                    self._center_finish(client)
                    return True
                if status.state is commands.UpgradeState.UPGRADING:
                    self._report(Stage.UPGRADING, status.percent)
                elif status.state is commands.UpgradeState.USER_CONFIRM:
                    self._report(Stage.USER_CONFIRM, detail="confirm on the device or controller")
                else:
                    self._report(Stage.VERIFY)
        self.journal.event("monitor-timeout")
        return False

    def _reconnect(self, deadline: float):
        while time.monotonic() < deadline:
            try:
                return self.open_client()
            except Exception as exc:
                self.journal.event("reconnect-wait", error=type(exc).__name__, text=str(exc))
            self.sleep(self.reconnect_interval)
        return None

    def _center_finish(self, client) -> None:
        """Assistant's closing pair, sent right after Complete/Success: 00/4F
        returns the installed package version, 00/41 [04] likely ends the
        pushes. Neither failing changes the verdict."""
        timeout = max(2.0, self.command_timeout)
        try:
            reply = self._center_command(client, commands.UPGRADE_RESULT,
                                         commands.result_query_payload(), timeout=timeout,
                                         length=13)
            self._result_version = commands.parse_result_reply(reply.payload)
            self.journal.event("result", version=str(self._result_version))
        except (NoReply, CommandRejected, UnexpectedReply, TransportError) as exc:
            self.journal.event("result-unavailable", text=str(exc))
        try:
            reply = self._center_command(client, commands.PUSH_CONTROL,
                                         commands.push_control_payload(), timeout=timeout)
            self.journal.event("push-control", payload=reply.payload.hex())
        except (NoReply, TransportError) as exc:
            self.journal.event("push-control-failed", text=str(exc))

    def _status(self, frame: Frame):
        """Parse an upgrade status push from any module."""
        if frame.response or frame.cmd_set != commands.GENERAL \
                or frame.cmd_id != commands.UPGRADE_STATUS:
            return None
        try:
            return commands.parse_upgrade_status(frame.payload)
        except UnexpectedReply as exc:
            self.journal.event("status-unparsed", text=str(exc))
            return None

    def _monitor(self, client, deadline: float, acknowledged: bool, early: _Early) -> bool:
        """Watch status pushes from the flashed module. Returns True when
        Complete/Success was seen.

        Only observes: a read error or a timeout is not a verdict, it hands
        over to the version read-back that follows. Without a sign of life, or
        after an early failure, the device must speak within start_timeout.
        """
        self._report(Stage.VERIFY)
        alive = (acknowledged or early.heard) and early.failure is None
        silence = None if alive else time.monotonic() + self.start_timeout
        ignored = early.foreign
        while time.monotonic() < deadline:
            if silence is not None and time.monotonic() > silence:
                if early.failure is not None:
                    raise FlashOutcomeUnknown(self._early_failure_text(early))
                raise FlashOutcomeUnknown(
                    "Start request was sent but neither acknowledged nor followed by a "
                    "status push from the flashed module"
                    + (f" ({ignored} from other modules were ignored)" if ignored else "")
                    + ". Do not retry and do not power off; read the device version when "
                    "it is idle."
                )
            try:
                frames = client.poll(self.poll_interval)
            except TransportError as exc:
                self.journal.event("link-lost", text=str(exc))
                return False
            for frame in frames:
                status = self._status(frame)
                if status is None:
                    continue
                if frame.sender != self._sender:
                    ignored += 1
                    self.journal.event("status-ignored", reason="not from the flashed module",
                                       sender=f"{frame.sender:#04x}",
                                       receiver=f"{frame.receiver:#04x}")
                    continue
                silence = None
                if status.state is commands.UpgradeState.COMPLETE:
                    if status.result != 1:
                        raise FlashFailed(f"Device reported upgrade result {status.result_name}.")
                    return True
                if status.state is commands.UpgradeState.UPGRADING:
                    self._report(Stage.UPGRADING, status.percent)
                elif status.state is commands.UpgradeState.USER_CONFIRM:
                    self._report(Stage.USER_CONFIRM, detail="confirm on the device or controller")
                else:
                    self._report(Stage.VERIFY)
        self.journal.event("monitor-timeout")
        return False

    def _confirm(self, target, previous, completion: bool, acknowledged: bool,
                 deadline: float) -> FirmwareVersion:
        """Reconnect after the reboot and read the installed version."""
        self._report(Stage.CONFIRM if completion else Stage.REBOOT)
        if previous == target and not completion:
            raise FlashOutcomeUnknown(
                "Same-version reflash: the device did not report completion, and the "
                "version cannot show whether it happened. Do not retry automatically; "
                "inspect the device."
            )
        # Always leave room for at least one settle period of read-backs.
        deadline = max(deadline, time.monotonic() + self.settle_timeout)
        patient = acknowledged and not completion  # still upgrading after a link loss
        seen = None
        unchanged_since = None
        while time.monotonic() < deadline:
            try:
                client = self.open_client()
                try:
                    seen = commands.get_version(client, self.profile.target, retries=0).firmware
                finally:
                    client.close()
            except Exception as exc:
                # Any failure here only means "not back yet".
                self.journal.event("reconnect-wait", error=type(exc).__name__, text=str(exc))
            else:
                if seen == NOT_READY:
                    # 0x1F is still starting after a reboot.
                    self.journal.event("version-not-ready")
                    self.sleep(self.reconnect_interval)
                    continue
                if seen == target:
                    return seen
                if seen != previous:
                    break
                unchanged_since = unchanged_since or time.monotonic()
                if not patient and time.monotonic() - unchanged_since >= self.settle_timeout:
                    break
            self.sleep(self.reconnect_interval)
        raise FlashOutcomeUnknown(
            f"Upgrade {'completed' if completion else 'not confirmed'} by the device, but the "
            f"version read back is {seen if seen is not None else 'unavailable'}, not {target}. "
            "Do not retry automatically; inspect the device."
        )
