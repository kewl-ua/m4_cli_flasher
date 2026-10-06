"""Synchronous request/reply client on top of a byte transport."""
from __future__ import annotations

import secrets
import time
from collections import Counter, deque
from collections.abc import Callable
from typing import Protocol

from .errors import NoReply, TransportError
from .frame import AckType, Frame, StreamParser
from .journal import Journal


class Transport(Protocol):
    def write(self, data: bytes) -> None: ...
    def read(self, timeout: float) -> bytes: ...
    def close(self) -> None: ...


#: Seconds between journal summaries of frames that are only counted.
SUMMARY_INTERVAL = 10.0


def general_set(frame: Frame) -> bool:
    """Default journal filter. The general set carries versions, upgrade
    commands and statuses; on the M4T everything else is telemetry, about
    1400 frames/s, too much to journal (and fsync) one by one."""
    return frame.cmd_set == 0


class DumlClient:
    """One request at a time; everything that is not the awaited reply is queued
    (or handed to the caller, see ``request(preceding=...)``).

    Requests are retried only when the caller says so; commands that change
    the device must keep ``retries=0``.
    """

    def __init__(self, transport: Transport, *, host: int, journal: Journal | None = None,
                 journal_rx: Callable[[Frame], bool] = general_set):
        self.transport = transport
        self.host = host
        self.journal = journal or Journal()
        #: Received frames it accepts are journaled one by one; the rest are
        #: only counted and summarised every SUMMARY_INTERVAL seconds.
        self.journal_rx = journal_rx
        #: Unsolicited frames it accepts are queued (inbox, ``preceding``); the
        #: rest are dropped after counting, so telemetry cannot crowd them out.
        self.keep: Callable[[Frame], bool] = general_set
        self.parser = StreamParser()
        self.inbox: deque[Frame] = deque(maxlen=65536)
        self._seq = secrets.randbelow(0x10000)
        self.stall_timeout = 0.2
        self._stalled: float | None = None
        self._counted: Counter[str] = Counter()
        self._summary_due = time.monotonic() + SUMMARY_INTERVAL
        #: Fixed replies to requests the device sends to this host, keyed by
        #: (cmd_set, cmd_id); such requests are answered and not passed on.
        self.responders: dict[tuple[int, int], bytes] = {}
        self._keepalive: tuple[float, Callable[[], Frame]] | None = None
        self._keepalive_due = 0.0
        self._deferred: TransportError | None = None

    def set_keepalive(self, interval: float, sender: int, receiver: int, cmd_set: int,
                      cmd_id: int, payload: bytes = b"") -> None:
        """Send this frame every ``interval`` seconds while reading. Not
        journaled one by one: it is periodic, like telemetry."""
        def build() -> Frame:
            return Frame(sender, receiver, self._next_seq(), cmd_set, cmd_id, payload)
        self._keepalive = (interval, build)
        self._keepalive_due = time.monotonic()

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0xFFFF
        return self._seq

    def _write(self, frame: Frame, *, log: bool = True) -> None:
        raw = frame.encode()
        if log:
            self.journal.event("tx", sync=False, frame=raw.hex(), text=frame.describe())
        self.transport.write(raw)

    def _write_later(self, frame: Frame, *, log: bool = True) -> None:
        """Write from inside a read without losing what that read returned:
        a failure is raised by the next read instead."""
        if self._deferred is not None:
            return
        try:
            self._write(frame, log=log)
        except TransportError as exc:
            self._deferred = exc

    def _read(self, timeout: float) -> list[Frame]:
        if self._deferred is not None:
            error, self._deferred = self._deferred, None
            raise error
        data = self.transport.read(timeout)
        frames = self.parser.feed(data)
        now = time.monotonic()
        # Progress means frames, not bytes: on the M4T telemetry keeps bytes
        # coming while a bogus header holds every frame behind it.
        if frames or not self.parser.pending:
            self._stalled = None
        elif self._stalled is None:
            self._stalled = now
        elif now - self._stalled >= self.stall_timeout:
            # An incomplete candidate has been blocking the stream: drop it.
            frames = self.parser.resync()
            self._stalled = None
        passed = []
        for frame in frames:
            if self.journal_rx(frame):
                self.journal.event("rx", sync=False, frame=frame.encode().hex(),
                                   text=frame.describe())
            else:
                self._counted[f"{frame.sender:#04x}>{frame.receiver:#04x} "
                              f"{frame.cmd_set:02x}/{frame.cmd_id:02x}"] += 1
            answer = self.responders.get((frame.cmd_set, frame.cmd_id))
            if answer is not None and not frame.response and frame.receiver == self.host:
                self._counted[f"answered {frame.cmd_set:02x}/{frame.cmd_id:02x}"] += 1
                self._write_later(frame.make_reply(answer), log=False)
            else:
                passed.append(frame)
        if self._keepalive is not None and now >= self._keepalive_due:
            interval, build = self._keepalive
            self._keepalive_due = now + interval
            self._counted["keepalive sent"] += 1
            self._write_later(build(), log=False)
        if self._counted and now >= self._summary_due:
            self._summarize(now)
        return passed

    def _summarize(self, now: float) -> None:
        self.journal.event("rx-counted", frames=dict(self._counted))
        self._counted.clear()
        self._summary_due = now + SUMMARY_INTERVAL

    def build(self, receiver: int, cmd_set: int, cmd_id: int, payload: bytes = b"",
              *, ack: AckType = AckType.AFTER_EXEC) -> Frame:
        return Frame(self.host, receiver, self._next_seq(), cmd_set, cmd_id, payload, ack=ack)

    def send(self, receiver: int, cmd_set: int, cmd_id: int, payload: bytes = b"", *,
             log: bool = True, ack: AckType = AckType.NONE) -> Frame:
        """Send without waiting. ``log=False`` keeps bulk data out of the
        journal; the caller journals a summary instead."""
        frame = self.build(receiver, cmd_set, cmd_id, payload, ack=ack)
        self._write(frame, log=log)
        return frame

    def send_frame(self, frame: Frame, *, log: bool = True) -> Frame:
        """Send a pre-built frame as-is, without waiting for a reply. For a
        custom sender or sequence number the ``send``/``request`` helpers do not
        set (they always use ``self.host`` and the running sequence)."""
        self._write(frame, log=log)
        return frame

    def send_batch(self, receiver: int, cmd_set: int, cmd_id: int, payloads, *,
                   ack: AckType = AckType.NONE, transfer: int = 2048) -> int:
        """Send many frames without waiting and without journaling them, as one
        byte stream cut into ``transfer``-byte USB writes (DJI Assistant writes
        2048 bytes at a time and lets frames span writes). Returns the count."""
        stream = bytearray()
        count = 0
        for payload in payloads:
            stream += self.build(receiver, cmd_set, cmd_id, payload, ack=ack).encode()
            count += 1
        for offset in range(0, len(stream), transfer):
            self.transport.write(bytes(stream[offset:offset + transfer]))
        return count

    def request(self, receiver: int, cmd_set: int, cmd_id: int, payload: bytes = b"",
                *, timeout: float = 2.0, retries: int = 0,
                preceding: list[Frame] | None = None,
                accept: Callable[[Frame], bool] | None = None) -> Frame:
        """Send and wait for the reply. Other frames go to the inbox, except
        that frames received ahead of the reply go to ``preceding`` when it is
        given: the device sent them before it answered. ``accept`` narrows what
        counts as the reply when the device also sends unsolicited frames that
        look like replies (M4T file transfer progress)."""
        early = self.inbox if preceding is None else preceding
        for _ in range(retries + 1):
            frame = self.build(receiver, cmd_set, cmd_id, payload)
            self._write(frame)
            deadline = time.monotonic() + timeout
            while (remaining := deadline - time.monotonic()) > 0:
                reply = None
                for incoming in self._read(min(remaining, 0.25)):
                    if reply is None and incoming.answers(frame)                             and (accept is None or accept(incoming)):
                        reply = incoming
                    elif not self.keep(incoming):
                        continue
                    elif reply is None:
                        early.append(incoming)
                    else:
                        self.inbox.append(incoming)
                if reply is not None:
                    return reply
        raise NoReply(
            f"No reply to set={cmd_set:02x} id={cmd_id:02x} from {receiver:#04x} "
            f"after {retries + 1} attempt(s)."
        )

    def poll(self, timeout: float) -> list[Frame]:
        """Return queued and newly received unsolicited frames.

        Frames that were already received are returned even if this read
        fails; the error then surfaces on the next call.
        """
        try:
            self.inbox.extend(frame for frame in self._read(timeout) if self.keep(frame))
        except TransportError:
            if not self.inbox:
                raise
        frames = list(self.inbox)
        self.inbox.clear()
        return frames

    def close(self) -> None:
        if self._counted:
            self._summarize(time.monotonic())
        self.transport.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
