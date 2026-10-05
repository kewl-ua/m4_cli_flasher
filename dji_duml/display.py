"""Console view of a flash.

Each stage gets one line. The transfer and the device's install percentage
are redrawn in place on a terminal, with a bar, and for the transfer also the
speed and the time left; redirected to a file or a pipe, they are printed in
10 % steps instead, so a log stays readable. ``verbose`` prints every
progress report on its own line, as dji-duml always did.
"""
from __future__ import annotations

import shutil
import sys
import time
from typing import TextIO

from .flasher import Progress, Stage

_BAR = 30
_TAIL = 30  # room kept after the bar, so the bar keeps its width as the text grows
_STEP = 10  # percent between lines when not on a terminal
_LABELS = {Stage.USER_CONFIRM: "waiting", Stage.REBOOT: "reboot"}
_NOTES = {Stage.REBOOT: "the device restarts; reconnecting",
          Stage.START: "requesting the install",
          Stage.CONFIRM: "the device reports success; reading the installed version"}


def _clock() -> str:
    return time.strftime("%H:%M:%S")


def _duration(seconds: float) -> str:
    seconds = max(0, int(seconds + 0.5))
    return f"{seconds // 60}:{seconds % 60:02d}"


class ProgressView:
    """Feed it Flasher progress reports (it is the ``on_progress`` callback);
    use it as a context manager so an open line is ended on any exit."""

    def __init__(self, total_bytes: int | None = None, *, verbose: bool = False,
                 stream: TextIO | None = None, interactive: bool | None = None,
                 monotonic=time.monotonic):
        self.stream = stream if stream is not None else sys.stdout
        self.total_bytes = total_bytes
        self.verbose = verbose
        if interactive is None:
            isatty = getattr(self.stream, "isatty", None)
            interactive = bool(isatty and isatty())
        self.interactive = interactive
        self.monotonic = monotonic
        self._stage: Stage | None = None
        self._started = 0.0      # when the current stage began
        self._installing = ""    # wall-clock time the install was requested
        self._stamp = ""         # wall-clock time the current stage began
        self._printed = -1       # last percent printed when not interactive
        self._held: tuple[Stage, int] | None = None  # a percent not printed yet
        self._open = 0           # length of the line being redrawn, 0 if none
        self._broken = False     # the stream failed: show nothing more

    def __enter__(self) -> "ProgressView":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        """End a line that is being redrawn, or print a held-back percent."""
        held, self._held = self._held, None
        if held is not None and held[1] != self._printed:
            self._printed = held[1]
            self._line(self._text(held[0], held[1], 0, _clock()))
        if self._open:
            self._open = 0
            self._write("\n")

    def __call__(self, progress: Progress) -> None:
        if self._broken:
            return
        if self.verbose:
            percent = "" if progress.percent is None else f" {progress.percent:3d}%"
            detail = f" {progress.detail}" if progress.detail else ""
            self._line(f"[{_clock()}] {progress.stage.value}{percent}{detail}")
            return
        if progress.stage is not self._stage:
            self.close()
            self._stage, self._started, self._stamp = progress.stage, self.monotonic(), _clock()
            self._printed = -1
            if progress.stage is Stage.START:
                self._installing = self._stamp
            if progress.percent is None or progress.stage is Stage.DONE:
                self._line(self._plain(progress))
                return
        elif progress.percent is None:
            return
        self._show(progress)

    def _plain(self, progress: Progress) -> str:
        label = _LABELS.get(progress.stage, progress.stage.value)
        detail = progress.detail or _NOTES.get(progress.stage, "")
        return f"[{self._stamp}] {label}" + (f"  {detail}" if detail else "")

    def _show(self, progress: Progress) -> None:
        percent = max(0, min(100, progress.percent))
        if not self.interactive:
            if percent != self._printed and (
                    self._printed < 0 or percent == 100 or percent >= self._printed + _STEP):
                self._held = None
                self._printed = percent
                self._line(self._text(progress.stage, percent, 0, _clock()))
            else:
                self._held = (progress.stage, percent)
            return
        width = shutil.get_terminal_size((80, 24)).columns - 1
        text = self._text(progress.stage, percent, width, self._stamp)
        self._write("\r" + text.ljust(min(self._open, width)))
        self._open = len(text)

    def _text(self, stage: Stage, percent: int, width: int, stamp: str) -> str:
        elapsed = self.monotonic() - self._started
        extra = ""
        if stage is Stage.TRANSFER:
            if percent >= 100:
                extra = f"in {_duration(elapsed)}"
            elif percent > 0 and elapsed > 0:
                left = elapsed * (100 - percent) / percent
                extra = f"{_duration(left)} left"
            if self.total_bytes and elapsed > 0 and percent > 0:
                speed = self.total_bytes * percent / 100 / elapsed / 1e6
                extra = f"{speed:.1f} MB/s  {extra}"
        elif stage is Stage.UPGRADING and self._installing:
            # The device reports rarely; a running clock would freeze between reports.
            extra = f"install since {self._installing}"
        head = f"[{stamp}] {stage.value:<9} "
        tail = f" {percent:3d}%" + (f"  {extra}" if extra else "")
        bar = _BAR
        if width and len(head) + bar + 2 + _TAIL > width:
            bar = max(10, width - len(head) - _TAIL - 2)
        filled = bar * percent // 100
        text = f"{head}[{'#' * filled}{'-' * (bar - filled)}]{tail}"
        return text[:width] if width else text

    def _line(self, text: str) -> None:
        if self._open:
            self._open = 0
            self._write("\n")
        self._write(text + "\n")

    def _write(self, text: str) -> None:
        if self._broken:
            return
        try:
            self.stream.write(text)
            self.stream.flush()
        except (OSError, ValueError):
            # A closed pipe or console: the flash goes on, the journal has it all.
            self._broken = True
