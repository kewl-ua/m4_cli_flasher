"""Append-only JSONL audit log: one line per frame, state change and decision."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path


class Journal:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._file = None
        self.error: OSError | None = None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(self.path, "a", encoding="utf-8")

    def event(self, kind: str, *, strict: bool = False, sync: bool = True, **fields) -> None:
        """Write one record. A write failure disables the journal instead of
        interrupting the caller, unless ``strict`` is set. ``sync=False``
        skips the fsync (the record still reaches the OS): an fsync per frame
        stalled reading for up to 0.5 s on a real M4T and lost a frame."""
        if self._file is None:
            if strict and self.error is not None:
                raise self.error
            return
        record = {"t": round(time.time(), 3), "event": kind, **fields}
        try:
            self._file.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            self._file.flush()
            if sync:
                os.fsync(self._file.fileno())
        except OSError as exc:
            self.error = exc
            try:
                self._file.close()
            except OSError:
                pass
            self._file = None
            if strict:
                raise

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
