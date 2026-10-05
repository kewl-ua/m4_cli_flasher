class DumlError(RuntimeError):
    """Base error of the direct DUML backend."""


class TransportError(DumlError):
    """USB device missing, busy or disconnected."""


class NoReply(DumlError):
    """The device did not answer a request in time."""


class CommandRejected(DumlError):
    def __init__(self, command: str, status: int):
        self.status = status
        super().__init__(f"Device rejected {command}: status 0x{status:02X}.")


class UnexpectedReply(DumlError):
    """A reply arrived but does not have the layout the profile expects."""


class PackageError(DumlError):
    """The firmware package is malformed or is for another product."""


class FlashRefused(DumlError):
    """A precondition failed. Nothing was sent that changes the device."""


class WriteRefused(DumlError):
    """A parameter write precondition failed (bad value, range, stale
    expectation or a missing authorization). Nothing that changes the
    device was sent."""


class WriteFailed(DumlError):
    """A parameter write was sent, but reading the value back does not show
    the value that was requested. The device's state is whatever the
    read-back reported; it is named so the old value can be restored."""

    def __init__(self, message: str, *, read_back: int | float | None = None):
        self.read_back = read_back
        super().__init__(message)


class FlashAborted(DumlError):
    """Stopped after upgrade mode was entered but before start was requested."""


class FlashFailed(DumlError):
    """The device itself reported that the upgrade failed."""


class FlashOutcomeUnknown(DumlError):
    """The start request may have been delivered. Never retry automatically."""
