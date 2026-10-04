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


class FlashAborted(DumlError):
    """Stopped after upgrade mode was entered but before start was requested."""


class FlashFailed(DumlError):
    """The device itself reported that the upgrade failed."""


class FlashOutcomeUnknown(DumlError):
    """The start request may have been delivered. Never retry automatically."""
