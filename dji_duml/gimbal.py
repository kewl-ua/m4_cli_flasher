"""Gimbal calibration triggers, reverse-engineered from the "DJI Gimbal
Calibration Tool" (Dr. Failov / QUADRO.UA) talking DUML to a live M4T on 2026-10-06.

All three calibrations are the *same* command -- gimbal set ``0x04``, id ``0x08``,
to the gimbal (``0x04``) -- with a one-byte selector, sent fire-and-forget (the
M4T sends no reply; ``ack`` is AFTER_EXEC, as the tool uses, and goes unanswered).
The tool sends DevMode as the camera (``0x02``) and the other two as the app
(``0x0A``); those exact senders are replicated here.

Only **DevMode** was observed to actually run on the M4T. JointCoarse and Linear
Hall are the same command with a different selector, but did not complete on the
M4T in testing (the tool is written for the Mavic 3 stereo-vision gimbal; what
looked like a Linear Hall calibration was likely the normal recenter after the
factory-mode reboot). They are kept here, marked unconfirmed, behind ``--force``.

These are ACTION commands: they start a calibration and move the gimbal.
"""
from __future__ import annotations

from dataclasses import dataclass

from .frame import Frame

GIMBAL_SET = 0x04        #: gimbal command set
CALIBRATE = 0x08         #: 04/08 -- the calibration trigger
GIMBAL_ADDRESS = 0x04    #: the gimbal (device type 4, index 0)
CAMERA_SENDER = 0x02     #: DevMode: the tool sends as the camera (device type 2)
APP_SENDER = 0x0A        #: JointCoarse/Linear Hall: the tool sends as the app (type 10, index 0)


@dataclass(frozen=True)
class Calibration:
    name: str
    selector: int
    sender: int
    confirmed: bool
    note: str


#: The gimbal calibrations the tool exposes, by CLI name.
CALIBRATIONS: dict[str, Calibration] = {
    "dev-mode": Calibration("DevMode", 0x71, CAMERA_SENDER, True,
                            "confirmed to run on the M4T"),
    "joint-coarse": Calibration("JointCoarse", 0x01, APP_SENDER, False,
                                "not confirmed on the M4T (did not complete in testing)"),
    "linear-hall": Calibration("Linear Hall", 0x02, APP_SENDER, False,
                               "not confirmed on the M4T (did not complete in testing)"),
}


def build(kind: str) -> Frame:
    """The gimbal-calibration frame the tool sends for ``kind`` (sequence 0, as
    the tool uses it). Fire-and-forget -- send it, expect no reply."""
    cal = CALIBRATIONS[kind]
    return Frame(cal.sender, GIMBAL_ADDRESS, 0, GIMBAL_SET, CALIBRATE, bytes([cal.selector]))


def calibrate(client, kind: str) -> Frame:
    """Send the gimbal-calibration trigger for ``kind``, fire-and-forget, and
    return the frame sent. This STARTS a calibration: the gimbal will move."""
    frame = build(kind)
    client.send_frame(frame)
    return frame


# --- factory mode -----------------------------------------------------------
# The tool's full calibration programs wrap the 04/08 trigger in factory mode.
# All frames go out from the host (0x2A), sequence 0, ack AFTER_EXEC, as captured.

GENERAL = 0x00           #: general command set
TEXT_COMMAND = 0x44      #: 00/44 -- run a named command (ASCII name in the body)
REBOOT = 0x0B            #: 00/0b -- Reboot Chip
FACTORY_TARGETS = (0x8F, 0x68)   #: 00/44 start/stop_factory goes to 1504 and 0803
REBOOT_TARGET = 0x0B             #: the 00/0b reboot goes to 1100


def factory_mode_frames(host: int, enter: bool) -> list[Frame]:
    """The frames the tool sends to enter (``enter=True``) or exit factory mode:
    ``00/44`` with ``start_factory``/``stop_factory`` to 1504 and 0803, then a
    ``00/0b`` whose mode byte is 01 to REBOOT into factory mode (enter) or 02 to
    POWER THE DRONE OFF (exit -- verified on the M4T; the tool's log calls it
    "TurnOff drone"). Sequence 0, ack AFTER_EXEC."""
    name = b"start_factory\x00" if enter else b"stop_factory\x00"
    body = bytes([0x80, 0x0A]) + name
    reboot = bytes([0x00, 0x01 if enter else 0x02]) + bytes(12)
    frames = [Frame(host, target, 0, GENERAL, TEXT_COMMAND, body) for target in FACTORY_TARGETS]
    frames.append(Frame(host, REBOOT_TARGET, 0, GENERAL, REBOOT, reboot))
    return frames


def factory_mode(client, enter: bool) -> list[Frame]:
    """Enter or exit factory mode as the tool does, fire-and-forget. On enter the
    drone REBOOTS into factory mode; on exit it POWERS OFF (leaves factory mode on
    the next power-on). Either way the USB link drops. Returns the frames sent."""
    frames = factory_mode_frames(client.host, enter)
    for frame in frames:
        client.send_frame(frame)
    return frames
