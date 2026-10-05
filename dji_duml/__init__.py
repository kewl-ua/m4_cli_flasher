"""Direct DUML access to DJI devices over USB bulk, without DJI Assistant.

The package has no Windows-only dependencies: framing, parsing and the flash
state machine are pure Python; only :mod:`dji_duml.transport` needs pyusb.
"""
from .frame import AckType, Frame, FrameError, StreamParser
from .kinematics import GimbalKinematics, M4T_REFERENCE_GIMBAL_KINEMATICS
from .version import FirmwareVersion

__all__ = [
    "AckType", "Frame", "FrameError", "StreamParser", "FirmwareVersion",
    "GimbalKinematics", "M4T_REFERENCE_GIMBAL_KINEMATICS",
]
__version__ = "0.1.0"
