"""DUML bus topology discovery.

Passive discovery is deliberately conservative: a module is confirmed when
it has actually transmitted a valid DUML frame. An address that only appears
as a receiver is a candidate, not proof that a module exists there.

Active discovery is opt-in and uses only GENERAL/0x01 (Version Inquiry), with
no retries. It never sends configuration, upgrade or control commands.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable

from .commands import GENERAL, VERSION_INQUIRY, VersionInfo, parse_version_reply
from .errors import NoReply, UnexpectedReply
from .frame import Frame, address

DEVICE_TYPES = {
    0: "Invalid/Any", 1: "Camera", 2: "App", 3: "Flight Controller",
    4: "Gimbal", 5: "Center Board", 6: "Remote Control", 7: "Wi-Fi Air",
    8: "DM36x Air", 9: "HD Link Air", 10: "PC", 11: "Battery", 12: "ESC",
    13: "DM36x Ground", 14: "HD Link Ground", 15: "USB Controller Air",
    16: "USB Controller Ground", 17: "Monocular", 18: "Binocular",
    19: "HD FPGA Air", 20: "HD FPGA Ground", 21: "Simulator",
    22: "Base Station", 23: "Airborne Computer", 24: "RC Battery",
    25: "IMU", 26: "GPS/RTK", 27: "Wi-Fi Ground", 28: "Signal Converter",
    29: "PMU", 30: "Unknown", 31: "Last/Unknown",
}


@dataclass
class Module:
    """Evidence accumulated for one 8-bit DUML address."""

    address: int
    sent: int = 0
    received: int = 0
    requests_sent: int = 0
    responses_sent: int = 0
    commands_sent: Counter[tuple[int, int]] = field(default_factory=Counter)
    commands_received: Counter[tuple[int, int]] = field(default_factory=Counter)
    active_probe: bool = False
    version: VersionInfo | None = None
    version_error: str | None = None

    @property
    def device_type(self) -> int:
        return self.address & 0x1F

    @property
    def index(self) -> int:
        return self.address >> 5

    @property
    def type_name(self) -> str:
        return DEVICE_TYPES.get(self.device_type, f"Type {self.device_type}")

    @property
    def confirmed(self) -> bool:
        return self.sent > 0 or self.active_probe

    @property
    def candidate(self) -> bool:
        return not self.confirmed and self.received > 0

    @property
    def label(self) -> str:
        return f"{self.type_name} {self.device_type:02d}:{self.index}"


class Topology:
    """Observed DUML address graph."""

    def __init__(self, *, host: int | None = None,
                 roles: dict[int, str] | None = None):
        self.host = host
        self.roles = dict(roles or {})
        self.nodes: dict[int, Module] = {}
        self.frames = 0

    def module(self, value: int) -> Module:
        if not 0 <= value <= 0xFF:
            raise ValueError("DUML address must be in 0..255")
        node = self.nodes.get(value)
        if node is None:
            node = self.nodes[value] = Module(value)
        return node

    def observe(self, frame: Frame) -> None:
        source = self.module(frame.sender)
        target = self.module(frame.receiver)
        source.sent += 1
        target.received += 1
        source.commands_sent[(frame.cmd_set, frame.cmd_id)] += 1
        target.commands_received[(frame.cmd_set, frame.cmd_id)] += 1
        if frame.response:
            source.responses_sent += 1
        else:
            source.requests_sent += 1
        self.frames += 1

    def extend(self, frames: Iterable[Frame]) -> "Topology":
        for frame in frames:
            self.observe(frame)
        return self

    @property
    def confirmed(self) -> tuple[Module, ...]:
        return tuple(node for node in self._ordered()
                     if node.confirmed and node.address != self.host)

    @property
    def candidates(self) -> tuple[Module, ...]:
        return tuple(node for node in self._ordered()
                     if node.candidate and node.address != self.host)

    def _ordered(self) -> list[Module]:
        return [self.nodes[key] for key in sorted(self.nodes)]

    def as_dict(self) -> dict:
        def item(node: Module) -> dict:
            result = {
                "address": node.address,
                "type": node.device_type,
                "index": node.index,
                "name": node.type_name,
                "role": self.roles.get(node.address),
                "confirmed": node.confirmed,
                "sent": node.sent,
                "received": node.received,
                "requests_sent": node.requests_sent,
                "responses_sent": node.responses_sent,
                "commands_sent": {
                    f"{cmd_set:02x}/{cmd_id:02x}": count
                    for (cmd_set, cmd_id), count in sorted(node.commands_sent.items())
                },
            }
            if node.version is not None:
                result["version"] = {
                    "hardware": node.version.hardware,
                    "loader": str(node.version.loader),
                    "firmware": str(node.version.firmware),
                }
            if node.version_error is not None:
                result["version_error"] = node.version_error
            return result

        return {
            "frames": self.frames,
            "host": self.host,
            "confirmed": [item(node) for node in self.confirmed],
            "candidates": [item(node) for node in self.candidates],
        }


def from_frames(frames: Iterable[Frame], *, host: int | None = None,
                roles: dict[int, str] | None = None) -> Topology:
    return Topology(host=host, roles=roles).extend(frames)


def from_capture(path, *, host: int | None = None, device: int | None = None,
                 endpoints: set[int] | None = None,
                 roles: dict[int, str] | None = None) -> Topology:
    """Build topology directly from a USBPcap/pcapng capture."""
    from . import pcap
    return from_frames(
        (entry.frame for entry in pcap.iter_frames(path, device=device, endpoints=endpoints)),
        host=host, roles=roles,
    )


def report(topology: Topology, *, commands_per_module: int = 8) -> str:
    """Compact human-readable topology report for captures and live probes."""
    lines = [f"DUML topology: {topology.frames} frames, "
             f"{len(topology.confirmed)} confirmed, {len(topology.candidates)} candidates"]

    def command_text(node: Module) -> str:
        most = node.commands_sent.most_common(max(0, commands_per_module))
        return ", ".join(f"{s:02X}/{i:02X} x{count}" for (s, i), count in most) or "-"

    for node in topology.confirmed:
        version = ""
        if node.version is not None:
            version = f"  fw={node.version.firmware} hw={node.version.hardware!r}"
        source = "active+passive" if node.active_probe and node.sent else (
            "active" if node.active_probe else "passive")
        role = topology.roles.get(node.address)
        label = f"{role} [{node.type_name}]" if role else node.type_name
        lines.append(
            f"+ 0x{node.address:02X}  {label} idx={node.index}  "
            f"{source}  tx={node.sent} rx={node.received}{version}"
        )
        lines.append(f"    commands: {command_text(node)}")

    for node in topology.candidates:
        role = topology.roles.get(node.address)
        label = f"{role} [{node.type_name}]" if role else node.type_name
        lines.append(
            f"? 0x{node.address:02X}  {label} idx={node.index}  "
            f"receiver-only  rx={node.received}"
        )
    return "\n".join(lines)


def addresses(device_types: Iterable[int], indexes: Iterable[int] = (0,)) -> tuple[int, ...]:
    """Build an explicit probe address list without scanning implicitly."""
    result = []
    for device_type in device_types:
        for index in indexes:
            result.append(address(device_type, index))
    return tuple(result)


def probe_versions(client, topology: Topology, probe: Iterable[int], *,
                   timeout: float = 0.2) -> Topology:
    """Confirm explicit addresses using only read-only Version Inquiry."""
    seen: set[int] = set()
    for target in probe:
        if target in seen or target == topology.host:
            continue
        seen.add(target)
        try:
            reply = client.request(target, GENERAL, VERSION_INQUIRY,
                                   timeout=timeout, retries=0)
        except NoReply:
            continue
        node = topology.module(target)
        node.active_probe = True
        topology.observe(reply)
        try:
            node.version = parse_version_reply(reply.payload)
            node.version_error = None
        except UnexpectedReply as exc:
            node.version_error = str(exc)
    return topology
