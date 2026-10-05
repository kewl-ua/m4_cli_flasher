"""DUML bus topology discovery and passive traffic fingerprinting.

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

# Names from the public legacy DUML v1 table. They describe the encoded type,
# not necessarily the physical role of the same address on newer products.
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

MAX_UNIQUE_PAYLOADS = 4096
MAX_SEQ_DELTAS = 64


@dataclass
class TrafficStream:
    """Aggregate one sender -> receiver / command / direction stream."""

    sender: int
    receiver: int
    cmd_set: int
    cmd_id: int
    response: bool
    count: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    payload_min: int | None = None
    payload_max: int | None = None
    _payloads: set[bytes] = field(default_factory=set, repr=False)
    payloads_capped: bool = False
    _first_payload: bytes | None = field(default=None, repr=False)
    changed_offsets: set[int] = field(default_factory=set)
    payload_length_changed: bool = False
    _previous_seq: int | None = field(default=None, repr=False)
    seq_steps: Counter[str] = field(default_factory=Counter)
    seq_deltas: Counter[int] = field(default_factory=Counter)
    seq_deltas_capped: bool = False
    ack_counts: Counter[int] = field(default_factory=Counter)

    def observe(self, frame: Frame, timestamp: float | None) -> None:
        self.count += 1
        self.ack_counts[int(frame.ack)] += 1
        if timestamp is not None:
            if self.first_seen is None:
                self.first_seen = timestamp
            self.last_seen = timestamp

        size = len(frame.payload)
        self.payload_min = size if self.payload_min is None else min(self.payload_min, size)
        self.payload_max = size if self.payload_max is None else max(self.payload_max, size)

        payload = bytes(frame.payload)
        if self._first_payload is None:
            self._first_payload = payload
        else:
            common = min(len(self._first_payload), len(payload))
            self.changed_offsets.update(
                index for index in range(common)
                if self._first_payload[index] != payload[index]
            )
            if len(self._first_payload) != len(payload):
                self.payload_length_changed = True
                self.changed_offsets.update(
                    range(common, max(len(self._first_payload), len(payload)))
                )

        if payload not in self._payloads:
            if len(self._payloads) < MAX_UNIQUE_PAYLOADS:
                self._payloads.add(payload)
            else:
                self.payloads_capped = True

        if self._previous_seq is not None:
            delta = (frame.seq - self._previous_seq) & 0xFFFF
            if delta == 1:
                self.seq_steps["+1"] += 1
            elif delta == 0:
                self.seq_steps["same"] += 1
            else:
                self.seq_steps["other"] += 1
            if delta in self.seq_deltas or len(self.seq_deltas) < MAX_SEQ_DELTAS:
                self.seq_deltas[delta] += 1
            else:
                self.seq_deltas_capped = True
        self._previous_seq = frame.seq

    @property
    def unique_payloads(self) -> int:
        return len(self._payloads)

    @property
    def sample_payload(self) -> bytes:
        return self._first_payload or b""

    @property
    def duration(self) -> float | None:
        if self.first_seen is None or self.last_seen is None:
            return None
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def rate_hz(self) -> float | None:
        duration = self.duration
        if duration is None or duration <= 0 or self.count < 2:
            return None
        return (self.count - 1) / duration

    def as_dict(self) -> dict:
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "cmd_set": self.cmd_set,
            "cmd_id": self.cmd_id,
            "response": self.response,
            "count": self.count,
            "rate_hz": self.rate_hz,
            "duration": self.duration,
            "payload_len": {"min": self.payload_min, "max": self.payload_max},
            "unique_payloads": self.unique_payloads,
            "unique_payloads_exact": not self.payloads_capped,
            "sample_payload": self.sample_payload.hex(),
            "changed_offsets": sorted(self.changed_offsets),
            "payload_length_changed": self.payload_length_changed,
            "seq_steps": dict(self.seq_steps),
            "seq_deltas": {str(delta): count for delta, count in self.seq_deltas.items()},
            "seq_deltas_exact": not self.seq_deltas_capped,
            "ack_counts": {str(ack): count for ack, count in self.ack_counts.items()},
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


class Topology:
    """Observed DUML address graph plus bounded stream fingerprints."""

    def __init__(self, *, host: int | None = None,
                 roles: dict[int, str] | None = None):
        self.host = host
        self.roles = dict(roles or {})
        self.nodes: dict[int, Module] = {}
        self.streams: dict[tuple[int, int, int, int, bool], TrafficStream] = {}
        self.frames = 0

    def module(self, value: int) -> Module:
        if not 0 <= value <= 0xFF:
            raise ValueError("DUML address must be in 0..255")
        node = self.nodes.get(value)
        if node is None:
            node = self.nodes[value] = Module(value)
        return node

    def observe(self, frame: Frame, timestamp: float | None = None) -> None:
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

        key = (frame.sender, frame.receiver, frame.cmd_set, frame.cmd_id, frame.response)
        stream = self.streams.get(key)
        if stream is None:
            stream = self.streams[key] = TrafficStream(*key)
        stream.observe(frame, timestamp)
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

    def streams_from(self, sender: int) -> tuple[TrafficStream, ...]:
        return tuple(sorted(
            (stream for stream in self.streams.values() if stream.sender == sender),
            key=lambda stream: (-stream.count, stream.receiver, stream.cmd_set,
                                stream.cmd_id, stream.response),
        ))

    def _ordered(self) -> list[Module]:
        return [self.nodes[key] for key in sorted(self.nodes)]

    def _module_dict(self, node: Module) -> dict:
        result = {
            "address": node.address,
            "type": node.device_type,
            "index": node.index,
            "legacy_type_name": node.type_name,
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
            "streams": [stream.as_dict() for stream in self.streams_from(node.address)],
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

    def as_dict(self) -> dict:
        return {
            "frames": self.frames,
            "host": self.host,
            "confirmed": [self._module_dict(node) for node in self.confirmed],
            "candidates": [self._module_dict(node) for node in self.candidates],
        }


def from_frames(frames: Iterable[Frame], *, host: int | None = None,
                roles: dict[int, str] | None = None) -> Topology:
    return Topology(host=host, roles=roles).extend(frames)


def from_capture(path, *, host: int | None = None, device: int | None = None,
                 endpoints: set[int] | None = None,
                 roles: dict[int, str] | None = None) -> Topology:
    """Build topology directly from a USBPcap/pcapng capture with timestamps."""
    from . import pcap

    topology = Topology(host=host, roles=roles)
    for entry in pcap.iter_frames(path, device=device, endpoints=endpoints):
        topology.observe(entry.frame, entry.time)
    return topology


def _label(topology: Topology, node: Module) -> str:
    legacy = f"type={node.device_type} legacy:{node.type_name}"
    role = topology.roles.get(node.address)
    return f"{role} [{legacy}]" if role else legacy


def _ascii_runs(data: bytes, *, minimum: int = 4) -> tuple[str, ...]:
    runs = []
    start = None
    for index, value in enumerate(data + b"\x00"):
        printable = 0x20 <= value < 0x7F
        if printable and start is None:
            start = index
        elif not printable and start is not None:
            if index - start >= minimum:
                runs.append(data[start:index].decode("ascii"))
            start = None
    return tuple(runs)


def _offset_ranges(offsets: set[int]) -> str:
    if not offsets:
        return "-"
    values = sorted(offsets)
    ranges = []
    start = previous = values[0]
    for value in values[1:]:
        if value == previous + 1:
            previous = value
            continue
        ranges.append((start, previous))
        start = previous = value
    ranges.append((start, previous))
    return ",".join(
        f"0x{start:02X}" if start == end else f"0x{start:02X}-0x{end:02X}"
        for start, end in ranges
    )


def report(topology: Topology, *, commands_per_module: int = 8,
           verbose: bool = False) -> str:
    """Human-readable topology report; verbose adds per-stream fingerprints."""
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
        lines.append(
            f"+ 0x{node.address:02X}  {_label(topology, node)} idx={node.index}  "
            f"{source}  tx={node.sent} rx={node.received}{version}"
        )
        lines.append(f"    commands: {command_text(node)}")
        if verbose:
            for stream in topology.streams_from(node.address):
                rate = f"{stream.rate_hz:.1f} Hz" if stream.rate_hz is not None else "rate=?"
                if stream.payload_min == stream.payload_max:
                    payload = f"len={stream.payload_min}"
                else:
                    payload = f"len={stream.payload_min}..{stream.payload_max}"
                unique = (
                    f"unique={stream.unique_payloads}"
                    if not stream.payloads_capped
                    else f"unique>={stream.unique_payloads}"
                )
                seq = "/".join(
                    f"{name}:{stream.seq_steps.get(name, 0)}"
                    for name in ("+1", "same", "other")
                )
                deltas = ",".join(
                    f"+{delta}:{count}"
                    for delta, count in stream.seq_deltas.most_common(5)
                ) or "-"
                if stream.seq_deltas_capped:
                    deltas += ",..."
                if stream.response:
                    kind = "response"
                elif set(stream.ack_counts) == {0}:
                    kind = "push"
                elif 0 not in stream.ack_counts:
                    kind = "request"
                else:
                    kind = "request/push"
                ack_names = {0: "none", 1: "before", 2: "after", 3: "reserved"}
                acks = ",".join(
                    f"{ack_names.get(ack, str(ack))}:{count}"
                    for ack, count in sorted(stream.ack_counts.items())
                )
                lines.append(
                    f"    -> 0x{stream.receiver:02X}  {stream.cmd_set:02X}/{stream.cmd_id:02X}  "
                    f"{kind}  n={stream.count}  {rate}  {payload}  {unique}  "
                    f"ack[{acks}]  seq[{seq}]"
                )
                sample = stream.sample_payload[:64].hex(" ")
                if len(stream.sample_payload) > 64:
                    sample += " ..."
                lines.append(
                    f"       sample: {sample or '-'}"
                )
                ascii_text = _ascii_runs(stream.sample_payload)
                if ascii_text:
                    lines.append("       ascii: " + ", ".join(repr(text) for text in ascii_text))
                if stream.cmd_set == 0x03 and stream.cmd_id == 0x43:
                    from .telemetry import parse_flyc_osd_general
                    try:
                        osd = parse_flyc_osd_general(stream.sample_payload)
                    except UnexpectedReply:
                        pass
                    else:
                        vx, vy, vz = osd.velocity_mps
                        pitch, roll, yaw = osd.attitude_deg
                        lines.append(
                            f"       decoded-prefix: h={osd.relative_height_m:.1f}m "
                            f"v=({vx:.1f},{vy:.1f},{vz:.1f})m/s "
                            f"att=({pitch:.1f},{roll:.1f},{yaw:.1f})deg "
                            f"ctrl=0x{osd.ctrl_info:02X} state=0x{osd.controller_state:08X} "
                            f"tail={len(osd.tail)}B"
                        )
                elif stream.cmd_set == 0x04 and stream.cmd_id == 0x05:
                    from .telemetry import parse_gimbal_params
                    try:
                        gimbal = parse_gimbal_params(stream.sample_payload)
                    except UnexpectedReply:
                        pass
                    else:
                        pitch, roll, yaw = gimbal.attitude_deg
                        line = (
                            f"       decoded-prefix: att=({pitch:.1f},{roll:.1f},{yaw:.1f})deg "
                            f"mode=0x{gimbal.mode_flags:02X} limits=0x{gimbal.limit_flags:02X}"
                        )
                        if gimbal.quaternion_wxyz is not None:
                            w, x, y, z = gimbal.quaternion_wxyz
                            line += (
                                f" q=({w:.6f},{x:.6f},{y:.6f},{z:.6f}) "
                                f"|q|={gimbal.quaternion_norm:.6f}"
                            )
                        line += f" opaque={len(gimbal.middle) + len(gimbal.tail)}B"
                        lines.append(line)
                lines.append(
                    f"       changed: {_offset_ranges(stream.changed_offsets)}"
                    + (" (length varies)" if stream.payload_length_changed else "")
                    + f"  seq-delta[{deltas}]"
                )

    for node in topology.candidates:
        lines.append(
            f"? 0x{node.address:02X}  {_label(topology, node)} idx={node.index}  "
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
