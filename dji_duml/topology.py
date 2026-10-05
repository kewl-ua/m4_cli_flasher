"""DUML bus topology discovery and passive traffic fingerprinting.

Passive discovery is deliberately conservative: a module is confirmed when
it has actually transmitted a valid DUML frame. An address that only appears
as a receiver is a candidate, not proof that a module exists there.

Active discovery is opt-in and uses only GENERAL/0x01 (Version Inquiry), with
no retries. It never sends configuration, upgrade or control commands.
"""
from __future__ import annotations

from collections import Counter, deque
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
MAX_STREAM_SAMPLES = 4096


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
    _samples: deque[tuple[float | None, bytes]] = field(
        default_factory=lambda: deque(maxlen=MAX_STREAM_SAMPLES), repr=False
    )

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
        self._samples.append((timestamp, payload))
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



def _range(values) -> tuple[float, float] | None:
    values = tuple(values)
    if not values:
        return None
    return min(values), max(values)


def _angle_error_degrees(left: float, right: float) -> float:
    return abs((left - right + 180.0) % 360.0 - 180.0)



def _pearson(left: list[float], right: list[float]) -> float | None:
    if len(left) != len(right) or len(left) < 3:
        return None
    mean_left = sum(left) / len(left)
    mean_right = sum(right) / len(right)
    dl = [value - mean_left for value in left]
    dr = [value - mean_right for value in right]
    denom_left = sum(value * value for value in dl)
    denom_right = sum(value * value for value in dr)
    if denom_left <= 0 or denom_right <= 0:
        return None
    return sum(a * b for a, b in zip(dl, dr)) / (denom_left * denom_right) ** 0.5


def _angle_delta_degrees(current: float, previous: float) -> float:
    return (current - previous + 180.0) % 360.0 - 180.0


def _gimbal_angle_correlations(stream: TrafficStream) -> dict[str, dict[str, float | None]]:
    """Correlate opaque int16 fields with the actual Euler angles."""
    if stream.cmd_set != 0x04 or stream.cmd_id != 0x05:
        return {}

    from .telemetry import parse_gimbal_params

    pitch = []
    roll = []
    yaw = []
    raw14 = []
    raw16 = []
    for _, payload in stream._samples:
        if len(payload) < 24:
            continue
        try:
            item = parse_gimbal_params(payload)
        except UnexpectedReply:
            continue
        p, r, y = item.attitude_deg
        pitch.append(p)
        roll.append(r)
        yaw.append(y)
        raw14.append(int.from_bytes(payload[0x14:0x16], "little", signed=True) / 10.0)
        raw16.append(int.from_bytes(payload[0x16:0x18], "little", signed=True) / 10.0)

    return {
        "i16@14/10": {
            "pitch": _pearson(raw14, pitch),
            "roll": _pearson(raw14, roll),
            "yaw": _pearson(raw14, yaw),
        },
        "i16@16/10": {
            "pitch": _pearson(raw16, pitch),
            "roll": _pearson(raw16, roll),
            "yaw": _pearson(raw16, yaw),
        },
    }


def _gimbal_pitch_model(stream: TrafficStream) -> dict | None:
    """Compare the M4T secondary pitch/joint field at 0x14 with packet pitch."""
    if stream.cmd_set != 0x04 or stream.cmd_id != 0x05:
        return None

    from .telemetry import parse_gimbal_params

    errors = []
    joint = []
    pitch = []
    for _, payload in stream._samples:
        try:
            item = parse_gimbal_params(payload)
        except UnexpectedReply:
            continue
        if item.pitch_joint_deg is None:
            continue
        joint.append(item.pitch_joint_deg)
        pitch.append(item.attitude_deg[0])
        errors.append(abs(item.pitch_joint_deg - item.attitude_deg[0]))

    if not errors:
        return None
    ordered = sorted(errors)
    median = ordered[len(ordered) // 2]
    return {
        "joint_range": _range(joint),
        "pitch_range": _range(pitch),
        "median_error": median,
        "max_error": max(errors),
        "correlation": _pearson(joint, pitch),
    }


def _gimbal_yaw_model(stream: TrafficStream) -> dict | None:
    """Test whether 0x10 is a yaw reference and legacy 0x08 is relative yaw."""
    if stream.cmd_set != 0x04 or stream.cmd_id != 0x05:
        return None

    from .telemetry import parse_gimbal_params

    references = []
    relatives = []
    errors = []
    for _, payload in stream._samples:
        if len(payload) < 20:
            continue
        try:
            item = parse_gimbal_params(payload)
        except UnexpectedReply:
            continue
        reference = int.from_bytes(payload[0x10:0x12], "little", signed=True) / 100.0
        predicted = reference + item.relative_yaw_deg
        error = _angle_error_degrees(predicted, item.attitude_deg[2])
        references.append(reference)
        relatives.append(item.relative_yaw_deg)
        errors.append(error)

    if not errors:
        return None
    ordered = sorted(errors)
    median = ordered[len(ordered) // 2]
    return {
        "reference_range": _range(references),
        "relative_range": _range(relatives),
        "median_error": median,
        "max_error": max(errors),
    }


def _gimbal_rate_correlations(stream: TrafficStream) -> dict[str, dict[str, float | None]]:
    """Correlate opaque int16 fields with Euler angular rates.

    Uses the device's verified millisecond timestamp, not host receive timing.
    This is an RE diagnostic only; opaque fields are intentionally left unnamed.
    """
    if stream.cmd_set != 0x04 or stream.cmd_id != 0x05:
        return {}

    from .telemetry import parse_gimbal_params

    rows = []
    for _, payload in stream._samples:
        if len(payload) < 24:
            continue
        try:
            item = parse_gimbal_params(payload)
        except UnexpectedReply:
            continue
        if item.timestamp_ms is None:
            continue
        rows.append((
            item.timestamp_ms,
            item.attitude_deg,
            int.from_bytes(payload[0x14:0x16], "little", signed=True),
            int.from_bytes(payload[0x16:0x18], "little", signed=True),
        ))

    pitch_rate: list[float] = []
    roll_rate: list[float] = []
    yaw_rate: list[float] = []
    raw14: list[float] = []
    raw16: list[float] = []
    for previous, current in zip(rows, rows[1:]):
        dt_ms = (current[0] - previous[0]) & 0xFFFFFFFF
        if not 0 < dt_ms <= 1000:
            continue
        dt = dt_ms / 1000.0
        pitch_rate.append(_angle_delta_degrees(current[1][0], previous[1][0]) / dt)
        roll_rate.append(_angle_delta_degrees(current[1][1], previous[1][1]) / dt)
        yaw_rate.append(_angle_delta_degrees(current[1][2], previous[1][2]) / dt)
        raw14.append(float(current[2]))
        raw16.append(float(current[3]))

    return {
        "i16@14": {
            "pitch": _pearson(raw14, pitch_rate),
            "roll": _pearson(raw14, roll_rate),
            "yaw": _pearson(raw14, yaw_rate),
        },
        "i16@16": {
            "pitch": _pearson(raw16, pitch_rate),
            "roll": _pearson(raw16, roll_rate),
            "yaw": _pearson(raw16, yaw_rate),
        },
    }

def _gimbal_window_stats(stream: TrafficStream) -> dict | None:
    """Aggregate verified and raw 04/05 fields across retained unique payloads."""
    if stream.cmd_set != 0x04 or stream.cmd_id != 0x05:
        return None

    from .telemetry import parse_gimbal_params

    decoded = []
    raw = []
    for payload in stream._payloads:
        try:
            item = parse_gimbal_params(payload)
        except UnexpectedReply:
            continue
        decoded.append(item)
        if len(payload) >= 24:
            raw.append((
                int.from_bytes(payload[0x0C:0x10], "little"),
                int.from_bytes(payload[0x10:0x12], "little", signed=True),
                int.from_bytes(payload[0x12:0x14], "little", signed=True),
                int.from_bytes(payload[0x14:0x16], "little", signed=True),
                int.from_bytes(payload[0x16:0x18], "little", signed=True),
            ))
    if not decoded:
        return None

    pitch = [item.attitude_deg[0] for item in decoded]
    roll = [item.attitude_deg[1] for item in decoded]
    yaw = [item.attitude_deg[2] for item in decoded]
    norms = [
        item.quaternion_norm for item in decoded
        if item.quaternion_norm is not None
    ]
    orientation_errors = [
        item.quaternion_orientation_error_deg for item in decoded
        if item.quaternion_orientation_error_deg is not None
    ]

    timestamps = [
        item.timestamp_ms for item in decoded
        if item.timestamp_ms is not None
    ]
    result = {
        "attitude_ranges": (_range(pitch), _range(roll), _range(yaw)),
        "quaternion_norm_range": _range(norms),
        "quaternion_orientation_error_max": max(orientation_errors) if orientation_errors else None,
        "timestamp_range": _range(timestamps),
    }
    if raw:
        result["raw_ranges"] = (
            _range(row[0] for row in raw),
            _range(row[1] for row in raw),
            _range(row[2] for row in raw),
            _range(row[3] for row in raw),
            _range(row[4] for row in raw),
        )
    return result


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
                        if gimbal.yaw_reference_deg is not None:
                            line += (
                                f" yaw-ref={gimbal.yaw_reference_deg:.2f}deg"
                                f" rel-yaw={gimbal.relative_yaw_deg:.1f}deg"
                                f" pred-yaw={gimbal.predicted_yaw_deg:.2f}deg"
                            )
                        if gimbal.pitch_joint_deg is not None:
                            line += f" joint-pitch={gimbal.pitch_joint_deg:.1f}deg"
                        if gimbal.quaternion_wxyz is not None:
                            w, x, y, z = gimbal.quaternion_wxyz
                            line += (
                                f" q=({w:.6f},{x:.6f},{y:.6f},{z:.6f}) "
                                f"|q|={gimbal.quaternion_norm:.6f}"
                            )
                            q_pitch, q_roll, q_yaw = gimbal.quaternion_euler_deg
                            line += (
                                f" q-euler=({q_pitch:.2f},{q_roll:.2f},{q_yaw:.2f})deg"
                            )
                        line += f" opaque={len(gimbal.middle) + len(gimbal.tail)}B"
                        lines.append(line)
                        stats = _gimbal_window_stats(stream)
                        if stats is not None:
                            att_ranges = stats["attitude_ranges"]
                            labels = ("pitch", "roll", "yaw")
                            parts = []
                            for label, value in zip(labels, att_ranges):
                                if value is not None:
                                    parts.append(f"{label}={value[0]:.1f}..{value[1]:.1f}")
                            if parts:
                                lines.append("       window-att: " + "  ".join(parts) + " deg")
                            qnorm = stats["quaternion_norm_range"]
                            qerr = stats["quaternion_orientation_error_max"]
                            if qnorm is not None:
                                line = (
                                    f"       q-check: |q|={qnorm[0]:.6f}..{qnorm[1]:.6f}"
                                )
                                if qerr is not None:
                                    line += f" orientation-max-error={qerr:.3f}deg"
                                lines.append(line)
                            timestamp_range = stats.get("timestamp_range")
                            if timestamp_range is not None:
                                device_span = timestamp_range[1] - timestamp_range[0]
                                wall_span = stream.duration
                                scale = (
                                    device_span / (wall_span * 1000.0)
                                    if wall_span and wall_span > 0 else None
                                )
                                clock = (
                                    f"       clock@0C: {int(timestamp_range[0])}.."
                                    f"{int(timestamp_range[1])} ms span={int(device_span)}ms"
                                )
                                if scale is not None:
                                    clock += f" scale={scale:.4f}x"
                                lines.append(clock)
                            raw_ranges = stats.get("raw_ranges")
                            if raw_ranges is not None:
                                raw_names = ("u32@0C", "i16@10", "i16@12", "i16@14", "i16@16")
                                raw_parts = []
                                for name, value in zip(raw_names, raw_ranges):
                                    if value is not None:
                                        raw_parts.append(f"{name}={int(value[0])}..{int(value[1])}")
                                lines.append("       opaque-window: " + "  ".join(raw_parts))
                            angle_correlations = _gimbal_angle_correlations(stream)
                            if angle_correlations:
                                corr_parts = []
                                for field_name, axes in angle_correlations.items():
                                    rendered = ",".join(
                                        f"{axis}={value:+.3f}"
                                        for axis, value in axes.items()
                                        if value is not None
                                    )
                                    if rendered:
                                        corr_parts.append(f"{field_name}[{rendered}]")
                                if corr_parts:
                                    lines.append("       angle-corr: " + "  ".join(corr_parts))
                            pitch_model = _gimbal_pitch_model(stream)
                            if pitch_model is not None:
                                joint = pitch_model["joint_range"]
                                packet_pitch = pitch_model["pitch_range"]
                                corr = pitch_model["correlation"]
                                corr_text = f"{corr:+.3f}" if corr is not None else "?"
                                lines.append(
                                    f"       pitch-model: packet={packet_pitch[0]:.1f}..{packet_pitch[1]:.1f}deg "
                                    f"joint@14={joint[0]:.1f}..{joint[1]:.1f}deg "
                                    f"corr={corr_text} median-error={pitch_model['median_error']:.3f}deg "
                                    f"max-error={pitch_model['max_error']:.3f}deg"
                                )
                            yaw_model = _gimbal_yaw_model(stream)
                            if yaw_model is not None:
                                ref = yaw_model["reference_range"]
                                rel = yaw_model["relative_range"]
                                lines.append(
                                    f"       yaw-model: ref@10={ref[0]:.2f}..{ref[1]:.2f}deg "
                                    f"relative@08={rel[0]:.1f}..{rel[1]:.1f}deg "
                                    f"median-error={yaw_model['median_error']:.3f}deg "
                                    f"max-error={yaw_model['max_error']:.3f}deg"
                                )
                            rate_correlations = _gimbal_rate_correlations(stream)
                            if rate_correlations:
                                corr_parts = []
                                for field_name, axes in rate_correlations.items():
                                    rendered = ",".join(
                                        f"{axis}={value:+.3f}"
                                        for axis, value in axes.items()
                                        if value is not None
                                    )
                                    if rendered:
                                        corr_parts.append(f"{field_name}[{rendered}]")
                                if corr_parts:
                                    lines.append("       rate-corr: " + "  ".join(corr_parts))
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
