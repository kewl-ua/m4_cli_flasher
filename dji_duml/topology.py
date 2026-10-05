"""DUML bus topology discovery and passive traffic fingerprinting.

Passive discovery is deliberately conservative: a module is confirmed when
it has actually transmitted a valid DUML frame. An address that only appears
as a receiver is a candidate, not proof that a module exists there.

Active discovery is opt-in and uses only GENERAL/0x01 (Version Inquiry), with
no retries. It never sends configuration, upgrade or control commands.
"""
from __future__ import annotations

from bisect import bisect_right
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


def _unwrap_degrees(values: list[float]) -> list[float]:
    if not values:
        return []
    result = [values[0]]
    for value in values[1:]:
        previous_wrapped = (result[-1] + 180.0) % 360.0 - 180.0
        delta = (value - previous_wrapped + 180.0) % 360.0 - 180.0
        result.append(result[-1] + delta)
    return result


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def _find_stream(topology: Topology, cmd_set: int, cmd_id: int) -> TrafficStream | None:
    matches = [
        stream for stream in topology.streams.values()
        if not stream.response and stream.cmd_set == cmd_set and stream.cmd_id == cmd_id
    ]
    if not matches:
        return None
    return max(matches, key=lambda stream: stream.count)


def _cross_attitude_diagnostics(topology: Topology) -> dict | None:
    """Interpolate FC attitude, solve body-relative gimbal orientation and rank joint orders."""
    from .telemetry import (
        euler_deg_to_quaternion,
        parse_flyc_osd_general,
        parse_gimbal_params,
        quaternion_angular_distance_deg,
        quaternion_average,
        quaternion_axis_angle_deg,
        quaternion_conjugate,
        quaternion_multiply,
        quaternion_slerp,
        quaternion_to_euler_deg,
        relative_quaternion,
    )

    fc_stream = _find_stream(topology, 0x03, 0x43)
    gimbal_stream = _find_stream(topology, 0x04, 0x05)
    if fc_stream is None or gimbal_stream is None:
        return None

    fc_rows = []
    for timestamp, payload in fc_stream._samples:
        if timestamp is None:
            continue
        try:
            item = parse_flyc_osd_general(payload)
        except UnexpectedReply:
            continue
        fc_rows.append((
            timestamp,
            item.attitude_deg,
            euler_deg_to_quaternion(item.attitude_deg),
        ))

    gimbal_rows = []
    for timestamp, payload in gimbal_stream._samples:
        if timestamp is None:
            continue
        try:
            item = parse_gimbal_params(payload)
        except UnexpectedReply:
            continue
        if (
            item.quaternion_wxyz is None
            or item.pitch_joint_deg is None
            or item.roll_joint_deg is None
        ):
            continue
        gimbal_rows.append((timestamp, item))

    if len(fc_rows) < 3 or len(gimbal_rows) < 3:
        return None

    raw_fc_axes = list(zip(*(row[1] for row in fc_rows)))
    axis_labels = ("pitch", "roll", "yaw")
    axis_spans = {
        label: max(values) - min(values)
        for label, values in zip(axis_labels, raw_fc_axes)
    }
    excited_axes = tuple(
        label for label in axis_labels if axis_spans[label] >= 20.0
    )
    if len(excited_axes) < 2:
        return {
            "insufficient_excitation": True,
            "axis_spans": axis_spans,
            "excited_axes": excited_axes,
        }

    fc_times = [row[0] for row in fc_rows]
    joint_orders = (
        ("yaw", "pitch", "roll"),
        ("yaw", "roll", "pitch"),
        ("pitch", "yaw", "roll"),
        ("pitch", "roll", "yaw"),
        ("roll", "yaw", "pitch"),
        ("roll", "pitch", "yaw"),
    )
    axis_for = {"pitch": "y", "roll": "x", "yaw": "z"}

    def candidate_joint_q(item, order):
        angles = {
            "pitch": item.pitch_joint_deg,
            "roll": item.roll_joint_deg,
            "yaw": item.relative_yaw_deg,
        }
        candidate = (1.0, 0.0, 0.0, 0.0)
        for name in order:
            candidate = quaternion_multiply(
                candidate,
                quaternion_axis_angle_deg(axis_for[name], angles[name]),
            )
        return candidate

    def aligned_rows(lag_seconds):
        rows = []
        bracket_ms = []
        for g_time, item in gimbal_rows:
            target = g_time + lag_seconds
            upper = bisect_right(fc_times, target)
            if upper <= 0 or upper >= len(fc_rows):
                continue
            left = fc_rows[upper - 1]
            right = fc_rows[upper]
            span = right[0] - left[0]
            if span <= 0 or span > 1.0:
                continue
            fraction = (target - left[0]) / span
            fc_q = quaternion_slerp(left[2], right[2], fraction)
            fc_att = quaternion_to_euler_deg(fc_q)
            rel_q = relative_quaternion(fc_q, item.quaternion_wxyz)
            rel_att = quaternion_to_euler_deg(rel_q)
            rows.append((g_time, fc_att, item, rel_att, rel_q))
            bracket_ms.append(span * 1000.0)
        return rows, bracket_ms

    def fit_mount(rows, order, side):
        """Bidirectional blocked CV for a constant mounting transform.

        Fit on the first contiguous half and validate on the second, then
        reverse the roles. The reported mount itself is fitted on all rows
        only after validation scores are established.
        """
        midpoint = len(rows) // 2
        first = rows[:midpoint]
        second = rows[midpoint:]
        if len(first) < 3 or len(second) < 3:
            return None

        def residuals_for(source):
            residuals = []
            for _, _, item, _, rel_q in source:
                joint_q = candidate_joint_q(item, order)
                if side == "left":
                    # rel = mount * joints
                    residuals.append(
                        quaternion_multiply(rel_q, quaternion_conjugate(joint_q))
                    )
                else:
                    # rel = joints * mount
                    residuals.append(
                        quaternion_multiply(quaternion_conjugate(joint_q), rel_q)
                    )
            return residuals

        def validation_errors(mount_q, target):
            errors = []
            for _, _, item, _, rel_q in target:
                joint_q = candidate_joint_q(item, order)
                predicted = (
                    quaternion_multiply(mount_q, joint_q)
                    if side == "left"
                    else quaternion_multiply(joint_q, mount_q)
                )
                errors.append(quaternion_angular_distance_deg(predicted, rel_q))
            return errors

        mount_first = quaternion_average(residuals_for(first))
        mount_second = quaternion_average(residuals_for(second))
        errors = (
            validation_errors(mount_first, second)
            + validation_errors(mount_second, first)
        )

        # After cross-validation, estimate the descriptive mount from all rows.
        mount_q = quaternion_average(residuals_for(rows))
        return {
            "side": side,
            "mount_q": mount_q,
            "median_error": _median(errors),
            "max_error": max(errors),
            "samples": len(errors),
            "cv": "blocked-halves",
        }

    mount_scores = []
    lag_scores = []
    for lag_ms in range(-300, 301, 10):
        rows, _ = aligned_rows(lag_ms / 1000.0)
        if len(rows) < 10:
            continue
        for order in joint_orders:
            errors = [
                quaternion_angular_distance_deg(candidate_joint_q(item, order), rel_q)
                for _, _, item, _, rel_q in rows
            ]
            lag_scores.append({
                "lag_ms": lag_ms,
                "order": "*".join(order),
                "median_error": _median(errors),
                "max_error": max(errors),
                "samples": len(errors),
            })
            for side in ("left", "right"):
                fitted = fit_mount(rows, order, side)
                if fitted is not None:
                    fitted.update({
                        "lag_ms": lag_ms,
                        "order": "*".join(order),
                    })
                    mount_scores.append(fitted)

    if not lag_scores or not mount_scores:
        return None

    lag_scores.sort(
        key=lambda item: (
            item["median_error"],
            item["max_error"],
            abs(item["lag_ms"]),
        )
    )
    mount_scores.sort(
        key=lambda item: (
            item["median_error"],
            item["max_error"],
            abs(item["lag_ms"]),
        )
    )
    best_mount = mount_scores[0]
    best_rows, bracket_ms = aligned_rows(best_mount["lag_ms"] / 1000.0)
    if len(best_rows) < 3:
        return None

    # Rank raw orders and mount-corrected orders at the chosen temporal alignment.
    order_scores = []
    for order in joint_orders:
        errors = [
            quaternion_angular_distance_deg(candidate_joint_q(item, order), rel_q)
            for _, _, item, _, rel_q in best_rows
        ]
        order_scores.append({
            "order": "*".join(order),
            "lag_ms": best_mount["lag_ms"],
            "median_error": _median(errors),
            "max_error": max(errors),
            "samples": len(errors),
        })
    order_scores.sort(key=lambda item: (item["median_error"], item["max_error"]))

    mount_order_scores = []
    for order in joint_orders:
        for side in ("left", "right"):
            fitted = fit_mount(best_rows, order, side)
            if fitted is None:
                continue
            fitted.update({
                "order": "*".join(order),
                "lag_ms": best_mount["lag_ms"],
            })
            mount_order_scores.append(fitted)
    mount_order_scores.sort(
        key=lambda item: (item["median_error"], item["max_error"])
    )

    fc_pitch = [row[1][0] for row in best_rows]
    fc_roll = [row[1][1] for row in best_rows]
    fc_yaw = [row[1][2] for row in best_rows]
    g_pitch = [row[2].attitude_deg[0] for row in best_rows]
    g_roll = [row[2].attitude_deg[1] for row in best_rows]
    g_yaw = [row[2].attitude_deg[2] for row in best_rows]
    rel_q_pitch = [row[3][0] for row in best_rows]
    rel_q_roll = [row[3][1] for row in best_rows]
    rel_q_yaw = [row[3][2] for row in best_rows]

    joint_pitch = [row[2].pitch_joint_deg for row in best_rows]
    roll_joint = [row[2].roll_joint_deg for row in best_rows]
    relative_yaw = [row[2].relative_yaw_deg for row in best_rows]
    ref10 = [
        row[2].yaw_reference_deg if row[2].yaw_reference_deg is not None else 0.0
        for row in best_rows
    ]

    pitch_errors = [
        _angle_error_degrees(field, solved)
        for field, solved in zip(joint_pitch, rel_q_pitch)
    ]
    roll_errors = [
        _angle_error_degrees(field, solved)
        for field, solved in zip(roll_joint, rel_q_roll)
    ]
    yaw_errors = [
        _angle_error_degrees(field, solved)
        for field, solved in zip(relative_yaw, rel_q_yaw)
    ]

    fc_yaw_u = _unwrap_degrees(fc_yaw)
    g_yaw_u = _unwrap_degrees(g_yaw)
    ref10_u = _unwrap_degrees(ref10)

    return {
        "pairs": len(best_rows),
        "best_lag_ms": best_mount["lag_ms"],
        "fc_bracket_median_ms": _median(bracket_ms),
        "fc_bracket_max_ms": max(bracket_ms),
        "fc_ranges": (_range(fc_pitch), _range(fc_roll), _range(fc_yaw_u)),
        "gimbal_ranges": (_range(g_pitch), _range(g_roll), _range(g_yaw_u)),
        "solved_relative_ranges": (
            _range(rel_q_pitch), _range(rel_q_roll), _range(rel_q_yaw)
        ),
        "field_ranges": (
            _range(joint_pitch), _range(roll_joint), _range(relative_yaw)
        ),
        "pitch_joint_corr": _pearson(joint_pitch, rel_q_pitch),
        "pitch_joint_error_median": _median(pitch_errors),
        "pitch_joint_error_max": max(pitch_errors),
        "roll_joint_corr": _pearson(roll_joint, rel_q_roll),
        "roll_joint_error_median": _median(roll_errors),
        "roll_joint_error_max": max(roll_errors),
        "relative_yaw_corr": _pearson(relative_yaw, rel_q_yaw),
        "relative_yaw_error_median": _median(yaw_errors),
        "relative_yaw_error_max": max(yaw_errors),
        "ref10_fc_corr": _pearson(ref10_u, fc_yaw_u),
        "ref10_gimbal_corr": _pearson(ref10_u, g_yaw_u),
        "ref10_range": _range(ref10_u),
        "joint_order_scores": order_scores,
        "mount_order_scores": mount_order_scores,
        "best_mount": best_mount,
        "lag_order_scores": lag_scores,
    }


def _flyc_tail_diagnostics(stream: TrafficStream) -> dict | None:
    """Describe post-prefix FLYC 03/43 bytes without promoting semantics.

    Public legacy DUML layouts extend through payload offset 0x36 (55 bytes).
    M4T carries 84 bytes, so offsets 0x37..0x53 are the genuinely newer
    extension. Legacy labels below are historical candidates only: a slot may
    have been repurposed on M4T.
    """
    if stream.cmd_set != 0x03 or stream.cmd_id != 0x43:
        return None

    from .telemetry import (
        euler_deg_to_quaternion,
        parse_flyc_osd_general,
        quaternion_conjugate,
        quaternion_multiply,
        quaternion_rotation_vector_deg,
    )

    rows = []
    for timestamp, payload in stream._samples:
        try:
            item = parse_flyc_osd_general(payload)
        except UnexpectedReply:
            continue
        if len(payload) < 84:
            continue
        vx, vy, vz = item.velocity_mps
        pitch, roll, yaw = item.attitude_deg
        rows.append((
            timestamp,
            payload,
            {
                "height": item.relative_height_m,
                "vx": vx,
                "vy": vy,
                "vz": vz,
                "pitch": pitch,
                "roll": roll,
                "yaw": yaw,
            },
        ))

    if len(rows) < 3:
        return None

    start = 36
    legacy_end = 55
    end = min(len(row[1]) for row in rows)
    changed = []
    byte_ranges = {}
    bit_masks = {}
    byte_steps = {}
    first = rows[0][1]

    for offset in range(start, end):
        values = [payload[offset] for _, payload, _ in rows]
        low, high = min(values), max(values)
        if low != high:
            changed.append(offset)
            byte_ranges[offset] = (low, high, len(set(values)))
            mask = 0
            base = first[offset]
            for value in values:
                mask |= base ^ value
            bit_masks[offset] = mask
            deltas = Counter(
                (current - previous) & 0xFF
                for previous, current in zip(values, values[1:])
            )
            byte_steps[offset] = tuple(deltas.most_common(3))

    changed_set = set(changed)

    # Sliding words are intentional: legacy unknown35 is at odd offset 0x35.
    words = []
    for offset in range(start, end - 1):
        if offset not in changed_set and offset + 1 not in changed_set:
            continue
        raw = [
            int.from_bytes(payload[offset:offset + 2], "little", signed=False)
            for _, payload, _ in rows
        ]
        if len(set(raw)) <= 1:
            continue
        signed = [
            value if value < 0x8000 else value - 0x10000
            for value in raw
        ]
        words.append({
            "offset": offset,
            "u16_range": (min(raw), max(raw)),
            "i16_range": (min(signed), max(signed)),
            "unique": len(set(raw)),
        })

    signals = {
        name: [known[name] for _, _, known in rows]
        for name in ("height", "vx", "vy", "vz", "pitch", "roll", "yaw")
    }

    body_rate_signals = {
        name: [None] * len(rows)
        for name in ("omega_x", "omega_y", "omega_z", "omega_mag")
    }
    for index in range(1, len(rows)):
        previous_time, _, previous = rows[index - 1]
        current_time, _, current = rows[index]
        if previous_time is None or current_time is None:
            continue
        dt = current_time - previous_time
        if not 0.1 <= dt <= 1.0:
            continue
        previous_q = euler_deg_to_quaternion(
            (previous["pitch"], previous["roll"], previous["yaw"])
        )
        current_q = euler_deg_to_quaternion(
            (current["pitch"], current["roll"], current["yaw"])
        )
        delta_q = quaternion_multiply(
            quaternion_conjugate(previous_q),
            current_q,
        )
        rx, ry, rz = quaternion_rotation_vector_deg(delta_q)
        wx, wy, wz = rx / dt, ry / dt, rz / dt
        body_rate_signals["omega_x"][index] = wx
        body_rate_signals["omega_y"][index] = wy
        body_rate_signals["omega_z"][index] = wz
        body_rate_signals["omega_mag"][index] = (
            wx * wx + wy * wy + wz * wz
        ) ** 0.5

    # Derivatives use host receive time. They are hints only because 03/43 has
    # no verified device timestamp and is only ~2 Hz.
    rate_signals = {
        name: [None] * len(rows)
        for name in ("height_rate", "ax", "ay", "az", "pitch_rate", "roll_rate", "yaw_rate")
    }
    source_names = {
        "height_rate": "height",
        "ax": "vx",
        "ay": "vy",
        "az": "vz",
        "pitch_rate": "pitch",
        "roll_rate": "roll",
        "yaw_rate": "yaw",
    }
    angle_sources = {"pitch_rate", "roll_rate", "yaw_rate"}
    for index in range(1, len(rows)):
        previous_time, _, previous = rows[index - 1]
        current_time, _, current = rows[index]
        if previous_time is None or current_time is None:
            continue
        dt = current_time - previous_time
        if not 0.1 <= dt <= 1.0:
            continue
        for target_name, source_name in source_names.items():
            delta = current[source_name] - previous[source_name]
            if target_name in angle_sources:
                delta = _angle_delta_degrees(current[source_name], previous[source_name])
            rate_signals[target_name][index] = delta / dt

    second_rate_signals = {
        name: [None] * len(rows)
        for name in ("pitch_accel", "roll_accel", "yaw_accel")
    }
    first_rate_name = {
        "pitch_accel": "pitch_rate",
        "roll_accel": "roll_rate",
        "yaw_accel": "yaw_rate",
    }
    for index in range(2, len(rows)):
        previous_time = rows[index - 1][0]
        current_time = rows[index][0]
        if previous_time is None or current_time is None:
            continue
        dt = current_time - previous_time
        if not 0.1 <= dt <= 1.0:
            continue
        for target_name, source_name in first_rate_name.items():
            previous_rate = rate_signals[source_name][index - 1]
            current_rate = rate_signals[source_name][index]
            if previous_rate is None or current_rate is None:
                continue
            second_rate_signals[target_name][index] = (
                current_rate - previous_rate
            ) / dt

    correlations = []
    rate_correlations = []
    second_rate_correlations = []
    body_rate_correlations = []
    for offset in range(start, end - 1):
        unsigned = [
            int.from_bytes(payload[offset:offset + 2], "little", signed=False)
            for _, payload, _ in rows
        ]
        if len(set(unsigned)) <= 2:
            continue
        signed = [
            value if value < 0x8000 else value - 0x10000
            for value in unsigned
        ]
        for signedness, values in (("u16", unsigned), ("i16", signed)):
            numeric = [float(value) for value in values]
            for signal, target in signals.items():
                corr = _pearson(numeric, target)
                if corr is None or abs(corr) < 0.80:
                    continue
                correlations.append({
                    "offset": offset,
                    "type": signedness,
                    "signal": signal,
                    "corr": corr,
                    "unique": len(set(values)),
                })
            for signal, target in rate_signals.items():
                paired = [
                    (numeric[index], value)
                    for index, value in enumerate(target)
                    if value is not None
                ]
                if len(paired) < 3:
                    continue
                raw_values = [item[0] for item in paired]
                rate_values = [item[1] for item in paired]
                corr = _pearson(raw_values, rate_values)
                if corr is None or abs(corr) < 0.75:
                    continue
                rate_correlations.append({
                    "offset": offset,
                    "type": signedness,
                    "signal": signal,
                    "corr": corr,
                    "unique": len(set(raw_values)),
                })
            for signal, target in second_rate_signals.items():
                paired = [
                    (numeric[index], value)
                    for index, value in enumerate(target)
                    if value is not None
                ]
                if len(paired) < 3:
                    continue
                raw_values = [item[0] for item in paired]
                accel_values = [item[1] for item in paired]
                corr = _pearson(raw_values, accel_values)
                if corr is None or abs(corr) < 0.70:
                    continue
                second_rate_correlations.append({
                    "offset": offset,
                    "type": signedness,
                    "signal": signal,
                    "corr": corr,
                    "unique": len(set(raw_values)),
                })
            for signal, target in body_rate_signals.items():
                paired = [
                    (numeric[index], value)
                    for index, value in enumerate(target)
                    if value is not None
                ]
                if len(paired) < 3:
                    continue
                raw_values = [item[0] for item in paired]
                body_values = [item[1] for item in paired]
                corr = _pearson(raw_values, body_values)
                if corr is None or abs(corr) < 0.70:
                    continue
                body_rate_correlations.append({
                    "offset": offset,
                    "type": signedness,
                    "signal": signal,
                    "corr": corr,
                    "unique": len(set(raw_values)),
                })

    correlations.sort(
        key=lambda item: (-abs(item["corr"]), item["offset"], item["type"], item["signal"])
    )
    rate_correlations.sort(
        key=lambda item: (-abs(item["corr"]), item["offset"], item["type"], item["signal"])
    )
    second_rate_correlations.sort(
        key=lambda item: (-abs(item["corr"]), item["offset"], item["type"], item["signal"])
    )
    body_rate_correlations.sort(
        key=lambda item: (-abs(item["corr"]), item["offset"], item["type"], item["signal"])
    )

    legacy_specs = (
        (0x24, 1, "gps_nums"),
        (0x25, 1, "gohome_reason"),
        (0x26, 1, "start_fail_state"),
        (0x27, 1, "controller_state_ext"),
        (0x28, 1, "battery_remain"),
        (0x29, 1, "ultrasonic_height"),
        (0x2A, 2, "motor_startup_time"),
        (0x2C, 1, "motor_start_count"),
        (0x2D, 1, "battery_alarm1"),
        (0x2E, 1, "battery_alarm2"),
        (0x2F, 1, "version_match"),
        (0x30, 1, "product_type"),
        (0x31, 1, "imu_init_fail_reason"),
        (0x32, 1, "motor_fail_reason"),
        (0x33, 1, "motor_start_cause"),
        (0x34, 1, "sdk_ctrl_device"),
        (0x35, 2, "unknown35"),
    )
    legacy_slots = []
    for offset, size, name in legacy_specs:
        if offset + size > end:
            continue
        raw_values = [
            int.from_bytes(payload[offset:offset + size], "little", signed=False)
            for _, payload, _ in rows
        ]
        signed_values = [
            int.from_bytes(payload[offset:offset + size], "little", signed=True)
            for _, payload, _ in rows
        ]
        legacy_slots.append({
            "offset": offset,
            "size": size,
            "name": name,
            "u_range": (min(raw_values), max(raw_values)),
            "i_range": (min(signed_values), max(signed_values)),
            "unique": len(set(raw_values)),
            "changed": len(set(raw_values)) > 1,
        })

    counter_candidates = []
    for offset in sorted(changed_set):
        values = [payload[offset] for _, payload, _ in rows]
        unique_ratio = len(set(values)) / len(values)
        rates = []
        steps = []
        for index in range(1, len(rows)):
            previous_time = rows[index - 1][0]
            current_time = rows[index][0]
            if previous_time is None or current_time is None:
                continue
            dt = current_time - previous_time
            if not 0.1 <= dt <= 1.0:
                continue
            step = (values[index] - values[index - 1]) & 0xFF
            steps.append(step)
            rates.append(step / dt)
        if len(rates) >= 5 and unique_ratio >= 0.70:
            median_rate = _median(rates)
            deviations = [abs(value - median_rate) for value in rates]
            median_deviation = _median(deviations)
            if median_rate is not None and median_rate > 0 and median_deviation <= max(2.0, median_rate * 0.08):
                counter_candidates.append({
                    "offset": offset,
                    "median_rate_hz": median_rate,
                    "median_step": _median([float(step) for step in steps]),
                    "mad_rate": median_deviation,
                    "unique_ratio": unique_ratio,
                })

    categorical_states = []
    for offset in sorted(changed_set):
        values = [payload[offset] for _, payload, _ in rows]
        unique_values = sorted(set(values))
        if not 2 <= len(unique_values) <= 8:
            continue
        states = []
        for value in unique_values:
            indexes = [index for index, current in enumerate(values) if current == value]
            medians = {}
            for signal in ("pitch_rate", "roll_rate", "yaw_rate"):
                samples = [
                    abs(rate_signals[signal][index])
                    for index in indexes
                    if rate_signals[signal][index] is not None
                ]
                medians[signal] = _median(samples) if samples else None
            states.append({
                "value": value,
                "count": len(indexes),
                "median_abs_rates": medians,
            })
        categorical_states.append({
            "offset": offset,
            "states": states,
        })

    return {
        "changed": changed_set,
        "legacy_changed": {offset for offset in changed_set if offset < legacy_end},
        "m4t_changed": {offset for offset in changed_set if offset >= legacy_end},
        "byte_ranges": byte_ranges,
        "bit_masks": bit_masks,
        "byte_steps": byte_steps,
        "words": words,
        "correlations": correlations[:12],
        "rate_correlations": rate_correlations[:12],
        "second_rate_correlations": second_rate_correlations[:12],
        "body_rate_correlations": body_rate_correlations[:12],
        "counter_candidates": counter_candidates,
        "categorical_states": categorical_states,
        "legacy_slots": legacy_slots,
        "samples": len(rows),
        "tail_start": start,
        "legacy_end": legacy_end,
        "tail_end": end,
    }



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
                        tail = _flyc_tail_diagnostics(stream)
                        if tail is not None:
                            lines.append(
                                f"       tail-changed: {_offset_ranges(tail['changed'])} "
                                f"samples={tail['samples']}"
                            )
                            lines.append(
                                "       tail-regions: "
                                f"legacy-layout@24..36={_offset_ranges(tail['legacy_changed'])}  "
                                f"m4t-extension@37..53={_offset_ranges(tail['m4t_changed'])}"
                            )
                            changed_legacy = [
                                item for item in tail["legacy_slots"] if item["changed"]
                            ]
                            if changed_legacy:
                                legacy_parts = []
                                for item in changed_legacy:
                                    ulo, uhi = item["u_range"]
                                    ilo, ihi = item["i_range"]
                                    value = (
                                        f"{ulo}..{uhi}"
                                        if item["size"] == 1
                                        else f"u={ulo}..{uhi}/i={ilo}..{ihi}"
                                    )
                                    legacy_parts.append(
                                        f"{item['name']}?@{item['offset']:02X}="
                                        f"{value}/uniq{item['unique']}"
                                    )
                                lines.append(
                                    "       legacy-slot-changes: " + "  ".join(legacy_parts)
                                )
                            if tail["byte_ranges"]:
                                byte_parts = []
                                for offset in sorted(tail["byte_ranges"])[:16]:
                                    low, high, unique = tail["byte_ranges"][offset]
                                    mask = tail["bit_masks"][offset]
                                    byte_parts.append(
                                        f"@{offset:02X}={low:02X}..{high:02X}"
                                        f"/u{unique}/mask{mask:02X}"
                                    )
                                if len(tail["byte_ranges"]) > 16:
                                    byte_parts.append("...")
                                lines.append(
                                    "       tail-bytes: " + "  ".join(byte_parts)
                                )
                                step_parts = []
                                for offset in sorted(tail["byte_steps"])[:12]:
                                    steps = ",".join(
                                        f"+{delta}:{count}" for delta, count in tail["byte_steps"][offset]
                                    )
                                    step_parts.append(f"@{offset:02X}[{steps}]")
                                if step_parts:
                                    lines.append(
                                        "       tail-byte-step: " + "  ".join(step_parts)
                                    )
                            if tail["words"]:
                                word_parts = []
                                for item in tail["words"][:12]:
                                    ulo, uhi = item["u16_range"]
                                    slo, shi = item["i16_range"]
                                    word_parts.append(
                                        f"@{item['offset']:02X} "
                                        f"u16={ulo}..{uhi} "
                                        f"i16={slo}..{shi} "
                                        f"uniq={item['unique']}"
                                    )
                                if len(tail["words"]) > 12:
                                    word_parts.append("...")
                                lines.append(
                                    "       tail-u16: " + "  ".join(word_parts)
                                )
                            if tail["correlations"]:
                                corr_parts = [
                                    f"{item['type']}@{item['offset']:02X}"
                                    f"->{item['signal']}={item['corr']:+.3f}"
                                    for item in tail["correlations"]
                                ]
                                lines.append(
                                    "       tail-corr: " + "  ".join(corr_parts)
                                )
                            if tail["rate_correlations"]:
                                corr_parts = [
                                    f"{item['type']}@{item['offset']:02X}"
                                    f"->{item['signal']}={item['corr']:+.3f}"
                                    for item in tail["rate_correlations"]
                                ]
                                lines.append(
                                    "       tail-rate-corr: " + "  ".join(corr_parts)
                                )
                            if tail["second_rate_correlations"]:
                                corr_parts = [
                                    f"{item['type']}@{item['offset']:02X}"
                                    f"->{item['signal']}={item['corr']:+.3f}"
                                    for item in tail["second_rate_correlations"]
                                ]
                                lines.append(
                                    "       tail-accel-corr: " + "  ".join(corr_parts)
                                )
                            if tail["body_rate_correlations"]:
                                corr_parts = [
                                    f"{item['type']}@{item['offset']:02X}"
                                    f"->{item['signal']}={item['corr']:+.3f}"
                                    for item in tail["body_rate_correlations"]
                                ]
                                lines.append(
                                    "       tail-body-rate-corr: " + "  ".join(corr_parts)
                                )
                            if tail["counter_candidates"]:
                                counter_parts = [
                                    f"@{item['offset']:02X}="
                                    f"{item['median_rate_hz']:.2f}/s "
                                    f"step~{item['median_step']:.1f} "
                                    f"mad={item['mad_rate']:.2f}"
                                    for item in tail["counter_candidates"]
                                ]
                                lines.append(
                                    "       tail-counter-like: " + "  ".join(counter_parts)
                                )
                            if tail["categorical_states"]:
                                for item in tail["categorical_states"][:8]:
                                    rendered_states = []
                                    for state in item["states"]:
                                        rates = state["median_abs_rates"]
                                        rate_text = ",".join(
                                            f"{name.replace('_rate', '')}={value:.1f}"
                                            for name, value in rates.items()
                                            if value is not None
                                        ) or "-"
                                        rendered_states.append(
                                            f"{state['value']:02X}:n{state['count']}"
                                            f"/|rate|[{rate_text}]"
                                        )
                                    lines.append(
                                        f"       tail-state@{item['offset']:02X}: "
                                        + "  ".join(rendered_states)
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
                                f" yaw-ref-candidate={gimbal.yaw_reference_deg:.2f}deg"
                                f" rel-yaw={gimbal.relative_yaw_deg:.1f}deg"
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

    if verbose:
        cross = _cross_attitude_diagnostics(topology)
        if cross is not None:
            if cross.get("insufficient_excitation"):
                spans = cross["axis_spans"]
                excited = ",".join(cross["excited_axes"]) or "none"
                lines.append(
                    "cross-attitude: skipped kinematic fit "
                    f"(insufficient excitation; "
                    f"spans pitch={spans['pitch']:.1f} "
                    f"roll={spans['roll']:.1f} "
                    f"yaw={spans['yaw']:.1f}deg; "
                    f"excited={excited})"
                )
                return "\n".join(lines)

            def corr(value):
                return f"{value:+.3f}" if value is not None else "?"
            fc_pitch, fc_roll, fc_yaw = cross["fc_ranges"]
            g_pitch, g_roll, g_yaw = cross["gimbal_ranges"]
            solved_pitch, solved_roll, solved_yaw = cross["solved_relative_ranges"]
            joint_pitch, joint_roll, relative_yaw = cross["field_ranges"]
            lines.append(
                "cross-attitude: "
                f"samples={cross['pairs']} "
                f"best-lag={cross['best_lag_ms']:+d}ms "
                f"fc-bracket={cross['fc_bracket_median_ms']:.1f}ms median/"
                f"{cross['fc_bracket_max_ms']:.1f}ms max"
            )
            lines.append(
                "    fc: "
                f"pitch={fc_pitch[0]:.1f}..{fc_pitch[1]:.1f} "
                f"roll={fc_roll[0]:.1f}..{fc_roll[1]:.1f} "
                f"yaw={fc_yaw[0]:.1f}..{fc_yaw[1]:.1f}deg"
            )
            lines.append(
                "    gimbal: "
                f"pitch={g_pitch[0]:.1f}..{g_pitch[1]:.1f} "
                f"roll={g_roll[0]:.1f}..{g_roll[1]:.1f} "
                f"yaw={g_yaw[0]:.1f}..{g_yaw[1]:.1f}deg"
            )
            lines.append(
                "    q-relative-solved: "
                f"pitch={solved_pitch[0]:.1f}..{solved_pitch[1]:.1f} "
                f"roll={solved_roll[0]:.1f}..{solved_roll[1]:.1f} "
                f"yaw={solved_yaw[0]:.1f}..{solved_yaw[1]:.1f}deg"
            )
            lines.append(
                "    relative-fields: "
                f"joint@14={joint_pitch[0]:.1f}..{joint_pitch[1]:.1f} "
                f"joint-roll@16={joint_roll[0]:.1f}..{joint_roll[1]:.1f} "
                f"yaw@08={relative_yaw[0]:.1f}..{relative_yaw[1]:.1f}deg"
            )
            lines.append(
                "    quaternion-relative-models: "
                f"pitch corr={corr(cross['pitch_joint_corr'])} "
                f"err={cross['pitch_joint_error_median']:.2f}/"
                f"{cross['pitch_joint_error_max']:.2f}deg median/max; "
                f"roll corr={corr(cross['roll_joint_corr'])} "
                f"err={cross['roll_joint_error_median']:.2f}/"
                f"{cross['roll_joint_error_max']:.2f}deg; "
                f"yaw corr={corr(cross['relative_yaw_corr'])} "
                f"err={cross['relative_yaw_error_median']:.2f}/"
                f"{cross['relative_yaw_error_max']:.2f}deg"
            )
            order_scores = cross.get("joint_order_scores") or []
            if order_scores:
                best = order_scores[:3]
                lines.append(
                    "    joint-kinematics: " + "  ".join(
                        f"{item['order']}={item['median_error']:.2f}/"
                        f"{item['max_error']:.2f}deg"
                        for item in best
                    ) + " median/max"
                )
            mount_scores = cross.get("mount_order_scores") or []
            if mount_scores:
                best_mounts = mount_scores[:3]
                lines.append(
                    "    mount-fit: " + "  ".join(
                        f"{item['side']}:{item['order']}="
                        f"{item['median_error']:.2f}/{item['max_error']:.2f}deg"
                        for item in best_mounts
                    ) + " blocked-cv median/max"
                )
                best_mount = cross.get("best_mount")
                if best_mount is not None:
                    from .telemetry import quaternion_to_euler_deg
                    mp, mr, my = quaternion_to_euler_deg(best_mount["mount_q"])
                    lines.append(
                        f"    best-mount: side={best_mount['side']} "
                        f"order={best_mount['order']} lag={best_mount['lag_ms']:+d}ms "
                        f"euler=({mp:.2f},{mr:.2f},{my:.2f})deg"
                    )
            ref10 = cross["ref10_range"]
            lines.append(
                "    field@10 candidate: "
                f"range={ref10[0]:.2f}..{ref10[1]:.2f}deg "
                f"corr(fc-yaw)={corr(cross['ref10_fc_corr'])} "
                f"corr(gimbal-yaw)={corr(cross['ref10_gimbal_corr'])}"
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
