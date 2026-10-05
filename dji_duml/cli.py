from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

from . import commands, installed, params, pcap
from .client import DumlClient
from .errors import (
    DumlError, FlashAborted, FlashFailed, FlashOutcomeUnknown, FlashRefused,
)
from .display import ProgressView
from .extract import REPORT, extract
from .flasher import PROCEDURES, UPGRADE_CENTER, Flasher, Stage, plan
from .frame import format_address
from .journal import Journal
from .pack import pack
from .package import inspect_package
from .profiles import PROFILES, get_profile
from .version import FirmwareVersion

EXIT_CODES = {FlashRefused: 2, FlashAborted: 3, FlashFailed: 4, FlashOutcomeUnknown: 5}
UPGRADE_IDS = {0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0F, 0x20, 0x21, 0x22, 0x23, 0x24,
               0x25, 0x26, 0x27, 0x28, 0x2A, 0x40, 0x41, 0x42, 0x43, 0x4F,
               0x81, 0x82, 0x83, 0x84, 0x85}


def _say(text: str = "") -> None:
    print(text, flush=True)


def _number(text: str) -> int:
    return int(text, 0)


def _opener(args, profile, journal: Journal | None = None, drone=None):
    if drone is not None:
        return lambda: drone.client(journal)

    opened = []

    def open_client() -> DumlClient:
        from .transport import UsbBulkTransport

        # The drone gets a new USB address on every reboot, so --usb-location
        # can only select the first connection; reconnects find it again.
        location = None if opened else args.usb_location
        transport = UsbBulkTransport.open(
            profile, backend=args.backend, location=location, serial=args.serial,
        )
        opened.append(True)
        return DumlClient(transport, host=profile.host, journal=journal)

    return open_client


def _drone(args, profile, image_version: str | None = None):
    if not args.simulate:
        return None
    from .sim import SimulatedM4T

    _say("SIMULATION: no USB device is used.")
    return SimulatedM4T(profile, args.simulate, image_version=image_version)


def cmd_scan(args, profile) -> int:
    from .transport import scan

    devices = scan(profile, args.backend)
    if not devices:
        _say(f"No {profile.name} found (VID {profile.vid:04X} PID {profile.pid:04X}).")
        return 1
    for device in devices:
        _say(f"{device.backend:8} location={device.location:8} serial={device.serial or '-':20} "
             f"duml-interface={'yes' if device.has_interface else 'no'}"
             + (f"  ({device.error})" if device.error else ""))
    return 0


def cmd_version(args, profile) -> int:
    journal = Journal(args.journal)
    with journal, _opener(args, profile, journal, _drone(args, profile))() as client:
        info = commands.get_version(client, profile.target)
    if args.json:
        _say(json.dumps({"hardware": info.hardware, "firmware": str(info.firmware),
                         "loader": str(info.loader), "raw": info.raw.hex()}))
    else:
        _say(f"hardware  {info.hardware}")
        _say(f"firmware  {info.firmware}")
        _say(f"loader    {info.loader}")
        _say(f"raw       {info.raw.hex(' ')}")
        if not profile.matches_hardware(info.hardware):
            _say(f"warning: hardware does not start with {profile.product_code!r}")
    return 0


def _show_package(package) -> None:
    _say(f"file      {package.path}")
    _say(f"kind      {package.kind}, {package.members} members, {package.size} bytes")
    _say(f"product   {package.product_code}")
    _say(f"version   {package.version or 'unknown: no readable manifest in the configuration'}")
    _say(f"config    {package.config_name}")
    _say(f"md5       {package.md5.hex()}")
    _say(f"sha256    {package.sha256}")


def cmd_inspect(args, profile) -> int:
    package = inspect_package(args.package)
    _show_package(package)
    if package.product_code.lower() != profile.product_code.lower():
        _say(f"warning: profile {profile.key} expects product {profile.product_code!r}")
    return 0


def cmd_plan(args, profile) -> int:
    package = inspect_package(args.package)
    procedure = args.procedure or profile.default_procedure
    verified = procedure in profile.verified_procedures
    _say(f"Procedure {procedure} for {profile.name}: "
         f"{'verified' if verified else 'NOT verified on this model'}. Nothing is sent.")
    for line in plan(profile, package, procedure):
        _say(line)
    return 0


def cmd_decode(args, profile) -> int:
    entries, stats = pcap.decode(
        args.capture, device=args.device,
        endpoints=set(args.endpoint) if args.endpoint else None,
    )
    if args.cmd_set is not None:
        entries = [entry for entry in entries if entry.frame.cmd_set == args.cmd_set]
    if args.upgrade_only:
        entries = [entry for entry in entries if entry.frame.cmd_set == commands.GENERAL
                   and entry.frame.cmd_id in UPGRADE_IDS]
    if args.summary:
        counts = Counter(
            (entry.direction, entry.endpoint, entry.frame.sender, entry.frame.receiver,
             entry.frame.response, entry.frame.cmd_set, entry.frame.cmd_id)
            for entry in entries
        )
        for (direction, endpoint, sender, receiver, response, cmd_set, cmd_id), count in sorted(
            counts.items(), key=lambda item: (item[0][5], item[0][6], item[0][0], item[0][4]),
        ):
            _say(f"{count:7}  {direction} ep={endpoint:02x} {format_address(sender)}>"
                 f"{format_address(receiver)} {'ack' if response else 'req'} "
                 f"set={cmd_set:02x} id={cmd_id:02x}  {commands.command_name(cmd_set, cmd_id)}")
    else:
        origin = entries[0].time if entries else 0.0
        for entry in entries:
            frame = entry.frame
            payload = frame.payload.hex()
            if not args.full and len(payload) > 64:
                payload = payload[:64] + "..."
            if args.json:
                _say(json.dumps({
                    "t": round(entry.time - origin, 6), "dir": entry.direction.strip(),
                    "device": entry.device, "endpoint": entry.endpoint,
                    "sender": frame.sender, "receiver": frame.receiver, "seq": frame.seq,
                    "response": frame.response, "ack": int(frame.ack),
                    "encrypt": frame.encrypt, "cmd_set": frame.cmd_set,
                    "cmd_id": frame.cmd_id, "payload": frame.payload.hex(),
                }))
            else:
                _say(f"{entry.time - origin:11.6f} {entry.direction} ep={entry.endpoint:02x} "
                     f"{format_address(frame.sender)}>{format_address(frame.receiver)} "
                     f"seq={frame.seq:04x} {'ack' if frame.response else 'req'} "
                     f"{commands.command_name(frame.cmd_set, frame.cmd_id):<22} "
                     f"[{len(frame.payload)}] {payload}")
    print(f"{stats.frames} frames in {stats.chunks} bulk transfers ({stats.bytes} bytes); "
          f"{stats.discarded} bytes were not DUML v1.", file=sys.stderr)
    return 0


def _frames(args):
    entries, _ = pcap.decode(args.capture, device=args.device)
    return [entry.frame for entry in entries]


def cmd_params(args, profile) -> int:
    if args.capture:
        found = params.from_frames(_frames(args))
        if not found:
            _say("No flight controller parameters (03/E1) in this capture.")
            return 2
    else:
        journal = Journal(args.journal)

        def progress(done: int, total: int) -> None:
            if done % 100 == 0 or done == total:
                print(f"\r{done}/{total} items", end="" if done < total else "\n",
                      file=sys.stderr, flush=True)

        with journal, _opener(args, profile, journal, _drone(args, profile))() as client:
            info, found = params.read(client, on_progress=progress)
        print(f"table {info.table}: {info.count} indexes, {len(found)} items, "
              f"crc {info.crc:08x}", file=sys.stderr)
    shown = [item for item in found
             if (not args.changed or item.changed)
             and (not args.name or args.name.lower() in item.name.lower())]
    if args.json:
        for item in shown:
            _say(json.dumps({"table": item.table, "index": item.index, "name": item.name,
                             "type": item.type_name, "value": item.value,
                             "raw": None if item.raw is None else item.raw.hex(),
                             "default": item.default, "min": item.minimum,
                             "max": item.maximum}))
    else:
        for item in shown:
            def show(value):
                return f"{value:g}" if isinstance(value, float) else str(value)
            _say(_ascii(f"{item.index:5} {item.type_name:4} {'*' if item.changed else ' '} "
                        f"{params.format_value(item):>12}  default {show(item.default):<10} "
                        f"[{show(item.minimum)}..{show(item.maximum)}]  {item.name}"))
    print(f"{len(shown)} of {len(found)} parameters shown"
          + ("; * = differs from default" if not args.json else ""), file=sys.stderr)
    return 0


def cmd_manifest(args, profile) -> int:
    if args.capture:
        data = installed.config_from_frames(_frames(args), profile.upgrade_center)
        if data is None:
            _say("No complete read of the installed configuration (00/4F type 01) "
                 "in this capture.")
            return 2
    else:
        if profile.upgrade_center is None:
            raise DumlError(f"{profile.name} has no known upgrade center.")
        journal = Journal(args.journal)
        with journal, _opener(args, profile, journal, _drone(args, profile))() as client:
            data = installed.read_config(client, profile.upgrade_center)
    config = installed.describe(data, profile.product_code)
    if args.output:
        with open(args.output, "xb") as handle:
            handle.write(config.data)
    if args.json:
        _say(json.dumps({"version": str(config.version) if config.version else None,
                         "size": len(config.data), "md5": config.md5.hex(),
                         "modules": [{"name": item.name, "size": item.size,
                                      "md5": item.md5.hex()} for item in config.modules]}))
    else:
        _say(f"version   {config.version or 'unknown: no readable manifest'}")
        _say(f"config    {len(config.data)} bytes, md5 {config.md5.hex()}")
        _say(f"modules   {len(config.modules)}")
        for item in config.modules:
            _say(_ascii(f"  {item.size:>11} {item.md5.hex()} {item.name}"))
        if args.output:
            _say(f"saved     {args.output}")
    if not args.compare:
        return 0
    package = inspect_package(args.compare)
    differences = installed.compare(config, package)
    if not differences:
        _say(f"The drone runs exactly {package.path.name} ({package.version}).")
        return 0
    _say(f"The drone does not run {package.path.name}:")
    for line in differences:
        _say(_ascii(f"  {line}"))
    return 2


def _ascii(text: str) -> str:
    """Text from a capture or manifest, printable on any console."""
    return text.encode("ascii", "backslashreplace").decode("ascii")


def cmd_extract(args, profile) -> int:
    result = extract(args.capture, args.output, device=args.device)
    for item in result.files:
        detail = "; ".join(item.problems) if item.problems else item.manifest
        _say(_ascii(f"{'ok  ' if item.ok else 'FAIL'} {item.size:>11} "
                    f"{item.saved_as:<56} {detail}"))
        for note in item.notes:
            _say(f"{'':17}note: {note}")
    for session in result.sessions:
        where = f"Manifest {session['config']} (USB {session['usb']})"
        if session["error"]:
            _say(_ascii(f"{where}: {session['error']}"))
            continue
        _say(f"{where}: version {session['version']}")
        if session["missing"]:
            _say(_ascii(f"  not in the capture: {', '.join(session['missing'])}"))
        if session["unlisted"]:
            _say(_ascii(f"  not in the manifest: {', '.join(session['unlisted'])}"))
    passed = sum(item.ok for item in result.files)
    if result.files:
        _say(f"{len(result.files)} file(s), {passed} passed every check; "
             f"report: {Path(args.output) / REPORT}")
    else:
        _say(f"No file transfers (00/2A) in this capture; report: {Path(args.output) / REPORT}")
    if not result.ok:
        _say("NOT a complete, verified set of files: see the report.")
    stats = result.stats
    print(f"{stats.frames} frames in {stats.chunks} bulk transfers ({stats.bytes} bytes); "
          f"{stats.discarded} bytes were not DUML v1; "
          f"{result.stray_frames} file-transfer frames outside a transfer.", file=sys.stderr)
    return 0 if result.ok else 2


def cmd_pack(args, profile) -> int:
    packed = pack(args.directory, args.output)
    package = packed.package
    _show_package(package)
    _say(f"files     {len(package.files)}, {package.files_size} bytes, "
         "each module as its signed manifest states")
    if packed.ignored:
        _say(_ascii(f"ignored   {', '.join(packed.ignored)}"))
    for note in packed.notes:
        _say(f"note: {note}")
    if package.product_code.lower() != profile.product_code.lower():
        _say(f"warning: profile {profile.key} expects product {profile.product_code!r}")
    _say(f"Flash it with: dji-duml flash {subprocess.list2cmdline([str(args.output)])} "
         f"--target {package.version} --expected-current <version on the drone> --yes"
         " (add --refresh if the drone already runs this version)")
    return 0


def cmd_flash(args, profile) -> int:
    if not args.yes:
        raise FlashRefused("Firmware write requires --yes. No device action was performed.")
    target = FirmwareVersion.parse(args.target)
    expected = FirmwareVersion.parse(args.expected_current)
    package = inspect_package(args.package)
    _show_package(package)
    journal_path = args.journal or Path("dji-duml-journal") / (
        time.strftime("%Y%m%d-%H%M%S") + f"-{profile.key}.jsonl")
    drone = _drone(args, profile, image_version=args.target)
    # The upgrade center gets the manifest's files, legacy-ftp the whole image.
    center = (args.procedure or profile.default_procedure) == UPGRADE_CENTER
    total = package.files_size if center and package.files else package.size
    with Journal(journal_path) as journal, ProgressView(total, verbose=args.verbose) as view:
        _say(f"journal   {journal_path}")
        flasher = Flasher(
            _opener(args, profile, journal, drone), profile, journal=journal,
            on_progress=view, **({"upload": drone.upload, "reconnect_interval": 0.05,
                                  "settle_timeout": 1.0, "greet_delay": 0.05}
                                 if drone else {}),
        )
        try:
            result = flasher.run(
                package, target=target, expected_current=expected, confirm=True,
                procedure=args.procedure, accept_unverified=args.accept_unverified,
                allow_same_version=args.refresh, timeout=args.timeout,
            )
        except KeyboardInterrupt:
            stage = flasher.stage
            view.close()
            _say()
            if stage in (Stage.START, Stage.VERIFY, Stage.USER_CONFIRM, Stage.UPGRADING,
                         Stage.REBOOT):
                _say("Interrupted. The device keeps flashing on its own: do NOT unplug or "
                     "power it off. Read its version when it is idle.")
            elif stage is Stage.DONE:
                _say("Interrupted after the flash finished; see the journal for the result.")
            elif stage is Stage.CONFIRM:
                _say("Interrupted after the device reported success, before its version was "
                     "read back. Leave it powered and read its version when it is idle.")
            elif stage in (None, Stage.PREFLIGHT):
                _say("Interrupted before anything was written to the device.")
            else:
                _say("Interrupted. Flashing was not started. Power-cycle the device before "
                     "another attempt.")
            return 130
    _say(f"Installed {result.installed} (was {result.previous}) in {result.seconds:.0f} s"
         + ("" if result.completion_observed else "; completion push was not seen, "
            "result confirmed by version read-back") + ".")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dji-duml", description="Direct DUML over USB, without DJI Assistant.")
    parser.add_argument("--profile", default="m4t", choices=sorted(PROFILES),
                        help="device model (default m4t)")
    parser.add_argument("--backend", default="auto", choices=("auto", "libusb0", "libusb1"),
                        help="USB library; libusb0 on Windows also means DJI's own DLL")
    parser.add_argument("--usb-location", help="bus:address as printed by scan")
    parser.add_argument("--serial", help="USB serial number of the device")
    parser.add_argument("--journal", type=Path, help="JSONL log of every frame and decision")
    parser.add_argument("--simulate", metavar="VERSION",
                        help="use an in-memory drone running VERSION instead of USB")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("scan", help="list matching USB devices (descriptor requests only)")
    version = sub.add_parser("version", help="read hardware and firmware version")
    version.add_argument("--json", action="store_true", help="one JSON object")
    inspect = sub.add_parser("inspect", help="check a firmware package without USB")
    inspect.add_argument("package", help="offline ZIP, dji_system.bin or a pack output")
    planner = sub.add_parser("plan", help="print the frames a flash would send; sends nothing")
    planner.add_argument("package", help="offline ZIP, dji_system.bin or a pack output")
    planner.add_argument("--procedure", choices=PROCEDURES,
                         help="default: the profile's (upgrade-center for m4t)")

    decode = sub.add_parser("decode", help="decode DUML frames from a USBPcap/usbmon capture")
    decode.add_argument("capture", help="pcap or pcapng, USBPcap or usbmon")
    decode.add_argument("--device", type=_number, help="USB device address to keep")
    decode.add_argument("--endpoint", type=_number, action="append",
                        help="endpoint address to keep, e.g. 0x04 and 0x85; repeatable")
    decode.add_argument("--cmd-set", type=_number, help="keep only this command set")
    decode.add_argument("--upgrade-only", action="store_true",
                        help="keep only upgrade and file-transfer commands of the general set")
    decode.add_argument("--summary", action="store_true", help="count frames per command")
    decode.add_argument("--full", action="store_true", help="do not truncate payloads")
    decode.add_argument("--json", action="store_true", help="one JSON object per frame")

    manifest = sub.add_parser(
        "manifest", help="read the signed manifest of the firmware installed on the drone")
    manifest.add_argument("--capture", help="take it from a capture of Assistant instead of USB")
    manifest.add_argument("--device", type=_number, help="with --capture: USB device address")
    manifest.add_argument("-o", "--output", help="save the .cfg.sig to this new file")
    manifest.add_argument("--compare", metavar="PACKAGE",
                          help="check whether the drone runs exactly this package")
    manifest.add_argument("--json", action="store_true", help="one JSON object")

    parameters = sub.add_parser(
        "params", help="read the flight controller's parameters (config table 0)")
    parameters.add_argument("--capture",
                            help="take them from a capture of Assistant instead of USB")
    parameters.add_argument("--device", type=_number, help="with --capture: USB device address")
    parameters.add_argument("--changed", action="store_true",
                            help="only parameters whose value differs from the default")
    parameters.add_argument("--name", help="only names containing this text")
    parameters.add_argument("--json", action="store_true", help="one JSON object per parameter")

    extractor = sub.add_parser(
        "extract", help="recover the files a capture shows being sent to the upgrade center")
    extractor.add_argument("capture", help="pcap or pcapng, USBPcap or usbmon")
    extractor.add_argument("-o", "--output", required=True,
                           help="new or empty directory for the files and report.json")
    extractor.add_argument("--device", type=_number, help="USB device address to keep")

    packer = sub.add_parser(
        "pack", help="build a package for flash from the files extract recovered")
    packer.add_argument("directory", help="extract's output, or a .cfg.sig with its modules")
    packer.add_argument("-o", "--output", required=True,
                        help="package file to write, e.g. 17.01.0516_dji_system.bin")

    flash = sub.add_parser("flash", help="write firmware (device must be prepared)")
    flash.add_argument("package", help="offline ZIP, dji_system.bin or a pack output")
    flash.add_argument("--target", required=True,
                       help="version the package installs; checked against its manifest")
    flash.add_argument("--expected-current", required=True,
                       help="version the drone runs now; checked before any changing command")
    flash.add_argument("--yes", action="store_true", help="authorize the firmware write")
    flash.add_argument("--procedure", choices=PROCEDURES,
                       help="default: the profile's (upgrade-center for m4t)")
    flash.add_argument("--accept-unverified", action="store_true",
                       help="run a procedure that is not verified for this model")
    flash.add_argument("--refresh", action="store_true", help="allow reflashing the same version")
    flash.add_argument("--timeout", type=float, default=1800,
                       help="seconds allowed for the upgrade after the start request")
    flash.add_argument("-v", "--verbose", action="store_true",
                       help="print every progress report on its own line")
    return parser


HANDLERS = {"scan": cmd_scan, "version": cmd_version, "inspect": cmd_inspect,
            "plan": cmd_plan, "decode": cmd_decode, "extract": cmd_extract,
            "pack": cmd_pack, "flash": cmd_flash, "manifest": cmd_manifest,
            "params": cmd_params}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return HANDLERS[args.command](args, get_profile(args.profile))
    except DumlError as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_CODES.get(type(exc), 1)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
