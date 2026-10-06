from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
import time
from collections import Counter
from contextlib import contextmanager
from datetime import date
from pathlib import Path

from . import commands, gimbal, installed, params, pcap, topology
from .client import DumlClient
from .errors import (
    DumlError, FlashAborted, FlashFailed, FlashOutcomeUnknown, FlashRefused,
)
from .display import ProgressView
from .extract import REPORT, extract
from .flasher import PROCEDURES, UPGRADE_CENTER, Flasher, Stage, plan
from .frame import address, format_address
from .ingest import add, harvest
from .journal import Journal
from .pack import pack
from .package import inspect_package
from .profiles import PC, PROFILES, get_profile
from .store import Store, StoreError, assistant_cache, size_text
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

    # stderr, so that --json output stays one JSON document
    print("SIMULATION: no USB device is used.", file=sys.stderr, flush=True)
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


def cmd_gimbal_cal(args, profile) -> int:
    """Start a gimbal calibration (gimbal 04/08), reversed from the Dr. Failov
    repair tool. DevMode is confirmed on the M4T; JointCoarse and Linear Hall are
    the same command with a different selector but not confirmed (need --force).
    Action command, fire-and-forget: the gimbal moves and the M4T sends no reply."""
    cal = gimbal.CALIBRATIONS[args.kind]
    if not cal.confirmed and not args.force:
        _say(f"{cal.name} is {cal.note}; re-run with --force to send it anyway.")
        return 2
    journal = Journal(args.journal)
    with journal, _opener(args, profile, journal, _drone(args, profile))() as client:
        frame = gimbal.calibrate(client, args.kind)
    _say(f"sent {cal.name}: {format_address(frame.sender)}>{format_address(frame.receiver)} "
         f"04/08 {frame.payload.hex()} (fire-and-forget; the M4T sends no reply)")
    if not cal.confirmed:
        _say(f"note: {cal.note}")
    return 0


def _capture_frames(path):
    return (entry.frame for entry in pcap.iter_frames(path))


def cmd_topology(args, profile) -> int:
    roles = {profile.target: "Primary target"}
    if profile.upgrade_center is not None:
        roles[profile.upgrade_center] = "Upgrade Center"
    if args.capture:
        graph = topology.from_capture(
            args.capture, host=profile.host, device=args.device,
            endpoints=set(args.endpoint) if args.endpoint else None, roles=roles,
        )
    else:
        graph = topology.Topology(host=profile.host, roles=roles)
        journal = Journal(args.journal)
        with journal, _opener(args, profile, journal, _drone(args, profile))() as client:
            # DumlClient normally keeps only the General set so telemetry cannot
            # flood flash/reader workflows. Discovery is the opposite use case:
            # every valid frame is evidence, while journal_rx still prevents
            # per-frame telemetry fsync/logging.
            client.keep = lambda frame: True
            if args.answer_center or args.assistant_session:
                client.responders[(commands.GENERAL, commands.CENTER_INFO)] = commands.CENTER_INFO_REPLY
                client.responders[(commands.GENERAL, commands.CENTER_STATE)] = commands.CENTER_STATE_REPLY
            if args.assistant_session:
                client.set_keepalive(
                    1.0, address(PC, 0), 0x00, commands.GENERAL,
                    commands.UPGRADE_REPORT, b"\x00",
                )
            warmup_deadline = time.monotonic() + args.warmup
            while time.monotonic() < warmup_deadline:
                client.poll(min(0.1, max(0.0, warmup_deadline - time.monotonic())))
            deadline = time.monotonic() + args.seconds
            while time.monotonic() < deadline:
                for frame in client.poll(min(0.1, max(0.0, deadline - time.monotonic()))):
                    graph.observe(frame, time.monotonic())
            if args.probe:
                topology.probe_versions(client, graph, args.probe, timeout=args.probe_timeout)

    if args.json:
        _say(json.dumps(graph.as_dict(), ensure_ascii=False))
    else:
        _say(topology.report(graph, commands_per_module=args.commands, verbose=args.verbose))
    return 0 if graph.confirmed else 2


def cmd_manifest(args, profile) -> int:
    if args.output and Path(args.output).exists():  # before anything is read
        raise FileExistsError(f"{args.output} already exists; manifest -o never overwrites.")
    if args.capture:
        data = installed.config_from_frames(_capture_frames(args.capture),
                                            profile.upgrade_center)
        if data is None:
            print("No complete read of the installed configuration (00/4F type 01) in this "
                  "capture.", file=sys.stderr)
            return 2
    else:
        journal = Journal(args.journal)
        with journal, _opener(args, profile, journal, _drone(args, profile))() as client:
            data = installed.read_config(client, profile.upgrade_center)
    if args.output:
        # Saved before it is parsed: a layout the parser does not know is
        # still worth keeping for the archive.
        with open(args.output, "xb") as handle:
            handle.write(data)
    config = installed.describe(data, profile.product_code)
    package = differences = None
    if args.compare:
        package = inspect_package(args.compare)
        differences = installed.compare(config, package)
    if args.json:
        result = {"version": str(config.version) if config.version else None,
                  "size": len(config.data), "md5": config.md5.hex(),
                  "modules": [{"name": item.name, "size": item.size, "md5": item.md5.hex()}
                              for item in config.modules]}
        if package is not None:
            result["compare"] = {"package": str(package.path), "version": str(package.version),
                                 "matches": not differences, "differences": differences}
        _say(json.dumps(result))
        return 2 if differences else 0
    _say(f"version   {config.version or 'unknown: no readable manifest'}")
    _say(f"config    {len(config.data)} bytes, md5 {config.md5.hex()}"
         + (f", saved to {args.output}" if args.output else ""))
    _say(f"modules   {len(config.modules)}")
    for item in config.modules:
        _say(_ascii(f"  {item.size:>11} {item.md5.hex()} {item.name}"))
    if package is None:
        return 0
    if differences:
        _say(_ascii(f"The drone does NOT run {package.path.name} ({package.version}):"))
        for line in differences:
            _say(_ascii(f"  {line}"))
        return 2
    _say(_ascii(f"The drone runs exactly {package.path.name} ({package.version})."))
    return 0


def cmd_params(args, profile) -> int:
    if args.capture:
        items = params.from_frames(_capture_frames(args.capture))
        if not items:
            print("No flight controller parameters (03/E1) in this capture.", file=sys.stderr)
            return 2
    else:
        def progress(done, count):
            if done % 250 == 0 or done == count:
                print(f"read {done} of {count} indexes", file=sys.stderr, flush=True)

        journal = Journal(args.journal)
        with journal, _opener(args, profile, journal, _drone(args, profile))() as client:
            info, items = params.read(client, on_progress=progress)
        print(f"table {info.table}: {info.count} indexes, {len(items)} parameters, "
              f"crc {info.crc:08x}", file=sys.stderr)
        if not items:
            print("The flight controller listed no parameters.", file=sys.stderr)
            return 2
    shown = [item for item in items
             if (not args.changed or item.changed)
             and (not args.name or args.name.lower() in item.name.lower())]
    if args.json:
        def finite(number):  # JSON has no NaN or infinity
            return None if isinstance(number, float) and not math.isfinite(number) else number

        _say(json.dumps([{"index": item.index, "name": item.name, "type": item.type_name,
                          "value": finite(item.value) if item.value is not None else
                          (item.raw.hex() if item.raw is not None else None),
                          "default": finite(item.default), "min": finite(item.minimum),
                          "max": finite(item.maximum), "changed": item.changed}
                         for item in shown], allow_nan=False))
        return 0
    def plain(number):
        return f"{number:g}" if isinstance(number, float) else str(number)

    for item in shown:
        _say(_ascii(f"{item.index:5} {item.type_name:4} {item.shown():>14}"
                    f"{'*' if item.changed else ' '} default {plain(item.default):<10} "
                    f"[{plain(item.minimum)}..{plain(item.maximum)}]  {item.name}"))
    _say(f"{len(shown)} of {len(items)} parameters shown; * = differs from the default")
    return 0


def _show_package(package) -> None:
    _say(_ascii(f"file      {package.path}"))
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


def _ascii(text: str) -> str:
    """Text from a capture, a manifest or the drone, printable on any console
    and unable to steer it: non-ASCII and control characters are escaped."""
    text = text.encode("ascii", "backslashreplace").decode("ascii")
    return "".join(char if " " <= char < "\x7f" else f"\\x{ord(char):02x}" for char in text)


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
    if args.from_store:
        with _store_package(args, profile, target) as (package, event):
            return _flash(args, profile, package, target, expected, event)
    package = inspect_package(args.package)
    _show_package(package)
    return _flash(args, profile, package, target, expected)


@contextmanager
def _store_package(args, profile, target):
    """The version from the store as a temporary package for the unchanged
    flasher: the same tar ``fw export`` writes. It is deleted however the
    flash ends; every store problem is a refusal before anything is sent."""
    product = profile.product_code
    try:
        store = Store.open(args.store)
        config, notes = store.select(product, target, args.config)
    except (StoreError, OSError, ValueError) as exc:  # ValueError: a hand-edited index
        raise FlashRefused(f"{exc} Nothing was sent.") from exc
    path = store.tmp / f"flash-{os.getpid()}-{product}-{target}-{config.sha[:8]}.bin"
    _say(_ascii(f"store     {store.root}: {product} {target}, config {config.sha[:12]}, "
                f"{config.held}/{len(config.entries)} modules"))
    try:
        try:
            store.tmp.mkdir(exist_ok=True)
            path.unlink(missing_ok=True)  # left by an earlier process with this pid
            package = store.export(config, path, temporary=True)
        except (DumlError, OSError) as exc:
            raise FlashRefused(f"The package could not be built from the store: {exc} "
                               "Nothing was sent.") from exc
        _say("build     written and read back; every file matches its manifest")
        for note in notes:
            _say(f"note: {note}")
        _show_package(package)
        yield package, {"store": str(store.root), "product": product, "version": str(target),
                        "config_sha256": config.sha, "package_sha256": package.sha256,
                        "package_md5": package.md5.hex()}
    finally:
        # Never raises: a file held by a virus scanner must not replace the
        # flash's own result (or exception) with a cleanup error.
        for leftover in (path, path.with_name(path.name + ".part")):
            try:
                leftover.unlink(missing_ok=True)
            except OSError as exc:
                _say(_ascii(f"note: could not delete {leftover} ({exc}); dji-duml fw check "
                            "--fix deletes it after 24 h"))


def _flash(args, profile, package, target, expected, store_event=None) -> int:
    journal_path = args.journal or Path("dji-duml-journal") / (
        time.strftime("%Y%m%d-%H%M%S") + f"-{profile.key}.jsonl")
    drone = _drone(args, profile, image_version=args.target)
    # The upgrade center gets the manifest's files, legacy-ftp the whole image.
    center = (args.procedure or profile.default_procedure) == UPGRADE_CENTER
    total = package.files_size if center and package.files else package.size
    with Journal(journal_path) as journal, ProgressView(total, verbose=args.verbose) as view:
        _say(_ascii(f"journal   {journal_path}"))
        if store_event is not None:
            journal.event("store-package", **store_event)
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


FLASH_NEXT = ("dji-duml flash --from-store --target {} --expected-current <version on the drone> "
              "--yes")
CHOOSE_NEXT = "dji-duml fw show {}   ({} complete configurations: choose one with --config)"


def _complete(store: Store, product: str, version: FirmwareVersion) -> list:
    found = next((item for item in store.versions(product) if item.version == version), None)
    return found.complete if found else []


def _target(store: Store, product: str, version: FirmwareVersion, chosen=None) -> str:
    """``V`` for FLASH_NEXT, with ``--config`` when V has more than one
    complete configuration: ``chosen``'s, else a placeholder naming them."""
    complete = _complete(store, product, version)
    if len(complete) <= 1:
        return str(version)
    if chosen is not None:
        return f"{version} --config {chosen.sha[:8]}"
    return f"{version} --config <{' or '.join(config.sha[:8] for config in complete)}>"


def _store(args, create: bool = False) -> Store:
    store = Store.open(args.store, create=create)
    _say(_ascii(f"store     {store.root}" + (" (created)" if store.created else "")))
    return store


def _next(store: Store, ready: str | None, otherwise: str, harvested: bool = False) -> None:
    """The one thing to do next: repair, harvest, flash, or ``otherwise``."""
    cache = store.unseen_cache(assistant_cache())
    model = store.model()
    if model.absent or model.unreadable or store.lost_index:
        _say("STORE DAMAGED: dji-duml fw check")
    elif cache and cache[1] and not harvested:
        _say(f"next      dji-duml fw harvest   (firm_cache: {cache[1]} files not in the store)")
    elif ready:
        _say(f"next      {FLASH_NEXT.format(ready)}")
    else:
        _say(f"next      {otherwise}")


def _spaced(number: int) -> str:
    return f"{number:,}".replace(",", " ")


def _note(text: str) -> str:
    """A release note from DJI, printable on any console."""
    return _ascii(text.replace("•", "*").replace("\t", " "))


def _origin(store: Store, config) -> str:
    """Where a version came from: its configuration's sources, and ``cache``
    when Assistant's cache holds all of its modules too. Modules shared with
    other versions would name every source, so they are not listed."""
    kinds = store.kinds([config.sha])
    if all(any(source["from"] == "cache" for source in store.index["objects"][digest]["sources"])
           for entry in config.entries for digest in entry.objects) and "cache" not in kinds:
        kinds += ", cache"
    return kinds


def _row(store: Store, version) -> str:
    release = version.release.date if version.release else ""
    best = version.best
    if best is None:
        return f"  {str(version.version):10}  {release:10}  not held{'':22}DJI release list only"
    row = (f"  {str(version.version):10}  {release:10}  {version.state:8}  "
           f"{best.held:>2}/{len(best.entries):<4}  {size_text(best.files_size):>9}  ")
    lost = [entry for entry in best.entries if entry.state != "ok"]
    if not lost:
        return row + _origin(store, best)
    first = lost[0].file
    return row + (f"missing {len(lost)} ({first.name}, {size_text(first.size)}"
                  + (", ..." if len(lost) > 1 else "") + f"): fw show {version.version}")


def _damage(store: Store) -> None:
    """What would otherwise vanish from the views: a lost index, and
    configuration objects that no longer read as one."""
    if store.lost_index:
        _say(_ascii(f"DAMAGED   {store.lost_text()}"))
    for digest, error in sorted(store.model().unreadable.items()):
        _say(_ascii(f"DAMAGED   unreadable config {digest[:12]}: {error}"))


def cmd_fw_list(args, profile) -> int:
    store = Store.open(args.store)
    model = store.model()
    _say(_ascii(f"store     {store.root}  ({len(model.present)} objects, "
                f"{size_text(sum(record['size'] for record in model.present.values()))})"))
    _damage(store)
    products = store.products()
    shown = [profile.product_code] + ([product for product in products
                                       if product != profile.product_code] if args.all else [])
    ready = None
    for product in shown:
        title = f"{profile.name} (profile {profile.key})" if product == profile.product_code \
            else "another product"
        _say(f"{product:9} {title}")
        versions = store.versions(product)
        if not versions:
            _say("  nothing held")
            continue
        _say("  version     released    state     modules  size       from")
        for version in versions:
            _say(_ascii(_row(store, version)))
            if product == profile.product_code and ready is None \
                    and version.state.startswith("ready"):
                ready = "<version>"
    others = [product for product in products if product not in shown]
    if others:
        _say(f"others    {', '.join(others)}: fw list --all")
    if args.all:
        for digest, entries in store.unassigned():
            listed = sorted(entry["version"] for entry in entries)
            _say(f"release list {digest[:8]}: {len(entries)} versions {listed[0]}..{listed[-1]}, "
                 "no held configuration matches")
    orphans = store.orphans()
    if orphans:
        _say(f"orphans   {len(orphans)} modules, "
             f"{size_text(sum(record['size'] for _, record in orphans))}, listed by no held "
             "configuration (fw orphans)")
    cache = store.unseen_cache(assistant_cache())
    if cache is not None:
        _say(f"assistant firm_cache: {cache[0]} files, "
             + (f"{cache[1]} not in the store" if cache[1] else "all in the store"))
    _next(store, ready, "dji-duml fw add <package, capture or folder>")
    return 0


def _release_text(release: dict[str, str]) -> str:
    parts = []
    for key, value in release.items():
        if key == "expire" and value.replace("/", "-") < date.today().isoformat():
            value += " (past; not enforced by the device)"
        parts.append(f"{key} {value}")
    return ", ".join(parts)


def cmd_fw_show(args, profile) -> int:
    store = _store(args)
    _damage(store)
    target = FirmwareVersion.parse(args.version)
    product = profile.product_code
    versions = store.versions(product)
    found = next((version for version in versions if version.version == target), None)
    if found is None:
        held = [str(version.version) for version in versions if version.configs]
        raise StoreError(f"{product} {target} is not held and no DJI list knows it. "
                         f"Held: {', '.join(held) or 'nothing'}.")
    release = found.release
    _say(f"version   {product} {target}" + (
        f", released {release.date}" + (f" ({release.flow})" if release.flow else "")
        if release else ""))
    configs = list(found.configs)
    if args.config is not None:
        configs = [config for config in configs if config.sha.startswith(args.config.lower())]
        if len(args.config) < 8 or len(configs) != 1:
            raise StoreError(f"--config {args.config} matches {len(configs)} configurations of "
                             f"{product} {target}; give at least 8 hex digits of one.")
    if not configs:
        _say("state     not held: known only from a DJI release list")
    for config in configs:
        _say(f"state     {'ready' if config.complete else config.state}: configuration and "
             f"{config.held} of {len(config.entries)} modules, {_spaced(config.files_size)} bytes")
        sources = store.index["objects"][config.sha]["sources"]
        _say(_ascii(f"config    {config.sha[:12]}  {_spaced(config.size)} bytes, seen as "
                    + ", ".join(sorted({source["name"] for source in sources}))
                    + f" ({store.kinds([config.sha])})"))
        _say(f"release   {_release_text(dict(config.info.release)) or 'no <release> fields'}")
        _say("modules   state     file" + " " * 59 + "size  md5       seen in")
        for entry in config.entries:
            item = entry.file
            _say(_ascii(f"          {entry.state:8}  {item.name:<56} {item.size:>10}  "
                        f"{item.md5.hex()[:8]}  {store.kinds(entry.objects)}"))
            if entry.state == "ok":
                continue
            _say(f"{'':20}md5 {item.md5.hex()}")
            if entry.state == "conflict":
                _say(f"{'':20}{len(entry.objects)} objects: "
                     + ", ".join(digest[:12] for digest in entry.objects)
                     + "; see dji-duml fw check")
            else:
                lost = [record for record in store.model().absent.values()
                        if (record["md5"], record["size"]) == (item.md5.hex(), item.size)]
                _say(_ascii(f"{'':20}" + (f"damaged: {store.hint(lost[0])}" if lost else
                                          "not in the store: add a package, capture or cache "
                                          "that holds it")))
    if release and release.note:
        for number, line in enumerate(release.note.strip().splitlines()):
            _say(_note(f"{'note' if number == 0 else '':9} {line}"))
    complete = [config for config in configs if config.complete]
    if complete:
        _next(store, _target(store, product, target, complete[0] if len(complete) == 1 else None),
              "")
    return 0 if complete else 1


def cmd_fw_add(args, profile) -> int:
    store = _store(args, create=True)
    return _added(store, add(store, args.paths, args.force), profile)


def cmd_fw_harvest(args, profile) -> int:
    store = _store(args, create=True)
    return _added(store, harvest(store, args.directory), profile, harvested=True)


def _added(store: Store, report, profile, harvested: bool = False) -> int:
    for line in report.lines:
        _say(_ascii(line))
    ready = []
    for number, (product, version, before, after) in enumerate(report.changes):
        name = version if product == profile.product_code else f"{product} {version}"
        _say(f"{'versions' if number == 0 else '':9} {name}  {before} -> {after}")
        if product == profile.product_code and after.startswith("ready") \
                and not before.startswith("ready"):
            ready.append(FirmwareVersion.parse(version))
    before, after = report.orphans
    if before != after:
        _say(f"orphans   {before} -> {after}" + (
            " modules, kept until a configuration that lists them arrives" if after > before
            else ""))
    otherwise = "dji-duml fw list"
    if ready:
        complete = len(_complete(store, profile.product_code, max(ready)))
        if complete > 1:  # flash --from-store would refuse it without --config
            otherwise, ready = CHOOSE_NEXT.format(max(ready), complete), []
    _next(store, str(max(ready)) if ready else None, otherwise, harvested)
    return report.code


def cmd_fw_export(args, profile) -> int:
    store = Store.open(args.store)
    product = profile.product_code
    config, notes = store.select(product, args.version, args.config)
    _say(_ascii(f"store     {store.root}: {product} {config.info.version}, "
                f"config {config.sha[:12]}"))
    package = store.export(config, Path(args.output))
    _show_package(package)
    _say(f"files     {len(package.files)}, {package.files_size} bytes, "
         "each module as its signed manifest states")
    for note in notes:
        _say(f"note: {note}")
    _say(f"next      {FLASH_NEXT.format(_target(store, product, config.info.version, config))}")
    return 0


def cmd_fw_orphans(args, profile) -> int:
    store = _store(args)
    orphans = store.orphans()
    _say(f"orphans   {len(orphans)} modules, "
         f"{size_text(sum(record['size'] for _, record in orphans))}, listed by no held "
         "configuration")
    if orphans:
        _say("  size         sha256        first seen        source")
        for digest, record in orphans:
            first = min(record["sources"], key=lambda source: source["added"])
            seen = first["added"][:16].replace("T", " ")
            _say(_ascii(f"  {record['size']:<11}  {digest[:12]}  {seen}  "
                        f"{first['from']} {first['name']}"))
        _say("note      They become usable when a configuration that lists them is added "
             "(a capture of the flash, an offline ZIP).")
    return 0


def cmd_fw_check(args, profile) -> int:
    store = _store(args)
    rehashed = []
    if args.fix:
        with store.writer(repair=True):
            problems = store.check(args.full, fix=True, on_bytes=rehashed.append)
    else:
        problems = store.check(args.full, on_bytes=rehashed.append)
    for problem in problems:
        _say(_ascii(f"{'fixed' if problem.fixed else 'PROBLEM':9} {problem.text}"))
        if problem.hint and not problem.fixed:
            _say(_ascii(f"{'':9} {problem.hint}"))
    remaining = [problem for problem in problems if not problem.fixed]
    model = store.model()
    _say(f"checked   {len(store.index['objects'])} objects"
         + (f" ({size_text(sum(rehashed))} rehashed)" if args.full else "")
         + f", {len(model.configs)} configurations, {len(store.index['releases'])} release "
         f"lists: " + (f"{len(remaining)} problem(s) remain" if remaining else "no problems"))
    return 2 if remaining else 0


FW_HANDLERS = {"list": cmd_fw_list, "show": cmd_fw_show, "add": cmd_fw_add,
               "harvest": cmd_fw_harvest, "export": cmd_fw_export, "orphans": cmd_fw_orphans,
               "check": cmd_fw_check}


def cmd_fw(args, profile) -> int:
    return FW_HANDLERS[args.fw_command or "list"](args, profile)


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
    parser.add_argument("--store", type=Path, metavar="DIR",
                        help="firmware store for fw and flash --from-store (default "
                             "%%DJI_DUML_STORE%%, else %%LOCALAPPDATA%%\\dji-duml\\store on "
                             "Windows and ~/.dji-duml/store elsewhere; under sudo pass it)")
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

    topo = sub.add_parser(
        "topology", help="discover DUML module types and indexes from traffic")
    topo.add_argument("--capture", help="pcap/pcapng instead of a live USB device")
    topo.add_argument("--device", type=_number, help="capture: USB device address to keep")
    topo.add_argument("--endpoint", type=_number, action="append",
                      help="capture: endpoint to keep; repeatable")
    topo.add_argument("--seconds", type=float, default=2.0,
                      help="live: observation window after warm-up (default 2.0)")
    topo.add_argument("--warmup", type=float, default=1.0,
                      help="live: drain USB backlog before measuring (default 1.0)")
    topo.add_argument("--probe", type=_number, action="append",
                      help="live: read-only Version Inquiry to this DUML address; repeatable")
    topo.add_argument("--answer-center", action="store_true",
                      help="live: answer M4T 00/81 and 00/82 with captured DJI Assistant replies")
    topo.add_argument("--assistant-session", action="store_true",
                      help="live: also send captured Assistant 00/0C keepalive once per second")
    topo.add_argument("--probe-timeout", type=float, default=0.2,
                      help="live: seconds per explicit Version Inquiry (default 0.2)")
    topo.add_argument("--commands", type=int, default=8,
                      help="text report: top commands per module (default 8)")
    topo.add_argument("-v", "--verbose", action="store_true",
                      help="show per-stream rate, payload and sequence fingerprints")
    topo.add_argument("--json", action="store_true", help="one JSON topology object")

    manifest = sub.add_parser(
        "manifest", help="read the signed manifest of the firmware installed on the drone")
    manifest.add_argument("--capture", help="take it from a capture instead of the drone")
    manifest.add_argument("-o", "--output", help="save the .cfg.sig there (a new file)")
    manifest.add_argument("--compare", metavar="PACKAGE",
                          help="exit 0 if the drone runs exactly this package, else 2")
    manifest.add_argument("--json", action="store_true", help="one JSON object")

    reader = sub.add_parser(
        "params", help="read the flight controller's parameters (config table 0); reads only")
    reader.add_argument("--capture", help="take them from a capture instead of the drone")
    reader.add_argument("--changed", action="store_true", help="only values off their default")
    reader.add_argument("--name", help="only names containing this text")
    reader.add_argument("--json", action="store_true", help="one JSON list")

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

    fw = sub.add_parser("fw", help="the local firmware store, used by version; no USB "
                                   "(bare fw = fw list)")
    fw.add_argument("--all", action="store_true", help=argparse.SUPPRESS)
    fw_sub = fw.add_subparsers(dest="fw_command")
    lister = fw_sub.add_parser("list", help="versions held, missing and known from DJI's lists")
    lister.add_argument("--all", action="store_true", default=argparse.SUPPRESS,
                        help="also other products and release lists of no held product")
    shower = fw_sub.add_parser("show", help="one version: configuration, modules, release note")
    shower.add_argument("version")
    shower.add_argument("--config", metavar="HEX", help="SHA-256 prefix of one configuration")
    adder = fw_sub.add_parser(
        "add", help="store packages, captures, extract output, folders or cache files")
    adder.add_argument("paths", nargs="+", metavar="PATH")
    adder.add_argument("--force", action="store_true", help="read sources again even if unchanged")
    harvester = fw_sub.add_parser("harvest",
                                  help="store what DJI Assistant downloaded (firm_cache)")
    harvester.add_argument("directory", nargs="?", metavar="DIR",
                           help="default %%DJI_DUML_ASSISTANT_CACHE%%, else Assistant's "
                                "firm_cache (Windows only)")
    exporter = fw_sub.add_parser("export", help="write a version as a package for flash")
    exporter.add_argument("version")
    exporter.add_argument("-o", "--output", required=True, help="new file outside the store")
    exporter.add_argument("--config", metavar="HEX", help="SHA-256 prefix of one configuration")
    fw_sub.add_parser("orphans", help="modules no held configuration lists")
    checker = fw_sub.add_parser("check", help="verify the store")
    checker.add_argument("--full", action="store_true", help="rehash every object")
    checker.add_argument("--fix", action="store_true",
                         help="quarantine damaged objects, adopt strays, sweep tmp")

    gcal = sub.add_parser(
        "gimbal-cal", help="start a gimbal calibration (04/08): dev-mode is confirmed on the "
                           "M4T, joint-coarse/linear-hall are not (need --force); the gimbal moves")
    gcal.add_argument("kind", choices=sorted(gimbal.CALIBRATIONS),
                      help="dev-mode (confirmed), joint-coarse or linear-hall (unconfirmed)")
    gcal.add_argument("--force", action="store_true",
                      help="send an unconfirmed calibration (joint-coarse/linear-hall) anyway")

    flash = sub.add_parser("flash", help="write firmware (device must be prepared)")
    flash.add_argument("package", nargs="?", help="offline ZIP, dji_system.bin or a pack output")
    flash.add_argument("--from-store", action="store_true",
                       help="build the package for --target from the firmware store")
    flash.add_argument("--config", metavar="HEX",
                       help="with --from-store: SHA-256 prefix of the configuration to use")
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
            "plan": cmd_plan, "decode": cmd_decode, "topology": cmd_topology,
            "manifest": cmd_manifest,
            "params": cmd_params, "gimbal-cal": cmd_gimbal_cal, "extract": cmd_extract,
            "pack": cmd_pack, "fw": cmd_fw, "flash": cmd_flash}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "flash":
        if (args.package is None) != args.from_store:
            parser.error("flash takes either a PACKAGE or --from-store")
        if args.config is not None and not args.from_store:
            parser.error("--config needs --from-store")
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
