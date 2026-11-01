# NEW — pulls real system/user/network events from the employee's machine

"""
Lightweight, polling-based collection — not true OS-level real-time hooks
(no ReadDirectoryChangesW, no Windows Event Log API, no pywin32/watchdog
dependency). Deliberate: this stays a single small dependency (psutil,
cross-platform and widely used) rather than pulling in platform-specific
low-level APIs, matching the "lightweight SME agent" brief. It's an
approximation of real endpoint monitoring, not a full EDR — worth being
explicit about rather than implying more coverage than this actually
provides.

Produces Log-shaped dicts matching routes/logs.py's LogEntry schema
(event_type, timestamp, username, action, status, process_name, filepath,
file_size, device_name, ip_address, additional_data, ...) — sent as-is to
POST /logs/ingest.

Upload/download/install coverage (added alongside the risk-scoring
per-type-decay refinement) -- what's actually observable without deeper
OS hooks, investigated and reported before implementing:

  DOWNLOADS: feasible, and mostly already covered -- WATCHED_DIRS already
  polls the Downloads folder; new files appearing there are now tagged
  event_type="download" instead of the generic "file", with a best-effort
  "did this come from the internet" signal via Windows Mark-of-the-Web
  (the Zone.Identifier NTFS alternate data stream browsers and other
  MOTW-aware apps tag downloaded files with -- the same mechanism Windows
  Defender/SmartScreen relies on). Plain file I/O, no elevated privileges,
  no new dependency. NOT a certainty: MOTW can be legitimately absent for
  a file that did come from the internet (copied via a network share,
  extracted from an archive, explicitly "unblocked" by the user) -- a
  heuristic, not proof. Windows-only (no ADS on other filesystems);
  always reports False elsewhere.

  INSTALLS: feasible at a heuristic level, reusing process polling that
  already exists -- a launched process whose name/cmdline matches known
  installer patterns (msiexec, *.msi, setup/install executables, pip/npm/
  winget/choco invocations) is tagged event_type="install". "Unverified
  source" is inferred from WHERE the executable is running from (the
  Downloads folder, or directly off a removable drive) rather than MOTW
  on the installer itself -- simpler and just as meaningful a signal for
  "did this arrive from outside normal channels."

  UPLOADS: investigated and NOT implemented. Attributing outbound network
  bytes to a specific file or upload action isn't reliably possible from
  userspace without packet inspection or browser integration -- psutil
  can see connections/bytes-per-process, but not what was actually being
  sent. A coarse "large outbound network volume" proxy was considered and
  rejected: video calls, cloud sync, and streaming would all trigger it,
  and a signal that noisy isn't worth shipping silently. Flagged as
  possible future work, not implemented here.
"""

import getpass
import os
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import psutil

# Directories polled for file-access approximation. A real deployment would
# want this configurable per-company/device; hardcoded here to keep the
# wizard to exactly what onboarding_flow.md describes (company code only,
# nothing else to configure at setup time).
WATCHED_DIRS = [Path.home() / "Desktop", Path.home() / "Documents", Path.home() / "Downloads"]
DOWNLOADS_DIR = Path.home() / "Downloads"

# Agent-local, deliberately NOT imported from backend/core/config.py --
# the agent is packaged standalone (packaging/agent/build_agent.ps1, a
# single PyInstaller exe with only requests+psutil as dependencies), so it
# can't pull in the backend's config module without dragging in FastAPI/
# SQLAlchemy/scikit-learn/torch. Size-based "is this LARGE" thresholds
# stay server-side (feature_extractor.py) on purpose -- the agent just
# reports raw facts (file_size, event_type), so tuning what counts as
# "large" doesn't require redeploying every installed agent.
INSTALLER_PROCESS_NAME_KEYWORDS = ("setup", "install", "msiexec")
INSTALLER_CMDLINE_KEYWORDS = ("pip install", "npm install", "winget install", "choco install")


@dataclass
class CollectorState:
    """Held in memory for the lifetime of one agent run — on restart, the
    agent re-baselines (emits a fresh "session started" event, and treats
    currently-running processes / current file states as the starting
    point rather than re-reporting them as new). Acceptable for a
    lightweight agent; a production EDR would persist this across
    restarts too.

    The *_baselined flags matter: without them, the first call after every
    restart would treat everything already running/present as "just
    started" (known_pids etc. start empty, so a diff against an empty set
    is everything) — confirmed directly, not theoretically: a real run on
    a real machine reported ~790 "process start" events on its first call
    for processes that had been running for hours. The first call now only
    records the baseline; diffs (and events) start from the second call on.

    known_removable is now {device_identifier: mountpoint} rather than a
    bare set -- file/process activity on a removable drive needs its
    mountpoint to scan, and needs to keep being tagged with that
    identifier for as long as the drive stays inserted (not just on the
    cycle it was first plugged in), since a large copy or an install
    launched from it can easily take longer than one 10-second cycle."""
    session_reported: bool = False
    processes_baselined: bool = False
    known_pids: set = field(default_factory=set)
    removable_baselined: bool = False
    known_removable: dict = field(default_factory=dict)
    files_baselined: bool = False
    known_file_mtimes: dict = field(default_factory=dict)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_heartbeat_event() -> dict:
    """Minimal Log-shaped dict for the agent's own liveness signal --
    main.py's run() loop sends one of these on a cycle where collect_events
    above found nothing real to report, instead of sending nothing.
    Deliberately carries NOTHING beyond event_type/timestamp: its only job
    is proving the agent process is alive and reachable right now, not
    describing device behavior, so there's no additional_data, no
    username, nothing else to add. No schema change needed on the server
    side for this -- routes/logs.py's LogEntry.event_type is a free string
    (no enum/CHECK constraint), and models/logs.py's Log.event_type column
    comment already listed "heartbeat" as a planned category alongside
    authentication/process/file/usb/etc., going back to the original
    dissertation's event taxonomy -- this is the first thing to actually
    populate it.

    Called fresh, at send time, every time -- never constructed once and
    reused, so its timestamp always reflects the moment it's actually being
    sent, not some earlier moment in the cycle."""
    return {"event_type": "heartbeat", "timestamp": _now_iso()}


def local_ip() -> str:
    """Doesn't actually send any traffic — connect() on a UDP socket just
    asks the OS to pick the local interface/address that would be used for
    that destination, entirely locally."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "unknown"


def _downloaded_from_internet(path: Path) -> bool:
    """Windows Mark-of-the-Web check -- see this file's module docstring.
    Always False on non-Windows (no NTFS alternate data streams)."""
    if os.name != "nt":
        return False
    try:
        with open(f"{path}:Zone.Identifier", "r"):
            return True
    except OSError:
        return False


def _looks_like_installer(name: str, cmdline: list) -> bool:
    lowered_name = (name or "").lower()
    if lowered_name.endswith(".msi") or any(kw in lowered_name for kw in INSTALLER_PROCESS_NAME_KEYWORDS):
        return True
    cmdline_str = " ".join(cmdline or []).lower()
    return any(kw in cmdline_str for kw in INSTALLER_CMDLINE_KEYWORDS)


def _install_source_signal(exe_path: str | None, removable_mounts: dict) -> tuple[bool, str | None]:
    """(unverified, device_name-or-None) for an installer's own
    executable -- inferred from WHERE it's running from (Downloads folder,
    or directly off a currently-mounted removable drive), not Mark-of-the-
    Web on the installer itself. A heuristic, same caveat as everything
    else here: an installer copied out of Downloads into another folder
    before running would be missed."""
    if not exe_path:
        return False, None
    exe_lower = exe_path.lower()

    if exe_lower.startswith(str(DOWNLOADS_DIR).lower()):
        return True, None

    for device_name, mount in removable_mounts.items():
        if exe_lower.startswith(str(mount).lower()):
            return True, device_name

    return False, None


def collect_events(state: CollectorState) -> list:
    """Returns newly-observed events since the last call, given the running
    CollectorState. Never lets a single collection sub-step's failure (e.g.
    no permission to read the process list) take down the whole call — a
    partial collection beats a crashed agent."""
    events = []
    username = getpass.getuser()
    ip_address = local_ip()

    if not state.session_reported:
        events.append({
            "event_type": "authentication",
            "timestamp": _now_iso(),
            "username": username,
            "action": "session_start",
            "status": "success",
            "ip_address": ip_address,
        })
        state.session_reported = True

    events.extend(_collect_removable_media(state, username))
    # known_removable is updated by the call above -- read after, so a
    # drive inserted THIS cycle is already included in what file/process
    # scanning below correlates against, not one cycle behind.
    events.extend(_collect_processes(state, username, state.known_removable))
    events.extend(_collect_file_activity(state, username, state.known_removable))

    return events


def _collect_processes(state: CollectorState, username: str, removable_mounts: dict) -> list:
    events = []
    try:
        current_pids = set(psutil.pids())
    except psutil.Error:
        return events

    if not state.processes_baselined:
        state.known_pids = current_pids
        state.processes_baselined = True
        return events

    for pid in current_pids - state.known_pids:
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            try:
                cmdline = proc.cmdline()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cmdline = []

            if _looks_like_installer(name, cmdline):
                try:
                    exe_path = proc.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    exe_path = None
                unverified, device_name = _install_source_signal(exe_path, removable_mounts)
                event = {
                    "event_type": "install",
                    "timestamp": _now_iso(),
                    "username": username,
                    "action": "start",
                    "status": "success",
                    "process_name": name,
                    "filepath": exe_path,
                    "additional_data": {"unverified_source": unverified},
                }
                if device_name:
                    event["device_name"] = device_name
                events.append(event)
            else:
                events.append({
                    "event_type": "process",
                    "timestamp": _now_iso(),
                    "username": username,
                    "action": "start",
                    "status": "success",
                    "process_name": name,
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    state.known_pids = current_pids
    return events


def _collect_removable_media(state: CollectorState, username: str) -> list:
    events = []
    try:
        partitions = psutil.disk_partitions()
    except psutil.Error:
        return events

    removable_now = {
        p.device: p.mountpoint
        for p in partitions
        if "removable" in p.opts.lower() or (os.name != "nt" and "/media/" in p.mountpoint.lower())
    }

    if not state.removable_baselined:
        state.known_removable = removable_now
        state.removable_baselined = True
        return events

    for device_name in removable_now.keys() - state.known_removable.keys():
        events.append({
            "event_type": "usb",
            "timestamp": _now_iso(),
            "username": username,
            "action": "insert",
            "status": "success",
            "device_name": device_name,
        })

    state.known_removable = removable_now
    return events


def _collect_file_activity(state: CollectorState, username: str, removable_mounts: dict) -> list:
    """Polling-based approximation of file access: compares mtimes of files
    in WATCHED_DIRS (plus, now, any currently-mounted removable drive's own
    root) against the last poll, reporting anything changed or new.
    Doesn't distinguish "read" from "write" (mtime doesn't change on a
    pure read) — this catches modifications and new files, not every
    access. A real-time filesystem hook would be needed for full coverage;
    out of scope for this agent's dependency budget.

    Files newly appearing in the Downloads folder specifically are
    reported as event_type="download" (with a best-effort Mark-of-the-Web
    check) rather than the generic "file" -- see this module's docstring.
    Files found under a removable drive's root are still event_type=
    "file", but tagged with that drive's device_name so feature_
    extractor.py's USB-followup check can correlate them back to the
    insertion event that reported the same identifier."""
    events = []
    current_mtimes = {}
    first_call = not state.files_baselined

    # (directory, device_name-or-None) -- device_name only set for
    # removable-drive roots.
    scan_targets = [(d, None) for d in WATCHED_DIRS]
    for device_name, mount in removable_mounts.items():
        scan_targets.append((Path(mount), device_name))

    for directory, device_name in scan_targets:
        if not directory.exists():
            continue
        try:
            for path in directory.iterdir():
                if not path.is_file():
                    continue
                try:
                    stat = path.stat()
                except OSError:
                    continue
                path_key = str(path)
                current_mtimes[path_key] = stat.st_mtime

                if first_call:
                    continue  # baseline only — files that already existed aren't "new"

                previous_mtime = state.known_file_mtimes.get(path_key)
                if previous_mtime is None or stat.st_mtime > previous_mtime:
                    is_new = previous_mtime is None
                    if directory == DOWNLOADS_DIR and is_new:
                        event = {
                            "event_type": "download",
                            "timestamp": _now_iso(),
                            "username": username,
                            "action": "create",
                            "status": "success",
                            "filepath": path_key,
                            "file_size": stat.st_size,
                            "additional_data": {"unverified_source": _downloaded_from_internet(path)},
                        }
                    else:
                        event = {
                            "event_type": "file",
                            "timestamp": _now_iso(),
                            "username": username,
                            "action": "access" if not is_new else "create",
                            "status": "success",
                            "filepath": path_key,
                            "file_size": stat.st_size,
                        }
                        if device_name:
                            event["device_name"] = device_name
                    events.append(event)
        except OSError:
            continue

    state.known_file_mtimes = current_mtimes
    state.files_baselined = True
    return events
