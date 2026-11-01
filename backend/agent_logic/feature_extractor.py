# FROM ai-agent-assignment: app/agent/feature_extractor.py — copied, needs changes: reads Feature/Log rows scoped by company+device instead of flat sample_logs.json

from datetime import timedelta, timezone

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from backend.agent_logic.baseline_learning import get_effective_baseline
from backend.agent_logic.departments import allowed_sensitive_keywords_for
from backend.core.config import (
    AFTER_HOURS_END,
    AFTER_HOURS_START,
    ANALYSIS_WINDOW_MINUTES,
    FAILED_LOGIN_STREAK_LOOKBACK,
    LARGE_DOWNLOAD_FILE_SIZE_BYTES,
    LARGE_PRINT_FILE_SIZE_BYTES,
    SENSITIVE_PATH_KEYWORDS,
    USB_ACTIVITY_WINDOW_MINUTES,
    USB_LARGE_TRANSFER_BYTES,
)
from backend.models.devices import Device, DeviceMetadata
from backend.models.features import Feature
from backend.models.logs import Log

# SENSITIVE_PATH_KEYWORDS / LARGE_PRINT_FILE_SIZE_BYTES now live in
# core/config.py — routes/logs.py's significant-events view needs the
# exact same definitions, so they moved to the shared config module rather
# than staying a copy local to this file. No dedicated "is this file
# sensitive" flag exists on Log — the original assignment got
# sensitive_files as a raw count straight from its log generator; this
# keyword heuristic is a stand-in until a real classification exists.


def _is_sensitive(filepath):
    if not filepath:
        return False
    lowered = filepath.lower()
    return any(keyword in lowered for keyword in SENSITIVE_PATH_KEYWORDS)


def _matched_sensitive_keywords(filepath):
    if not filepath:
        return []
    lowered = filepath.lower()
    return [kw for kw in SENSITIVE_PATH_KEYWORDS if kw in lowered]


def _out_of_scope_sensitive_count(db: Session, company_id: int, file_events, department: str) -> int:
    """Files that ARE sensitive (matched SENSITIVE_PATH_KEYWORDS) but
    whose matched keyword ISN'T in this department's own allow-list
    (agent_logic/departments.py's allowed_sensitive_keywords_for, a
    per-company admin-managed Department row -- was a fixed core/
    config.py dict lookup) -- e.g. HR touching a payroll file is in-scope
    and doesn't count here; Engineering touching the same file does.
    Replaces the old flat "sensitive_access_allowed" boolean that treated
    a whole department as either fully blocked or fully permitted
    regardless of which specific file was touched."""
    allowed = allowed_sensitive_keywords_for(db, company_id, department)
    count = 0
    for log in file_events:
        matched = _matched_sensitive_keywords(log.filepath)
        if matched and not any(kw in allowed for kw in matched):
            count += 1
    return count


def _consecutive_failed_logins(db: Session, device_id: int, as_of) -> int:
    """Current losing streak of failed authentications as of `as_of` --
    recomputed fresh from Log history every call, not an incrementally
    maintained counter. A persisted counter would double-count under the
    real-time rolling-window scheduler: the same physical failures
    reappear in dozens of consecutive analysis cycles as a 15-minute
    window slides past them, the same class of problem the alert-title
    dedup fix addressed last round. Walking actual history instead means
    a success resets this to zero the instant it's the most recent login
    event, with nothing that needs explicit resetting. Capped at
    FAILED_LOGIN_STREAK_LOOKBACK rows looked at -- a real streak longer
    than that is reported as exactly that many, which is already far past
    any severity threshold regardless of the true count.

    Returns 0 if the most recent authentication event is older than
    ANALYSIS_WINDOW_MINUTES -- without this, a device that fails a few
    logins and then simply has no further authentication activity at all
    (no retry, no success) would report the exact same streak forever,
    since "most recent N auth events" never changes when there are no new
    ones. That kept feeding DeviceRiskComponent's failed_logins bucket a
    nonzero raw_score indefinitely, which defeats its decay entirely
    (decay only applies when raw_score has actually dropped) -- confirmed
    live: a component that should have faded to near-zero after 30
    quiet minutes hadn't moved at all. Every other signal in this module
    is naturally window-scoped (nothing happened => 0), this recency
    check gives the streak the same property."""
    rows = (
        db.query(Log.status, Log.timestamp)
        .filter(Log.device_id == device_id, Log.event_type == "authentication", Log.timestamp < as_of)
        .order_by(Log.timestamp.desc())
        .limit(FAILED_LOGIN_STREAK_LOOKBACK)
        .all()
    )
    if not rows:
        return 0

    most_recent_timestamp = rows[0][1]
    # SQLite round-trip can drop tzinfo even though every write is UTC --
    # same fix as analyzer.py's _decay_and_rise.
    if most_recent_timestamp.tzinfo is None:
        most_recent_timestamp = most_recent_timestamp.replace(tzinfo=timezone.utc)
    as_of_aware = as_of if as_of.tzinfo is not None else as_of.replace(tzinfo=timezone.utc)
    if (as_of_aware - most_recent_timestamp) > timedelta(minutes=ANALYSIS_WINDOW_MINUTES):
        return 0

    streak = 0
    for status, _ts in rows:
        if status == "fail":
            streak += 1
        else:
            break
    return streak


def _usb_followup_activity(db: Session, company_id: int, device_id: int, window_end) -> bool:
    """True only if a USB insertion within USB_ACTIVITY_WINDOW_MINUTES
    before `window_end` was followed by a large file transfer or an
    install/execution tied to that SAME physical device -- a bare
    insertion with no qualifying follow-up returns False. Plugging in a
    drive is routine; illicit use following it is the actual signal (see
    core/config.py's USB section). "Same device" is matched via
    Log.device_name: agent/collector.py tags file activity observed on a
    removable drive's mount, and process/install events launched from it,
    with that drive's own device_name -- the same field USB insert events
    already carry -- so this is a direct correlation, not fuzzy path
    matching."""
    window_start = window_end - timedelta(minutes=USB_ACTIVITY_WINDOW_MINUTES)
    inserts = (
        db.query(Log.device_name, Log.timestamp)
        .filter(
            Log.company_id == company_id,
            Log.device_id == device_id,
            Log.event_type == "usb",
            Log.action == "insert",
            Log.timestamp >= window_start,
            Log.timestamp < window_end,
            Log.device_name.isnot(None),
        )
        .all()
    )
    if not inserts:
        return False

    for device_name, inserted_at in inserts:
        followup = (
            db.query(Log.log_id)
            .filter(
                Log.company_id == company_id,
                Log.device_id == device_id,
                Log.device_name == device_name,
                Log.timestamp >= inserted_at,
                Log.timestamp < window_end,
                or_(
                    and_(Log.event_type == "file", Log.file_size.isnot(None), Log.file_size >= USB_LARGE_TRANSFER_BYTES),
                    Log.event_type == "install",
                    Log.event_type == "process",
                ),
            )
            .first()
        )
        if followup is not None:
            return True
    return False


def extract_features(db: Session, company_id: int, device_id: int, window_start, window_end) -> dict:
    """Aggregates one device's raw Log rows over [window_start, window_end)
    into the same feature shape the original single-session extractor
    produced. The original took one flat raw_log dict per call; here the
    equivalent input is "every event this device logged in the window,"
    which is why counting/aggregation replaces direct field lookups
    throughout this function."""

    logs = (
        db.query(Log)
        .filter(
            Log.company_id == company_id,
            Log.device_id == device_id,
            Log.timestamp >= window_start,
            Log.timestamp < window_end,
        )
        .all()
    )

    device = db.query(Device).filter(Device.device_id == device_id).first()
    metadata = db.query(DeviceMetadata).filter(DeviceMetadata.device_id == device_id).first()

    # Department now comes from DeviceMetadata (set by an admin at
    # device-approval time), not a fixed employee roster. Genuinely None
    # (not a fallback department name like the old "engineering" default)
    # when nothing is set -- either never assigned, or actively cleared by
    # routes/company.py's remove_department when this device's department
    # was soft-removed. agent_logic/departments.py's baseline_floor_for/
    # allowed_sensitive_keywords_for already treat None exactly like an
    # unrecognized name (generic floor, no special sensitive access) --
    # confirmed live, not assumed, when that fallback path was built.
    department = metadata.department if metadata and metadata.department else None
    # Learned, continuously-updated baseline (agent_logic/baseline_
    # learning.py) -- blends toward the static ROLE_BASELINES constants
    # until enough real history exists, and returns them completely
    # unchanged on a cold start. Same shape as a ROLE_BASELINES entry, so
    # nothing below this line needs to change.
    baseline = get_effective_baseline(db, device_id, company_id, department)

    login_events = [log for log in logs if log.event_type == "authentication"]
    failed_logins = sum(1 for log in login_events if log.status == "fail")
    consecutive_failed_logins = _consecutive_failed_logins(db, device_id, window_end)

    file_events = [log for log in logs if log.event_type == "file"]
    files_accessed = len(file_events)
    files_moved = sum(1 for log in file_events if log.action == "move" or log.destination_path)
    sensitive_files = sum(1 for log in file_events if _is_sensitive(log.filepath))
    out_of_scope_sensitive_count = _out_of_scope_sensitive_count(db, company_id, file_events, department)

    usb_events = [log for log in logs if log.event_type == "usb"]
    usb_usage_count = len(usb_events)
    usb_followup_activity = _usb_followup_activity(db, company_id, device_id, window_end)

    process_events = [log for log in logs if log.event_type == "process"]
    processes_used = len(process_events)

    download_events = [log for log in logs if log.event_type == "download"]
    downloads_count = len(download_events)
    large_downloads_count = sum(
        1 for log in download_events if log.file_size and log.file_size >= LARGE_DOWNLOAD_FILE_SIZE_BYTES
    )

    # "unverified" is set by agent/collector.py at collection time (Mark-
    # of-the-Web / Zone.Identifier for internet-sourced files, or a
    # removable-drive path) -- only the agent can check a file's actual
    # provenance, the server just reads what it reported.
    install_events = [log for log in logs if log.event_type == "install"]
    installs_count = len(install_events)
    unverified_installs_count = sum(
        1 for log in install_events if log.additional_data and log.additional_data.get("unverified_source")
    )

    privilege_escalation = any(
        log.event_type == "privilege_escalation" or (log.action and "escalat" in log.action.lower()) for log in logs
    )
    large_print_job = any(
        log.event_type == "print" and log.file_size and log.file_size >= LARGE_PRINT_FILE_SIZE_BYTES for log in logs
    )

    active_hours = len({log.timestamp.hour for log in logs}) if logs else 0

    if logs:
        earliest = min(log.timestamp for log in logs)
        latest = max(log.timestamp for log in logs)
        session_duration = max(int((latest - earliest).total_seconds() / 60), 1)
    else:
        session_duration = max(int((window_end - window_start).total_seconds() / 60), 1)

    access_velocity = round(files_accessed / session_duration, 2) if session_duration > 0 else 0.0
    sensitive_ratio = round(sensitive_files / files_accessed, 2) if files_accessed > 0 else 0.0

    # Time deviation / after_hours: the original computed this from one
    # login_hour. A window can contain several logins, so this takes the
    # worst (most-outside-hours) login rather than averaging them away.
    normal_start, normal_end = baseline["normal_hours"]
    after_hours = False
    time_deviation = 0.0
    login_hour = None
    for log in login_events:
        hour = log.timestamp.hour
        login_hour = hour
        if hour < normal_start:
            deviation = normal_start - hour
        elif hour >= normal_end:
            deviation = hour - normal_end
        else:
            deviation = 0
        if deviation > 0:
            after_hours = True
        time_deviation = max(time_deviation, deviation)

    # The original formula compared a whole session's files_accessed
    # against avg_files_per_day directly — workable when a "session" was
    # roughly day-scale, but here windows can be an hour, so files_accessed
    # is naturally tiny next to a daily average and the raw difference
    # alone fires a false deviation on nearly every window. Fixed by (a)
    # scaling the baseline down to the window's actual duration and (b)
    # normalizing by an actual variance term instead of an arbitrary
    # fraction of the mean: file-access counts are count data, so treating
    # them as approximately Poisson-distributed (variance ~= mean) gives a
    # principled standard deviation of sqrt(expected) rather than a made-up
    # constant.
    avg_files = baseline["avg_files_per_day"]
    window_hours = max((window_end - window_start).total_seconds() / 3600, 1 / 60)
    expected_files = avg_files * (window_hours / 24)
    if expected_files > 0:
        baseline_deviation = round(abs(files_accessed - expected_files) / max(expected_files ** 0.5, 1), 2)
    else:
        baseline_deviation = 0.0

    department_mismatch = out_of_scope_sensitive_count > 0

    return {
        "label": device.label if device else None,
        "hostname": device.hostname if device else None,
        "ip_address": device.ip_address if device else None,
        "department": department,
        # Window-scaled expected file count — exposed so
        # behavioural_profiler.py's file_volume_ratio can be normalized the
        # same way (same window-duration + Poisson-variance fix) without
        # duplicating the window-duration math here.
        "expected_files": expected_files,
        "login_count": len(login_events),
        "failed_logins": failed_logins,
        "consecutive_failed_logins": consecutive_failed_logins,
        "files_accessed": files_accessed,
        "files_moved": files_moved,
        "sensitive_files": sensitive_files,
        "out_of_scope_sensitive_count": out_of_scope_sensitive_count,
        "usb_usage_count": usb_usage_count,
        "usb_inserted": usb_usage_count > 0,
        "usb_followup_activity": usb_followup_activity,
        "processes_used": processes_used,
        "downloads_count": downloads_count,
        "large_downloads_count": large_downloads_count,
        "installs_count": installs_count,
        "unverified_installs_count": unverified_installs_count,
        "active_hours": active_hours,
        "session_duration": session_duration,
        "privilege_escalation": privilege_escalation,
        "large_print_job": large_print_job,
        "login_hour": login_hour,
        "after_hours": after_hours,
        "department_mismatch": department_mismatch,
        "access_velocity": access_velocity,
        "sensitive_ratio": sensitive_ratio,
        "time_deviation": time_deviation,
        "baseline_deviation": baseline_deviation,
        # The effective (possibly learned/blended) baseline actually used
        # above -- exposed so behavioural_profiler.py compares against the
        # exact same numbers this function did, instead of independently
        # re-deriving (and potentially disagreeing with, if it called
        # get_effective_baseline() a second time) its own copy.
        "baseline_avg_files_per_day": baseline["avg_files_per_day"],
        "baseline_normal_hours": baseline["normal_hours"],
        "baseline_avg_failed_logins": baseline["avg_failed_logins"],
    }


def extract_feature_sequence(
    db: Session,
    company_id: int,
    device_id: int,
    window_start,
    window_end,
    sequence_length: int,
    current_features: dict | None = None,
) -> list[dict]:
    """Returns `sequence_length` consecutive feature-window dicts ending at
    [window_start, window_end) — the current window is last, chronological
    order otherwise. This is what the CNN's score_fn needs (see
    agent_logic/analyzer.py) and what predict_isolation_forest.py's
    score_fn also now accepts, using only the last element.

    Earlier windows are recomputed directly from Log via extract_features()
    rather than read back from Feature — Feature's approved columns don't
    carry sensitive_files, login_hour, privilege_escalation, or
    large_print_job (those were always transient, never persisted), so
    Feature alone can't reconstruct a full historical feature vector. Log
    is append-only and never pruned, so this is always possible, just N
    Log queries instead of 1.

    A brand-new device with less than `sequence_length` windows of real
    history needs no special padding logic: a window's slice that predates
    the device's first Log row simply has zero matching rows, and
    extract_features() already handles an empty window correctly (returns
    a quiet, all-zero-ish dict — verified in the agent_logic phase's
    "quiet window" test) rather than erroring. So the earliest slots of a
    new device's sequence are naturally "nothing happened here" rather than
    an artificial pad value.

    One known side effect worth being aware of, not a bug: baseline_deviation
    compares files_accessed against a nonzero expected_files for those
    pre-existence windows too, so a very new device's early sequence slots
    can show a mildly elevated baseline_deviation purely from not existing
    yet, not from any real behaviour. This is a byproduct of reusing
    extract_features() unchanged for padding rather than a special case
    — flagging it rather than quietly working around it.

    New fields added alongside the risk-model refinement (consecutive_
    failed_logins, usb_followup_activity, out_of_scope_sensitive_count,
    downloads/installs counts) are computed for every window in the
    sequence too, same as everything else here -- but none of them are in
    ai/preprocessing.py's ML_FEATURES list, so the CNN/Isolation Forest's
    input vector is unaffected; these only feed the rule-based path
    (anomaly_detector.py / risk_scorer.py).
    """
    duration = window_end - window_start
    sequence = []
    for k in range(sequence_length - 1, 0, -1):
        w_start = window_start - k * duration
        w_end = window_end - k * duration
        sequence.append(extract_features(db, company_id, device_id, w_start, w_end))
    sequence.append(current_features if current_features is not None else extract_features(db, company_id, device_id, window_start, window_end))
    return sequence


def save_feature(db: Session, company_id: int, device_id: int, window_start, window_end, time_window: str, features: dict) -> Feature:
    """Persists the subset of `features` that maps onto Feature's fixed
    columns — this is the real, queryable audit/training record. The
    richer flags (privilege_escalation, after_hours, department_mismatch,
    etc.) have no columns on the approved Feature schema, so they stay
    in-memory only and flow directly to the rest of the pipeline via the
    `features` dict — see the phase report for why."""
    feature = Feature(
        company_id=company_id,
        device_id=device_id,
        time_window=time_window,
        window_start=window_start,
        window_end=window_end,
        login_count=features["login_count"],
        failed_login_count=features["failed_logins"],
        files_accessed=features["files_accessed"],
        files_moved=features["files_moved"],
        usb_usage_count=features["usb_usage_count"],
        processes_used=features["processes_used"],
        active_hours=features["active_hours"],
        session_duration=features["session_duration"],
        access_velocity=features["access_velocity"],
        sensitive_ratio=features["sensitive_ratio"],
        time_deviation=features["time_deviation"],
        baseline_deviation=features["baseline_deviation"],
    )
    db.add(feature)
    db.commit()
    db.refresh(feature)
    return feature
