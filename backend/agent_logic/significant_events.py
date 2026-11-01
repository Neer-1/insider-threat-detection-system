# NEW — shared "is this Log row significant" predicate, used by routes/logs.py's
# GET /logs/significant view AND backend/reasoning/core.py's evidence gathering

"""
Factored out on its own (not left inline in routes/logs.py) so both the
admin-facing significant-events view and the Reasoning Core's evidence
bundle use the exact same definition of "significant" rather than two
copies that could drift apart — same reasoning as SENSITIVE_PATH_KEYWORDS
living in core/config.py instead of a local copy per file. Lives in
agent_logic/ rather than routes/ so backend/reasoning/ (a core-logic
layer) doesn't end up importing from routes/ (the API layer) to get it.
"""

from sqlalchemy import and_, extract, or_

from backend.core.config import AFTER_HOURS_END, AFTER_HOURS_START, LARGE_PRINT_FILE_SIZE_BYTES, SENSITIVE_PATH_KEYWORDS
from backend.models.logs import Log


def significant_log_predicate():
    """Mirrors agent_logic/anomaly_detector.py's per-row-expressible
    checks (USB, privilege escalation, failed logins, sensitive
    filepaths, large print jobs, after-hours, downloads, installs).
    Deliberately does NOT try to reproduce window-aggregate checks like
    access_velocity or baseline_deviation — those are properties of a
    whole feature window, not any single log row.

    Wrapped in an outer AND excluding event_type="heartbeat" -- found and
    fixed while adding the heartbeat mechanism (agent/collector.py's
    build_heartbeat_event), not a pre-existing concern about heartbeats
    specifically: the after-hours clause below is NOT scoped to any
    event_type, so without this exclusion, EVERY heartbeat generated
    during the after-hours window (22:00-06:00 -- a third of the day)
    would match on timing alone and get surfaced as "significant," despite
    carrying zero behavioral information. Every other event_type this
    predicate already covers is a real, meaningful signal at any hour;
    heartbeat is the one category that's pure plumbing and should never be
    "significant" regardless of when it happens to land -- confirmed this
    would otherwise have been a real, live bug against a device left
    idle overnight, not a hypothetical."""
    sensitive_path = or_(*[Log.filepath.ilike(f"%{kw}%") for kw in SENSITIVE_PATH_KEYWORDS])
    return and_(
        Log.event_type != "heartbeat",
        or_(
            Log.event_type.in_(("usb", "privilege_escalation", "download", "install")),
            Log.action.ilike("%escalat%"),
            and_(Log.event_type == "authentication", Log.status == "fail"),
            and_(Log.event_type == "file", sensitive_path),
            and_(Log.event_type == "print", Log.file_size.isnot(None), Log.file_size >= LARGE_PRINT_FILE_SIZE_BYTES),
            or_(extract("hour", Log.timestamp) >= AFTER_HOURS_START, extract("hour", Log.timestamp) < AFTER_HOURS_END),
        ),
    )
