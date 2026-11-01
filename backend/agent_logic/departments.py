# NEW — shared Department-row lookups, replacing core/config.py's static
# ROLE_BASELINES / DEPARTMENT_ALLOWED_SENSITIVE_PATTERNS / POLICY_
# DEPARTMENT_KEYWORDS dicts as the RUNTIME source of per-department
# configuration. Those three dicts still exist in core/config.py, but only
# as the seed data every company's departments table is initialized from
# (database/init_db.py's _seed_default_departments, routes/company.py's
# create_department/register_company) -- nothing at request/analysis time
# reads them directly any more; everything goes through here instead.

"""
Lives in agent_logic/, not routes/ or models/ -- the same "core logic
multiple layers depend on, without depending on each other" reasoning
already applied to significant_events.py's shared predicate and
baseline_learning.py itself. Callers span agent_logic/ (feature_
extractor.py, baseline_learning.py), reasoning/ (policy_document.py,
already an established agent_logic-depends-on direction -- see reasoning/
core.py's own existing import of significant_events), and routes/
(device.py's approve/update validation, baselines.py's display endpoint).

Every function here is read-only. New assignments require an active row;
the removal route clears current device assignments before deactivating a
department. Name-based inputs are resolved together with company_id.
"""

from sqlalchemy.orm import Session

from backend.core.config import DEFAULT_DEPARTMENT_BASELINE, SENSITIVE_PATH_KEYWORDS
from backend.models.department import Department


def get_department(db: Session, company_id: int, name: str | None, *, active_only: bool = False) -> Department | None:
    """Lookup by (company_id, name). None if `name` itself is None/empty
    (callers already handle "no department set" the same way they always
    have) or if it doesn't match any row for this company.

    active_only defaults to False deliberately: the baseline/keyword/
    policy resolvers below (what every real-time lookup for an ALREADY-
    ASSIGNED device goes through) must keep resolving a soft-removed
    department's own settings exactly as before it was removed -- that's
    the whole point of soft-delete over a hard block (see models/
    department.py's own docstring: "anyone already assigned to it keeps
    their exact current sensitive-access scope and baseline"). Only
    NEW-assignment validation (routes/device.py's approve_device/
    update_device) should ever pass active_only=True -- that's the one
    place "is this a currently offered option" is the actual question."""
    if not name:
        return None
    query = db.query(Department).filter(Department.company_id == company_id, Department.name == name)
    if active_only:
        query = query.filter(Department.is_active.is_(True))
    return query.first()


def parse_keywords(text: str | None) -> tuple[str, ...]:
    """Comma-separated Department.allowed_sensitive_keywords/policy_keywords
    -> a clean tuple -- trims whitespace, drops empty entries so a
    trailing/double comma doesn't produce a phantom "" keyword."""
    if not text:
        return ()
    return tuple(kw.strip() for kw in text.split(",") if kw.strip())


def baseline_floor_for(db: Session, company_id: int, department: str | None) -> dict:
    """Static baseline FLOOR -- same {"avg_files_per_day", "normal_hours",
    "avg_failed_logins"} shape core/config.py's old ROLE_BASELINES[dept]
    provided, now DB-backed and per-company. Falls back to
    DEFAULT_DEPARTMENT_BASELINE (a single generic, not-department-specific
    floor) for a department with no matching active row -- unset,
    soft-removed, or a stale name that never existed for this company.
    agent_logic/baseline_learning.py's get_effective_baseline() is the
    only caller that matters at real-time analysis; its own blend-toward-
    the-learned-EWMA mechanism is completely unchanged, only where the
    floor value itself comes from is new."""
    dept = get_department(db, company_id, department)
    if dept is None:
        return dict(DEFAULT_DEPARTMENT_BASELINE)
    return {
        "avg_files_per_day": dept.avg_files_per_day,
        "normal_hours": (dept.normal_hours_start, dept.normal_hours_end),
        "avg_failed_logins": dept.avg_failed_logins,
    }


def allowed_sensitive_keywords_for(db: Session, company_id: int, department: str | None) -> tuple[str, ...]:
    """Replaces DEPARTMENT_ALLOWED_SENSITIVE_PATTERNS.get(department, ())
    -- same empty-tuple default for an unknown/unset/removed department
    (no special sensitive access). full_sensitive_access=True short-
    circuits to the CURRENT full SENSITIVE_PATH_KEYWORDS set -- the
    data-driven replacement for the old hardcoded executive/compliance
    name check, re-reading that global list live on every call (not a
    frozen copy taken at Department-row creation time), the same "always
    full, always current" property the old dict's by-reference tuple
    assignment had."""
    dept = get_department(db, company_id, department)
    if dept is None:
        return ()
    if dept.full_sensitive_access:
        return SENSITIVE_PATH_KEYWORDS
    return parse_keywords(dept.allowed_sensitive_keywords)


def policy_keywords_for(db: Session, company_id: int, department: str | None) -> list[str]:
    """Replaces POLICY_DEPARTMENT_KEYWORDS.get(department.lower(), []) --
    purely additive input to reasoning/policy_document.py's excerpt
    selection (see that module's _keywords_for): an empty result here
    doesn't break anything, it just means no department-specific relevance
    boost on top of the always-available anomaly-type keywords."""
    dept = get_department(db, company_id, department)
    if dept is None:
        return []
    return list(parse_keywords(dept.policy_keywords))
