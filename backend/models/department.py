# NEW — per-company, admin-managed departments. Replaces core/config.py's
# hardcoded ROLE_BASELINES / DEPARTMENT_ALLOWED_SENSITIVE_PATTERNS /
# POLICY_DEPARTMENT_KEYWORDS dicts as the RUNTIME source of per-department
# configuration -- those three dicts still exist, but only as the seed
# data every company's starting department set is copied from (database/
# init_db.py's _seed_default_departments, routes/company.py's
# register_company). See agent_logic/departments.py for the shared
# lookup/fallback helpers every runtime consumer now goes through instead
# of reading the old dicts directly.

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class Department(Base):
    """A company's own department definition -- name, the static baseline
    floor get_effective_baseline() blends toward (agent_logic/
    baseline_learning.py, unchanged mechanism, just a new source for the
    floor value), which sensitive-content keywords are in-scope for it,
    and an optional policy-excerpt relevance boost.

    DeviceMetadata and DepartmentBaseline reference this row by id. The
    migration resolves every legacy name with both company id and name, so
    identical names in separate tenants cannot be conflated.

    Soft-delete only (is_active), never a hard DELETE -- same "never
    hard-delete a company-scoped named entity other rows may point at"
    precedent as Admin's own soft removal (routes/admin.py's remove_admin):
    removal route clears current assignments before deactivation, preserving
    the existing "no department set" fallback."""

    __tablename__ = "departments"
    __table_args__ = (
        UniqueConstraint("company_id", "name", name="uq_department_company_name"),
    )

    id = Column(Integer, primary_key=True)
    company_id = Column(Integer, ForeignKey("companies.company_id"), nullable=False, index=True)
    name = Column(String(50), nullable=False)

    # Static baseline FLOOR -- same {"avg_files_per_day", "normal_hours",
    # "avg_failed_logins"} shape core/config.py's old ROLE_BASELINES[dept]
    # provided. A brand-new admin-created department is seeded with
    # core/config.py's DEFAULT_DEPARTMENT_BASELINE (a single generic,
    # not-guessed-per-department floor) rather than asking the admin to
    # type numbers -- the real, per-department comparison point is still
    # the learned DepartmentBaseline/DeviceBaseline EWMA (models/
    # baselines.py, itself already company-scoped and untouched by this
    # table) once real activity accumulates; this is only ever the
    # cold-start fallback that system blends away from.
    avg_files_per_day = Column(Float, nullable=False)
    normal_hours_start = Column(Integer, nullable=False)
    normal_hours_end = Column(Integer, nullable=False)
    avg_failed_logins = Column(Float, nullable=False)

    # Comma-separated subset of core/config.py's SENSITIVE_PATH_KEYWORDS --
    # same vocabulary DEPARTMENT_ALLOWED_SENSITIVE_PATTERNS scoped from,
    # not a new one. Null/empty = no special sensitive access, matching
    # the old dict's .get(department, ()) default for an unlisted
    # department exactly. Ignored entirely when full_sensitive_access is
    # set (see below).
    allowed_sensitive_keywords = Column(Text, nullable=True)

    # Data-driven replacement for the old hardcoded executive/compliance
    # name check (core/config.py's DEPARTMENT_ALLOWED_SENSITIVE_PATTERNS
    # literally assigning those two keys the full SENSITIVE_PATH_KEYWORDS
    # tuple, by reference) -- when true, department_mismatch can never
    # fire for this department, and it tracks whatever
    # SENSITIVE_PATH_KEYWORDS currently contains (agent_logic/
    # departments.py's allowed_sensitive_keywords_for re-reads that list
    # live on every call), not a frozen snapshot -- same "always full,
    # always current" property the old by-reference dict assignment had.
    # Any admin can set this on any department now, not just the two
    # originally seeded with it.
    full_sensitive_access = Column(Boolean, nullable=False, default=False)

    # Optional -- comma-separated, feeds reasoning/policy_document.py's
    # excerpt relevance selection as an ADDITIONAL signal alongside the
    # always-available anomaly-type keywords (POLICY_ANOMALY_KEYWORDS,
    # untouched by this feature). Purely additive: a department with
    # nothing here doesn't break excerpt selection, it just contributes no
    # extra relevance boost -- see select_relevant_excerpt's own
    # docstring for the graceful-degradation behavior this relies on.
    policy_keywords = Column(Text, nullable=True)

    is_active = Column(Boolean, nullable=False, default=True)

    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))

    company = relationship("Company")
