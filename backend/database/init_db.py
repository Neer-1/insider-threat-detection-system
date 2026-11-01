# KEEP litds/backend/database/init_db.py

from sqlalchemy.orm import Session

from backend.core.config import DEFAULT_DEPARTMENT_BASELINE, DEPARTMENT_ALLOWED_SENSITIVE_PATTERNS, POLICY_DEPARTMENT_KEYWORDS, ROLE_BASELINES
from backend.database.db import Base, SessionLocal, engine

# Every model module has to be imported before create_all runs — SQLAlchemy
# only registers a table on Base.metadata once its class has been defined,
# so an unimported model is silently skipped rather than erroring.
from backend.models import (  # noqa: F401
    admin,
    alert_anomaly,
    alert_decision,
    alerts,
    baselines,
    company,
    company_policy_document,
    company_smtp_config,
    department,
    devices,
    employee_notification,
    features,
    logs,
    reasoning,
    reasoning_decision,
    responses,
    risk_components,
    risk_snapshot,
)
from backend.models.company import Company
from backend.models.department import Department
from backend.database.normalization import migrate_normalized_schema

# create_all() only creates missing TABLES -- it never alters a table that
# already exists, even if the model gained a new column since that table
# was first created (its own docstring below). With no migration tool in
# this project, a new column on an EXISTING table needs an explicit,
# idempotent ALTER TABLE instead, or it silently never exists in a real
# dev/production DB that predates the model change -- confirmed this
# matters in practice, not just in theory: adding Company.
# employee_notification_enabled and DeviceMetadata.email is exactly this
# case against an already-populated database.
# (table, column, SQLite column-definition DDL fragment)
_ADDITIVE_COLUMNS = [
    ("companies", "employee_notification_enabled", "BOOLEAN NOT NULL DEFAULT 0"),
    ("device_metadata", "email", "VARCHAR(255)"),
]


def _add_missing_columns() -> None:
    """Runs after create_all(), so on a brand-new DB every column above
    already exists (created fresh from the current model) and this is a
    no-op -- PRAGMA table_info reflects the real, current column set
    either way, so this stays safe and idempotent to run on every
    startup, not just once."""
    with engine.connect() as conn:
        for table, column, ddl_type in _ADDITIVE_COLUMNS:
            existing_columns = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
            if column not in existing_columns:
                conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}")
                conn.commit()
                print(f"[init_db] added missing column {table}.{column} to existing database")


def seed_default_departments(db: Session, company_id: int) -> None:
    """Inserts the original 8 departments (finance/engineering/hr/it/
    sales/operations/executive/compliance) for one company, using
    core/config.py's ROLE_BASELINES/DEPARTMENT_ALLOWED_SENSITIVE_PATTERNS/
    POLICY_DEPARTMENT_KEYWORDS as the seed data -- those three dicts are no
    longer read anywhere else at runtime (see their own "NEW STATUS"
    comments in core/config.py); this is the one place their values still
    matter, translated once into real per-company rows. Called from two
    places: routes/company.py's register_company, for every NEW company
    going forward, and _seed_departments_for_existing_companies below, a
    one-time (per company) backfill for every company that existed before
    this feature shipped -- either way this function itself has no
    idempotency check of its own; callers are responsible for only calling
    it for a company that doesn't already have departments (see that
    backfill's own check).

    executive/compliance -> full_sensitive_access=True is the ONE place a
    name-based check for those two departments still exists anywhere in
    this codebase -- and only here, at seed time, translating the OLD
    hardcoded scheme into the new data-driven flag once. Nothing at
    runtime (agent_logic/departments.py) ever compares a department name
    against "executive"/"compliance" again after this."""
    for name, baseline in ROLE_BASELINES.items():
        sensitive_keywords = DEPARTMENT_ALLOWED_SENSITIVE_PATTERNS.get(name, ())
        full_access = name in ("executive", "compliance")
        policy_kw = POLICY_DEPARTMENT_KEYWORDS.get(name, [])
        normal_start, normal_end = baseline["normal_hours"]
        db.add(Department(
            company_id=company_id,
            name=name,
            avg_files_per_day=baseline["avg_files_per_day"],
            normal_hours_start=normal_start,
            normal_hours_end=normal_end,
            avg_failed_logins=baseline["avg_failed_logins"],
            # Skipped (left null) when full_access already grants
            # everything -- storing the full keyword list here too would
            # just be redundant, unused data that could go stale relative
            # to SENSITIVE_PATH_KEYWORDS without anyone noticing.
            allowed_sensitive_keywords=None if full_access else (", ".join(sensitive_keywords) or None),
            full_sensitive_access=full_access,
            policy_keywords=", ".join(policy_kw) or None,
        ))
    db.commit()


def _seed_departments_for_existing_companies(db: Session) -> None:
    """Backfill for every company created before this feature shipped --
    idempotent and safe to run on every startup: a company is only ever
    seeded if it has NO Department rows at all yet, active or inactive, so
    this never re-seeds a company that has since customized (added/
    removed) its own set -- "no rows yet" and "removed everything on
    purpose" are different states, and only the first one should trigger
    seeding."""
    company_ids_with_departments = {row[0] for row in db.query(Department.company_id).distinct().all()}
    all_company_ids = {row[0] for row in db.query(Company.company_id).all()}
    for company_id in all_company_ids - company_ids_with_departments:
        seed_default_departments(db, company_id)
        print(f"[init_db] seeded default departments for existing company {company_id}")


def init_db():
    """Create any tables that don't exist yet, then patch in any columns
    that were added to a model after its table already existed (see
    _add_missing_columns above) -- the combination is what actually keeps
    an existing database's schema in sync with the current models, since
    create_all() alone only covers the "brand new table" half of that.
    Department backfill runs last, since it depends on the departments
    table (and companies) already existing."""
    from sqlalchemy import inspect
    if inspect(engine).get_table_names():
        raise RuntimeError("Initialization requires an empty disposable database; existing databases are never migrated")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        _seed_departments_for_existing_companies(db)
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    print(f"Tables created using {engine.url}")
