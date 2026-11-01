# KEEP litds/backend/database/db.py — swap DATABASE_URL to Postgres via env var per our earlier decision, SQLite fallback for local dev

from backend.core import env  # noqa: F401 -- loads .env before any os.getenv() below

import os
from datetime import timezone

from sqlalchemy import DateTime, TypeDecorator, create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker


class UTCDateTime(TypeDecorator):
    """DateTime(timezone=True), plus one guarantee that alone doesn't give
    on SQLite: a value read back always carries explicit UTC tzinfo.
    SQLite has no native datetime type -- every write in this codebase
    uses datetime.now(timezone.utc), but the round-trip through SQLite's
    TEXT storage can come back tz-naive. Confirmed live this was leaking
    all the way to the API: GET /employees/{id} returned "enrolled_at":
    "2026-08-24T19:57:52.483773" -- no "Z"/"+00:00" at all. A genuinely-
    UTC value with no offset marker in its JSON string is exactly what
    makes a browser's `new Date(...)` treat it as LOCAL time instead of
    UTC, silently mis-displaying every timestamp by the gap between the
    viewer's timezone and UTC (this is what dashboard/index.html's
    Mauritius-time conversion depends on being fixed -- it can't reliably
    convert "UTC -> Mauritius time" if the string doesn't unambiguously
    say UTC in the first place).

    agent_logic/analyzer.py's _decay_and_rise and feature_extractor.py's
    _consecutive_failed_logins already hand-patch around this same gap
    locally, for their own decay/streak math -- left exactly as they are
    (harmless once a value is already tz-aware; the `if tzinfo is None`
    check just becomes a no-op). This fixes it once, at the column level,
    for every read path, present or future, instead of requiring every
    new call site to remember to patch around it individually. Doesn't
    change what's written to disk -- only normalizes the Python-side
    value SQLAlchemy hands back after a read, and only when it actually
    comes back naive."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value

# SQLite is the real production target for this deployment model (a single
# admin-installed server, not a horizontally-scaled multi-writer service —
# see the packaging-phase decision) — not just a local-dev convenience
# anymore. Postgres stays fully supported for anyone who wants to scale
# past single-office concurrency: set DATABASE_URL to
# postgresql+psycopg2://user:pass@host:5432/litds.
#
# `or` rather than getenv's own default arg: .env.example ships DATABASE_URL
# as a blank `DATABASE_URL=` line (documented as optional, safe to leave
# blank), and install.ps1 copies that template to .env verbatim on a fresh
# install. load_dotenv() then sets this to "" (present-but-empty), not
# unset — getenv's default only kicks in when the key is absent entirely,
# so a blank .env value would otherwise reach create_engine() below as ""
# and crash the server on every fresh install. Found directly via a real
# clean-room install test, not theoretical.
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("Set DATABASE_URL to a dedicated synthetic demo database")

# SQLite hands each connection to a single thread by default, which breaks
# under FastAPI's threaded request handling. Postgres has no such
# restriction, so this only needs to apply when running on SQLite.
IS_SQLITE = DATABASE_URL.startswith("sqlite")
connect_args = {"check_same_thread": False} if IS_SQLITE else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)

if IS_SQLITE:
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        # SQLite does NOT enforce foreign keys by default — every FK
        # constraint this schema relies on (company/device/log/alert
        # relationships, the per-company device_fingerprint uniqueness,
        # all of it) has been silently unenforced without this. Found and
        # fixed while formalizing SQLite as the production target, not
        # caught earlier because nothing in testing so far deliberately
        # tried to violate a constraint.
        cursor.execute("PRAGMA foreign_keys=ON")
        # WAL mode allows concurrent readers alongside a writer instead of
        # SQLite's default of blocking everyone during a write — matters
        # now that this is a real production target with a dashboard
        # polling reads while agents are actively writing logs.
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency — yields one session per request and always closes it,
    even if the route raises, so a failed request can't leak a connection."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
