# NEW — learned per-device and per-department behavioral baselines, see
# agent_logic/baseline_learning.py for the update/blend logic that owns
# these tables.

from datetime import datetime, timezone

from sqlalchemy import Column, Float, ForeignKey, Integer
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class DeviceBaseline(Base):
    """Learned, continuously-updated per-device behavioral baseline -- an
    EWMA of this device's own daily activity, updated at most once per
    rolling BASELINE_ROLLUP_INTERVAL_HOURS (agent_logic/baseline_
    learning.py), never on the 10-second real-time detection cadence --
    see that module's docstring for why (the same ~15 minutes of activity
    would otherwise get folded in dozens of times before aging out of the
    rolling analysis window).

    Purely a READ input to feature_extractor.py/behavioural_profiler.py's
    existing comparisons via get_effective_baseline() -- nothing here (or
    in baseline_learning.py) ever writes to Device.current_risk_score,
    DeviceRiskComponent, or any downstream scoring table. Same boundary
    already verified for the AI Reasoning Core and for admin-device
    linking: this system only ever informs what counts as "normal," it
    never itself decides what's risky.

    sample_count is the number of daily rollups ever folded in -- i.e.
    literally days of history for this device, which is what makes
    MIN_DAYS_FOR_PERSONAL_TRUST (core/config.py) interpretable as an
    actual day count rather than an arbitrary number. login_hour_sample_
    count is tracked SEPARATELY from sample_count -- a day with zero
    logins still counts toward general history (files/failed-logins still
    got a real sample that day), but must NOT silently feed a fabricated
    "midnight" value into the login-hour average.

    Reset to a fresh (all-zero, sample_count=0) row whenever DeviceMetadata.
    department changes (routes/device.py's update_device) -- a personal
    baseline mixing two different roles' "normal" would be actively
    misleading, so a role change starts this over rather than silently
    blending two behavioral contexts together."""

    __tablename__ = "device_baselines"

    device_id = Column(Integer, ForeignKey("devices.device_id"), primary_key=True)

    files_accessed_mean = Column(Float, nullable=False, default=0.0)
    files_accessed_var = Column(Float, nullable=False, default=0.0)
    login_hour_mean = Column(Float, nullable=False, default=0.0)
    login_hour_var = Column(Float, nullable=False, default=0.0)
    failed_logins_mean = Column(Float, nullable=False, default=0.0)
    failed_logins_var = Column(Float, nullable=False, default=0.0)
    # NEW -- EWMA of this device's own daily "biggest single-cycle upward
    # risk-score jump," same fold-at-daily-rollup mechanism as the three
    # stats above (agent_logic/baseline_learning.py's get_expected_max_
    # delta). Backs the sharp-delta trigger (core/config.py's
    # SHARP_DELTA_* constants) -- "is this jump unusual for THIS device,"
    # not a one-size-fits-all number.
    risk_delta_mean = Column(Float, nullable=False, default=0.0)
    risk_delta_var = Column(Float, nullable=False, default=0.0)
    # NEW -- NOT three-tier-blended like the fields above; a plain running
    # accumulator updated in REAL TIME every analysis cycle (agent_logic/
    # analyzer.py), not at the daily-rollup cadence -- unlike files/hours/
    # failed-logins, a risk-score delta can't be reconstructed
    # retroactively from raw Log rows at rollup time (there's no persisted
    # history of past current_risk_score values to scan back over), so
    # this bridges that gap: each cycle takes max(pending_max_delta_today,
    # max(0, this cycle's score increase)), and maybe_update_baselines()
    # folds the accumulated value into risk_delta_mean/var as that day's
    # one sample at the next rollup, then resets this back to 0.0.
    pending_max_delta_today = Column(Float, nullable=False, default=0.0)

    sample_count = Column(Integer, nullable=False, default=0)
    login_hour_sample_count = Column(Integer, nullable=False, default=0)
    updated_at = Column(UTCDateTime, nullable=True)

    device = relationship("Device")


class DepartmentBaseline(Base):
    """Learned, continuously-updated per-(company, department) baseline --
    same EWMA/daily-rollup mechanism as DeviceBaseline, pooled across every
    device in that department instead of one device. sample_count counts
    daily rollups folded in from ANY device in the department combined
    (not distinct device count), so one long-tenured device and several
    brand-new ones don't understate how much real history actually backs
    this number.

    The department foreign key supplies tenant identity. Departments with
    the same name in different companies remain separate rows because their
    primary keys differ.

    An offboarded device's PAST contributions stay baked into this EWMA
    permanently (deliberate, approved call -- there's no clean way to
    un-bake one contributor from an incremental average, and their history
    while employed is legitimately still part of what this department's
    real behavior has looked like). Only NEW contributions stop, which
    happens automatically since an offboarded device already drops out of
    the scheduler's approved-only device query -- no special-case code
    needed for this."""

    __tablename__ = "department_baselines"

    department_id = Column(Integer, ForeignKey("departments.id"), primary_key=True)

    files_accessed_mean = Column(Float, nullable=False, default=0.0)
    files_accessed_var = Column(Float, nullable=False, default=0.0)
    login_hour_mean = Column(Float, nullable=False, default=0.0)
    login_hour_var = Column(Float, nullable=False, default=0.0)
    failed_logins_mean = Column(Float, nullable=False, default=0.0)
    failed_logins_var = Column(Float, nullable=False, default=0.0)
    # NEW -- same statistic as DeviceBaseline's own risk_delta_mean/var,
    # pooled across the department the same way the other three already
    # are. No department-level "pending_max_delta_today" -- it's folded
    # in from the same per-device daily sample that feeds the three
    # existing stats, not a separate accumulator.
    risk_delta_mean = Column(Float, nullable=False, default=0.0)
    risk_delta_var = Column(Float, nullable=False, default=0.0)

    sample_count = Column(Integer, nullable=False, default=0)
    login_hour_sample_count = Column(Integer, nullable=False, default=0)
    updated_at = Column(UTCDateTime, nullable=True)

    department_record = relationship("Department")

    @property
    def department(self) -> str:
        return self.department_record.name

    @property
    def company_id(self) -> int:
        return self.department_record.company_id
