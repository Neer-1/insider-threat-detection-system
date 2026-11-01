# NEW — learned per-device/per-department behavioral baselines, replacing
# ROLE_BASELINES as the actual comparison point once enough real history
# exists. See core/config.py's "Learned behavioral baselines" section for
# the full rationale on every constant used here.

"""
Two responsibilities, kept in this one module because they share the same
EWMA/blend math and the same two tables (models/baselines.py):

  get_effective_baseline() -- called from feature_extractor.py's
  extract_features(), on the real-time 10-second detection cadence, EVERY
  cycle. Pure READS (DeviceBaseline, DepartmentBaseline, ROLE_BASELINES),
  no writes at all. Returns the exact same shape ROLE_BASELINES[department]
  already does ({"avg_files_per_day", "normal_hours", "avg_failed_logins"})
  so feature_extractor.py/behavioural_profiler.py's own comparison math
  (the Poisson-approximation z-score, the profile-flag thresholds, and
  everything downstream of them -- anomaly_detector.py, risk_scorer.py,
  DeviceRiskComponent decay) needs ZERO changes beyond swapping where the
  baseline dict comes from. This module only ever informs what counts as
  "normal" -- it never writes to Device.current_risk_score,
  DeviceRiskComponent, or any alert/response table. Same boundary already
  verified for the AI Reasoning Core and admin-device linking.

  maybe_update_baselines() -- called once per device per scheduler cycle
  (backend/scheduler.py), but is a cheap no-op unless BASELINE_ROLLUP_
  INTERVAL_HOURS has actually elapsed since that device's last update.
  When due, aggregates the last rolling 24h of real Log activity into ONE
  new sample folded into both that device's own baseline and its
  department's pooled baseline via a fixed-alpha EWMA update.

Deliberately NOT wired into the CNN/Isolation Forest at all, and never
touches backend/reasoning/ (the LLM layer) -- this is a statistics/data-
engineering feature, not a model-retraining or LLM feature; both of those
are separate, out-of-scope questions.
"""

import math
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from backend.agent_logic.departments import baseline_floor_for, get_department
from backend.core.config import (
    BASELINE_EWMA_HALF_LIFE_DAYS,
    BASELINE_HOURS_SPREAD_STD_MULTIPLIER,
    BASELINE_ROLLUP_INTERVAL_HOURS,
    DEFAULT_EXPECTED_MAX_DELTA,
    MIN_DAYS_FOR_PERSONAL_TRUST,
    MIN_SAMPLES_FOR_DEPARTMENT_TRUST,
)
from backend.models.baselines import DepartmentBaseline, DeviceBaseline
from backend.models.devices import Device, DeviceMetadata
from backend.models.logs import Log

# Fixed per-sample alpha, not a per-call dt-based decay (unlike
# DeviceRiskComponent's _decay_and_rise) -- BASELINE_ROLLUP_INTERVAL_HOURS
# already enforces "one sample ~= one real day," so BASELINE_EWMA_HALF_
# LIFE_DAYS directly gives the half-life in units of samples.
_ALPHA = 1 - math.exp(-math.log(2) / BASELINE_EWMA_HALF_LIFE_DAYS)


def _ewma_update(mean: float, var: float, x: float) -> tuple[float, float]:
    """Standard exponential-moving mean/variance update. Callers are
    responsible for the sample_count==0 (first-ever sample) special case --
    this always blends against whatever mean/var is already stored, which
    is only correct once a real first value has been set."""
    delta = x - mean
    new_mean = mean + _ALPHA * delta
    new_var = (1 - _ALPHA) * (var + _ALPHA * delta * delta)
    return new_mean, new_var


def _apply_daily_sample(baseline, files_accessed: int, login_hours: list[int], failed_streak: int, max_delta: float = 0.0) -> None:
    """Folds one day's rollup into `baseline` (a DeviceBaseline or
    DepartmentBaseline row) in place. login_hour_sample_count is tracked
    SEPARATELY from the general sample_count -- a day with zero logins
    still counts as a real day of history for files/failed-logins, but
    must not silently feed a fabricated "midnight" value into the
    login-hour average. max_delta (the day's biggest single-cycle upward
    risk-score jump) has no such caveat -- 0.0 on a genuinely flat day is
    itself a real, meaningful sample, not a "no data" case, so it folds
    in unconditionally alongside files/failed-logins rather than being
    gated the way login_hours is."""
    if baseline.sample_count == 0:
        baseline.files_accessed_mean = float(files_accessed)
        baseline.files_accessed_var = 0.0
        baseline.failed_logins_mean = float(failed_streak)
        baseline.failed_logins_var = 0.0
        baseline.risk_delta_mean = float(max_delta)
        baseline.risk_delta_var = 0.0
    else:
        baseline.files_accessed_mean, baseline.files_accessed_var = _ewma_update(
            baseline.files_accessed_mean, baseline.files_accessed_var, float(files_accessed)
        )
        baseline.failed_logins_mean, baseline.failed_logins_var = _ewma_update(
            baseline.failed_logins_mean, baseline.failed_logins_var, float(failed_streak)
        )
        baseline.risk_delta_mean, baseline.risk_delta_var = _ewma_update(
            baseline.risk_delta_mean, baseline.risk_delta_var, float(max_delta)
        )
    baseline.sample_count += 1

    if login_hours:
        avg_hour = sum(login_hours) / len(login_hours)
        if baseline.login_hour_sample_count == 0:
            baseline.login_hour_mean = avg_hour
            baseline.login_hour_var = 0.0
        else:
            baseline.login_hour_mean, baseline.login_hour_var = _ewma_update(
                baseline.login_hour_mean, baseline.login_hour_var, avg_hour
            )
        baseline.login_hour_sample_count += 1


def _max_consecutive_fails(logs: list[Log]) -> int:
    """Worst consecutive-failed-login streak observed at any point during
    the rollup period -- deliberately "how bad did the worst moment get,"
    not "what's the streak right now" (that's feature_extractor.py's
    _consecutive_failed_logins, a different question serving a different,
    real-time purpose). Self-contained rather than reusing that function,
    since the two intentionally answer different questions over different
    time spans."""
    auth_events = sorted((log for log in logs if log.event_type == "authentication"), key=lambda log: log.timestamp)
    streak = 0
    worst = 0
    for log in auth_events:
        if log.status == "fail":
            streak += 1
            worst = max(worst, streak)
        else:
            streak = 0
    return worst


def maybe_update_baselines(db: Session, device: Device, now: datetime) -> None:
    """Called once per device per scheduler cycle -- a cheap no-op unless
    BASELINE_ROLLUP_INTERVAL_HOURS has actually elapsed since this
    device's last update. Aggregates real Log rows only; never touches
    Feature, Alert, DeviceRiskComponent, or Device.current_risk_score."""
    dev_baseline = db.query(DeviceBaseline).filter(DeviceBaseline.device_id == device.device_id).first()
    if dev_baseline is None:
        # Column-level defaults (default=0/0.0) only apply at flush/INSERT
        # time, not immediately on construction -- _apply_daily_sample
        # below reads these attributes back before any flush happens, so
        # they're explicitly set here rather than left to rely on that
        # (confirmed live: relying on the column defaults left sample_count
        # as a real Python None, not 0, and crashed the very first EWMA
        # update on a brand-new row).
        dev_baseline = DeviceBaseline(
            device_id=device.device_id,
            files_accessed_mean=0.0, files_accessed_var=0.0,
            login_hour_mean=0.0, login_hour_var=0.0,
            failed_logins_mean=0.0, failed_logins_var=0.0,
            risk_delta_mean=0.0, risk_delta_var=0.0, pending_max_delta_today=0.0,
            sample_count=0, login_hour_sample_count=0,
            updated_at=None,
        )
        db.add(dev_baseline)

    if dev_baseline.updated_at is not None:
        last = dev_baseline.updated_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if (now - last) < timedelta(hours=BASELINE_ROLLUP_INTERVAL_HOURS):
            return  # not due yet

    window_start = now - timedelta(hours=BASELINE_ROLLUP_INTERVAL_HOURS)
    logs = (
        db.query(Log)
        .filter(Log.device_id == device.device_id, Log.timestamp >= window_start, Log.timestamp < now)
        .all()
    )

    files_accessed = sum(1 for log in logs if log.event_type == "file")
    login_hours = [log.timestamp.hour for log in logs if log.event_type == "authentication"]
    failed_streak = _max_consecutive_fails(logs)
    # Real-time-accumulated (agent_logic/analyzer.py's update_pending_max_
    # delta, called every analysis cycle), not derivable from `logs` above
    # -- see models/baselines.py's pending_max_delta_today docstring for
    # why this one stat can't be reconstructed retroactively the way the
    # other three can.
    max_delta = dev_baseline.pending_max_delta_today

    _apply_daily_sample(dev_baseline, files_accessed, login_hours, failed_streak, max_delta)
    dev_baseline.updated_at = now
    dev_baseline.pending_max_delta_today = 0.0

    metadata = db.query(DeviceMetadata).filter(DeviceMetadata.device_id == device.device_id).first()
    # Genuinely None when unset -- not the old "engineering" fallback name.
    department_row = metadata.department_record if metadata else None
    department = department_row.name if department_row is not None else None

    # DepartmentBaseline.department_id is the primary key, so an unassigned
    # device cannot be pooled into an invented department cohort. Skipped for an
    # unassigned device instead of inventing a synthetic "unassigned"
    # department to pool them under: "no department" isn't a real cohort
    # to learn a collective baseline for the way an actual department is,
    # and this device's own DeviceBaseline (personal) update above is
    # completely unaffected either way -- an unassigned device still
    # builds up its own personal history, it just never blends toward a
    # department-level number it doesn't have one for (agent_logic/
    # departments.py's baseline_floor_for already gives it the generic
    # static floor to blend from instead).
    if department_row is not None:
        dept_baseline = (
            db.query(DepartmentBaseline)
            .filter(DepartmentBaseline.department_id == department_row.id)
            .first()
        )
        if dept_baseline is None:
            # Same explicit-initialization fix as dev_baseline above.
            dept_baseline = DepartmentBaseline(
                department_id=department_row.id,
                files_accessed_mean=0.0, files_accessed_var=0.0,
                login_hour_mean=0.0, login_hour_var=0.0,
                failed_logins_mean=0.0, failed_logins_var=0.0,
                risk_delta_mean=0.0, risk_delta_var=0.0,
                sample_count=0, login_hour_sample_count=0,
                updated_at=None,
            )
            db.add(dept_baseline)
        # Same per-device-day sample folded into the department pool -- no
        # separate department-level accumulator (models/baselines.py's
        # DepartmentBaseline docstring).
        _apply_daily_sample(dept_baseline, files_accessed, login_hours, failed_streak, max_delta)
        dept_baseline.updated_at = now

    db.commit()


def update_pending_max_delta(db: Session, device: Device, delta: float) -> None:
    """Called every real-time analysis cycle (agent_logic/analyzer.py),
    NOT gated by BASELINE_ROLLUP_INTERVAL_HOURS like maybe_update_baselines
    above -- see DeviceBaseline.pending_max_delta_today's own docstring
    for why this one statistic needs a real-time accumulator instead of
    being reconstructed from raw Log rows at rollup time. Only positive
    (upward) jumps count -- decay/decrease is not what "sharp increase"
    means. A no-op if this device has no DeviceBaseline row yet (nothing
    to accumulate into); maybe_update_baselines creates one on this
    device's first rollup regardless, so this simply has nothing to do
    until then."""
    if delta <= 0:
        return
    dev_baseline = db.query(DeviceBaseline).filter(DeviceBaseline.device_id == device.device_id).first()
    if dev_baseline is None:
        return
    dev_baseline.pending_max_delta_today = max(dev_baseline.pending_max_delta_today, delta)


def get_expected_max_delta(db: Session, device_id: int, company_id: int, department: str) -> tuple[float, float]:
    """(mean, std) of this device/department's own learned "typical
    biggest single-cycle upward risk-score jump" -- same three-tier
    device<-department<-static blend pattern as get_effective_baseline
    above, kept as its OWN function rather than a new key on that one's
    return dict: get_effective_baseline's shape ({"avg_files_per_day",
    "normal_hours", "avg_failed_logins"}) is an explicit contract
    feature_extractor.py depends on, and this is an unrelated statistic
    with no natural home in it.

    Cold start (no risk_delta history at either level) returns
    (DEFAULT_EXPECTED_MAX_DELTA, 0.0) -- there's no natural per-role
    static default to reason this one from the way ROLE_BASELINES could
    for file counts, so one single global floor stands in, same as
    everywhere else in this module falls back to the static tier."""
    mean = DEFAULT_EXPECTED_MAX_DELTA
    std = 0.0

    department_row = get_department(db, company_id, department)
    dept_baseline = None
    if department_row is not None:
        dept_baseline = db.query(DepartmentBaseline).filter(
            DepartmentBaseline.department_id == department_row.id
        ).first()
    if dept_baseline is not None and dept_baseline.sample_count > 0:
        w = min(1.0, dept_baseline.sample_count / MIN_SAMPLES_FOR_DEPARTMENT_TRUST)
        learned_std = math.sqrt(max(dept_baseline.risk_delta_var, 0.0))
        mean = w * dept_baseline.risk_delta_mean + (1 - w) * mean
        std = w * learned_std + (1 - w) * std

    dev_baseline = db.query(DeviceBaseline).filter(DeviceBaseline.device_id == device_id).first()
    if dev_baseline is not None and dev_baseline.sample_count > 0:
        w = min(1.0, dev_baseline.sample_count / MIN_DAYS_FOR_PERSONAL_TRUST)
        learned_std = math.sqrt(max(dev_baseline.risk_delta_var, 0.0))
        mean = w * dev_baseline.risk_delta_mean + (1 - w) * mean
        std = w * learned_std + (1 - w) * std

    return mean, std


def _effective_hours(dept_baseline, dev_baseline, static_hours: tuple[int, int]) -> tuple[int, int]:
    """Blends a learned (mean, std) login-hour distribution into a
    (start, end) range compatible with the existing normal_hours shape --
    represented as (midpoint, half-width) so it can blend the same
    weighted way as the scalar metrics below. With no learned data at
    either level this reconstructs static_hours exactly: mid-half=start
    and mid+half=end are algebraic identities of how mid/half were
    derived from it, not an approximation."""
    mid = (static_hours[0] + static_hours[1]) / 2
    half = (static_hours[1] - static_hours[0]) / 2

    if dept_baseline is not None and dept_baseline.login_hour_sample_count > 0:
        w = min(1.0, dept_baseline.login_hour_sample_count / MIN_SAMPLES_FOR_DEPARTMENT_TRUST)
        learned_half = BASELINE_HOURS_SPREAD_STD_MULTIPLIER * math.sqrt(max(dept_baseline.login_hour_var, 0.0))
        mid = w * dept_baseline.login_hour_mean + (1 - w) * mid
        half = w * learned_half + (1 - w) * half

    if dev_baseline is not None and dev_baseline.login_hour_sample_count > 0:
        w = min(1.0, dev_baseline.login_hour_sample_count / MIN_DAYS_FOR_PERSONAL_TRUST)
        learned_half = BASELINE_HOURS_SPREAD_STD_MULTIPLIER * math.sqrt(max(dev_baseline.login_hour_var, 0.0))
        mid = w * dev_baseline.login_hour_mean + (1 - w) * mid
        half = w * learned_half + (1 - w) * half

    start = max(0, min(24, round(mid - half)))
    end = max(0, min(24, round(mid + half)))
    return (start, end)


def get_effective_baseline(db: Session, device_id: int, company_id: int, department: str) -> dict:
    """Three-tier blend: device-personal <- department-learned (itself
    blended toward the static default) <- static floor (agent_logic/
    departments.py's baseline_floor_for, a per-company admin-managed
    Department row -- see that module's own docstring; this used to be a
    fixed core/config.py ROLE_BASELINES[department] dict lookup, now
    DB-backed). Returns the exact same shape either way -- callers
    (feature_extractor.py) need no changes to their own comparison math,
    only to where the baseline dict comes from.

    On a cold start (no DepartmentBaseline/DeviceBaseline rows at all --
    e.g. immediately after a fresh install or a full data reset) this
    returns the static floor completely unchanged: both blend blocks
    below are skipped entirely when sample_count is 0, so
    avg_files_per_day/avg_failed_logins are the exact static float
    values (not just numerically equal -- literally untouched), and
    normal_hours reconstructs the exact static tuple via the algebraic
    identity in _effective_hours above."""
    static = baseline_floor_for(db, company_id, department)

    department_row = get_department(db, company_id, department)
    dept_baseline = None
    if department_row is not None:
        dept_baseline = db.query(DepartmentBaseline).filter(
            DepartmentBaseline.department_id == department_row.id
        ).first()
    dev_baseline = db.query(DeviceBaseline).filter(DeviceBaseline.device_id == device_id).first()

    avg_files = static["avg_files_per_day"]
    avg_failed = static["avg_failed_logins"]

    if dept_baseline is not None and dept_baseline.sample_count > 0:
        w = min(1.0, dept_baseline.sample_count / MIN_SAMPLES_FOR_DEPARTMENT_TRUST)
        avg_files = w * dept_baseline.files_accessed_mean + (1 - w) * avg_files
        avg_failed = w * dept_baseline.failed_logins_mean + (1 - w) * avg_failed

    if dev_baseline is not None and dev_baseline.sample_count > 0:
        w = min(1.0, dev_baseline.sample_count / MIN_DAYS_FOR_PERSONAL_TRUST)
        avg_files = w * dev_baseline.files_accessed_mean + (1 - w) * avg_files
        avg_failed = w * dev_baseline.failed_logins_mean + (1 - w) * avg_failed

    normal_hours = _effective_hours(dept_baseline, dev_baseline, static["normal_hours"])

    return {"avg_files_per_day": avg_files, "normal_hours": normal_hours, "avg_failed_logins": avg_failed}
