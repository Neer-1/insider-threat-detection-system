# NEW — periodic Device.current_risk_score snapshots for the Live Employee
# Monitoring card's 24h risk sparkline. Purely observational: reads
# Device.current_risk_score (already computed elsewhere, every real-time
# analysis cycle) and writes to its own dedicated table
# (models/risk_snapshot.py's DeviceRiskSnapshot) -- never the other way
# around.

"""
Same read-only-with-respect-to-the-real-scoring-pipeline boundary already
enforced for agent_logic/baseline_learning.py and the AI Reasoning Core
(backend/reasoning/): this module has exactly one write target
(DeviceRiskSnapshot), and it is never read by anything in agent_logic/
analyzer.py's or agent_logic/dismissal.py's own scoring/decay/rollback
math. Checked directly, not just assumed by design -- grep the codebase
for any import of this module, or of DeviceRiskSnapshot, outside of
scheduler.py (which calls maybe_record_snapshot/prune_old_snapshots) and
routes/employees.py (which only ever reads DeviceRiskSnapshot for the
sparkline's own GET endpoint): there is none.

Two responsibilities, both called from scheduler.py's run_analysis_cycle:

  maybe_record_snapshot() -- per-device, called every cycle, a cheap no-op
  unless RISK_SNAPSHOT_INTERVAL_MINUTES has actually elapsed since that
  device's last snapshot (same gating pattern as baseline_learning.py's
  maybe_update_baselines).

  prune_old_snapshots() -- global, not per-device, called once per cycle
  but only actually executes its DELETE roughly once every
  RISK_SNAPSHOT_PRUNE_INTERVAL_HOURS (gated via an in-memory timestamp in
  scheduler.py, the same pattern already used for that module's own
  _last_cycle_completed_at).
"""

from datetime import timedelta, timezone

from sqlalchemy.orm import Session

from backend.core.config import RISK_SNAPSHOT_INTERVAL_MINUTES, RISK_SNAPSHOT_RETENTION_HOURS
from backend.models.devices import Device
from backend.models.risk_snapshot import DeviceRiskSnapshot


def maybe_record_snapshot(db: Session, device: Device, now) -> None:
    """Inserts one DeviceRiskSnapshot row for `device` if
    RISK_SNAPSHOT_INTERVAL_MINUTES has elapsed since its last one (or if it
    has none yet). Reads Device.current_risk_score only -- never writes to
    Device, DeviceRiskComponent, or any other table. Does NOT commit --
    caller's transaction, same convention as maybe_update_baselines."""
    last = (
        db.query(DeviceRiskSnapshot.recorded_at)
        .filter(DeviceRiskSnapshot.device_id == device.device_id)
        .order_by(DeviceRiskSnapshot.recorded_at.desc())
        .first()
    )
    if last is not None:
        last_at = last[0]
        # UTCDateTime already guarantees tz-aware on read (database/db.py) --
        # this is the same defensive fallback baseline_learning.py's own
        # rollup-gating check uses, not a sign this actually happens here.
        if last_at.tzinfo is None:
            last_at = last_at.replace(tzinfo=timezone.utc)
        if (now - last_at) < timedelta(minutes=RISK_SNAPSHOT_INTERVAL_MINUTES):
            return

    db.add(DeviceRiskSnapshot(
        company_id=device.company_id,
        device_id=device.device_id,
        risk_score=device.current_risk_score or 0.0,
        recorded_at=now,
    ))


def prune_old_snapshots(db: Session, now) -> int:
    """Deletes every DeviceRiskSnapshot older than RISK_SNAPSHOT_RETENTION_
    HOURS, across every company/device -- global, not per-device, since
    there's nothing device-specific about "how long do we keep this kind
    of row." Returns the number of rows deleted (for the caller's own log
    line). Commits its own transaction -- unlike maybe_record_snapshot
    above, this is called at most once per scheduler cycle (gated by
    scheduler.py), not once per device, so there's no shared-transaction
    reason to defer it to the caller."""
    cutoff = now - timedelta(hours=RISK_SNAPSHOT_RETENTION_HOURS)
    deleted = db.query(DeviceRiskSnapshot).filter(DeviceRiskSnapshot.recorded_at < cutoff).delete(synchronize_session=False)
    db.commit()
    return deleted
