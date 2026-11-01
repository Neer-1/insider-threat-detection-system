# NEW — periodic Device.current_risk_score snapshots, purely observational.
# Backs the Live Employee Monitoring card's 24h risk sparkline
# (routes/employees.py's GET /employees/risk-history). See agent_logic/
# risk_snapshots.py for the recording/pruning logic that owns this table.

from datetime import datetime, timezone

from sqlalchemy import Column, Float, ForeignKey, Index, Integer
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class DeviceRiskSnapshot(Base):
    """One row per device per ~15-minute interval (core/config.py's
    RISK_SNAPSHOT_INTERVAL_MINUTES), holding a copy of Device.
    current_risk_score at that moment. Deliberately NOT the same table (or
    even the same kind of thing) as DeviceRiskComponent -- that table IS
    the live scoring mechanism (per-anomaly-type, continuously decaying,
    read and written by the real-time detection pipeline every cycle);
    this one is a read-only, append-only historical copy of the single
    AGGREGATE number the pipeline already produces, taken far less often,
    kept only long enough to draw a 24h trend line. Nothing in agent_logic/
    analyzer.py or agent_logic/dismissal.py has ever read from or written
    to this table, and nothing ever should -- see agent_logic/
    risk_snapshots.py's own docstring for how that boundary is enforced.

    Pruned automatically (agent_logic/risk_snapshots.py's
    prune_old_snapshots) once a row is older than core/config.py's
    RISK_SNAPSHOT_RETENTION_HOURS -- this table is not meant to accumulate
    indefinitely the way Log/Feature/Alert rows deliberately do."""

    __tablename__ = "device_risk_snapshots"
    __table_args__ = (
        # Backs the sparkline's own query directly: "every snapshot for
        # this device, in this time range, in order" -- a composite index
        # on exactly those two columns rather than relying on the two
        # single-column indexes below to be combined by the query planner.
        Index("ix_device_risk_snapshots_device_recorded", "device_id", "recorded_at"),
    )

    id = Column(Integer, primary_key=True)
    company_id = Column(Integer, ForeignKey("companies.company_id"), nullable=False, index=True)
    device_id = Column(Integer, ForeignKey("devices.device_id"), nullable=False, index=True)
    risk_score = Column(Float, nullable=False)
    recorded_at = Column(UTCDateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    company = relationship("Company")
    device = relationship("Device")
