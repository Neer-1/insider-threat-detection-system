# NEW — per-(device, anomaly_type) decaying risk contribution, see agent_logic/analyzer.py

from datetime import datetime, timezone

from sqlalchemy import Column, Float, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class DeviceRiskComponent(Base):
    """One decaying score per (device, anomaly_type) — what Device.
    current_risk_score is now derived from (sum, capped at 100), instead
    of a single global decay/rise pair applied to one aggregate number.
    core/config.py's ANOMALY_TYPE_TAU_SECONDS is what makes each type
    decay at its own rate (a failed-login streak forgiven in minutes,
    sustained privilege escalation staying elevated for a day) — this
    table is just the persisted state that decay operates on, one row per
    type that's ever been detected for that device.

    "score" here uses the same decay-toward-0 / rise-only-if-higher
    formula (analyzer.py's _decay_and_rise), applied per (device,
    anomaly_type) instead of once per device."""

    __tablename__ = "device_risk_components"

    device_id = Column(Integer, ForeignKey("devices.device_id"), primary_key=True)
    anomaly_type = Column(String(50), primary_key=True)

    score = Column(Float, nullable=False, default=0.0)
    updated_at = Column(UTCDateTime, nullable=True, default=lambda: datetime.now(timezone.utc))

    device = relationship("Device")
