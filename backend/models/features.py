# KEEP litds/backend/models/features.py

from datetime import datetime, timezone

from sqlalchemy import Column, Float, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class Feature(Base):
    __tablename__ = "features"

    feature_id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.company_id"), nullable=False, index=True)
    device_id = Column(Integer, ForeignKey("devices.device_id"), nullable=False, index=True)

    time_window = Column(String(20), nullable=False)  # e.g. "hourly", "daily"
    window_start = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    window_end = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))

    # Draft's 8 behavioural metrics
    login_count = Column(Integer, default=0)
    failed_login_count = Column(Integer, default=0)
    files_accessed = Column(Integer, default=0)
    files_moved = Column(Integer, default=0)
    usb_usage_count = Column(Integer, default=0)
    processes_used = Column(Integer, default=0)
    active_hours = Column(Integer, default=0)
    session_duration = Column(Integer, default=0)  # minutes

    # New — the ratio/deviation features from the ai-agent-assignment
    # feature_extractor.py, not in the original draft's fixed-column list.
    access_velocity = Column(Float, default=0.0)
    sensitive_ratio = Column(Float, default=0.0)
    time_deviation = Column(Float, default=0.0)
    baseline_deviation = Column(Float, default=0.0)

    device = relationship("Device", back_populates="features")
