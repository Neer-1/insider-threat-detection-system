# KEEP litds/backend/models/logs.py

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class Log(Base):
    __tablename__ = "logs"

    log_id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.company_id"), nullable=False, index=True)
    device_id = Column(Integer, ForeignKey("devices.device_id"), nullable=False, index=True)

    timestamp = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc), index=True)
    event_type = Column(String(50), nullable=False)  # authentication, process, file, usb, network, system, download, heartbeat

    username = Column(String(100))
    action = Column(String(100))
    status = Column(String(20))  # success / fail

    process_name = Column(String(100))
    filepath = Column(String(255))
    destination_path = Column(String(255))
    file_size = Column(Integer)
    device_name = Column(String(100))  # USB device name, when event_type is usb
    domain = Column(String(100))
    ip_address = Column(String(50))

    # Anything event-specific that doesn't have its own column, so adding a
    # new event_type doesn't need a migration.
    additional_data = Column(JSON)

    # New — not in the original draft. The feature-extraction pipeline's
    # work queue is "Log where processed = false"; there is no separate
    # staging table.
    processed = Column(Boolean, default=False, nullable=False, index=True)

    company = relationship("Company")
    # back_populates is required here (rather than the draft's plain
    # one-directional relationship) because Device.logs already declares
    # back_populates="device" and SQLAlchemy needs both sides to agree.
    device = relationship("Device", back_populates="logs")
