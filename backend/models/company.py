# KEEP litds/backend/models/company.py

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, Integer, String
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class Company(Base):
    __tablename__ = "companies"

    company_id = Column(Integer, primary_key=True, index=True)
    company_name = Column(String(150), nullable=False)
    api_key = Column(String(255), unique=True, nullable=False)

    # Soft-delete only — companies are deactivated, never hard-deleted, so
    # historical logs/alerts stay intact for audit purposes.
    is_active = Column(Boolean, default=True, nullable=False)

    # Company-wide opt-in for the admin-triggered "Notify Employee" alert
    # email (backend/routes/device.py's notify_employee) -- default off,
    # same opt-in-by-default posture as Admin.email_notifications_enabled.
    # Deliberately manual-only regardless of this flag: this only gates
    # whether the feature is reachable at all, never triggers a send on
    # its own -- an automatic version risks tipping off a genuinely
    # malicious actor before any human has reviewed the situation.
    employee_notification_enabled = Column(Boolean, default=False, nullable=False)

    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))

    admins = relationship("Admin", back_populates="company", cascade="all, delete")
    devices = relationship("Device", back_populates="company", cascade="all, delete")
