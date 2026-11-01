# NEW — audit trail for the admin-triggered "Notify Employee" alert email
# (backend/routes/device.py's notify_employee). Deliberately NOT
# AlertDecision: every AlertDecision row anchors to exactly one of
# alert_id/judgment_id (models/alert_decision.py), but this action is a
# standalone, device-level admin action -- reachable any time an admin is
# viewing an employee's profile, regardless of current risk level or
# whether any alert/judgment exists at all. Forcing it into that table
# would mean inventing a fake anchor for something that isn't one.

from datetime import datetime, timezone

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class EmployeeNotification(Base):
    """One row per actual send attempt -- a failed send is still recorded
    (an admin DID attempt to notify this employee, at this time, with this
    exact text), same "never silently drop a failure" discipline
    CompanySmtpConfig's last_send_status/last_send_error already applies
    to the automatic trigger-notification path. message is the exact
    final text actually sent (after any admin edits to the pre-filled
    default) -- never re-derived or summarized after the fact, per this
    project's audit-trail standard (dismiss reasons, admin promotions,
    SMTP config changes are all recorded verbatim, not paraphrased)."""

    __tablename__ = "employee_notifications"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.device_id"), nullable=False, index=True)
    admin_id = Column(Integer, ForeignKey("admins.admin_id"), nullable=False)

    message = Column(Text, nullable=False)
    sent_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    status = Column(String(10), nullable=False)  # "success" | "failed"
    error = Column(Text, nullable=True)

    device = relationship("Device")
    admin = relationship("Admin")
