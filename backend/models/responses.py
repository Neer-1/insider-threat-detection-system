# NEW split — Response class pulled out of alerts.py draft into its own file

from datetime import datetime, timezone

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class Response(Base):
    """An action taken against an alert — either automatic (response_engine.py
    acting on its own) or an admin action from the dashboard. triggered_by_admin_id
    is nullable specifically to distinguish the two: null means the system
    acted on its own, a value means a named admin did."""

    __tablename__ = "responses"

    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False, index=True)
    triggered_by_admin_id = Column(Integer, ForeignKey("admins.admin_id"), nullable=True)

    action_taken = Column(String(100), nullable=False)  # e.g. "notify_admin", "lock_device", "flag_for_review"
    status = Column(String(20), nullable=False, default="pending")  # "pending" / "completed" / "failed"

    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))

    alert = relationship("Alert", back_populates="responses")
    triggered_by_admin = relationship("Admin", back_populates="responses_triggered")
