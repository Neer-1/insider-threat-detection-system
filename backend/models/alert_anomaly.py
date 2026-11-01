from sqlalchemy import Column, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from backend.database.db import Base


class AlertAnomaly(Base):
    """One ordered detector finding attached to an alert."""

    __tablename__ = "alert_anomalies"
    __table_args__ = (
        UniqueConstraint("alert_id", "position", name="uq_alert_anomaly_position"),
    )

    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    position = Column(Integer, nullable=False)
    anomaly_type = Column(String(50), nullable=True)
    message = Column(Text, nullable=False)
    severity = Column(Float, nullable=True)

    alert = relationship("Alert", back_populates="anomaly_records")

    def as_dict(self) -> dict:
        return {
            "type": self.anomaly_type,
            "message": self.message,
            "severity": self.severity,
        }
