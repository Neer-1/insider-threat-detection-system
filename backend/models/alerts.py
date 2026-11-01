# KEEP litds/backend/models/alerts.py

from datetime import datetime, timezone

from sqlalchemy import Column, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime
from backend.models.alert_anomaly import AlertAnomaly


class Alert(Base):
    """A risk event surfaced to the dashboard."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    company_id = Column(Integer, ForeignKey("companies.company_id"), nullable=False, index=True)
    device_id = Column(Integer, ForeignKey("devices.device_id"), nullable=False, index=True)

    # Matches the thresholds defined in core/config.py — kept as a plain
    # string here rather than a DB-level enum/check so threshold tuning
    # stays a config-file change, not a migration.
    risk_level = Column(String(20), nullable=False)  # "low" / "medium" / "high" / "critical"

    # The actual 0-100 score behind risk_level. Needed as a real continuous
    # value (not re-derived from the level band) for the ROC-AUC/Precision/
    # Recall evaluation the dissertation commits to in section 5.7, and for
    # historical trend detection in agent_logic/analyzer.py to work off
    # real numbers instead of an approximation.
    risk_score = Column(Float, nullable=False)

    # Stable rule identifier (e.g. "failed_logins", "baseline_deviation") --
    # what analyzer.py's dedup now matches on instead of exact title text.
    # title and child anomaly messages embed live-computed numbers that drift
    # between analysis cycles even for unchanged behaviour (confirmed
    # live: "...(8.74 sigma)" vs "...(9.74 sigma)" for the same ongoing
    # condition one cycle apart); anomaly_type never changes for the same
    # rule, so it's the only thing safe to key an "is this the same
    # ongoing episode" check on under the real-time rolling-window
    # scheduler.
    anomaly_type = Column(String(50), nullable=False)

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # "open" / "resolved" (auto, agent_logic/analyzer.py's stale-cleanup
    # pass -- low/medium only, pure triage-queue bookkeeping) / "dismissed"
    # (admin-driven, reason-required, terminal, reachable from either of the
    # other two -- see routes/alerts.py's POST /{id}/dismiss and
    # agent_logic/dismissal.py).
    # Deliberately a separate axis from "resolved": dismissing an alert is a
    # human judgment call with a risk-rollback consequence, auto-resolve is
    # just staleness bookkeeping -- see analyzer.py's dedup/stale-cleanup/
    # fallback queries, all of which exclude "dismissed" alongside "resolved"
    # so a dismissal is never silently overwritten or re-attached to.
    status = Column(String(20), nullable=False, default="open")

    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))

    device = relationship("Device", back_populates="alerts")
    responses = relationship("Response", back_populates="alert")
    anomaly_records = relationship(
        "AlertAnomaly",
        back_populates="alert",
        cascade="all, delete-orphan",
        order_by="AlertAnomaly.position",
    )

    @property
    def anomalies(self) -> list[str]:
        """Backward-compatible message list used by the dashboard API."""
        return [record.message for record in self.anomaly_records]

    @property
    def anomaly_details(self) -> list[dict]:
        return [record.as_dict() for record in self.anomaly_records]

    def replace_anomalies(self, anomalies: list[dict]) -> None:
        """Store detector output while retaining stable child-row positions."""
        if anomalies:
            self.anomaly_type = anomalies[0]["type"]
            self.title = anomalies[0]["message"]
        records = list(self.anomaly_records)
        for position, anomaly in enumerate(anomalies):
            if position < len(records):
                record = records[position]
            else:
                record = AlertAnomaly(position=position)
                self.anomaly_records.append(record)
            record.position = position
            record.anomaly_type = anomaly["type"]
            record.message = anomaly["message"]
            record.severity = anomaly["severity"]
        for record in records[len(anomalies):]:
            self.anomaly_records.remove(record)
