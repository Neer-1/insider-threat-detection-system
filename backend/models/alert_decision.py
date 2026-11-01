# NEW — append-only dismiss/undo decision log, shared by an alert-anchored
# toggle (routes/alerts.py) and an orphan-judgment-anchored toggle
# (routes/reasoning.py) -- see agent_logic/dismissal.py's dismiss()/undo()
# for the one shared implementation both routes call.

from datetime import datetime, timezone

from sqlalchemy import Column, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class AlertDecision(Base):
    """One row per admin dismiss-or-undo toggle. Anchored to exactly ONE of
    alert_id / judgment_id (never both, never neither -- enforced in the
    routes, not a DB constraint, consistent with how the rest of this
    codebase validates): alert_id for the common case (an alert, whether or
    not it has a linked ReasoningJudgment); judgment_id only for an orphan
    judgment with no linked Alert at all (models/reasoning.py's alert_id is
    nullable -- the aggregate-score trigger doesn't always correspond to
    one specific Alert row), which has nothing else to anchor a toggle to.

    Genuine back-and-forth is expected -- dismissed, undone, dismissed
    again -- so this is a plain append-only event log, not a single-slot
    "current decision" field: every row here is one toggle, and "is this
    currently dismissed" is read off Alert.status / ReasoningJudgment.status
    directly (whichever this row is anchored to), not re-derived from this
    table.

    score_snapshot carries the risk-rollback math across a dismiss/undo
    pair without needing to search for a "matching" row: on a "dismiss"
    row it's the DeviceRiskComponent score captured immediately BEFORE
    resetting it to 0 (what a later undo restores toward); on an "undo"
    row it's the score actually written back (after undo's own
    max(current, snapshot) safety comparison -- see dismissal.py). Null on
    both an orphan-judgment toggle (nothing to roll back -- no anomaly_type
    exists without a linked Alert) and any row where there was no matching
    DeviceRiskComponent to touch."""

    __tablename__ = "alert_decisions"

    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True, index=True)
    judgment_id = Column(Integer, ForeignKey("reasoning_judgments.id"), nullable=True, index=True)

    decision = Column(String(10), nullable=False)  # "dismiss" / "undo"
    reason = Column(Text, nullable=False)
    score_snapshot = Column(Float, nullable=True)

    admin_id = Column(Integer, ForeignKey("admins.admin_id"), nullable=False)
    decided_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))

    alert = relationship("Alert")
    judgment = relationship("ReasoningJudgment")
    admin = relationship("Admin")
