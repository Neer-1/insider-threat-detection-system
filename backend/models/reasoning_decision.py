# NEW — append-only decision log for ReasoningJudgment, see routes/reasoning.py

from datetime import datetime, timezone

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class ReasoningDecision(Base):
    """One row per admin decision event on a ReasoningJudgment. Previously
    a judgment only ever recorded its single, latest decision directly on
    itself (status/admin_decision/decided_by/decided_at) and re-deciding
    an already-decided judgment was blocked outright. Now that an admin
    can revisit and change a past decision (dashboard's re-openable alert
    history), that single-slot design would silently lose the prior
    decision -- including whatever dismiss reason was given -- the moment
    a new one was recorded. This table makes the decision history itself
    append-only, matching how Response rows are already treated as an
    immutable action log rather than a current-state-only pointer:
    ReasoningJudgment.status/admin_decision/decided_by/decided_at still
    reflect the LATEST decision for quick reads, but every decision ever
    made (accept/override/dismiss, and every dismiss reason) stays here
    permanently."""

    __tablename__ = "reasoning_decisions"

    id = Column(Integer, primary_key=True)
    judgment_id = Column(Integer, ForeignKey("reasoning_judgments.id"), nullable=False, index=True)

    decision = Column(String(20), nullable=False)  # "accept" / "override" / "dismiss"
    # The recommendation value actually acted on (same meaning as
    # ReasoningJudgment.admin_decision) -- null for "dismiss", which takes
    # no action by design.
    action_value = Column(String(30), nullable=True)
    # Required (validated in routes/reasoning.py, not at the DB layer) when
    # decision == "dismiss" -- an admin declaring a judgment a false
    # positive must say why, both for later admin-agreement evaluation and
    # so a re-opened dismissed entry shows real context instead of a bare
    # status flip.
    dismiss_reason = Column(Text, nullable=True)

    admin_id = Column(Integer, ForeignKey("admins.admin_id"), nullable=False)
    decided_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))

    judgment = relationship("ReasoningJudgment")
    admin = relationship("Admin")
