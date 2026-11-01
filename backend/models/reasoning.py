# NEW — AI Reasoning Core: stored judgments + admin decisions, see backend/reasoning/

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, Column, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class ReasoningJudgment(Base):
    """One completed two-pass LLM judgment about a device that just
    crossed into high/critical risk (agent_logic/analyzer.py's
    _reasoning_trigger_fires), awaiting or having received an explicit
    admin decision (routes/reasoning.py). Rows only ever exist for
    judgments that actually completed both passes successfully -- if LM
    Studio is unreachable or produces unparseable output at any point, no
    row is created at all (backend/reasoning/worker.py logs it and moves
    on); there is deliberately no "failed" status cluttering the admin's
    view for something that never produced anything to review."""

    __tablename__ = "reasoning_judgments"

    id = Column(Integer, primary_key=True)
    company_id = Column(Integer, ForeignKey("companies.company_id"), nullable=False, index=True)
    device_id = Column(Integer, ForeignKey("devices.device_id"), nullable=False, index=True)
    # Nullable: the trigger is the device's AGGREGATE current_risk_score
    # crossing into high/critical, which doesn't always correspond to one
    # specific Alert row (e.g. several already-decaying components summing
    # past the threshold with no single new anomaly this cycle). When
    # present, this is the most relevant open alert at trigger time, and
    # what accept/override attaches Response rows to.
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)

    triggered_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    trigger_risk_score = Column(Float, nullable=False)
    trigger_risk_level = Column(String(20), nullable=False)

    # The full evidence bundle handed to the LLM (features, risk
    # components, department, recent alerts/significant events) -- stored
    # for reproducibility/auditability and so the dashboard can show the
    # admin what the judgment was actually based on, not just the verdict.
    context_snapshot = Column(JSON, nullable=False)

    # Pass 1 ("Analyst") and Pass 2 ("Critic") -- both kept, not just the
    # final one: "how often did the critic pass revise the analyst pass"
    # is itself a small evaluation metric, alongside admin-agreement rate.
    initial_explanation = Column(Text, nullable=False)
    initial_recommendation = Column(String(30), nullable=False)
    initial_confidence = Column(Float, nullable=True)

    final_explanation = Column(Text, nullable=False)
    final_recommendation = Column(String(30), nullable=False)
    final_confidence = Column(Float, nullable=True)
    critic_changed_judgment = Column(Boolean, nullable=False, default=False)

    model_used = Column(String(100), nullable=False)

    # "awaiting_admin" / "accepted" / "overridden" / "dismissed"
    status = Column(String(20), nullable=False, default="awaiting_admin")
    # The recommendation value actually acted on -- final_recommendation
    # if accepted, the admin's own choice if overridden, null if dismissed.
    admin_decision = Column(String(30), nullable=True)
    decided_by_admin_id = Column(Integer, ForeignKey("admins.admin_id"), nullable=True)
    decided_at = Column(UTCDateTime, nullable=True)

    device = relationship("Device")
    alert = relationship("Alert")
    decided_by = relationship("Admin")
