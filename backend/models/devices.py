# KEEP litds/backend/models/devices.py

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class Device(Base):
    """One employee machine running the agent."""

    __tablename__ = "devices"
    __table_args__ = (
        # Unique per company, not globally — found via real multi-company
        # testing: the same physical machine legitimately enrolling under
        # two different companies (e.g. a contractor working with more than
        # one client, or just re-testing against a second company) isn't a
        # duplicate-enrollment bug, it's two separate tenants each with
        # their own record of that device. A global unique constraint
        # rejected the second company's enrollment outright (500 on
        # /device/enroll) — this is the correct scope for what
        # device_fingerprint is actually deduping against.
        UniqueConstraint("company_id", "device_fingerprint", name="uq_device_company_fingerprint"),
    )

    device_id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.company_id"), nullable=False, index=True)

    # Returned to the agent at enrollment and stored in its local config —
    # what the agent presents on every later request, not the internal id.
    public_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))

    # Hardware-derived fingerprint, distinct from public_id: this is what
    # stops the same physical machine being enrolled twice under two
    # different device rows within the SAME company, which a random
    # public_id can't do on its own. See __table_args__ for why this is a
    # per-company constraint, not a column-level global one.
    device_fingerprint = Column(String(255), nullable=False, index=True)

    # New — not in the original draft. Issued once, at approval time, and
    # used for every /logs/ingest call after that. Deliberately separate
    # from the company-wide api_key: that code is handled during onboarding
    # (typed, pasted, screen-shared) far more casually than a credential
    # that streams on every log batch should be, and a per-device secret
    # means one device can be individually revoked without rotating the
    # code for the whole company.
    device_token = Column(String(64), unique=True, nullable=True)

    label = Column(String(255), nullable=True)
    hostname = Column(String(255), nullable=False)
    username = Column(String(100), nullable=True)  # OS/Windows user of this device
    os_info = Column(String(255), nullable=True)
    ip_address = Column(String(50), nullable=True)

    # Connectivity (is the agent currently checking in) is tracked
    # separately from authorization (has an admin vetted this device) — a
    # device can be approved but currently offline, or pending and online.
    connection_status = Column(String(20), nullable=False, default="offline")  # online / offline
    # pending / approved / rejected / revoked / offboarded. "offboarded"
    # is distinct from "revoked": revoked implies a trust/security problem
    # with the device itself, offboarded means the employee left and their
    # device was deliberately retired -- same practical effect (excluded
    # from live views, scheduler stops analyzing it, /logs/ingest rejects
    # it) but keeps the two situations distinguishable in the data, and
    # its logs/features/alerts are kept as an archive rather than deleted.
    # "rejected" (routes/device.py's reject_device) is different again --
    # a denied ENROLLMENT request, reachable only from "pending" and never
    # from "approved": there's nothing to keep as an archive yet, since
    # this device was never actually let in. Re-enrolling the same
    # physical device (routes/device.py's enroll_device) resets a
    # rejected row back to "pending" for a fresh review -- not a
    # permanent mark on the device, only on that one request.
    approval_status = Column(String(20), nullable=False, default="pending")

    enrolled_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(UTCDateTime, nullable=True)

    # Persisted, continuously-decaying risk score (0-100) — replaces
    # "highest-severity unresolved alert" as the definition of a device's
    # current risk. Derived from the sum (capped at 100) of per-anomaly-
    # type DeviceRiskComponent rows (models/risk_components.py), each
    # decaying/rising on its own core/config.py-tuned schedule
    # (agent_logic/analyzer.py's _update_risk_components /
    # _decay_and_rise) rather than one global rate for everything — a
    # failed-login streak forgiven in minutes, sustained privilege
    # escalation staying elevated far longer. Updated every analysis
    # cycle regardless of whether that cycle found anything anomalous —
    # this is what lets a device's displayed risk actually drop again
    # after genuinely clean behaviour, instead of only ever being able to
    # climb.
    current_risk_score = Column(Float, nullable=False, default=0.0)
    risk_score_updated_at = Column(UTCDateTime, nullable=True)

    # Set by an admin (POST /device/{id}/request-refresh) to ask for
    # up-to-date hostname/username/os_info/ip_address. The agent has no
    # listening port (push-only by design — onboarding_flow.md), so this
    # can't be an instant pull: it's a flag the agent's NEXT /logs/ingest
    # check-in notices and fulfils (see routes/logs.py's ingest_logs),
    # clearing itself once applied.
    info_refresh_requested = Column(Boolean, nullable=False, default=False)

    # NEW -- the one shared high-water-mark for ALL THREE Reasoning Core
    # trigger types (agent_logic/analyzer.py: the original edge-crossing
    # trigger, the sharp-delta medium-band trigger, and the sustained-
    # escalation re-trigger), updated whichever of the three actually
    # fires. Deliberately one scalar pair, not a per-anomaly-type or
    # per-trigger-type table -- the escalation re-trigger reads this
    # directly to ask "has the real aggregate score climbed meaningfully
    # further since we last notified," which composes correctly with the
    # existing dismiss/rollback system for free: a dismissal lowers
    # current_risk_score (agent_logic/dismissal.py's rollback), so a
    # genuinely-settled device simply can't clear last_reasoning_trigger_
    # score + ESCALATION_MIN_SCORE_INCREASE again without a real further
    # climb -- no separate dismiss-awareness logic needed here.
    last_reasoning_trigger_score = Column(Float, nullable=True)
    last_reasoning_trigger_at = Column(UTCDateTime, nullable=True)

    company = relationship("Company", back_populates="devices")
    device_info = relationship("DeviceMetadata", back_populates="device", uselist=False, cascade="all, delete")
    logs = relationship("Log", back_populates="device")
    features = relationship("Feature", back_populates="device")
    alerts = relationship("Alert", back_populates="device")


class DeviceMetadata(Base):
    """Optional secondary device info, 1:1 with Device — the PK doubles as
    the FK to enforce that 1:1 relationship, matching the draft."""

    __tablename__ = "device_metadata"

    device_id = Column(Integer, ForeignKey("devices.device_id"), primary_key=True)

    # Canonical department identity is a foreign key. The migration resolves
    # legacy names within the device's own company before removing the old
    # text column.
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=True, index=True)

    # New -- optional. Settable at approval time (routes/device.py's
    # DeviceApproveRequest) or later via the edit-employee form
    # (DeviceUpdateRequest). The only consumer is
    # the admin-triggered "Notify Employee" alert email
    # (routes/device.py's notify_employee) -- nothing automated reads or
    # depends on this being set.
    email = Column(String(255), nullable=True)

    device = relationship("Device", back_populates="device_info")
    department_record = relationship("Department")

    @property
    def department(self) -> str | None:
        """Department name retained as a read-only application convenience."""
        return self.department_record.name if self.department_record is not None else None
