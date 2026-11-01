# NEW split — Admin class currently lives inside company.py in litds, pulled into its own file to match one-model-per-file pattern

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class Admin(Base):
    __tablename__ = "admins"

    admin_id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.company_id"))

    username = Column(String(50), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)

    # "manager" replaces the draft's "superadmin" — the two dashboard-access
    # roles are admin / manager, both scoped to one company; neither
    # crosses tenant boundaries.
    role = Column(String(20))  # admin / manager

    # Soft-delete only — an admin is deactivated, not deleted, so past
    # actions (responses_triggered) keep a valid reference.
    is_active = Column(Boolean, default=True, nullable=False)

    # NEW — every admin is ultimately tied to their own onboarded, monitored
    # device (routes/admin.py). Nullable to cover the one unavoidable
    # bootstrap gap: the FIRST admin is created at POST /company/register,
    # before any device exists yet to link to -- they link it themselves
    # afterward via POST /admin/link-device once their own device has gone
    # through normal approval. Every admin after that is created already
    # linked, via POST /admin/promote (an existing manager promoting an
    # already-approved device).
    #
    # Deliberately NOT unique=True at the column level, matching the
    # existing precedent on `username` above: SQLite's ALTER TABLE can't
    # add a UNIQUE constraint to an already-existing table without
    # recreating it, and this column was added to a database that already
    # had real admin/device rows in it. One-admin-per-device (and vice
    # versa) is enforced in routes/admin.py before every write instead --
    # same "application-layer is good enough here" call already made for
    # username's uniqueness.
    linked_device_id = Column(Integer, ForeignKey("devices.device_id"), nullable=True)

    # NEW — Reasoning Core trigger notifications (notifications/mailer.py).
    # Both nullable/default-False so every existing admin row is
    # unaffected until they opt in themselves (PATCH /admin/me/notifications
    # -- self-service, same as password change). Deliberately not offered
    # to the "owner" role at all (blocked at that same endpoint) -- same
    # reasoning as linked_device_id being refused for owner: notifications
    # are a daily-use-account feature, and the owner account exists
    # specifically to stay out of daily routine exposure.
    email = Column(String(255), nullable=True)
    email_notifications_enabled = Column(Boolean, default=False, nullable=False)

    created_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))

    company = relationship("Company", back_populates="admins")
    responses_triggered = relationship("Response", back_populates="triggered_by_admin")
    linked_device = relationship("Device")
