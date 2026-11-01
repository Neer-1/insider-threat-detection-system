# NEW — a company's own send-only SMTP account, 1:1 with Company, same
# "optional secondary info in its own table" pattern as DeviceMetadata
# (models/devices.py) rather than nullable columns bolted onto Company
# itself -- keeps the encrypted password physically out of the frequently-
# read Company row.

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class CompanySmtpConfig(Base):
    """A company's own SMTP credentials for outbound Reasoning Core
    trigger notifications (notifications/mailer.py) -- send-only, never
    used to check or process any incoming mail. smtp_password_encrypted
    holds Fernet ciphertext (core/secrets.py) -- the plaintext password is
    never written anywhere, only ever decrypted in memory at the moment an
    email is actually being sent.

    Company-wide, not personal -- write access is owner-only
    (routes/company.py's PATCH /company/smtp, gated by require_owner),
    same rationale as admin-account management: this is tenant-wide
    configuration with real blast radius (a misused credential could send
    mail as the company), the exact category the owner role exists to
    hold narrowly. Any admin/manager can still READ the non-secret fields
    (host/port/username, never the password) -- same openness GET
    /company/me already gives every admin for company_name/code."""

    __tablename__ = "company_smtp_config"

    company_id = Column(Integer, ForeignKey("companies.company_id"), primary_key=True)

    smtp_host = Column(String(255), nullable=False)
    smtp_port = Column(Integer, nullable=False)
    smtp_username = Column(String(255), nullable=False)
    smtp_password_encrypted = Column(Text, nullable=False)

    # NEW — visibility into the last real send attempt (notifications/
    # mailer.py, via smtp_resolver.py's record_send_result), so a bad
    # credential is visible on the Company Profile SMTP status line
    # itself rather than only discoverable by reading server logs or
    # noticing a missing email after the fact. Only ever updated for a
    # send that actually used THIS company's own config (source=="company"
    # in smtp_resolver.py) -- a send made via the .env fallback never
    # touches these, since there's no company config row to attribute it
    # to. Null/None until the very first send attempt.
    last_send_status = Column(String(10), nullable=True)  # "success" / "failed"
    last_send_at = Column(UTCDateTime, nullable=True)
    last_send_error = Column(Text, nullable=True)  # only set when last_send_status == "failed", cleared on success

    company = relationship("Company")
