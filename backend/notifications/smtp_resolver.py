# NEW — resolves which SMTP credentials a company's outbound notifications
# actually use: its own configured account, or (local/dev only) the
# .env fallback -- see core/config.py's SMTP_FALLBACK_* docstring.

"""
Deliberately never silent about which one it picked -- mailer.py logs the
resolved `source` on every single send attempt, so "is this actually
using the company's real SMTP account or my local dev fallback" is never
something you have to guess by reading code. The dashboard's Company
Profile SMTP section (GET /company/smtp) surfaces the same thing to the
admin, not just the server log.
"""

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.core.config import SMTP_FALLBACK_HOST, SMTP_FALLBACK_PASSWORD, SMTP_FALLBACK_PORT, SMTP_FALLBACK_USERNAME
from backend.core.secrets import decrypt_secret
from backend.models.company_smtp_config import CompanySmtpConfig


@dataclass
class ResolvedSmtpConfig:
    host: str
    port: int
    username: str
    password: str
    source: str  # "company" | "fallback"


def fallback_is_configured() -> bool:
    """All four .env fallback values must be set for it to be usable at
    all -- a partial set is treated as "no fallback," never an attempt to
    send with a missing field."""
    return bool(SMTP_FALLBACK_HOST and SMTP_FALLBACK_PORT and SMTP_FALLBACK_USERNAME and SMTP_FALLBACK_PASSWORD)


def resolve_smtp_config(db: Session, company_id: int) -> ResolvedSmtpConfig | None:
    """A company's own configured SMTP always takes priority over the
    fallback -- never the other way around, and never merged/partial
    (e.g. company host + fallback password). Returns None if neither is
    usable; callers treat that as "notifications are off for this
    company," not an error."""
    company_config = db.query(CompanySmtpConfig).filter(CompanySmtpConfig.company_id == company_id).first()
    if company_config is not None:
        return ResolvedSmtpConfig(
            host=company_config.smtp_host,
            port=company_config.smtp_port,
            username=company_config.smtp_username,
            password=decrypt_secret(company_config.smtp_password_encrypted),
            source="company",
        )

    if fallback_is_configured():
        try:
            port = int(SMTP_FALLBACK_PORT)
        except ValueError:
            print(f"[notifications] SMTP_FALLBACK_PORT={SMTP_FALLBACK_PORT!r} is not a valid integer -- fallback config ignored")
            return None
        return ResolvedSmtpConfig(
            host=SMTP_FALLBACK_HOST,
            port=port,
            username=SMTP_FALLBACK_USERNAME,
            password=SMTP_FALLBACK_PASSWORD,
            source="fallback",
        )

    return None


def record_send_result(db: Session, company_id: int, source: str, *, success: bool, error: str | None) -> None:
    """Persists the outcome of the most recent real send attempt onto the
    company's own CompanySmtpConfig row -- what GET /company/smtp surfaces
    on the Company Profile SMTP status line, so a bad credential (or any
    other send failure) is visible in the dashboard itself, not only in a
    server log an admin has no everyday reason to read.

    Only does anything when source=="company" -- a send made via the
    .env fallback has no CompanySmtpConfig row to attribute a result to
    (the fallback is local/dev-only in the first place, not something the
    dashboard tracks status for). Silently a no-op in that case, and if
    the row has since been deleted/reconfigured out from under a send
    already in flight -- never raises, since this is best-effort
    bookkeeping around an already-completed send, not something worth
    failing the caller over."""
    if source != "company":
        return
    config = db.query(CompanySmtpConfig).filter(CompanySmtpConfig.company_id == company_id).first()
    if config is None:
        return
    config.last_send_status = "success" if success else "failed"
    config.last_send_at = datetime.now(timezone.utc)
    config.last_send_error = None if success else error
    db.commit()
