# NEW — a company's own uploaded bylaws/administrative guidelines, 1:1
# with Company, same pattern as CompanySmtpConfig/DeviceMetadata.

from datetime import datetime, timezone

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from backend.database.db import Base, UTCDateTime


class CompanyPolicyDocument(Base):
    """The company's own policy/bylaws document, converted once at upload
    time (reasoning/policy_document.py's convert_pdf_to_markdown) and
    stored as Markdown so it's never re-converted on every judgment or
    every dashboard view -- converted_markdown is the single source of
    truth; sections are re-derived from it on demand (reasoning/
    policy_document.py's split_into_sections), not stored redundantly.

    Only ever a READ-ONLY input to the Reasoning Core's evidence bundle
    (reasoning/core.py's gather_context) -- never touches
    current_risk_score, DeviceRiskComponent, or any part of the
    deterministic scoring path. Write access (upload/replace/delete) is
    owner-only, same rationale as CompanySmtpConfig: company-wide
    configuration with real influence over what the AI produces. Read
    access (including the full converted text, not just "a file exists")
    is open to any admin -- bylaws aren't a credential, and being able to
    see exactly what's being fed to the AI is the whole point of the
    transparency this was built with."""

    __tablename__ = "company_policy_documents"

    company_id = Column(Integer, ForeignKey("companies.company_id"), primary_key=True)

    original_filename = Column(String(255), nullable=False)
    converted_markdown = Column(Text, nullable=False)
    uploaded_at = Column(UTCDateTime, default=lambda: datetime.now(timezone.utc))

    company = relationship("Company")
