# NEW — POST /company/register: creates Company + first Admin, generates company ID + api_key

import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.agent_logic.departments import parse_keywords
from backend.auth.dependencies import get_current_admin, require_owner
from backend.auth.security import hash_password
from backend.core.config import DEFAULT_DEPARTMENT_BASELINE, POLICY_MAX_UPLOAD_BYTES
from backend.core.secrets import encrypt_secret
from backend.database.db import get_db
from backend.database.init_db import seed_default_departments
from backend.models.admin import Admin
from backend.models.baselines import DeviceBaseline
from backend.models.company import Company
from backend.models.company_policy_document import CompanyPolicyDocument
from backend.models.company_smtp_config import CompanySmtpConfig
from backend.models.department import Department
from backend.models.devices import Device, DeviceMetadata
from backend.notifications.smtp_resolver import fallback_is_configured
from backend.reasoning.policy_document import PolicyDocumentError, convert_pdf_to_markdown

router = APIRouter(prefix="/company", tags=["company"])


class CompanyRegisterRequest(BaseModel):
    company_name: str = Field(min_length=1, max_length=150)
    admin_username: str = Field(min_length=1, max_length=50)
    admin_password: str = Field(min_length=8)


class CompanyRegisterResponse(BaseModel):
    company_code: str
    company_name: str
    admin_username: str


@router.post("/register", response_model=CompanyRegisterResponse, status_code=status.HTTP_201_CREATED)
def register_company(payload: CompanyRegisterRequest, db: Session = Depends(get_db)):
    """Creates a company and its first admin (role="owner") in one step.
    The generated company_code is what onboarding_flow.md calls the
    "company id" — a long alphanumeric string the admin copies into the
    agent wizard on every employee device. It lives in Company.api_key and
    does double duty as both that copy-pasted value and the credential
    device-facing routes check on every agent request; there's no separate
    field for it.

    "owner", not "admin"/"manager" -- this account's only real purpose
    going forward is creating/promoting the company's actual admin
    accounts (see auth/dependencies.py's require_owner). It's deliberately
    NOT meant to double as anyone's daily-use dashboard login: it can't
    even be linked to a device (routes/admin.py's link_my_device refuses
    an owner outright). The real person registering the company is
    expected to also create themselves a normal admin/manager account
    afterward, linked to their own device, exactly like any other
    employee -- see docs/known_limitations.md for what's NOT built yet
    (no owner-recovery path if these credentials are lost)."""

    # Admin.username has no DB-level unique constraint (matching the
    # original draft), so uniqueness is enforced here at the application
    # layer instead — good enough for login-by-username to stay unambiguous.
    if db.query(Admin).filter(Admin.username == payload.admin_username).first() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")

    password_hash = hash_password(payload.admin_password)
    company = Company(
        company_name=payload.company_name,
        api_key=secrets.token_hex(16),
    )
    db.add(company)
    db.flush()

    admin = Admin(
        company_id=company.company_id,
        username=payload.admin_username,
        password_hash=password_hash,
        role="owner",
    )
    db.add(admin)
    db.commit()

    # Every new company starts with the same 8 default departments
    # (database/init_db.py's seed_default_departments -- shared with the
    # backfill that seeds every company that existed before this feature
    # shipped) -- an admin can add/remove from there via POST/{id}/remove
    # below, but the dashboard's approve/edit-employee dropdowns need
    # SOMETHING to populate from the moment a company is created, not an
    # empty list on day one.
    seed_default_departments(db, company.company_id)

    return CompanyRegisterResponse(
        company_code=company.api_key,
        company_name=company.company_name,
        admin_username=admin.username,
    )


class CompanyMeResponse(BaseModel):
    company_name: str
    company_code: str
    # New -- the Notify Employee feature's company-wide opt-in (default
    # off). Included here (rather than a dedicated GET) so the dashboard
    # picks it up for free from the /company/me call it already makes on
    # every load, no extra round-trip needed.
    employee_notification_enabled: bool


@router.get("/me", response_model=CompanyMeResponse)
def get_my_company(admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    """NEW — added during the dashboard/ phase. company_code is only ever
    returned once, at /register — there was no way for an admin logging
    back in later (not immediately after registration) to see it again,
    which the onboarding flow needs: enrolling a second or third device
    days later requires pasting the same code into that device's agent
    wizard. Scoped to admin.company_id like every other admin-facing route
    — an admin can only ever see their own company's code."""
    company = db.query(Company).filter(Company.company_id == admin.company_id).first()
    return CompanyMeResponse(
        company_name=company.company_name,
        company_code=company.api_key,
        employee_notification_enabled=company.employee_notification_enabled,
    )


class EmployeeNotificationToggleRequest(BaseModel):
    enabled: bool


@router.patch("/employee-notifications", response_model=CompanyMeResponse)
def update_employee_notification_toggle(
    payload: EmployeeNotificationToggleRequest,
    admin: Admin = Depends(require_owner),
    db: Session = Depends(get_db),
):
    """Owner-only -- same tier as PATCH /company/smtp and the policy-
    document upload: company-wide configuration that changes what a
    feature is even allowed to do, not a routine per-employee action.
    This only gates whether "Notify Employee" is reachable at all; it
    never sends anything or triggers a notification on its own."""
    company = db.query(Company).filter(Company.company_id == admin.company_id).first()
    company.employee_notification_enabled = payload.enabled
    db.commit()
    return CompanyMeResponse(
        company_name=company.company_name,
        company_code=company.api_key,
        employee_notification_enabled=company.employee_notification_enabled,
    )


class CompanySmtpOut(BaseModel):
    configured: bool  # true if this company has its own SmtpConfig row
    smtp_host: str | None
    smtp_port: int | None
    smtp_username: str | None
    password_set: bool  # never the password itself, just whether one exists
    # Whether a send would actually work right now if nothing else changes
    # -- true if this company has its own config, OR (local/dev only) all
    # four .env fallback values are set. Surfaced explicitly so "which
    # credentials would actually be used" is never something an admin has
    # to guess -- see notifications/smtp_resolver.py's own docstring.
    would_use_fallback: bool
    # NEW -- visibility into the last real send attempt (notifications/
    # smtp_resolver.py's record_send_result), so a bad credential shows up
    # here instead of only in a server log nobody has an everyday reason
    # to read. All null/"never" until the first send attempt against this
    # company's own config; a send made via the .env fallback never
    # touches these (see record_send_result's own docstring for why).
    last_send_status: str | None  # "success" / "failed" / None (never attempted)
    last_send_at: str | None
    last_send_error: str | None


@router.get("/smtp", response_model=CompanySmtpOut)
def get_company_smtp(admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    """Read is open to any admin/manager/owner -- same openness GET
    /company/me already gives every admin for company_name/code, since
    this is informational (never the password) and an ordinary admin
    reasonably needs to know whether notifications are even configured.
    Only the write side (PATCH below) is owner-gated."""
    config = db.query(CompanySmtpConfig).filter(CompanySmtpConfig.company_id == admin.company_id).first()
    if config is not None:
        return CompanySmtpOut(
            configured=True,
            smtp_host=config.smtp_host,
            smtp_port=config.smtp_port,
            smtp_username=config.smtp_username,
            password_set=True,
            would_use_fallback=False,
            last_send_status=config.last_send_status,
            last_send_at=config.last_send_at.isoformat() if config.last_send_at else None,
            last_send_error=config.last_send_error,
        )
    return CompanySmtpOut(
        configured=False,
        smtp_host=None,
        smtp_port=None,
        smtp_username=None,
        password_set=False,
        would_use_fallback=fallback_is_configured(),
        last_send_status=None,
        last_send_at=None,
        last_send_error=None,
    )


class CompanySmtpUpdateRequest(BaseModel):
    smtp_host: str = Field(min_length=1, max_length=255)
    smtp_port: int = Field(gt=0, lt=65536)
    smtp_username: str = Field(min_length=1, max_length=255)
    # Optional -- omit (or send null) to keep the currently-stored password
    # unchanged. This is the "never redisplay, only overwrite if a new
    # value is actually entered" behavior: GET /company/smtp above never
    # returns the real password, so the frontend has nothing to resubmit
    # unless the admin actually typed a new one.
    smtp_password: str | None = Field(default=None, min_length=1)


@router.patch("/smtp", response_model=CompanySmtpOut)
def update_company_smtp(
    payload: CompanySmtpUpdateRequest,
    admin: Admin = Depends(require_owner),
    db: Session = Depends(get_db),
):
    """Owner-only -- this is tenant-wide infrastructure config with real
    blast radius (a misused credential could send mail as the company),
    the same category admin-account management sits in, which is exactly
    why the owner role exists (auth/dependencies.py's require_owner)."""
    config = db.query(CompanySmtpConfig).filter(CompanySmtpConfig.company_id == admin.company_id).first()
    if config is None:
        if payload.smtp_password is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="smtp_password is required the first time SMTP is configured",
            )
        config = CompanySmtpConfig(
            company_id=admin.company_id,
            smtp_host=payload.smtp_host,
            smtp_port=payload.smtp_port,
            smtp_username=payload.smtp_username,
            smtp_password_encrypted=encrypt_secret(payload.smtp_password),
        )
        db.add(config)
    else:
        config.smtp_host = payload.smtp_host
        config.smtp_port = payload.smtp_port
        config.smtp_username = payload.smtp_username
        if payload.smtp_password is not None:
            config.smtp_password_encrypted = encrypt_secret(payload.smtp_password)
            # A new password makes the previous send result stale/
            # potentially misleading -- e.g. an owner who just fixed a bad
            # credential shouldn't still see the OLD "failed: BadCredentials"
            # line sitting there right after saving. Only reset on an
            # actual password change, not a plain host/port/username edit,
            # since the credential itself (and therefore whether it
            # authenticates) is unchanged in that case.
            config.last_send_status = None
            config.last_send_at = None
            config.last_send_error = None

    db.commit()
    return CompanySmtpOut(
        configured=True,
        smtp_host=config.smtp_host,
        smtp_port=config.smtp_port,
        smtp_username=config.smtp_username,
        password_set=True,
        would_use_fallback=False,
        last_send_status=config.last_send_status,
        last_send_at=config.last_send_at.isoformat() if config.last_send_at else None,
        last_send_error=config.last_send_error,
    )


class CompanyPolicyDocumentOut(BaseModel):
    configured: bool
    original_filename: str | None
    uploaded_at: str | None
    converted_markdown: str | None  # the full text -- transparency into exactly what's fed to the AI, not just "a file exists"


@router.get("/policy-document", response_model=CompanyPolicyDocumentOut)
def get_company_policy_document(admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    """Read is open to any admin/manager/owner, same reasoning as GET
    /company/smtp's non-secret fields -- bylaws aren't a credential, and
    seeing exactly what's being fed to the Reasoning Core (the full
    converted text, not just a filename) is the transparency this
    feature was explicitly built with. Only the write side (upload/
    delete below) is owner-gated."""
    doc = db.query(CompanyPolicyDocument).filter(CompanyPolicyDocument.company_id == admin.company_id).first()
    if doc is None:
        return CompanyPolicyDocumentOut(configured=False, original_filename=None, uploaded_at=None, converted_markdown=None)
    return CompanyPolicyDocumentOut(
        configured=True,
        original_filename=doc.original_filename,
        uploaded_at=doc.uploaded_at.isoformat() if doc.uploaded_at else None,
        converted_markdown=doc.converted_markdown,
    )


@router.post("/policy-document", response_model=CompanyPolicyDocumentOut, status_code=status.HTTP_201_CREATED)
async def upload_company_policy_document(
    file: UploadFile = File(...),
    admin: Admin = Depends(require_owner),
    db: Session = Depends(get_db),
):
    """Owner-only, same rationale as PATCH /company/smtp -- this is
    company-wide configuration with real influence over what the
    Reasoning Core produces (reasoning/core.py's gather_context reads it
    for every judgment), the exact category the owner role exists to hold
    narrowly. Replaces any existing document outright (one document per
    company, not a version history) -- re-upload to update.

    Converts once, here, at upload time (reasoning/policy_document.py's
    convert_pdf_to_markdown) and stores the result -- never re-converted
    on every judgment. The PDF bytes themselves are never stored; only
    the converted Markdown."""
    if file.content_type not in ("application/pdf", "application/x-pdf") and not (file.filename or "").lower().endswith(".pdf"):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Only PDF files are accepted")

    pdf_bytes = await file.read()
    if not pdf_bytes.startswith(b"%PDF"):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="This doesn't look like a real PDF file")
    if len(pdf_bytes) > POLICY_MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File is too large -- the limit is {POLICY_MAX_UPLOAD_BYTES // (1024 * 1024)}MB",
        )

    try:
        markdown = convert_pdf_to_markdown(pdf_bytes)
    except PolicyDocumentError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

    doc = db.query(CompanyPolicyDocument).filter(CompanyPolicyDocument.company_id == admin.company_id).first()
    now = datetime.now(timezone.utc)
    if doc is None:
        doc = CompanyPolicyDocument(
            company_id=admin.company_id,
            original_filename=file.filename or "policy.pdf",
            converted_markdown=markdown,
            uploaded_at=now,
        )
        db.add(doc)
    else:
        doc.original_filename = file.filename or "policy.pdf"
        doc.converted_markdown = markdown
        doc.uploaded_at = now

    db.commit()
    return CompanyPolicyDocumentOut(
        configured=True,
        original_filename=doc.original_filename,
        uploaded_at=doc.uploaded_at.isoformat(),
        converted_markdown=doc.converted_markdown,
    )


@router.delete("/policy-document")
def delete_company_policy_document(admin: Admin = Depends(require_owner), db: Session = Depends(get_db)):
    """Owner-only, same gate as upload. Simply removes the document --
    the Reasoning Core stops getting a policy_excerpt for future
    judgments (reasoning/core.py's gather_context, None when no
    CompanyPolicyDocument row exists); already-created judgments/reports
    that quoted a policy excerpt are untouched, same append-only
    treatment every other historical record in this app gets."""
    doc = db.query(CompanyPolicyDocument).filter(CompanyPolicyDocument.company_id == admin.company_id).first()
    if doc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No policy document is configured")
    db.delete(doc)
    db.commit()
    return {"status": "ok"}


# ── Departments -- per-company, admin-managed (replaces core/config.py's
# old hardcoded 8-department list) ──────────────────────────────────────

class DepartmentOut(BaseModel):
    id: int
    name: str
    avg_files_per_day: float
    normal_hours: tuple[int, int]
    avg_failed_logins: float
    allowed_sensitive_keywords: list[str]
    full_sensitive_access: bool
    policy_keywords: list[str]
    is_active: bool


def _to_department_out(d: Department) -> DepartmentOut:
    return DepartmentOut(
        id=d.id,
        name=d.name,
        avg_files_per_day=d.avg_files_per_day,
        normal_hours=(d.normal_hours_start, d.normal_hours_end),
        avg_failed_logins=d.avg_failed_logins,
        allowed_sensitive_keywords=list(parse_keywords(d.allowed_sensitive_keywords)),
        full_sensitive_access=d.full_sensitive_access,
        policy_keywords=list(parse_keywords(d.policy_keywords)),
        is_active=d.is_active,
    )


@router.get("/departments", response_model=list[DepartmentOut])
def list_departments(admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    """Read is open to any admin/manager/owner -- same tier as GET
    /company/smtp's non-secret fields and GET /company/policy-document:
    every admin routinely needs this list to populate the approve/edit-
    employee department dropdown, not just the owner. Returns every
    department this company has ever had, active or soft-removed (same
    "GET returns everything, active AND removed, UI renders the removed
    ones differently" precedent as GET /admin) -- only the write side
    below is owner-gated. The frontend is responsible for only offering
    is_active=True rows as options for a NEW assignment."""
    departments = (
        db.query(Department)
        .filter(Department.company_id == admin.company_id)
        .order_by(Department.is_active.desc(), Department.name)
        .all()
    )
    return [_to_department_out(d) for d in departments]


class DepartmentCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=50)
    # Comma-separated subset of SENSITIVE_PATH_KEYWORDS -- optional,
    # ignored entirely when full_sensitive_access is set.
    allowed_sensitive_keywords: str | None = None
    full_sensitive_access: bool = False
    policy_keywords: str | None = None


@router.post("/departments", response_model=DepartmentOut, status_code=status.HTTP_201_CREATED)
def create_department(
    payload: DepartmentCreateRequest,
    admin: Admin = Depends(require_owner),
    db: Session = Depends(get_db),
):
    """Owner-only, same tier as SMTP/policy-document configuration -- a
    department's sensitive-access scope and full_sensitive_access flag
    have real influence over detection, the exact category the owner role
    exists to hold narrowly.

    No baseline-number fields are accepted here on purpose (core/
    config.py's DEFAULT_DEPARTMENT_BASELINE docstring has the full
    reasoning): asking an admin to guess avg_files_per_day/normal_hours/
    avg_failed_logins for a department with zero history yet would just
    be inventing a number with no more basis than litds's own generic
    default already has. The real, department-specific comparison point
    is the learned DepartmentBaseline EWMA (agent_logic/
    baseline_learning.py), which starts accumulating the moment real
    employees in this department generate real activity -- unchanged
    mechanism; this department just starts at the same cold-start floor
    every department (admin-created or originally seeded) starts at
    before it has any learned history of its own.

    A name, once used for this company (whether still active or
    previously soft-removed), can't be reused -- the DB-level
    UNIQUE(company_id, name) constraint enforces this. Reactivating or
    renaming a removed department isn't built here -- only add +
    soft-remove, matching what was actually asked for."""
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Department name is required")

    existing = db.query(Department).filter(Department.company_id == admin.company_id, Department.name == name).first()
    if existing is not None:
        detail = f"A department named '{name}' already exists for this company"
        if not existing.is_active:
            detail += " (it was previously removed -- reusing a removed department's name isn't supported)"
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)

    department = Department(
        company_id=admin.company_id,
        name=name,
        avg_files_per_day=DEFAULT_DEPARTMENT_BASELINE["avg_files_per_day"],
        normal_hours_start=DEFAULT_DEPARTMENT_BASELINE["normal_hours"][0],
        normal_hours_end=DEFAULT_DEPARTMENT_BASELINE["normal_hours"][1],
        avg_failed_logins=DEFAULT_DEPARTMENT_BASELINE["avg_failed_logins"],
        allowed_sensitive_keywords=(payload.allowed_sensitive_keywords or "").strip() or None,
        full_sensitive_access=payload.full_sensitive_access,
        policy_keywords=(payload.policy_keywords or "").strip() or None,
    )
    db.add(department)
    db.commit()
    db.refresh(department)
    return _to_department_out(department)


class DepartmentUpdateRequest(BaseModel):
    # Comma-separated subset of SENSITIVE_PATH_KEYWORDS -- same field/format
    # as DepartmentCreateRequest's own allowed_sensitive_keywords.
    allowed_sensitive_keywords: str | None = None
    full_sensitive_access: bool = False


@router.post("/departments/{department_id}/update", response_model=DepartmentOut)
def update_department(
    department_id: int,
    payload: DepartmentUpdateRequest,
    admin: Admin = Depends(require_owner),
    db: Session = Depends(get_db),
):
    """Owner-only, same tier as create_department. Deliberately accepts
    ONLY allowed_sensitive_keywords and full_sensitive_access -- the name
    is NOT accepted here at all (not even ignored-if-present), by design:
    Department names remain immutable in this interface so reports and
    historical descriptions retain stable vocabulary. Assignments now use
    Department.id, so they cannot be orphaned by name matching.

    Baseline numbers (avg_files_per_day/normal_hours/avg_failed_logins)
    stay out of scope too, same reasoning as create_department: the
    learned DepartmentBaseline EWMA is the real, department-specific
    comparison point, not a hand-edited seed number."""
    department = db.query(Department).filter(Department.id == department_id, Department.company_id == admin.company_id).first()
    if department is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Department not found")
    if not department.is_active:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This department has been removed and can't be edited")

    department.allowed_sensitive_keywords = (payload.allowed_sensitive_keywords or "").strip() or None
    department.full_sensitive_access = payload.full_sensitive_access
    db.commit()
    db.refresh(department)
    return _to_department_out(department)


class DepartmentRemoveResponse(BaseModel):
    department: DepartmentOut
    # Informational only -- see remove_department's own docstring for why
    # this is never a block.
    assigned_employee_count: int


@router.post("/departments/{department_id}/remove", response_model=DepartmentRemoveResponse)
def remove_department(
    department_id: int,
    admin: Admin = Depends(require_owner),
    db: Session = Depends(get_db),
):
    """Owner-only soft removal -- is_active=False, never a hard delete,
    same pattern as routes/admin.py's remove_admin. UNLIKE that precedent
    (and a deliberate change from this feature's first round): every
    device currently assigned to this department has DeviceMetadata.
    department_id actively cleared to None ("no department set") rather than
    left pointing at a now-inactive row -- reassigned, not silently
    stranded. Confirmed live (not assumed) that a None department falls
    through cleanly to agent_logic/departments.py's existing generic-
    floor/no-special-access fallback everywhere it's read, exactly the
    same path an employee who was never assigned a department in the
    first place already goes through.

    Also resets each affected device's own learned personal baseline
    (DeviceBaseline) -- same treatment routes/device.py's update_device
    already gives a genuine department CHANGE ("mixing 'normal as X' with
    'normal as unassigned' into one running average would be actively
    misleading"), applied consistently here since losing a department is
    just as real a change to what's being compared against as switching
    to a different one.

    assigned_employee_count is returned so the admin UI can surface a
    clear "N employees were set to 'No department set'" notice -- this
    already happened by the time the response comes back, not a
    confirmation gate the server waits on."""
    department = db.query(Department).filter(Department.id == department_id, Department.company_id == admin.company_id).first()
    if department is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Department not found")
    if not department.is_active:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This department is already removed")

    affected_metadata = (
        db.query(DeviceMetadata)
        .join(Device, Device.device_id == DeviceMetadata.device_id)
        .filter(Device.company_id == admin.company_id, DeviceMetadata.department_id == department.id)
        .all()
    )
    assigned_count = len(affected_metadata)

    for metadata in affected_metadata:
        metadata.department_id = None
        existing_baseline = db.query(DeviceBaseline).filter(DeviceBaseline.device_id == metadata.device_id).first()
        if existing_baseline is not None:
            db.delete(existing_baseline)

    department.is_active = False
    db.commit()
    db.refresh(department)
    return DepartmentRemoveResponse(department=_to_department_out(department), assigned_employee_count=assigned_count)
