# NEW — POST /device/enroll (agent hits this with company ID + device info), POST /device/{id}/approve (admin action)

import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.agent_logic.departments import get_department
from backend.auth.dependencies import get_current_admin
from backend.database.db import get_db
from backend.models.admin import Admin
from backend.models.baselines import DeviceBaseline
from backend.models.company import Company
from backend.models.department import Department
from backend.models.devices import Device, DeviceMetadata
from backend.models.employee_notification import EmployeeNotification
from backend.notifications.mailer import send_employee_notification

router = APIRouter(prefix="/device", tags=["device"])


def _validate_department(db: Session, company_id: int, department: str | None) -> Department | None:
    """Resolve a submitted name within the current tenant."""
    if not department:
        return None
    resolved = get_department(db, company_id, department, active_only=True)
    if resolved is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"'{department}' is not a valid department for this company -- check Company Profile's department list",
        )
    return resolved


# ── Agent-facing: enrollment (no admin auth — this is the agent's very
# first contact with the server, before any human has approved anything) ──

class DeviceEnrollRequest(BaseModel):
    company_code: str  # pasted into the agent wizard — Company.api_key
    device_fingerprint: str
    hostname: str
    username: str | None = None
    os_info: str | None = None
    ip_address: str | None = None


class DeviceEnrollResponse(BaseModel):
    device_id: str  # Device.public_id — what the agent stores locally, not the internal PK
    approval_status: str


@router.post("/enroll", response_model=DeviceEnrollResponse, status_code=status.HTTP_201_CREATED)
def enroll_device(payload: DeviceEnrollRequest, db: Session = Depends(get_db)):
    company = db.query(Company).filter(Company.api_key == payload.company_code, Company.is_active.is_(True)).first()
    if company is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid company code")

    existing = (
        db.query(Device)
        .filter(Device.company_id == company.company_id, Device.device_fingerprint == payload.device_fingerprint)
        .first()
    )
    if existing is not None:
        # Re-running the wizard on an already-enrolled machine — treat as a
        # refresh, not a duplicate device, since device_fingerprint exists
        # precisely to prevent that.
        existing.hostname = payload.hostname
        existing.username = payload.username
        existing.os_info = payload.os_info
        existing.ip_address = payload.ip_address
        existing.last_seen = datetime.now(timezone.utc)
        existing.connection_status = "online"
        # A previously-rejected device gets a genuine second chance on a
        # fresh enrollment attempt — reset back to "pending" for a new
        # admin review, not left stuck showing "rejected" forever just
        # because the row already existed. Every other status (approved/
        # offboarded) is deliberately left untouched here: re-running the
        # wizard on an already-approved device shouldn't silently knock it
        # back into the review queue, and offboarding is its own separate,
        # deliberate admin decision this isn't meant to undo.
        if existing.approval_status == "rejected":
            existing.approval_status = "pending"
        db.commit()
        return DeviceEnrollResponse(device_id=existing.public_id, approval_status=existing.approval_status)

    device = Device(
        company_id=company.company_id,
        hostname=payload.hostname,
        username=payload.username,
        os_info=payload.os_info,
        ip_address=payload.ip_address,
        device_fingerprint=payload.device_fingerprint,
        connection_status="online",
        approval_status="pending",
        last_seen=datetime.now(timezone.utc),
    )
    db.add(device)
    db.commit()
    db.refresh(device)

    return DeviceEnrollResponse(device_id=device.public_id, approval_status=device.approval_status)


class DeviceStatusResponse(BaseModel):
    approval_status: str
    device_token: str | None  # only present once approval_status == "approved"


@router.get("/{device_public_id}/status", response_model=DeviceStatusResponse)
def check_enrollment_status(
    device_public_id: str,
    x_company_code: str = Header(..., alias="X-Company-Code"),
    db: Session = Depends(get_db),
):
    """Require the active tenant's company code before releasing status or a
    device token. The public device UUID identifies a record; it is not
    sufficient authorization by itself. Company-code holders are still
    trusted at tenant scope; per-device enrollment proof remains future work.
    """
    device = db.query(Device).filter(Device.public_id == device_public_id).first()
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    company = db.query(Company).filter(Company.company_id == device.company_id).first()
    if (
        company is None
        or not company.is_active
        or not isinstance(x_company_code, str)
        or not secrets.compare_digest(company.api_key.encode('utf-8'), x_company_code.encode('utf-8'))
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid company code")

    return DeviceStatusResponse(
        approval_status=device.approval_status,
        device_token=device.device_token if device.approval_status == "approved" else None,
    )


# ── Admin-facing: listing + approval ─────────────────────────────────────

class DeviceOut(BaseModel):
    device_id: str
    label: str | None
    hostname: str
    username: str | None
    ip_address: str | None
    connection_status: str
    approval_status: str
    last_seen: datetime | None
    info_refresh_requested: bool
    email: str | None = None


def _to_device_out(d: Device) -> DeviceOut:
    metadata = d.device_info
    connection_status = d.connection_status
    return DeviceOut(
        device_id=d.public_id,
        label=d.label,
        hostname=d.hostname,
        username=d.username,
        ip_address=d.ip_address,
        connection_status=connection_status,
        approval_status=d.approval_status,
        last_seen=d.last_seen,
        info_refresh_requested=d.info_refresh_requested,
        email=metadata.email if metadata else None,
    )


@router.get("", response_model=list[DeviceOut])
def list_devices(admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    devices = db.query(Device).filter(Device.company_id == admin.company_id).all()
    return [_to_device_out(d) for d in devices]


class DeviceApproveRequest(BaseModel):
    label: str = Field(min_length=1, max_length=255)  # the employee this device belongs to
    department: str | None = None
    # New -- optional. Only ever used by the admin-triggered "Notify
    # Employee" alert (notify_employee below); nothing automated depends on
    # this being set.
    email: str | None = None


@router.post("/{device_public_id}/approve", response_model=DeviceOut)
def approve_device(
    device_public_id: str,
    payload: DeviceApproveRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    # Scoped by company_id, not just public_id — without this an admin from
    # one company could approve (and start seeing logs for) a device that
    # actually belongs to a different company.
    device = (
        db.query(Device)
        .filter(Device.public_id == device_public_id, Device.company_id == admin.company_id)
        .first()
    )
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    selected_department = _validate_department(db, admin.company_id, payload.department)

    device.label = payload.label
    device.approval_status = "approved"
    # Generated here, not at /enroll — this is the credential the device
    # switches to for every future /logs/ingest call, replacing the
    # one-time-use company_code. Not returned to the admin: only the
    # device itself ever sees it, via /status.
    device.device_token = secrets.token_hex(32)

    metadata = db.query(DeviceMetadata).filter(DeviceMetadata.device_id == device.device_id).first()
    if metadata is None:
        metadata = DeviceMetadata(device_id=device.device_id)
        db.add(metadata)
    metadata.department_id = selected_department.id if selected_department is not None else None
    metadata.email = payload.email

    db.commit()
    db.refresh(device)

    return _to_device_out(device)


@router.post("/{device_public_id}/reject", response_model=DeviceOut)
def reject_device(
    device_public_id: str,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Denies a pending enrollment -- soft, not a hard delete, same
    is_active/approval_status pattern this project uses everywhere else
    rather than removing rows. Only valid from "pending": this is
    specifically about denying an enrollment request before it was ever
    approved, not a general-purpose revocation of an already-approved
    device (models/devices.py's approval_status docstring already
    reserves "revoked" for that separate, not-yet-built concept -- this
    doesn't touch or repurpose it).

    The enrolling device's wizard picks this up on its next GET /device/
    {id}/status poll (agent/main.py's wait_for_approval) and exits with a
    clear "Request rejected" message. Re-enrolling the SAME physical
    device afterward (enroll_device above) resets this back to "pending"
    for a fresh review -- rejection isn't permanent for the device
    itself, only for that one request."""
    device = (
        db.query(Device)
        .filter(Device.public_id == device_public_id, Device.company_id == admin.company_id)
        .first()
    )
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    if device.approval_status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Only a pending device can be rejected (this one is '{device.approval_status}')",
        )

    device.approval_status = "rejected"
    db.commit()
    db.refresh(device)

    return _to_device_out(device)


class DeviceUpdateRequest(BaseModel):
    # All optional -- a PATCH only touches the fields it's given. label
    # lets an admin correct the name once it's been auto-filled from the
    # device's own username at approval time (see approveDevice in the
    # dashboard) -- the agent has no idea what an employee's real name is,
    # only their OS username, so this is expected to need occasional
    # correction, not a rare edge case.
    label: str | None = Field(default=None, min_length=1, max_length=255)
    department: str | None = None
    # New -- the second of the two "optional at onboarding, editable
    # later" paths for the Notify Employee feature.
    email: str | None = None


@router.patch("/{device_public_id}", response_model=DeviceOut)
def update_device(
    device_public_id: str,
    payload: DeviceUpdateRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    device = (
        db.query(Device)
        .filter(Device.public_id == device_public_id, Device.company_id == admin.company_id)
        .first()
    )
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    if device.approval_status == "offboarded":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Cannot edit an offboarded employee's record")

    if payload.label is not None:
        device.label = payload.label
    if payload.department is not None:
        selected_department = _validate_department(db, admin.company_id, payload.department)
        metadata = db.query(DeviceMetadata).filter(DeviceMetadata.device_id == device.device_id).first()
        if metadata is None:
            metadata = DeviceMetadata(device_id=device.device_id)
            db.add(metadata)
        selected_department_id = selected_department.id if selected_department is not None else None
        department_changed = metadata.department_id != selected_department_id
        metadata.department_id = selected_department_id

        # A real role change -- reset this device's learned personal
        # baseline (agent_logic/baseline_learning.py) rather than let it
        # keep blending "normal as an engineer" with "normal as finance"
        # into one running average. The device falls back to comparing
        # against its (new) department's baseline and starts the same
        # gradual personal-trust ramp-up a brand-new employee gets. The
        # department baseline itself is untouched by this -- deliberately
        # not retroactively re-attributed to the new department either.
        if department_changed:
            existing_baseline = (
                db.query(DeviceBaseline).filter(DeviceBaseline.device_id == device.device_id).first()
            )
            if existing_baseline is not None:
                db.delete(existing_baseline)

    if payload.email is not None:
        metadata = db.query(DeviceMetadata).filter(DeviceMetadata.device_id == device.device_id).first()
        if metadata is None:
            metadata = DeviceMetadata(device_id=device.device_id)
            db.add(metadata)
        metadata.email = payload.email

    db.commit()
    db.refresh(device)

    return _to_device_out(device)


@router.post("/{device_public_id}/offboard", response_model=DeviceOut)
def offboard_device(
    device_public_id: str,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Employee left -- retire their device without deleting anything.
    approval_status="offboarded" is enough on its own to: drop out of
    list_employees()'s "approved" filter (leaves the live grid), drop out
    of the scheduler's "approved" filter (backend/scheduler.py -- stops
    being analyzed), and fail /logs/ingest's approval check (agent falls
    back to local buffering, same as any other rejection). Logs, features,
    and alerts are untouched -- get_employee() still allows "offboarded"
    devices through so the profile/history stays viewable as an archive."""
    device = (
        db.query(Device)
        .filter(Device.public_id == device_public_id, Device.company_id == admin.company_id)
        .first()
    )
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    device.approval_status = "offboarded"
    db.commit()
    db.refresh(device)

    return _to_device_out(device)


@router.post("/{device_public_id}/request-refresh", response_model=DeviceOut)
def request_device_info_refresh(
    device_public_id: str,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Profile page "Refresh device info" button. Not an instant pull --
    the agent never listens for incoming connections (push-only by
    design, onboarding_flow.md), so the server can't reach out to it.
    This only sets a flag; the device's own next /logs/ingest check-in
    (routes/logs.py's ingest_logs) notices it, applies a fresh
    hostname/username/os_info/ip_address snapshot the agent already sends
    on every call, and clears the flag. Blocked for offboarded devices --
    same "no further check-ins are coming, nothing to wait for" reasoning
    as blocking edits on them (update_device, above)."""
    device = (
        db.query(Device)
        .filter(Device.public_id == device_public_id, Device.company_id == admin.company_id)
        .first()
    )
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    if device.approval_status == "offboarded":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Cannot refresh an offboarded device -- it no longer checks in")

    device.info_refresh_requested = True
    db.commit()
    db.refresh(device)

    return _to_device_out(device)


class NotifyEmployeeRequest(BaseModel):
    message: str = Field(min_length=1)


class NotifyEmployeeResponse(BaseModel):
    status: str  # "success" | "failed"
    error: str | None


@router.post("/{device_public_id}/notify-employee", response_model=NotifyEmployeeResponse)
def notify_employee(
    device_public_id: str,
    payload: NotifyEmployeeRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Admin-triggered, manual-only "Notify Employee" alert email --
    deliberately never fired automatically by the detection pipeline
    (an automatic version risks tipping off a genuinely malicious actor
    before any human has reviewed the situation). Gated on the company-
    level opt-in (Company.employee_notification_enabled, default off) so
    the feature isn't reachable at all unless an owner has turned it on,
    same posture as every other opt-in notification feature here.

    Every attempt is recorded (EmployeeNotification), success or failure
    -- an admin DID attempt to notify this employee at this time with
    this exact text, which stays true regardless of whether the SMTP
    send itself actually succeeded."""
    if not payload.message.strip():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Message cannot be empty")

    device = (
        db.query(Device)
        .filter(Device.public_id == device_public_id, Device.company_id == admin.company_id)
        .first()
    )
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    if device.approval_status == "offboarded":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Cannot notify an offboarded employee")

    company = db.query(Company).filter(Company.company_id == admin.company_id).first()
    if not company.employee_notification_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="The Notify Employee feature is turned off for this company")

    metadata = db.query(DeviceMetadata).filter(DeviceMetadata.device_id == device.device_id).first()
    employee_email = metadata.email if metadata else None
    if not employee_email:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="This employee has no email on file -- add one via the edit-employee form first")

    send_status, error = send_employee_notification(
        db, company_id=admin.company_id, to_email=employee_email, message=payload.message,
    )

    db.add(EmployeeNotification(
        device_id=device.device_id,
        admin_id=admin.admin_id,
        message=payload.message,
        status=send_status,
        error=error,
    ))
    db.commit()

    return NotifyEmployeeResponse(status=send_status, error=error)
