# NEW — admin-account management: linking an admin to their own monitored
# device, promoting an already-approved device into a new admin account,
# self-service profile/password. See models/admin.py's linked_device_id
# docstring for the schema, and docs/onboarding_flow.md line 15 for why
# this was the original intent (the first admin linking their own device),
# never previously implemented.

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.auth.dependencies import get_current_admin, require_owner
from backend.auth.security import hash_password, verify_password
from backend.database.db import get_db
from backend.models.admin import Admin
from backend.models.devices import Device

router = APIRouter(prefix="/admin", tags=["admin"])


class AdminOut(BaseModel):
    admin_id: int
    username: str
    role: str
    # public_id, not the internal Device.device_id -- same "never leak
    # internal PKs to a client" pattern every other admin-facing route
    # follows (routes/employees.py, routes/alerts.py).
    linked_device_id: str | None
    linked_device_label: str | None
    # NEW -- notifications/mailer.py. Always present in the response shape
    # (never omitted), but only meaningful for admin/manager -- an owner's
    # values here are always null/false and the frontend doesn't offer any
    # control to change them (see PATCH /admin/me/notifications, which
    # refuses an owner outright).
    email: str | None
    email_notifications_enabled: bool
    # NEW -- soft-removal (remove_admin below). GET /admin now returns
    # every admin the company has ever had, not just currently-active
    # ones, so the owner can see who's been removed rather than have them
    # silently vanish from the roster -- the frontend renders an inactive
    # row differently (greyed, "Removed" tag, no Remove button) instead of
    # omitting it.
    is_active: bool


def _to_admin_out(db: Session, a: Admin) -> AdminOut:
    device_public_id = None
    device_label = None
    if a.linked_device_id is not None:
        device = db.query(Device).filter(Device.device_id == a.linked_device_id).first()
        if device is not None:
            device_public_id = device.public_id
            device_label = device.label or device.hostname
    return AdminOut(
        admin_id=a.admin_id,
        username=a.username,
        role=a.role,
        linked_device_id=device_public_id,
        linked_device_label=device_label,
        email=a.email,
        email_notifications_enabled=a.email_notifications_enabled,
        is_active=a.is_active,
    )


def _validate_email(email: str | None) -> str:
    email = (email or "").strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="A valid email is required")
    return email


@router.get("", response_model=list[AdminOut])
def list_admins(admin: Admin = Depends(require_owner), db: Session = Depends(get_db)):
    """Owner-only -- backs the "Admin accounts" nav panel's roster and
    lets it know which devices are already linked, so the promote form can
    exclude them. Returns EVERY admin this company has ever had, active or
    removed (remove_admin below is a soft is_active=False, never a hard
    delete) -- a removed admin's own ReasoningDecision/AlertDecision rows
    stay fully attributed to their username regardless, and this list is
    where the owner would actually see who's been removed."""
    admins = (
        db.query(Admin)
        .filter(Admin.company_id == admin.company_id)
        .order_by(Admin.is_active.desc(), Admin.admin_id)
        .all()
    )
    return [_to_admin_out(db, a) for a in admins]


@router.get("/me", response_model=AdminOut)
def get_my_profile(admin: Admin = Depends(get_current_admin), db: Session = Depends(get_db)):
    """Every admin's own profile view -- also what the dashboard's nav
    drawer account section reads from now, replacing the earlier client-
    side-remembered-at-login username (a stopgap from before this endpoint
    existed)."""
    return _to_admin_out(db, admin)


class PromoteRequest(BaseModel):
    device_public_id: str
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=8)
    role: str = "admin"  # "admin" | "manager" -- the promoting owner picks in one step. NOT "owner" -- see promote_device_to_admin's docstring.
    # Mandatory -- see promote_device_to_admin's docstring for why this
    # moved from "addable later via self-service" to "required now."
    email: str = Field(min_length=1, max_length=255)


@router.post("/promote", response_model=AdminOut, status_code=status.HTTP_201_CREATED)
def promote_device_to_admin(
    payload: PromoteRequest,
    admin: Admin = Depends(require_owner),
    db: Session = Depends(get_db),
):
    """The normal path for every admin after the first one: their device is
    already onboarded and approved through the ordinary employee-enrollment
    flow, and the owner promotes it here, giving them a starting password.
    Only ever READS Device state (public_id/company_id/approval_status/
    device_id) to validate and look up the row -- never writes to
    approval_status, current_risk_score, or anything else on the device.
    The only row this ever writes to is the new Admin row; the promoted
    device keeps being monitored exactly as it was, through the exact same
    pipeline as every other employee's device -- see docs/
    known_limitations.md, promoting a device to admin access is an
    identity/login link only, never an exemption from monitoring.

    "owner" is deliberately NOT an accepted value here -- only ONE owner
    account ever exists, created once at POST /company/register. Letting
    this endpoint mint a second one would let any owner spawn another
    account with the exact account-management privilege this role exists
    to keep narrow, defeating the point.

    email is mandatory here (unlike the self-service PATCH /admin/me/
    notifications path, where it's still optional) -- this is now the
    ONLY point a new admin's email ever gets set for the first time, not
    an optional add-on left for them to remember later. Defaults
    email_notifications_enabled=True at creation (PATCH /admin/me/
    notifications still stays the normal opt-out path afterward, exactly
    as self-service as before): the owner is now actively typing a real
    email in as a required step, not leaving an empty field for someone
    to notice and fill in themselves -- if that requirement doesn't also
    turn notifications on by default, mandatory collection accomplishes
    nothing functionally, since the field would just sit unused until
    each admin separately remembers a toggle exists. New admins remain
    free to opt back out themselves at any time."""
    if payload.role not in ("admin", "manager"):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="role must be 'admin' or 'manager'")
    email = _validate_email(payload.email)

    device = (
        db.query(Device)
        .filter(Device.public_id == payload.device_public_id, Device.company_id == admin.company_id)
        .first()
    )
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    if device.approval_status != "approved":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Device must be approved through the normal onboarding flow before it can be promoted to an admin account",
        )

    already_linked = db.query(Admin).filter(Admin.linked_device_id == device.device_id).first()
    if already_linked is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This device is already linked to an admin account")

    if db.query(Admin).filter(Admin.company_id == admin.company_id, Admin.username == payload.username).first() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")

    new_admin = Admin(
        company_id=admin.company_id,
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role,
        linked_device_id=device.device_id,
        email=email,
        email_notifications_enabled=True,
    )
    db.add(new_admin)
    db.commit()
    db.refresh(new_admin)
    return _to_admin_out(db, new_admin)


class LinkDeviceRequest(BaseModel):
    device_public_id: str


@router.post("/link-device", response_model=AdminOut)
def link_my_device(
    payload: LinkDeviceRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Self-service, no owner gate -- this is how every regular admin/
    manager ends up linked to their own device, including one created via
    promote_device_to_admin (already linked at creation) and, historically,
    the very first admin before "owner" existed (POST /company/register
    creates that account before any device exists to link to). Same
    read-only-on-Device discipline as promote_device_to_admin above --
    only ever reads Device state to validate; the only write is
    admin.linked_device_id on the calling admin's own row.

    The owner account itself is explicitly refused here -- this is the one
    thing that would make it a daily-use identity, which is exactly what
    the owner/admin split exists to prevent (see require_owner's
    docstring). The real person who registered the company is expected to
    hold TWO separate accounts: the owner login for account management,
    and their own personal admin/manager account (created the normal way,
    via promote, linked to their own device) for daily use."""
    if admin.role == "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The owner account cannot be linked to a device — create a separate admin account for daily use instead",
        )
    if admin.linked_device_id is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Your account is already linked to a device")

    device = (
        db.query(Device)
        .filter(Device.public_id == payload.device_public_id, Device.company_id == admin.company_id)
        .first()
    )
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    if device.approval_status != "approved":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Device must be approved before it can be linked")

    already_linked = db.query(Admin).filter(Admin.linked_device_id == device.device_id).first()
    if already_linked is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This device is already linked to another admin account")

    admin.linked_device_id = device.device_id
    db.commit()
    db.refresh(admin)
    return _to_admin_out(db, admin)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


@router.patch("/me/password")
def change_my_password(
    payload: ChangePasswordRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Self-service password change -- every admin manages their own
    password going forward instead of relying on another admin to reset
    it. Requires the current password to be re-entered server-side (not
    just trusted from an already-authenticated session) before allowing
    the change."""
    if not verify_password(payload.current_password, admin.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")

    admin.password_hash = hash_password(payload.new_password)
    db.commit()
    return {"status": "ok"}


class NotificationSettingsRequest(BaseModel):
    email: str | None = Field(default=None, max_length=255)
    email_notifications_enabled: bool = False


@router.patch("/me/notifications", response_model=AdminOut)
def update_my_notification_settings(
    payload: NotificationSettingsRequest,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Self-service, like change_my_password above -- an admin sets their
    own notification email, nobody sets it for them. Refused outright for
    the owner role: notifications are a daily-use-account feature, and the
    owner account exists specifically to stay out of daily routine
    exposure (models/admin.py's email/email_notifications_enabled
    docstring) -- same hard-block precedent as link_my_device above, not
    just a default-off toggle.

    Basic application-layer validation only (non-empty, contains "@") --
    deliberately not pulling in a dedicated email-validation dependency
    for this, consistent with this project's existing minimalism (e.g.
    Admin.username's own uniqueness is enforced the same way, not via a
    library)."""
    if admin.role == "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The owner account does not receive notifications",
        )

    if payload.email_notifications_enabled:
        admin.email = _validate_email(payload.email)
    else:
        admin.email = (payload.email or "").strip() or None

    admin.email_notifications_enabled = payload.email_notifications_enabled
    db.commit()
    db.refresh(admin)
    return _to_admin_out(db, admin)


@router.post("/{admin_id}/remove", response_model=AdminOut)
def remove_admin(
    admin_id: int,
    admin: Admin = Depends(require_owner),
    db: Session = Depends(get_db),
):
    """Owner-only soft removal -- is_active=False, never a hard delete.
    Reuses the existing deactivation gate in auth/dependencies.py's
    get_current_admin (`if admin is None or not admin.is_active: raise
    credentials_error`) for the actual login block; nothing new to
    enforce here beyond flipping the flag.

    Deliberately does NOT touch ReasoningDecision/AlertDecision rows --
    both are plain admin_id FKs, not scoped to active admins, and
    Admin.username stays readable off a deactivated row for display. The
    audit trail this whole feature exists for must never lose an entry
    just because the person who made the decision is no longer an active
    admin.

    Also clears linked_device_id: a device staying "linked" to an admin
    who can no longer log in isn't a meaningful state, and leaving it set
    would permanently block that device from ever being promoted to a
    different person later (promote_device_to_admin's own already-linked
    check would keep rejecting it). The device itself keeps being
    monitored exactly as before -- this only clears the identity link,
    same "never touches Device state" discipline as promote/link-device."""
    target = db.query(Admin).filter(Admin.admin_id == admin_id, Admin.company_id == admin.company_id).first()
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin not found")

    if target.admin_id == admin.admin_id:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The owner cannot remove themselves")

    if not target.is_active:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This admin is already removed")

    target.is_active = False
    target.linked_device_id = None
    db.commit()
    db.refresh(target)
    return _to_admin_out(db, target)
