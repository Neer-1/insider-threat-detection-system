# NEW — get_current_admin() dependency, admin/superadmin role check, used to scope every route to one company

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from backend.auth.security import decode_access_token
from backend.database.db import get_db
from backend.models.admin import Admin
from backend.models.company import Company

# tokenUrl is only used to populate FastAPI's auto-generated docs with a
# login form — the actual route is wired up in routes/auth.py.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Admin:
    """Resolves the logged-in admin from the bearer token. Every
    company-scoped route should depend on this and read company_id off the
    returned Admin, rather than accepting company_id as a request
    parameter — a client-supplied company_id would let one company's admin
    reach another's data just by changing a value in the request."""

    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        raise credentials_error

    admin_id = payload.get("sub")
    try:
        if isinstance(admin_id, bool):
            raise ValueError('Invalid subject')
        admin_id = int(admin_id)
        if admin_id <= 0:
            raise ValueError('Invalid subject')
    except (TypeError, ValueError, OverflowError):
        raise credentials_error

    admin = db.query(Admin).filter(Admin.admin_id == admin_id).first()
    if admin is None or not admin.is_active:
        raise credentials_error

    company = db.query(Company).filter(Company.company_id == admin.company_id).first()
    if company is None or not company.is_active:
        raise credentials_error

    return admin


def require_owner(admin: Admin = Depends(get_current_admin)) -> Admin:
    """Gate for admin-management actions (creating/promoting other admins).
    Every regular "admin"/"manager" account can use the dashboard fully
    (reviewing alerts, dismiss/undo, generating reports, etc.) but cannot
    create or promote other admin accounts -- only the single "owner"
    account created at POST /company/register can. This used to be gated
    on "manager" (the account created at registration got that role
    directly), which meant the master account was both the one that can
    mint new admins AND a normal daily-use login with nothing stopping it
    -- every login was an unnecessary chance to compromise the whole
    company's access control, not just one person's data. "owner" is a
    narrower, separate role specifically so that account can be kept for
    account-management only (see routes/admin.py's link_my_device, which
    refuses to let an owner link a device at all -- the thing that would
    make it a daily-use identity)."""
    if admin.role != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Owner role required",
        )
    return admin
