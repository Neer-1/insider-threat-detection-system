# NEW — POST /admin/login

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.auth.security import create_access_token, verify_password
from backend.database.db import get_db
from backend.models.admin import Admin
from backend.models.company import Company

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    admin = db.query(Admin).filter(Admin.username == payload.username).first()

    # Same error for "no such user" and "wrong password" — a distinct
    # message for each would let someone enumerate valid usernames.
    invalid_credentials = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password"
    )

    if admin is None or not admin.is_active:
        raise invalid_credentials
    company = db.query(Company).filter(Company.company_id == admin.company_id).first()
    if company is None or not company.is_active:
        raise invalid_credentials
    if not verify_password(payload.password, admin.password_hash):
        raise invalid_credentials

    token = create_access_token(admin.admin_id)
    return LoginResponse(access_token=token, role=admin.role)
