# NEW — password hashing + session/JWT token creation for Admin login

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from backend.core.config import ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, SECRET_KEY


def hash_password(password: str) -> str:
    # bcrypt generates and embeds its own per-hash salt, so there's no
    # separate salt column on Admin — the salt travels inside this string.
    from fastapi import HTTPException
    if not 8 <= len(password.encode("utf-8")) <= 72:
        raise HTTPException(status_code=422, detail="Password must be 8-72 UTF-8 bytes")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not 8 <= len(plain_password.encode("utf-8")) <= 72:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(admin_id: int) -> str:
    # Only the admin's id goes in the payload. Role, company_id, and
    # is_active are read fresh from the database on every request (see
    # dependencies.py) rather than trusted from the token, so revoking an
    # admin or changing their role takes effect immediately instead of
    # waiting for the token to expire.
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(admin_id), "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    # Lets jwt.PyJWTError (expired / bad signature / malformed) propagate —
    # the caller decides how that becomes an HTTP response, not this module.
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"require": ["exp", "sub"]})
