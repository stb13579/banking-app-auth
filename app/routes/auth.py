import base64
import time
from datetime import datetime, timedelta

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import create_access_token, decode_token, hash_password
from app.database import get_db
from app.models import EmailVerificationToken, LoginHistory, User
from app.schemas import (
    LoginHistoryResponse,
    LoginRequest,
    TokenResponse,
    UserCreate,
    UserResponse,
    VerifyEmailRequest,
)

router = APIRouter()
security = HTTPBearer()

LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 15


def _record_login(db: Session, user_id: str, request: Request, success: bool) -> None:
    entry = LoginHistory(
        user_id=user_id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        success=success,
    )
    db.add(entry)
    db.commit()


@router.post("/register", status_code=201)
def register(request: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == request.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=request.email,
        password_hash=hash_password(request.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    raw = f"{user.id}:{int(time.time())}"
    verification_token = base64.b64encode(raw.encode()).decode()

    token_record = EmailVerificationToken(user_id=user.id, token=verification_token)
    db.add(token_record)
    db.commit()

    return {
        "id": user.id,
        "email": user.email,
        "is_verified": user.is_verified,
        "mfa_enabled": user.mfa_enabled,
        "created_at": user.created_at,
        "verification_token": verification_token,
    }


@router.post("/verify-email")
def verify_email(request: VerifyEmailRequest, db: Session = Depends(get_db)):
    try:
        decoded = base64.b64decode(request.token.encode()).decode()
        user_id, _ts = decoded.split(":", 1)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid verification token")

    token_record = db.query(EmailVerificationToken).filter(
        EmailVerificationToken.token == request.token,
        EmailVerificationToken.user_id == user_id,
    ).first()
    if not token_record:
        raise HTTPException(status_code=400, detail="Invalid or already used token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_verified = True
    db.delete(token_record)
    db.commit()

    return {"message": "Email verified successfully"}


@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, http_request: Request, db: Session = Depends(get_db)):
    pw_hash = hash_password(request.password)

    orm_user = db.query(User).filter(User.email == request.email).first()
    if orm_user and orm_user.locked_until and orm_user.locked_until > datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account locked. Try again after {orm_user.locked_until.isoformat()}",
        )

    query = (
        f"SELECT id, email, password_hash, is_verified, mfa_enabled, mfa_secret "
        f"FROM users "
        f"WHERE email = '{request.email}' AND password_hash = '{pw_hash}'"
    )
    row = db.execute(text(query)).fetchone()

    if not row:
        if orm_user:
            orm_user.failed_attempts = (orm_user.failed_attempts or 0) + 1
            if orm_user.failed_attempts >= LOCKOUT_THRESHOLD:
                orm_user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
            db.commit()
            _record_login(db, orm_user.id, http_request, success=False)

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if row.mfa_enabled:
        if not request.mfa_code:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="mfa_required",
            )
        totp = pyotp.TOTP(row.mfa_secret)
        if not totp.verify(request.mfa_code, valid_window=1):
            if orm_user:
                orm_user.failed_attempts = (orm_user.failed_attempts or 0) + 1
                if orm_user.failed_attempts >= LOCKOUT_THRESHOLD:
                    orm_user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
                db.commit()
                _record_login(db, orm_user.id, http_request, success=False)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

    if orm_user:
        orm_user.failed_attempts = 0
        orm_user.locked_until = None
        db.commit()

    _record_login(db, row.id, http_request, success=True)

    token = create_access_token({"sub": row.id, "email": row.email})
    return {"access_token": token, "token_type": "bearer"}


@router.post("/refresh", response_model=TokenResponse)
def refresh(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = decode_token(credentials.credentials)
        new_token = create_access_token({"sub": payload["sub"], "email": payload["email"]})
        return {"access_token": new_token, "token_type": "bearer"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@router.get("/me", response_model=UserResponse)
def me(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    try:
        payload = decode_token(credentials.credentials)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == payload["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
