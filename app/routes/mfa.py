import pyotp
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.auth import decode_token
from app.database import get_db
from app.models import User
from app.schemas import MfaEnableResponse, MfaVerifyRequest

router = APIRouter()
security = HTTPBearer()


def _get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = decode_token(credentials.credentials)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == payload["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.post("/enable", response_model=MfaEnableResponse)
def enable_mfa(
    user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    secret = pyotp.random_base32()

    db_user = db.query(User).filter(User.id == user.id).first()
    db_user.mfa_secret = secret
    db.commit()

    qr_uri = pyotp.TOTP(secret).provisioning_uri(
        name=db_user.email,
        issuer_name="BankingApp",
    )

    return {"secret": secret, "qr_uri": qr_uri}


@router.post("/verify")
def verify_mfa(
    request: MfaVerifyRequest,
    user: User = Depends(_get_current_user),
    db: Session = Depends(get_db),
):
    db_user = db.query(User).filter(User.id == user.id).first()

    if not db_user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA setup not initiated. Call POST /mfa/enable first.")

    totp = pyotp.TOTP(db_user.mfa_secret)
    if not totp.verify(request.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid or expired MFA code")

    db_user.mfa_enabled = True
    db.commit()

    return {"message": "MFA enabled successfully"}
