from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    is_verified: bool
    mfa_enabled: bool
    created_at: datetime

    class Config:
        orm_mode = True


class LoginRequest(BaseModel):
    email: str
    password: str
    mfa_code: Optional[str] = None  # required when user has MFA enabled


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class VerifyEmailRequest(BaseModel):
    token: str


class MfaEnableResponse(BaseModel):
    secret: str
    qr_uri: str


class MfaVerifyRequest(BaseModel):
    code: str


class LoginHistoryResponse(BaseModel):
    id: str
    user_id: str
    ip_address: Optional[str]
    user_agent: Optional[str]
    success: bool
    created_at: datetime

    class Config:
        orm_mode = True
