import uuid
from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, Integer, String
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id            = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email         = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    is_verified   = Column(Boolean, default=False)
    mfa_enabled   = Column(Boolean, default=False)
    mfa_secret      = Column(String, nullable=True)
    failed_attempts = Column(Integer, default=0)
    locked_until    = Column(DateTime, nullable=True)
    created_at      = Column(DateTime, default=datetime.utcnow)


class EmailVerificationToken(Base):
    __tablename__ = "email_verification_tokens"

    id       = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id  = Column(String, nullable=False, index=True)
    token    = Column(String, nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class LoginHistory(Base):
    __tablename__ = "login_history"

    id         = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id    = Column(String, nullable=False, index=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    success    = Column(Boolean, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
