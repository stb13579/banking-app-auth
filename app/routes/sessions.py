from typing import List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.auth import decode_token
from app.database import get_db
from app.models import LoginHistory
from app.schemas import LoginHistoryResponse

router = APIRouter()
security = HTTPBearer()


@router.get("/sessions", response_model=List[LoginHistoryResponse])
def get_sessions(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """
    Return the last 20 login events for the authenticated user,
    ordered most-recent first. Includes IP address, user-agent, and
    whether the attempt succeeded — useful for anomaly detection.
    """
    try:
        payload = decode_token(credentials.credentials)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    records = (
        db.query(LoginHistory)
        .filter(LoginHistory.user_id == payload["sub"])
        .order_by(LoginHistory.created_at.desc())
        .limit(20)
        .all()
    )

    return records
