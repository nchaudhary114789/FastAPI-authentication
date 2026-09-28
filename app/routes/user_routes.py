from fastapi import APIRouter, Depends, HTTPException, Request
from ..rate_limit import limiter
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

import jwt

from ..database import get_db
from ..models import User, RevokedToken
from ..schemas import UserResponse
from ..auth import settings

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)
security = HTTPBearer()

def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(security),
        db: Session = Depends(get_db)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        user_id = payload.get("sub")
        jti = payload.get("jti")

        if user_id is None or jti is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token has expired"
        )    
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )
    revoked_token = (
        db.query(RevokedToken)
        .filter(RevokedToken.jti == jti)
        .first()
    )
    if revoked_token:
        raise HTTPException(
            status_code = 401,
            detail = "Token has been revoked"
        )
    user = (
        db.query(User)
        .filter(User.id == int(user_id))
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )
    return user

@router.get(
    "/me",
    response_model=UserResponse
)
@limiter.limit("30/minute")
def get_me(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    return current_user