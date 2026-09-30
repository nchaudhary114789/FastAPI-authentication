from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from ..rate_limit import limiter
from sqlalchemy.orm import Session
from ..auth import settings, PUBLIC_KEY
from ..database import get_db
from ..models import User, RevokedToken
from ..schemas import (
    UserCreate,
    UserResponse,
    LoginRequest,
    TokenResponse
)
import jwt
from ..auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token
)
from datetime import datetime, timedelta, timezone

security = HTTPBearer()

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED
)
@limiter.limit("5/minute")
def register(
    request: Request,
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    existing_user = (
        db.query(User)
        .filter(User.email == user_data.email)
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    new_user = User(
        name=user_data.name,
        email=user_data.email,
        hashed_password=hash_password(
            user_data.password
        )
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user

@router.post(
    "/login",
    response_model=TokenResponse
)
@limiter.limit("5/minute")
def login(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    user = (
        db.query(User)
        .filter(User.email == login_data.email)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )
    now = datetime.now(timezone.utc)
    if user.locked_until is not None:
        if user.locked_until > now:
            raise HTTPException(
                status_code = 403,
                detail = "Account is temporarily locked. Please try again later."
            )
        user.locked_until = None
        user.failed_login_attempts = 0
        db.commit()
    if not user.is_active:
        raise HTTPException(
            status_code = 403,
            detail = "User account is inactive"
        )

    if not verify_password(
        login_data.password,
        user.hashed_password
    ):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.locked_until = (
                now + timedelta(minutes = 15)
            )
            db.commit()

        raise HTTPException(
            status_code = 401,
            detail="Invalid email or password"
        )
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@router.post("/refresh")
def refresh_access_token(
   credentials: HTTPAuthorizationCredentials = Depends(security),
   db: Session = Depends(get_db)
):
   token = credentials.credentials
   try:
       payload = jwt.decode(
           token,
           PUBLIC_KEY,
           algorithms=[settings.ALGORITHM]
       )
       
       if payload.get("type") != "refresh":
           raise HTTPException(
               status_code=401,
               detail="Invalid token"
           )
       jti = payload.get("jti")
       user_id = payload.get("sub")
       if not jti or not user_id:
           raise HTTPException(
               status_code=401,
               detail="Invalid refresh token"
           )
   except jwt.ExpiredSignatureError:
       raise HTTPException(
           status_code=401,
           detail="Refresh token has expired"
       )
   except jwt.InvalidTokenError:
       raise HTTPException(
           status_code=401,
           detail="Invalid refresh token"
       )
   
   revoked_token = (
       db.query(RevokedToken)
       .filter(RevokedToken.jti == jti)
       .first()
   )
   if revoked_token:
       raise HTTPException(
           status_code=401,
           detail="Refresh token has been revoked"
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
   
   if not user.is_active:
       raise HTTPException(
           status_code=403,
           detail="User account is inactive"
       )
   
   access_token = create_access_token(user.id)
   return {
       "access_token": access_token,
       "token_type": "bearer"
   }

@router.post("/logout")
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials

    try:
        payload =jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=[settings.ALGORITHM]
        )
        jti = payload.get("jti")
        exp = payload.get("exp")

        if not jti or not exp:
            raise HTTPException(
                status_code = 401,
                detail = "Invalid Token"
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code = 401,
            detail = "Token has already expired"
        )
    except jwt.InvalidTokenError:
            raise HTTPException(
                status_code = 401,
                detail = "Invalid Token"
            )
    existing_token = (
        db.query(RevokedToken)
        .filter(RevokedToken.jti == jti)
        .first()
    )
    if not existing_token:
        revoked_token = RevokedToken(
            jti = jti,
            expires_at = exp
        )
        db.add(revoked_token)
        db.commit()

    return {
        "message": "Successfully logged out"
    }