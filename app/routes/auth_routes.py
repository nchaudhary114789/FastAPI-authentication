from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pymongo.errors import DuplicateKeyError
from ..rate_limit import limiter
from urllib.parse import urlencode
from ..email_service import send_verification_email
from ..email_verification import create_verification_token, consume_verification_token
from ..auth import (
   settings,
   PUBLIC_KEY,
   hash_password,
   verify_password,
   create_access_token,
   create_refresh_token,
   DUMMY_PASSWORD_HASH
)
from ..audit import log_audit_event
from ..database import (
   users_collection,
   revoked_tokens_collection
)
from ..encryption import encrypt_data
from ..schemas import (
   UserCreate,
   UserResponse,
   LoginRequest,
   TokenResponse,
   MessageResponse
)
import jwt
from datetime import datetime, timedelta, timezone

security = HTTPBearer()
router = APIRouter(
   prefix="/auth",
   tags=["Authentication"]
)

@router.post(
   "/register",
   response_model=MessageResponse,
   status_code=status.HTTP_201_CREATED
)
@limiter.limit("5/minute")
def register(
   request: Request,
   user_data: UserCreate
):
   request_id = getattr(
       request.state,
       "request_id",
       None
   )
   existing_username = users_collection.find_one({
       "username": user_data.username
   })
   existing_email = users_collection.find_one({
       "email": str(user_data.email)
   })
   if existing_username or existing_email:
       log_audit_event(
           event="registration",
           outcome="failure",
           request_id=request_id,
           details={
               "reason": "duplicate_registration"
           }
       )
       return {
           "message": (
               "Registration request processed successfully. "
               "If eligible, a verification email will be sent."
           )
       }
   now = datetime.now(timezone.utc)
   new_user = {
       "username": user_data.username,
       "first_name": user_data.first_name,
       "last_name": user_data.last_name,
       "name": (
           f"{user_data.first_name} "
           f"{user_data.last_name}"
       ),
       "email": str(user_data.email),
       "hashed_password": hash_password(
           user_data.password
       ),
       "phone": (
           encrypt_data(user_data.phone)
           if user_data.phone
           else None
       ),
       "role": "user",
       "is_active": True,
       "is_verified": False,
       "failed_login_attempts": 0,
       "locked_until": None,
       "created_at": now,
       "updated_at": now,
       "last_login": None
   }
   try:
       result = users_collection.insert_one(new_user)
   except DuplicateKeyError:
       log_audit_event(
           event="registration",
           outcome="failure",
           request_id=request_id,
           details={
               "reason": "duplicate_registration"
           }
       )
       return {
           "message": (
               "Registration request processed successfully. "
               "If eligible, a verification email will be sent."
           )
       }
   user_id = str(result.inserted_id)
   try:
       verification_token = create_verification_token(
           str(user_data.email)
       )
       verification_url = (
           f"{settings.EMAIL_VERIFICATION_BASE_URL}"
           f"?{urlencode({'token': verification_token})}"
       )
       send_verification_email(
           recipient_email=str(user_data.email),
           verification_url=verification_url
       )
   except Exception:
       log_audit_event(
           event="registration",
           outcome="failure",
           request_id=request_id,
           user_id=user_id,
           details={
               "reason": "verification_email_delivery_failed"
           }
       )
       raise HTTPException(
           status_code=503,
           detail=(
               "Registration could not be completed. "
               "Please try again later."
           )
       )
   log_audit_event(
       event="registration",
       outcome="success",
       request_id=request_id,
       user_id=user_id,
       details={
           "role": "user"
       }
   )
   return {
       "message": (
           "Registration successful. "
           "Please check your email to verify your account."
       )
   }

def verify_login_password(user, password: str) -> bool:
   if user:
       return verify_password(
           password,
           user["hashed_password"]
       )
   verify_password(
       password,
       DUMMY_PASSWORD_HASH
   )
   return False

def record_failed_login(user, request_id: str | None) -> None:
   if user:
       now = datetime.now(timezone.utc)
       failed_attempts = (
           user.get("failed_login_attempts", 0) + 1
       )
       update_data = {
           "failed_login_attempts": failed_attempts
       }
       if failed_attempts >= 5:
           update_data["locked_until"] = (
               now + timedelta(minutes=15)
           )
       users_collection.update_one(
           {"_id": user["_id"]},
           {"$set": update_data}
       )
       if failed_attempts == 5:
           log_audit_event(
               event="account_lockout",
               outcome="success",
               request_id=request_id,
               user_id=str(user["_id"]),
               details={
                   "reason": "too_many_failed_attempts"
               }
           )
   log_audit_event(
       event="login",
       outcome="failure",
       request_id=request_id,
       user_id=str(user["_id"]) if user else None,
       details={
           "reason": "invalid_credentials"
       }
   )

def is_account_locked(user) -> bool:
   locked_until = user.get("locked_until")
   if locked_until is None:
       return False
   if locked_until.tzinfo is None:
       locked_until = locked_until.replace(
           tzinfo=timezone.utc
       )
   now = datetime.now(timezone.utc)
   if locked_until > now:
       return True
   users_collection.update_one(
       {"_id": user["_id"]},
       {
           "$set": {
               "locked_until": None,
               "failed_login_attempts": 0
           }
       }
   )
   return False

def audit_login_failure(
   request_id: str | None,
   user_id: str,
   reason: str
) -> None:
   log_audit_event(
       event="login",
       outcome="failure",
       request_id=request_id,
       user_id=user_id,
       details={
           "reason": reason
       }
   )

@router.post(
   "/login",
   response_model=TokenResponse
)
@limiter.limit("5/minute")
def login(
   request: Request,
   login_data: LoginRequest
):
   request_id = getattr(
       request.state,
       "request_id",
       None
   )
   user = users_collection.find_one({
       "email": login_data.email
   })
   password_valid = verify_login_password(
       user,
       login_data.password
   )
   if not user or not password_valid:
       record_failed_login(user, request_id)
       raise HTTPException(
           status_code=401,
           detail="Invalid email or password"
       )
   user_id = str(user["_id"])
   if is_account_locked(user):
       audit_login_failure(
           request_id,
           user_id,
           "account_temporarily_locked"
       )
       raise HTTPException(
           status_code=403,
           detail=(
               "Account is temporarily locked. "
               "Please try again later."
           )
       )
   if not user.get("is_active", True):
       audit_login_failure(
           request_id,
           user_id,
           "inactive_account"
       )
       raise HTTPException(
           status_code=403,
           detail="User account is inactive"
       )
   if not user.get("is_verified", False):
        audit_login_failure(
            request_id,
            user_id,
            "email_not_verified"
        )
        raise HTTPException(
            status_code=403,
            detail="Please verify your email before logging in."
        )
   now = datetime.now(timezone.utc)
   users_collection.update_one(
       {"_id": user["_id"]},
       {
           "$set": {
               "failed_login_attempts": 0,
               "locked_until": None,
               "last_login": now,
               "updated_at": now
           }
       }
   )
   access_token = create_access_token(user_id)
   refresh_token = create_refresh_token(user_id)
   log_audit_event(
       event="login",
       outcome="success",
       request_id=request_id,
       user_id=user_id,
       details={
           "authentication_method": "password"
       }
   )
   return {
       "access_token": access_token,
       "refresh_token": refresh_token,
       "token_type": "bearer"
   }
@router.post("/refresh")
def refresh_access_token(
   credentials: HTTPAuthorizationCredentials = Depends(security)
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
               detail="Token is invalid"
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
   revoked_token = revoked_tokens_collection.find_one({
       "jti": jti
   })
   if revoked_token:
       raise HTTPException(
           status_code=401,
           detail="Refresh token has been revoked"
       )
   from bson import ObjectId
   try:
       object_id = ObjectId(user_id)
   except Exception:
       raise HTTPException(
           status_code=401,
           detail="Invalid user ID"
       )
   user = users_collection.find_one({
       "_id": object_id
   })
   if not user:
       raise HTTPException(
           status_code=401,
           detail="User not found"
       )
   if not user.get("is_active", True):
       raise HTTPException(
           status_code=403,
           detail="User account is inactive"
       )
   access_token = create_access_token(
       str(user["_id"])
   )
   return {
       "access_token": access_token,
       "token_type": "bearer"
   }

@router.post("/logout")
def logout(
   credentials: HTTPAuthorizationCredentials = Depends(security)
):
   token = credentials.credentials
   try:
       payload = jwt.decode(
           token,
           PUBLIC_KEY,
           algorithms=[settings.ALGORITHM]
       )
       jti = payload.get("jti")
       exp = payload.get("exp")
       if not jti or not exp:
           raise HTTPException(
               status_code=401,
               detail="Invalid token"
           )
   except jwt.ExpiredSignatureError:
       raise HTTPException(
           status_code=401,
           detail="Token has already expired"
       )
   except jwt.InvalidTokenError:
       raise HTTPException(
           status_code=401,
           detail="Invalid token"
       )
   existing_token = revoked_tokens_collection.find_one({
       "jti": jti
   })
   if not existing_token:
       revoked_tokens_collection.insert_one({
           "jti": jti,
           "expires_at": datetime.fromtimestamp(
               exp,
               tz=timezone.utc
           )
       })
   return {
       "message": "Successfully logged out"
   }

@router.get("/verify-email")
def verify_email(token: str = Query(..., min_length=20)):
   email = consume_verification_token(token)
   if not email:
       raise HTTPException(
           status_code=400,
           detail="Verification link is invalid or has expired."
       )
   result = users_collection.update_one(
       {
           "email": email,
           "is_verified": False
       },
       {
           "$set": {
               "is_verified": True,
               "updated_at": datetime.now(timezone.utc)
           }
       }
   )
   if result.matched_count == 0:
       return {
           "message": "Email verification could not be completed. The account may already be verified."
       }
   return {
       "message": "Email verified successfully. You can now log in."
   }