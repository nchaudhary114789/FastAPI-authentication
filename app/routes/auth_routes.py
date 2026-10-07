from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from ..rate_limit import limiter
from ..auth import (
   settings,
   PUBLIC_KEY,
   hash_password,
   verify_password,
   create_access_token,
   create_refresh_token,
   DUMMY_PASSWORD_HASH
)
from ..database import (
   users_collection,
   revoked_tokens_collection
)
from ..encryption import encrypt_data
from ..schemas import (
   UserCreate,
   UserResponse,
   LoginRequest,
   TokenResponse
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
   response_model=UserResponse,
   status_code=status.HTTP_201_CREATED
)
@limiter.limit("5/minute")
def register(
   request: Request,
   user_data: UserCreate
):
   existing_user = users_collection.find_one({
       "email": user_data.email
   })
   if existing_user:
       raise HTTPException(
           status_code=400,
           detail="Email already registered"
       )
   new_user = {
       "name": user_data.name,
       "email": user_data.email,
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
       "failed_login_attempts": 0,
       "locked_until": None
   }
   result = users_collection.insert_one(new_user)
   new_user["id"] = str(result.inserted_id)
   return {
       "id": new_user["id"],
       "name": new_user["name"],
       "email": new_user["email"],
       "is_active": new_user["is_active"],
       "role": new_user["role"]
   }

@router.post(
   "/login",
   response_model=TokenResponse
)
@limiter.limit("5/minute")
def login(
   request: Request,
   login_data: LoginRequest
):
   user = users_collection.find_one({
       "email": login_data.email
   })
   if user:
       password_valid = verify_password(
           login_data.password,
           user["hashed_password"]
       )
   else:
       password_valid = verify_password(
           login_data.password,
           DUMMY_PASSWORD_HASH
       )
   if not user:
       raise HTTPException(
           status_code=401,
           detail="Invalid email or password"
       )
   now = datetime.now(timezone.utc)
   locked_until = user.get("locked_until")
   if locked_until is not None:
       if locked_until.tzinfo is None:
           locked_until = locked_until.replace(
               tzinfo=timezone.utc
           )
       if locked_until > now:
           raise HTTPException(
               status_code=403,
               detail="Account is temporarily locked. Please try again later."
           )
       users_collection.update_one(
           {"_id": user["_id"]},
           {
               "$set": {
                   "locked_until": None,
                   "failed_login_attempts": 0
               }
           }
       )
       user["locked_until"] = None
       user["failed_login_attempts"] = 0
   if not user.get("is_active", True):
       raise HTTPException(
           status_code=403,
           detail="User account is inactive"
       )
   if not password_valid:
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
           {
               "$set": update_data
           }
       )
       raise HTTPException(
           status_code=401,
           detail="Invalid email or password"
       )
   users_collection.update_one(
       {"_id": user["_id"]},
       {
           "$set": {
               "failed_login_attempts": 0,
               "locked_until": None
           }
       }
   )
   user_id = str(user["_id"])
   access_token = create_access_token(user_id)
   refresh_token = create_refresh_token(user_id)
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