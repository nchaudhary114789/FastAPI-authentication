from fastapi import APIRouter, Depends, HTTPException, Request
from ..rate_limit import limiter
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from bson import ObjectId
from ..database import (
   users_collection,
   revoked_tokens_collection
)
from ..schemas import UserResponse
from ..auth import PUBLIC_KEY, settings

router = APIRouter(
   prefix="/users",
   tags=["Users"]
)
security = HTTPBearer()

def get_current_user(
   credentials: HTTPAuthorizationCredentials = Depends(security)
):
   token = credentials.credentials
   # ------------------------------------------
   # 1. Decode and validate JWT
   # ------------------------------------------
   try:
       payload = jwt.decode(
           token,
           PUBLIC_KEY,
           algorithms=[settings.ALGORITHM]
       )
       user_id = payload.get("sub")
       jti = payload.get("jti")
       token_type = payload.get("type")
       if user_id is None or jti is None:
           raise HTTPException(
               status_code=401,
               detail="Invalid token"
           )
       # Only access tokens can access /users/me
       if token_type != "access":
           raise HTTPException(
               status_code=401,
               detail="Invalid access token"
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
   # ------------------------------------------
   # 2. Check token revocation
   # ------------------------------------------
   revoked_token = revoked_tokens_collection.find_one({
       "jti": jti
   })
   if revoked_token:
       raise HTTPException(
           status_code=401,
           detail="Token has been revoked"
       )
   # ------------------------------------------
   # 3. Convert JWT user ID to MongoDB ObjectId
   # ------------------------------------------
   try:
       object_id = ObjectId(user_id)
   except Exception:
       raise HTTPException(
           status_code=401,
           detail="Invalid user ID"
       )
   # ------------------------------------------
   # 4. Find user in MongoDB
   # ------------------------------------------
   user = users_collection.find_one({
       "_id": object_id
   })
   if not user:
       raise HTTPException(
           status_code=401,
           detail="User not found"
       )
   # ------------------------------------------
   # 5. Check whether account is active
   # ------------------------------------------
   if not user.get("is_active", True):
       raise HTTPException(
           status_code=403,
           detail="User account is inactive"
       )
   return user

@router.get(
   "/me",
   response_model=UserResponse
)
@limiter.limit("30/minute")
def get_me(
   request: Request,
   current_user = Depends(get_current_user)
):
   return {
       "id": str(current_user["_id"]),
       "name": current_user["name"],
       "email": current_user["email"],
       "is_active": current_user["is_active"],
       "role": current_user["role"]
   }