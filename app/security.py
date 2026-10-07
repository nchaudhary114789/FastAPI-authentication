from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from bson import ObjectId
import jwt

from .auth import PUBLIC_KEY, settings
from .database import users_collection, revoked_tokens_collection

security = HTTPBearer()

def get_current_user(
   credentials: HTTPAuthorizationCredentials = Depends(security)
):
   token = credentials.credentials
   try:
       payload = jwt.decode(
           token,
           PUBLIC_KEY,
           algorithms=[settings.ALGORITHM],
           issuer = settings.JWT_ISSUER,
           audience = settings.JWT_AUDIENCE
       )
       user_id = payload.get("sub")
       jti = payload.get("jti")
       token_type = payload.get("type")
       if user_id is None or jti is None:
           raise HTTPException(
               status_code=401,
               detail="Invalid token"
           )
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
   revoked_token = revoked_tokens_collection.find_one({
       "jti": jti
   })
   if revoked_token:
       raise HTTPException(
           status_code=401,
           detail="Token has been revoked"
       )
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
   return user