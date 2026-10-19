import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from .auth import settings
from .database import email_verification_tokens_collection

def hash_verification_token(token: str) -> str:
   return hashlib.sha256(token.encode("utf-8")).hexdigest()

def create_verification_token(email: str) -> str:
   token = secrets.token_urlsafe(32)
   now = datetime.now(timezone.utc)
   expires_at = now + timedelta(
       minutes=settings.EMAIL_VERIFICATION_EXPIRE_MINUTES
   )
   email_verification_tokens_collection.insert_one({
       "_id": hash_verification_token(token),
       "email": email,
       "created_at": now,
       "expires_at": expires_at
   })
   return token

def consume_verification_token(token: str) -> str | None:
   token_hash = hash_verification_token(token)
   now = datetime.now(timezone.utc)
   record = email_verification_tokens_collection.find_one_and_delete({
       "_id": token_hash,
       "expires_at": {"$gt": now}
   })
   if not record:
       return None
   return record["email"]