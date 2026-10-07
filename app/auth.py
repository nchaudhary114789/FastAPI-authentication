from datetime import datetime, timedelta, timezone
from pathlib import Path
import jwt
import uuid
from pwdlib import PasswordHash
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    ALGORITHM: str = "RS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    MONGODB_URL: str
    MONGODB_DATABASE: str
    FERNET_KEY: str

    class Config:
        env_file = ".env"

settings = Settings()

BASE_DIR = Path(__file__).resolve().parent.parent

PRIVATE_KEY = (
    BASE_DIR / "private_key.pem"
).read_text()

PUBLIC_KEY = (
    BASE_DIR / "public_key.pem"
).read_text()

password_hash = PasswordHash.recommended()

DUMMY_PASSWORD_HASH = password_hash.hash(
    "dummy-password-for-timing-protection"
)

def hash_password(password: str) -> str:
    return password_hash.hash(password)

def verify_password(
        plain_password: str,
        hashed_password: str
) -> bool:
    return password_hash.verify(
        plain_password,
        hashed_password
    )

def create_access_token(user_id: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    jti = str(uuid.uuid4())
    
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "type":"access",
        "exp": expire
    }

    return jwt.encode(
        payload,
        PRIVATE_KEY,
        algorithm=settings.ALGORITHM
    )

def create_refresh_token(user_id: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    jti = str(uuid.uuid4())
    
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "type":"refresh",
        "exp": expire
    }

    return jwt.encode(
        payload,
        PRIVATE_KEY,
        algorithm=settings.ALGORITHM
    )