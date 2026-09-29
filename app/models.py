from sqlalchemy import Column, Integer, String, Boolean, DateTime
from .database import Base

class User(Base):
    __tablename__="users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(
        String,
        unique=True,
        index=True,
        nullable=False
    )
    hashed_password = Column(
        String,
        nullable=False
    )
    is_active = Column(
        Boolean,
        default=True
    )
    failed_login_attempts = Column(Integer, default = 0)
    locked_until = Column(DateTime(timezone = True), nullable = True)

class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    id = Column(Integer, primary_key = True, index = True)
    jti = Column(
        String,
        unique = True,
        index = True,
        nullable = False
    )
    expires_at = Column(
        Integer,
        nullable = False
    )