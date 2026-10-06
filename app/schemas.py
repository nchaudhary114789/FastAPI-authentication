from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, Literal

class UserCreate(BaseModel):
   name: str = Field(
       min_length=2,
       max_length=50
   )
   email: EmailStr
   password: str = Field(
       min_length=8,
       max_length=100
   )
   phone: Optional[str] = Field(
       default=None,
       min_length=10,
       max_length=15
   )

class UserResponse(BaseModel):
   id: str
   name: str
   email: EmailStr
   is_active: bool
   role: str
   model_config = ConfigDict(
       from_attributes=True
   )

class LoginRequest(BaseModel):
   email: EmailStr
   password: str

class TokenResponse(BaseModel):
   access_token: str
   refresh_token: str
   token_type: str

class AdminUserUpdate(BaseModel):
   name: str | None = Field(
      default = None,
      min_length = 2,
      max_length = 50
   )
   phone: str | None = None
   is_active: bool | None = None

class RoleUpdate(BaseModel):
   role: Literal["admin", "supervisor", "agent", "user"]

class SupervisorUserUpdate(BaseModel):
   name: str | None = None
   email: EmailStr | None = None
   is_active: bool | None = None