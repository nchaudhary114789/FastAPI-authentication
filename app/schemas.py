from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator
import re
from typing import Optional, Literal

class UserCreate(BaseModel):
   username: str = Field(
       min_length=3,
       max_length=30
   )
   first_name: str = Field(
    min_length=1,
    max_length=50
   )
   last_name: str = Field(
      min_length=1,
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
   @field_validator("username", "first_name", "last_name")
   @classmethod
   def validate_names(cls, value: str) -> str:
    value = value.strip()

    if not re.fullmatch(r"[A-Za-z]+", value):
       raise ValueError(
          "Only English letters are allowed; "
          "numbers, spaces and symbols are not permitted."
       )
    return value
   
   @field_validator("password")
   @classmethod
   def validate_password_complexity(cls, value: str) -> str:
       if not re.search(r"[A-Z]", value):
           raise ValueError(
               "Password must contain at least one uppercase letter"
           )
       if not re.search(r"[a-z]", value):
           raise ValueError(
               "Password must contain at least one lowercase letter"
           )
       if not re.search(r"\d", value):
           raise ValueError(
               "Password must contain at least one digit"
           )
       if not re.search(r"[^A-Za-z0-9]", value):
           raise ValueError(
               "Password must contain at least one special character"
           )
       return value

class UserResponse(BaseModel):
   id: str
   username: str
   first_name: str
   last_name: str
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

class MessageResponse(BaseModel):
   message: str

class RegistrationResponse(BaseModel):
   id: str
   username: str
   first_name: str
   last_name: str
   email: EmailStr
   is_active: bool
   role: str
   message: str