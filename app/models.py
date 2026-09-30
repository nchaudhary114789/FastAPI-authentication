from datetime import datetime
from typing import Optional

class User:
   def __init__(
       self,
       name: str,
       email: str,
       hashed_password: str,
       phone: Optional[str] = None,
       role: str = "user",
       is_active: bool = True,
       failed_login_attempts: int = 0,
       locked_until: Optional[datetime] = None
   ):
       self.name = name
       self.email = email
       self.hashed_password = hashed_password
       self.phone = phone
       self.role = role
       self.is_active = is_active
       self.failed_login_attempts = failed_login_attempts
       self.locked_until = locked_until