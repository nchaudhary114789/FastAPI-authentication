from fastapi import Depends, HTTPException, status
from .roles import Role
from .security import get_current_user

def require_roles(*allowed_roles: Role):
    def role_checker(
            current_user = Depends(get_current_user)
    ):
        user_role = current_user.get("role")
        allowed_role_values = {
            Role.value for Role in allowed_roles
        }
        if user_role not in allowed_role_values:
            raise HTTPException(
                status_code = status.HTTP_403_FORBIDDEN,
                detail = "Insufficient permissions"
            )
        return current_user
    return role_checker
admin_required = require_roles(Role.ADMIN)
supervisor_required = require_roles(Role.SUPERVISOR)
agent_required = require_roles(Role.AGENT)
user_required = require_roles(Role.USER)