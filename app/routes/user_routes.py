from fastapi import APIRouter, Depends, HTTPException, Request, status
from ..rate_limit import limiter
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from bson import ObjectId
from ..database import (
   users_collection,
   revoked_tokens_collection
)
from ..encryption import encrypt_data
from ..roles import Role
from ..security import get_current_user
from ..schemas import UserResponse, AdminUserUpdate, UserCreate, RoleUpdate, SupervisorUserUpdate
from ..auth import PUBLIC_KEY, settings, hash_password
from ..dependencies import (
    admin_required,
    supervisor_required,
    agent_required,
    user_required
)

router = APIRouter(
   prefix="/users",
   tags=["Users"]
)
security = HTTPBearer()

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

@router.get("/admin")
@limiter.limit("30/minute")
def admin_endpoint(
    request: Request,
    current_user = Depends(admin_required)
):
    return {
        "message": "Admin endpoint",
        "email": current_user["email"],
        "role": current_user["role"]
    }

@router.get("/supervisor")
@limiter.limit("30/minute")
def supervisor_endpoint(
    request: Request,
    current_user = Depends(supervisor_required)
):
    return {
        "message": "Supervisor endpoint",
        "email": current_user["email"],
        "role": current_user["role"]
    }

@router.get("/agent")
@limiter.limit("30/minute")
def agent_endpoint(
    request: Request,
    current_user = Depends(agent_required)
):
    return {
        "message": "Agent endpoint",
        "email": current_user["email"],
        "role": current_user["role"]
    }

@router.get("/user")
@limiter.limit("30/minute")
def user_endpoint(
    request: Request,
    current_user = Depends(user_required)
):
    return {
        "message": "User endpoint",
        "email": current_user["email"],
        "role": current_user["role"]
    }

@router.post(
   "/admin/users",
   status_code=status.HTTP_201_CREATED
)
@limiter.limit("30/minute")
def admin_add_user(
   request: Request,
   user_data: UserCreate,
   current_user=Depends(admin_required)
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
       "role": Role.USER.value,
       "is_active": True,
       "failed_login_attempts": 0,
       "locked_until": None
   }
   result = users_collection.insert_one(new_user)
   return {
       "message": "User created successfully",
       "user_id": str(result.inserted_id),
       "email": new_user["email"],
       "role": new_user["role"]
   }

@router.patch("/admin/users/{user_id}")
@limiter.limit("30/minute")
def admin_update_user(
   user_id: str,
   request: Request,
   user_data: AdminUserUpdate,
   current_user=Depends(admin_required)
):
   if not ObjectId.is_valid(user_id):
       raise HTTPException(
           status_code=400,
           detail="Invalid User ID"
       )
   update_data = {}
   if user_data.name is not None:
       update_data["name"] = user_data.name
   if user_data.phone is not None:
       update_data["phone"] = encrypt_data(
           user_data.phone
       )
   if user_data.is_active is not None:
       update_data["is_active"] = user_data.is_active
   if not update_data:
       raise HTTPException(
           status_code=400,
           detail="No fields to update"
       )
   result = users_collection.update_one(
       {"_id": ObjectId(user_id)},
       {"$set": update_data}
   )
   if result.matched_count == 0:
       raise HTTPException(
           status_code=404,
           detail="User not Found"
       )
   return {
       "message": "User updated successfully"
   }

@router.delete("/admin/users/{user_id}")
@limiter.limit("30/minute")
def admin_delete_user(
   user_id: str,
   request: Request,
   current_user=Depends(admin_required)
):
   if not ObjectId.is_valid(user_id):
       raise HTTPException(
           status_code=400,
           detail="Invalid user ID"
       )
   if str(current_user["_id"]) == user_id:
       raise HTTPException(
           status_code=400,
           detail="Admin cannot delete their own account"
       )
   result = users_collection.delete_one({
       "_id": ObjectId(user_id)
   })
   if result.deleted_count == 0:
       raise HTTPException(
           status_code=404,
           detail="User not found"
       )
   return {
       "message": "User deleted successfully"
   }

@router.patch("/admin/users/{user_id}/role")
@limiter.limit("30/minute")
def admin_update_role(
   user_id: str,
   request: Request,
   role_data: RoleUpdate,
   current_user=Depends(admin_required)
):
   if not ObjectId.is_valid(user_id):
       raise HTTPException(
           status_code=400,
           detail="Invalid user ID"
       )
   # Prevent admin from changing their own role
   if str(current_user["_id"]) == user_id:
       raise HTTPException(
           status_code=400,
           detail="Admin cannot change their own role"
       )
   target_user = users_collection.find_one({
       "_id": ObjectId(user_id)
   })
   if not target_user:
       raise HTTPException(
           status_code=404,
           detail="User not found"
       )
   users_collection.update_one(
       {"_id": ObjectId(user_id)},
       {
           "$set": {
               "role": role_data.role
           }
       }
   )
   return {
       "message": "User role updated successfully",
       "user_id": user_id,
       "new_role": role_data.role
   }

@router.get("/supervisor/users")
@limiter.limit("30/minute")
def supervisor_view_users(
    request: Request,
    current_user=Depends(supervisor_required)
):
    users = list(
        users_collection.find(
            {"role": "user"},
            {
                "_id": 1,
                "name": 1,
                "email": 1,
                "role": 1,
                "is_active": 1
            }
        )
    )
    for user in users:
        user["id"] = str(user.pop("_id"))
    return users

@router.get("/supervisor/agents")
@limiter.limit("30/minute")
def supervisor_view_agents(
   request: Request,
   current_user=Depends(supervisor_required)
):
   agents = list(
       users_collection.find(
           {"role": "agent"},
           {
               "_id": 1,
               "name": 1,
               "email": 1,
               "role": 1,
               "is_active": 1
           }
       )
   )
   for agent in agents:
       agent["id"] = str(agent.pop("_id"))
   return agents


@router.patch("/supervisor/users/{user_id}")
@limiter.limit("30/minute")
def supervisor_edit_user(
   user_id: str,
   request: Request,
   user_data: SupervisorUserUpdate,
   current_user=Depends(supervisor_required)
):
   if not ObjectId.is_valid(user_id):
       raise HTTPException(
           status_code=400,
           detail="Invalid user ID"
       )
   target_user = users_collection.find_one({
       "_id": ObjectId(user_id)
   })
   if not target_user:
       raise HTTPException(
           status_code=404,
           detail="User not found"
       )
   # Supervisor cannot modify admin or another supervisor
   if target_user.get("role") in ["admin", "supervisor"]:
       raise HTTPException(
           status_code=403,
           detail="Supervisor cannot modify this user"
       )
   update_data = user_data.model_dump(exclude_unset=True)
   if not update_data:
       raise HTTPException(
           status_code=400,
           detail="No fields provided for update"
       )
   users_collection.update_one(
       {"_id": ObjectId(user_id)},
       {"$set": update_data}
   )
   return {
       "message": "User updated successfully",
       "user_id": user_id
   }

@router.get("/agent/users")
@limiter.limit("30/minute")
def agent_view_users(
   request: Request,
   current_user=Depends(agent_required)
):
   users = list(
       users_collection.find(
           {"role": "user"},
           {
               "_id": 1,
               "name": 1,
               "email": 1,
               "role": 1,
               "is_active": 1
           }
       )
   )
   for user in users:
       user["id"] = str(user.pop("_id"))
   return users