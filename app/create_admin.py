from getpass import getpass
from pymongo.errors import DuplicateKeyError
from .database import users_collection
from .auth import hash_password

def create_admin():
   print("=== Create Admin User ===")
   name = input("Name: ").strip()
   email = input("Email: ").strip().lower()
   password = getpass("Password: ")
   confirm_password = getpass("Confirm password: ")
   if password != confirm_password:
       print("Passwords do not match.")
       return
   existing_user = users_collection.find_one({
       "email": email
   })
   if existing_user:
       print("A user with this email already exists.")
       return
   admin_user = {
       "name": name,
       "email": email,
       "hashed_password": hash_password(password),
       "phone": None,
       "role": "admin",
       "is_active": True,
       "failed_login_attempts": 0,
       "locked_until": None
   }
   try:
       result = users_collection.insert_one(admin_user)
       print("Admin created successfully.")
       print(f"Admin ID: {result.inserted_id}")
       print(f"Email: {email}")
       print("Role: admin")
   except DuplicateKeyError:
       print("A user with this email already exists.")

if __name__ == "__main__":
   create_admin()