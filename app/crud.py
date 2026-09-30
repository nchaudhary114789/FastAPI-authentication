from .database import users_collection

def get_user_by_email(email: str):
   return users_collection.find_one({
       "email": email
   })

def get_user_by_id(user_id):
   return users_collection.find_one({
       "_id": user_id
   })

def create_user(user_data: dict):
   result = users_collection.insert_one(user_data)
   return users_collection.find_one({
       "_id": result.inserted_id
   })