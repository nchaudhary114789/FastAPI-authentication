import re

def up(db):
   users = db["users"]
   existing_users = users.find(
       {
           "$or": [
               {"username": {"$exists": False}},
               {"username": None},
               {"username": ""}
           ]
       },
       {"_id": 1}
   )
   for user in existing_users:
       user_id = str(user["_id"])
       base_username = "legacy_" + re.sub(
           r"[^a-zA-Z0-9_]",
           "",
           user_id
       )
       username = base_username
       counter = 1
       while users.find_one({"username": username}):
           username = f"{base_username}_{counter}"
           counter += 1
       users.update_one(
           {"_id": user["_id"]},
           {"$set": {"username": username}}
       )
   users.create_index(
       [("username", 1)],
       unique=True,
       name="unique_username"
   )