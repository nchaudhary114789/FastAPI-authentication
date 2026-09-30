from pymongo import MongoClient
from .auth import settings

client = MongoClient(settings.MONGODB_URL)

db = client[settings.MONGODB_DATABASE]

users_collection = db["users"]
revoked_tokens_collection = db["revoked_tokens"]
