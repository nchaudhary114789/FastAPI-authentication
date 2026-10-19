from pymongo import MongoClient
from .auth import settings

client = MongoClient(settings.MONGODB_URL)

db = client[settings.MONGODB_DATABASE]

users_collection = db["users"]
revoked_tokens_collection = db["revoked_tokens"]
audit_logs_collection = db["audit_logs"]
email_verification_tokens_collection = db["email_verification_tokens"]