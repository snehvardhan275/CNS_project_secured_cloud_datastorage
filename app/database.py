from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.database import Database

from app.config import Settings


def connect_database(settings: Settings) -> tuple[MongoClient, Database]:
    if not settings.mongodb_uri:
        raise RuntimeError("MONGODB_URI is required")
    client = MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
    client.admin.command("ping")
    database = client[settings.mongodb_database]
    database.users.create_index([("username_normalized", ASCENDING)], unique=True)
    database.users.create_index([("email_normalized", ASCENDING)], unique=True)
    database.email_otps.create_index([("email_normalized", ASCENDING), ("purpose", ASCENDING), ("created_at", DESCENDING)])
    database.email_otps.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
    database.auth_rate_limits.create_index([("scope_key", ASCENDING)], unique=True)
    database.auth_rate_limits.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
    database.sessions.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
    database.sessions.create_index([("token_hash", ASCENDING)], unique=True)
    return client, database
