import re

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.database import Database
from pymongo.errors import InvalidURI

from app.config import Settings


def normalize_mongodb_uri(value: str) -> str:
    """Accept a raw URI or common copied env-file wrappers without logging it."""
    uri = value.strip()
    assignment = re.match(r"^MONGODB_URI\s*=\s*", uri, flags=re.IGNORECASE)
    if assignment:
        uri = uri[assignment.end():].strip()
    if len(uri) >= 2 and uri[0] == uri[-1] and uri[0] in ("'", '"'):
        uri = uri[1:-1].strip()
    if not (uri.startswith("mongodb://") or uri.startswith("mongodb+srv://")):
        raise ValueError(
            "MONGODB_URI must contain only the complete MongoDB connection URI, "
            "starting with mongodb:// or mongodb+srv://. Do not include the variable name."
        )
    if any(character.isspace() for character in uri):
        raise ValueError("MONGODB_URI contains whitespace; remove spaces and line breaks from the connection URI.")
    return uri


def connect_database(settings: Settings) -> tuple[MongoClient, Database]:
    if not settings.mongodb_uri:
        raise RuntimeError("MONGODB_URI is required")
    uri = normalize_mongodb_uri(settings.mongodb_uri)
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=15000, connectTimeoutMS=10000)
    except InvalidURI:
        raise RuntimeError(
            "MONGODB_URI is malformed. Copy the complete URI from MongoDB Atlas > Connect > Drivers."
        ) from None
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
