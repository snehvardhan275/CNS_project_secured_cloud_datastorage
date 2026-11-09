import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from app.config import Settings

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
_dummy_hash = password_hasher.hash("not-a-real-user-password")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return password_hasher.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def perform_dummy_password_check(password: str) -> None:
    verify_password(_dummy_hash, password)


def new_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def otp_digest(settings: Settings, email: str, purpose: str, otp: str, salt: str) -> str:
    secret = settings.app_secret.encode("utf-8")
    message = f"otp:v1:{purpose}:{email}:{salt}:{otp}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def safe_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode(), right.encode())


def expiry(seconds: int) -> datetime:
    return utcnow() + timedelta(seconds=seconds)
