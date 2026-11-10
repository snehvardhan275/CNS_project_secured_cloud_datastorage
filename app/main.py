import re
import logging
import smtplib
import ssl
from contextlib import asynccontextmanager
from datetime import timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Annotated

from bson import ObjectId
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, EmailStr, StringConstraints, field_validator
from pymongo import MongoClient
from pymongo import ReturnDocument
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from app.auth import (expiry, hash_password, new_otp, new_token, otp_digest,
                      perform_dummy_password_check, safe_equal, token_hash,
                      utcnow, verify_password)
from app.config import Settings, get_settings
from app.database import connect_database

STATIC_DIR = Path(__file__).parent / "static"
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
SESSION_COOKIE = "secure_session"
logger = logging.getLogger(__name__)


class EmailDeliveryError(Exception):
    def __init__(self, category: str):
        self.category = category


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.mongo_client = None
    app.state.db = None
    if settings.mongodb_uri:
        if len(settings.app_secret.encode("utf-8")) < 32:
            raise RuntimeError("APP_SECRET must contain at least 32 bytes in configured deployments")
        if settings.production and not all((settings.smtp_host, settings.smtp_username,
                                            settings.smtp_password, settings.smtp_from_email)):
            raise RuntimeError("Production email requires SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD, and SMTP_FROM_EMAIL")
        client, database = connect_database(settings)
        app.state.mongo_client, app.state.db = client, database
    try:
        yield
    finally:
        if app.state.mongo_client is not None:
            app.state.mongo_client.close()


app = FastAPI(title="Secure Cloud Storage", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    if request.url.path.startswith("/auth/") or request.url.path.startswith("/files"):
        response.headers["Cache-Control"] = "no-store"
    elif request.url.path == "/" or request.url.path.endswith(".html"):
        response.headers["Cache-Control"] = "no-cache"
    if get_settings().production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def settings_dependency() -> Settings:
    return get_settings()


def get_database(request: Request) -> Database:
    database = getattr(request.app.state, "db", None)
    if database is None:
        raise HTTPException(status_code=503, detail="Storage is not configured")
    return database


def send_otp_email(settings: Settings, email: str, otp: str, purpose: str) -> None:
    if not all((settings.smtp_host, settings.smtp_username, settings.smtp_password, settings.smtp_from_email)):
        raise EmailDeliveryError("missing_configuration")
    message = EmailMessage()
    message["Subject"] = "Your Secure Cloud verification code"
    message["From"] = settings.smtp_from_email
    message["To"] = email
    message.set_content(f"Your {purpose} verification code is {otp}. It expires in five minutes. If you did not request this, ignore this email.")
    try:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(message)
    except smtplib.SMTPAuthenticationError:
        raise EmailDeliveryError("authentication_rejected") from None
    except smtplib.SMTPRecipientsRefused:
        raise EmailDeliveryError("recipient_rejected") from None
    except smtplib.SMTPSenderRefused:
        raise EmailDeliveryError("sender_rejected") from None
    except (smtplib.SMTPException, ssl.SSLError, OSError):
        raise EmailDeliveryError("transport_failure") from None


def _deliver_otp_email(settings: Settings, email: str, otp: str, purpose: str) -> None:
    try:
        send_otp_email(settings, email, otp, purpose)
    except EmailDeliveryError as error:
        logger.error("OTP email delivery failed (%s)", error.category)
        raise HTTPException(
            status_code=503,
            detail="Email delivery is unavailable. Check the SMTP settings and try again later.",
        ) from None
    except Exception:
        logger.error("OTP email delivery failed (unexpected error)")
        raise HTTPException(
            status_code=503,
            detail="Email delivery is unavailable. Check the SMTP settings and try again later.",
        ) from None


class RegisterStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=32)]
    email: EmailStr

    @field_validator("username")
    @classmethod
    def valid_username(cls, value: str) -> str:
        if not USERNAME_PATTERN.fullmatch(value):
            raise ValueError("Use 3–32 letters, numbers, dots, underscores or hyphens")
        return value


class OtpVerify(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    otp: Annotated[str, StringConstraints(pattern=r"^\d{6}$")]


class RegisterComplete(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: Annotated[str, StringConstraints(min_length=3, max_length=32)]
    email: EmailStr
    verification_token: Annotated[str, StringConstraints(min_length=30, max_length=200)]
    password: Annotated[str, StringConstraints(min_length=12, max_length=1024)]

    @field_validator("username")
    @classmethod
    def valid_username(cls, value: str) -> str:
        if not USERNAME_PATTERN.fullmatch(value):
            raise ValueError("Invalid username")
        return value


class LoginPassword(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username_or_email: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=254)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=1024)]


class LoginOtpVerify(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: Annotated[str, StringConstraints(min_length=20, max_length=100)]
    otp: Annotated[str, StringConstraints(pattern=r"^\d{6}$")]


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _check_rate(db: Database, email: str, ip: str, purpose: str, settings: Settings) -> None:
    latest = db.email_otps.find_one({"email_normalized": email, "purpose": purpose}, sort=[("created_at", -1)])
    if latest:
        created_at = latest["created_at"]
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if created_at > utcnow() - timedelta(seconds=settings.otp_resend_seconds):
            raise HTTPException(status_code=429, detail="Please wait before requesting another code")
    now = utcnow()
    for kind, value in (("email", email), ("ip", ip)):
        scope_key = f"{purpose}:{kind}:{value}"
        record = db.auth_rate_limits.find_one_and_update(
            {"scope_key": scope_key, "expires_at": {"$gt": now}},
            {"$inc": {"count": 1}}, return_document=ReturnDocument.AFTER,
        )
        if record is None:
            db.auth_rate_limits.update_one(
                {"scope_key": scope_key},
                {"$set": {"count": 1, "expires_at": expiry(settings.otp_rate_window_seconds)}},
                upsert=True,
            )
            record = db.auth_rate_limits.find_one({"scope_key": scope_key})
        if record["count"] > settings.otp_rate_max:
            raise HTTPException(status_code=429, detail="Too many verification requests. Try again later")


def _create_otp(db: Database, email: str, purpose: str, ip: str, settings: Settings) -> tuple[str, ObjectId]:
    code = new_otp()
    salt = new_token()
    result = db.email_otps.insert_one({
        "email_normalized": email,
        "purpose": purpose,
        "otp_hash": otp_digest(settings, email, purpose, code, salt),
        "salt": salt,
        "attempts": 0,
        "used": False,
        "created_at": utcnow(),
        "expires_at": expiry(settings.otp_ttl_seconds),
        "ip": ip,
    })
    return code, result.inserted_id


def _consume_otp(db: Database, email: str, purpose: str, code: str, settings: Settings, challenge_id=None):
    query = {
        "email_normalized": email,
        "purpose": purpose,
        "used": False,
        "expires_at": {"$gt": utcnow()},
    }
    if challenge_id is not None:
        query["_id"] = challenge_id
    challenge = db.email_otps.find_one(query, sort=[("created_at", -1)])
    if challenge is None or challenge.get("attempts", 0) >= settings.otp_max_attempts:
        raise HTTPException(status_code=400, detail="The code is invalid or expired")
    expected = otp_digest(settings, email, purpose, code, challenge["salt"])
    if not safe_equal(expected, challenge["otp_hash"]):
        db.email_otps.update_one({"_id": challenge["_id"]}, {"$inc": {"attempts": 1}})
        raise HTTPException(status_code=400, detail="The code is invalid or expired")
    return challenge


def _session(db: Database, session_cookie: str | None = Cookie(default=None, alias=SESSION_COOKIE)) -> dict:
    if not session_cookie:
        raise HTTPException(status_code=401, detail="Sign in to continue")
    record = db.sessions.find_one({"token_hash": token_hash(session_cookie), "expires_at": {"$gt": utcnow()}})
    if record is None:
        raise HTTPException(status_code=401, detail="Sign in to continue")
    return record


def get_session(db: Database = Depends(get_database), session_cookie: str | None = Cookie(default=None, alias=SESSION_COOKIE)) -> dict:
    return _session(db, session_cookie)


def _check_csrf(session: dict, csrf_token: str | None) -> None:
    if not csrf_token or not safe_equal(token_hash(csrf_token), session["csrf_hash"]):
        raise HTTPException(status_code=403, detail="Request verification failed")


@app.get("/healthz")
def healthz(request: Request):
    if getattr(request.app.state, "db", None) is None:
        return JSONResponse({"status": "degraded", "database": "not_configured"}, status_code=503)
    try:
        request.app.state.db.command("ping")
    except Exception:
        return JSONResponse({"status": "degraded", "database": "unavailable"}, status_code=503)
    return {"status": "ok"}


@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/auth/register/start", status_code=202)
def register_start(payload: RegisterStart, request: Request, db: Database = Depends(get_database), settings: Settings = Depends(settings_dependency)):
    username, email = payload.username.strip(), str(payload.email).strip().lower()
    if db.users.find_one({"$or": [{"username_normalized": username.lower()}, {"email_normalized": email}]}):
        raise HTTPException(status_code=409, detail="An account with those details already exists")
    _check_rate(db, email, _ip(request), "registration", settings)
    code, challenge_id = _create_otp(db, email, "registration", _ip(request), settings)
    db.email_otps.update_one({"_id": challenge_id}, {"$set": {"username_normalized": username.lower()}})
    try:
        _deliver_otp_email(settings, email, code, "registration")
    except HTTPException:
        db.email_otps.delete_one({"_id": challenge_id})
        raise
    return {"message": "If the address can receive mail, a verification code is on its way."}


@app.post("/auth/register/verify")
def register_verify(payload: OtpVerify, db: Database = Depends(get_database), settings: Settings = Depends(settings_dependency)):
    email = str(payload.email).strip().lower()
    challenge = _consume_otp(db, email, "registration", payload.otp, settings)
    verification_token = new_token()
    db.email_otps.update_one({"_id": challenge["_id"]}, {"$set": {
        "used": True,
        "verified_token_hash": token_hash(verification_token),
        "verified_until": expiry(10 * 60),
    }})
    return {"verification_token": verification_token}


@app.post("/auth/register/complete", status_code=201)
def register_complete(payload: RegisterComplete, db: Database = Depends(get_database)):
    username, email = payload.username.strip(), str(payload.email).strip().lower()
    challenge = db.email_otps.find_one({
        "email_normalized": email,
        "purpose": "registration",
        "username_normalized": username.lower(),
        "used": True,
        "verified_token_hash": token_hash(payload.verification_token),
        "verified_until": {"$gt": utcnow()},
    })
    if challenge is None:
        raise HTTPException(status_code=400, detail="Complete email verification before creating an account")
    try:
        db.users.insert_one({
            "username": username,
            "username_normalized": username.lower(),
            "email": email,
            "email_normalized": email,
            "password_hash": hash_password(payload.password),
            "role": "user",
            "account_status": "active",
            "created_at": utcnow(),
        })
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="An account with those details already exists")
    db.email_otps.update_one({"_id": challenge["_id"]}, {"$set": {"verified_token_hash": None, "verified_until": utcnow()}})
    return {"message": "Your account is ready. Sign in to continue."}


@app.post("/auth/login/password", status_code=202)
def login_password(payload: LoginPassword, request: Request, db: Database = Depends(get_database), settings: Settings = Depends(settings_dependency)):
    identity = payload.username_or_email.strip().lower()
    user = db.users.find_one({"$or": [{"username_normalized": identity}, {"email_normalized": identity}], "account_status": "active"})
    if user is None or not verify_password(user.get("password_hash", ""), payload.password):
        perform_dummy_password_check(payload.password)
        raise HTTPException(status_code=401, detail="The sign in details are incorrect")
    email = user["email_normalized"]
    _check_rate(db, email, _ip(request), "login", settings)
    code, challenge_id = _create_otp(db, email, "login", _ip(request), settings)
    try:
        _deliver_otp_email(settings, email, code, "sign in")
    except HTTPException:
        db.email_otps.delete_one({"_id": challenge_id})
        raise
    return {"message": "A sign in code was sent to your registered email.", "challenge_id": str(challenge_id)}


@app.post("/auth/login/verify-otp")
def login_verify_otp(payload: LoginOtpVerify, response: Response, db: Database = Depends(get_database), settings: Settings = Depends(settings_dependency)):
    if not ObjectId.is_valid(payload.challenge_id):
        raise HTTPException(status_code=400, detail="The code is invalid or expired")
    challenge = db.email_otps.find_one({"_id": ObjectId(payload.challenge_id), "purpose": "login", "used": False})
    if challenge is None:
        raise HTTPException(status_code=400, detail="The code is invalid or expired")
    checked = _consume_otp(db, challenge["email_normalized"], "login", payload.otp, settings, ObjectId(payload.challenge_id))
    db.email_otps.update_one({"_id": checked["_id"]}, {"$set": {"used": True}})
    user = db.users.find_one({"email_normalized": checked["email_normalized"], "account_status": "active"})
    if user is None:
        raise HTTPException(status_code=401, detail="The sign in details are incorrect")
    session_id, csrf_token = new_token(), new_token()
    db.sessions.insert_one({
        "token_hash": token_hash(session_id),
        "csrf_hash": token_hash(csrf_token),
        "user_id": user["_id"],
        "created_at": utcnow(),
        "expires_at": expiry(settings.session_ttl_seconds),
    })
    response.set_cookie(SESSION_COOKIE, session_id, max_age=settings.session_ttl_seconds,
                        httponly=True, secure=settings.cookie_secure, samesite="lax", path="/")
    return {"user": {"username": user["username"], "email": user["email"]}, "csrf_token": csrf_token}


@app.get("/auth/me")
def auth_me(session: dict = Depends(get_session), db: Database = Depends(get_database)):
    user = db.users.find_one({"_id": session["user_id"], "account_status": "active"})
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in to continue")
    return {"username": user["username"], "email": user["email"]}


@app.get("/auth/csrf")
def auth_csrf(response: Response, session: dict = Depends(get_session), db: Database = Depends(get_database)):
    csrf = new_token()
    db.sessions.update_one({"_id": session["_id"]}, {"$set": {"csrf_hash": token_hash(csrf)}})
    return {"csrf_token": csrf}


@app.post("/auth/logout", status_code=204)
def logout(response: Response, x_csrf_token: str | None = Header(default=None), session: dict = Depends(get_session), db: Database = Depends(get_database)):
    _check_csrf(session, x_csrf_token)
    db.sessions.delete_one({"_id": session["_id"]})
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, secure=get_settings().cookie_secure, samesite="lax")
