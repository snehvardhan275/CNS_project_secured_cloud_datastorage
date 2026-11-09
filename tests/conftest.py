import pytest
import mongomock
from fastapi.testclient import TestClient

from app import main
from app.config import Settings


@pytest.fixture
def db():
    database = mongomock.MongoClient().secure_storage
    database.users.create_index("username_normalized", unique=True)
    database.users.create_index("email_normalized", unique=True)
    database.sessions.create_index("token_hash", unique=True)
    return database


@pytest.fixture
def client(db, monkeypatch):
    delivered = []
    monkeypatch.setattr(main, "send_otp_email", lambda settings, email, otp, purpose: delivered.append((email, otp, purpose)))
    settings = Settings(
        app_env="test", app_secret="test-secret-with-at-least-32-bytes",
        otp_ttl_seconds=300, otp_resend_seconds=60, otp_max_attempts=5,
        otp_rate_window_seconds=900, otp_rate_max=5, session_ttl_seconds=600,
    )
    main.app.dependency_overrides[main.get_database] = lambda: db
    main.app.dependency_overrides[main.settings_dependency] = lambda: settings
    with TestClient(main.app) as test_client:
        test_client.app.state.db = db
        test_client.app.state.mailbox = delivered
        yield test_client
    main.app.dependency_overrides.clear()


@pytest.fixture
def delivered(client):
    return client.app.state.mailbox


def create_account(client, delivered, username="alice", email="alice@example.com", password="a-long-passphrase-123"):
    start = client.post("/auth/register/start", json={"username": username, "email": email})
    assert start.status_code == 202
    code = delivered[-1][1]
    verified = client.post("/auth/register/verify", json={"email": email, "otp": code})
    assert verified.status_code == 200
    completion = client.post("/auth/register/complete", json={
        "username": username, "email": email,
        "verification_token": verified.json()["verification_token"], "password": password,
    })
    assert completion.status_code == 201
    return password
