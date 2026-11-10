from datetime import timedelta

from app.auth import utcnow
from app import main

from tests.conftest import create_account


def test_s1_01_valid_registration_sends_email_otp(client, delivered):
    response = client.post("/auth/register/start", json={"username": "alice", "email": "alice@example.com"})
    assert response.status_code == 202
    assert delivered[-1][0] == "alice@example.com"
    assert delivered[-1][2] == "registration"
    challenge = client.app.state.db.email_otps.find_one({"email_normalized": "alice@example.com"})
    assert delivered[-1][1] not in challenge["otp_hash"]


def test_s1_02_invalid_email_and_username_rejected(client):
    assert client.post("/auth/register/start", json={"username": "x", "email": "bad"}).status_code == 422
    assert client.post("/auth/register/start", json={"username": "valid", "email": "bad"}).status_code == 422


def test_s1_03_wrong_registration_otp_rejected(client, delivered):
    client.post("/auth/register/start", json={"username": "alice", "email": "alice@example.com"})
    response = client.post("/auth/register/verify", json={"email": "alice@example.com", "otp": "999999"})
    assert response.status_code == 400
    assert not client.app.state.db.users.count_documents({})


def test_s1_04_expired_registration_otp_rejected(client, delivered):
    client.post("/auth/register/start", json={"username": "alice", "email": "alice@example.com"})
    client.app.state.db.email_otps.update_one({}, {"$set": {"expires_at": utcnow() - timedelta(seconds=1)}})
    response = client.post("/auth/register/verify", json={"email": "alice@example.com", "otp": delivered[-1][1]})
    assert response.status_code == 400


def test_s1_05_registration_otp_cannot_be_reused(client, delivered):
    client.post("/auth/register/start", json={"username": "alice", "email": "alice@example.com"})
    code = delivered[-1][1]
    assert client.post("/auth/register/verify", json={"email": "alice@example.com", "otp": code}).status_code == 200
    assert client.post("/auth/register/verify", json={"email": "alice@example.com", "otp": code}).status_code == 400


def test_s1_06_complete_registration_creates_user(client, delivered):
    create_account(client, delivered)
    user = client.app.state.db.users.find_one({"email_normalized": "alice@example.com"})
    assert user is not None
    assert user["role"] == "user"


def test_s1_07_registration_stores_only_argon2id_hash(client, delivered):
    create_account(client, delivered)
    user = client.app.state.db.users.find_one({"email_normalized": "alice@example.com"})
    assert user["password_hash"].startswith("$argon2id$")
    assert "password" not in user


def test_s1_08_wrong_password_does_not_send_otp(client, delivered):
    create_account(client, delivered)
    count = len(delivered)
    response = client.post("/auth/login/password", json={"username_or_email": "alice", "password": "wrong-password"})
    assert response.status_code == 401
    assert len(delivered) == count


def test_s1_09_correct_password_sends_login_otp(client, delivered):
    create_account(client, delivered)
    response = client.post("/auth/login/password", json={"username_or_email": "alice", "password": "a-long-passphrase-123"})
    assert response.status_code == 202
    assert delivered[-1][2] == "sign in"
    assert response.json()["challenge_id"]


def test_s1_10_wrong_login_otp_does_not_create_session(client, delivered):
    create_account(client, delivered)
    challenge = client.post("/auth/login/password", json={"username_or_email": "alice", "password": "a-long-passphrase-123"}).json()
    response = client.post("/auth/login/verify-otp", json={"challenge_id": challenge["challenge_id"], "otp": "999999"})
    assert response.status_code == 400
    assert client.app.state.db.sessions.count_documents({}) == 0


def test_s1_11_correct_login_otp_creates_http_only_session(client, delivered):
    create_account(client, delivered)
    challenge = client.post("/auth/login/password", json={"username_or_email": "alice", "password": "a-long-passphrase-123"}).json()
    response = client.post("/auth/login/verify-otp", json={"challenge_id": challenge["challenge_id"], "otp": delivered[-1][1]})
    assert response.status_code == 200
    assert response.cookies.get("secure_session")
    assert "httponly" in response.headers["set-cookie"].lower()
    assert client.get("/auth/me").json()["username"] == "alice"


def test_s1_12_logout_requires_csrf_and_invalidates_session(client, delivered):
    create_account(client, delivered)
    challenge = client.post("/auth/login/password", json={"username_or_email": "alice", "password": "a-long-passphrase-123"}).json()
    login = client.post("/auth/login/verify-otp", json={"challenge_id": challenge["challenge_id"], "otp": delivered[-1][1]})
    assert client.post("/auth/logout").status_code == 403
    csrf = login.json()["csrf_token"]
    assert client.post("/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 204
    assert client.get("/auth/me").status_code == 401


def test_s1_13_rate_limits_otp_requests_and_isolates_accounts(client, delivered):
    create_account(client, delivered)
    client.app.dependency_overrides[main.settings_dependency] = lambda: main.Settings(
        app_env="test", app_secret="test-secret-with-at-least-32-bytes", otp_rate_max=1,
        otp_resend_seconds=0, otp_rate_window_seconds=900,
    )
    first = client.post("/auth/login/password", json={"username_or_email": "alice", "password": "a-long-passphrase-123"})
    assert first.status_code == 202
    client.app.state.db.email_otps.update_many({"purpose": "login"}, {"$set": {"created_at": utcnow() - timedelta(seconds=61)}})
    second = client.post("/auth/login/password", json={"username_or_email": "alice", "password": "a-long-passphrase-123"})
    assert second.status_code == 429
    assert client.get("/auth/me").status_code == 401
    client.app.dependency_overrides[main.settings_dependency] = lambda: main.Settings(
        app_env="test", app_secret="test-secret-with-at-least-32-bytes", otp_rate_max=10,
        otp_resend_seconds=0, otp_rate_window_seconds=900,
    )
    other_password = "another-long-passphrase-456"
    create_account(client, delivered, username="bob", email="bob@example.com", password=other_password)
    other = client.post("/auth/login/password", json={"username_or_email": "bob", "password": other_password})
    assert other.status_code == 202
    login = client.post("/auth/login/verify-otp", json={
        "challenge_id": other.json()["challenge_id"], "otp": delivered[-1][1],
    })
    assert login.status_code == 200
    assert client.get("/auth/me").json()["username"] == "bob"


def test_s1_14_health_route_reports_database_readiness(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers.get("cache-control") is None


def test_frontend_pages_and_security_headers_are_served(client):
    for page in ("register.html", "verify-register.html", "create-password.html", "login.html", "verify-login.html", "dashboard.html", "privacy.html"):
        response = client.get(f"/static/{page}")
        assert response.status_code == 200
        assert "X-Content-Type-Options" in response.headers
        assert "Content-Security-Policy" in response.headers
        assert response.headers["cache-control"] == "no-cache"
        assert "unsafe-inline" not in response.headers["Content-Security-Policy"]
        assert response.headers["Permissions-Policy"] == "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"


def test_private_auth_response_is_never_cached(client):
    response = client.get("/auth/me")
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"


def test_email_provider_failure_is_logged_as_safe_category(client, caplog, monkeypatch):
    def fail_delivery(*args, **kwargs):
        raise main.EmailDeliveryError("authentication_rejected")

    monkeypatch.setattr(main, "send_otp_email", fail_delivery)
    response = client.post("/auth/register/start", json={"username": "alice", "email": "alice@example.com"})
    assert response.status_code == 503
    assert "SMTP settings" in response.json()["detail"]
    assert "authentication_rejected" in caplog.text
    assert "alice@example.com" not in caplog.text
    assert client.app.state.db.email_otps.count_documents({}) == 0
