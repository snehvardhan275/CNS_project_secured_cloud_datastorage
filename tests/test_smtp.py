import smtplib
import ssl

import pytest

from app import main
from app.config import Settings


class FakeSMTP:
    def __init__(self, *args, **kwargs):
        self.calls = []
        self.context = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self, context):
        self.calls.append("starttls")
        self.context = context

    def login(self, username, password):
        self.calls.append("login")
        assert username == "smtp-user"
        assert password == "smtp-password"

    def send_message(self, message):
        self.calls.append("send_message")
        assert message["To"] == "person@example.com"


def test_email_uses_starttls_12_or_newer_and_never_implicit_ssl(monkeypatch):
    smtp = FakeSMTP()
    monkeypatch.setattr(main.smtplib, "SMTP", lambda *args, **kwargs: smtp)
    monkeypatch.setattr(main.smtplib, "SMTP_SSL", lambda *args, **kwargs: pytest.fail("implicit SSL must not be used"))
    settings = Settings(
        app_env="test", app_secret="test-secret-with-at-least-32-bytes",
        smtp_host="smtp.example.com", smtp_port=587,
        smtp_username="smtp-user", smtp_password="smtp-password",
        smtp_from_email="sender@example.com",
    )

    main.send_otp_email(settings, "person@example.com", "123456", "registration")

    assert smtp.calls == ["ehlo", "starttls", "ehlo", "login", "send_message"]
    assert isinstance(smtp.context, ssl.SSLContext)
    assert smtp.context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_email_fails_closed_if_server_rejects_starttls(monkeypatch):
    smtp = FakeSMTP()
    def reject_starttls(context):
        smtp.calls.append("starttls")
        raise smtplib.SMTPNotSupportedError("STARTTLS unavailable")
    smtp.starttls = reject_starttls
    monkeypatch.setattr(main.smtplib, "SMTP", lambda *args, **kwargs: smtp)
    settings = Settings(
        app_env="test", app_secret="test-secret-with-at-least-32-bytes",
        smtp_host="smtp.example.com", smtp_port=587,
        smtp_username="smtp-user", smtp_password="smtp-password",
        smtp_from_email="sender@example.com",
    )

    with pytest.raises(main.EmailDeliveryError) as error:
        main.send_otp_email(settings, "person@example.com", "123456", "registration")

    assert error.value.category == "transport_failure"
    assert smtp.calls == ["ehlo", "starttls"]
