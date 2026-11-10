# Secure Cloud Storage

Sprint 1 provides the account foundation for the browser-based secure file storage prototype: email-verified registration, Argon2id password hashing, password-plus-email-code sign-in, server-managed sessions, CSRF protection, and a responsive dashboard shell.

## Requirements

- Python 3.12 or Docker Compose
- MongoDB 7 for local development, or a MongoDB Atlas database
- An SMTP account for email verification and sign-in codes

## Configure locally

Copy `.env.example` to `.env`, set a random `APP_SECRET` with at least 32 bytes, and set SMTP sender credentials. For local Compose, the app connects to the included MongoDB container. Start it with:

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Open <http://localhost:8000>. The health endpoint is <http://localhost:8000/healthz>.

## MongoDB URL for GitHub and Render

Do not commit a real MongoDB connection string into a GitHub file. Add it as the `MONGODB_URI` environment variable in the Render service dashboard. The checked-in `render.yaml` declares the variable as `sync: false`, so Render prompts for its value. For local runs, put it in the untracked `.env` file. `.env.example` contains only a local placeholder.

Set `MONGODB_DATABASE` to the desired database name. Set `APP_SECRET` to a different, randomly generated value in Render; never reuse a sample value. Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_FROM_EMAIL` in the Render environment so OTP delivery works. Email uses authenticated STARTTLS on port 587 and requires TLS 1.2 or newer. The service fails closed if the SMTP server doesn't support STARTTLS; it never falls back to plaintext or implicit SSL.

For Atlas, `MONGODB_URI` must be the complete value that starts with `mongodb+srv://` or `mongodb://`. Paste only the URI into the Render value field, not `MONGODB_URI=` or surrounding Markdown/code formatting. The application trims common environment-file wrappers and reports malformed values without exposing the URI. The Docker image reads Render's `PORT` at startup and defaults to port 10000; do not override `PORT` unless you intend to use another port.

## Run the tests

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

The test suite uses an in-memory MongoDB mock and a fake email sender. It does not contact Atlas or send real email.

## Deployment

`render.yaml` configures a Docker web service with automatic deployment enabled and `/healthz` as its health check. Connect the GitHub repository to Render and review the environment variables in the Render dashboard. A Render service must be connected to the repository for pushes to deploy automatically.

Sprint 1 deliberately contains no file upload or encryption routes; those belong to later sprint gates.
