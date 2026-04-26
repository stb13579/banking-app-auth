# banking-app-auth — Auth Service

Python 3.11 / FastAPI authentication service. Handles user registration, email verification, login, JWT issuance, MFA, and session history.

Part of the mock consumer banking application.

---

## Quick Start

### Standalone (with Docker)

```bash
docker compose up
```

Service starts on port **8001**. Swagger UI at http://localhost:8001/docs.

### Local development

```bash
cp .env.example .env
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001
```

---

## API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/register` | No | Create user account |
| `POST` | `/verify-email` | No | Verify email with token |
| `POST` | `/login` | No | Login — returns JWT |
| `POST` | `/refresh` | Bearer | Refresh access token |
| `GET` | `/me` | Bearer | Current user profile |
| `POST` | `/mfa/enable` | Bearer | Generate TOTP secret |
| `POST` | `/mfa/verify` | Bearer | Activate MFA |
| `GET` | `/health` | No | Health check |

---

## curl Examples

### Register

```bash
curl -s -X POST http://localhost:8001/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"password123"}' | jq
```

### Verify email

```bash
curl -s -X POST http://localhost:8001/verify-email \
  -H "Content-Type: application/json" \
  -d '{"token":"<verification_token>"}' | jq
```

### Login — capture JWT

```bash
TOKEN=$(curl -s -X POST http://localhost:8001/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"password123"}' \
  | jq -r '.access_token')
echo "Token: $TOKEN"
```

### Get profile

```bash
curl -s http://localhost:8001/me \
  -H "Authorization: Bearer $TOKEN" | jq
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://banking:banking@localhost:5432/banking` | PostgreSQL connection string |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `JWT_SECRET` | `supersecret123` | JWT signing secret |
| `PORT` | `8001` | Service port |
