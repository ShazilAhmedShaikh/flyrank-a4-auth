# FlyRank Auth · Login & Protect API (Supabase Auth & FastAPI)

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Framework-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![Supabase](https://img.shields.io/badge/IdP-Supabase%20Auth-3ECF8E.svg)](https://supabase.com/)
[![Tests](https://img.shields.io/badge/Tests-40%20Passed-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-purple.svg)]()

> **FlyRank Backend Internship — Week 2 · Assignment A4**  
> A production-grade, secure authentication and authorization microservice built with **FastAPI** and **Supabase Auth**. Demonstrates user signup, session creation, JSON Web Token (JWT) verification, reusable dependency guards, Swagger UI Bearer authentication, and defense-in-depth protection against brute-force attacks.

---

## 📑 Table of Contents
1. [Architecture & The Trust Triangle](#-architecture--the-trust-triangle)
2. [API Reference & Endpoint Matrix](#-api-reference--endpoint-matrix)
3. [Environment Configuration & Secrets](#-environment-configuration--secrets)
4. [Quickstart (Run in Under 2 Minutes)](#-quickstart-run-in-under-2-minutes)
5. [Interactive Swagger UI (`/docs`)](#-interactive-swagger-ui-docs)
6. [Testing & Verification Suite](#-testing--verification-suite)
7. [Security & Auth Deep Dives](#-security--auth-deep-dives)
   - [401 Unauthorized vs. 403 Forbidden](#1-401-unauthorized-vs-403-forbidden)
   - [Why Access Tokens are Short-Lived](#2-why-access-tokens-are-short-lived)
   - [Why Login Rate Limiting is Mandatory](#3-why-login-rate-limiting-is-mandatory)
   - [The Reality of Stateless JWT Logout](#4-the-reality-of-stateless-jwt-logout)
8. [Stage 7: AI Rematch ("AI vs Me")](#-stage-7-the-ai-rematch-ai-vs-me)

---

## 🏛️ Architecture & The Trust Triangle

Modern secure backend systems adhere to the **Trust Triangle**: password hashing and cryptographic token signing are delegated to a hardened Identity Provider (Supabase), while the backend API verifies incoming signatures and enforces authorization policies.

```
       ┌────────────────────────────────────────────────────────┐
       │                 1. Sign up / Log in                    │
       │         (email + password sent to Supabase)            │
       ▼                                                        │
┌──────────────┐          2. Signed JWT Token            ┌──────────────┐
│    Client    │ ◄────────────────────────────────────── │   Supabase   │
│   (Browser / │                                         │  (Identity   │
│    Postman)  │ ────┐                                   │   Provider)  │
└──────────────┘     │                                   └──────────────┘
                     │                                          ▲
                     │ 3. HTTP Request with                     │ 4. Verify Pass
                     │    Authorization: Bearer <JWT>           │    (Token signature
                     ▼                                          │     & expiration)
              ┌──────────────┐                                  │
              │  FlyRank API │ ─────────────────────────────────┘
              │  (FastAPI)   │  5. Response 200 / 401 / 403
              └──────────────┘
```

1. **Client $\to$ Supabase**: Client registers or logs in with credentials.
2. **Supabase $\to$ Client**: Supabase verifies credentials, issues an asymmetric/HMAC-signed JWT `access_token` and a `refresh_token`.
3. **Client $\to$ Backend**: Client issues API calls with `Authorization: Bearer <access_token>`.
4. **Backend $\to$ Supabase**: The backend middleware guard inspects the header and verifies token authenticity via `supabase.auth.get_user(token)`.
5. **Backend $\to$ Client**: Upon valid signature, request proceeds; otherwise, requests are halted with structured JSON errors.

---

## 🚪 API Reference & Endpoint Matrix

All error responses strictly return a standardized JSON schema: `{"error": "<descriptive_message>"}`.

| Method | Endpoint | Purpose | Auth Header Required? | Expected Status Codes |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/` | Service health & Supabase connection check | None | `200 OK` |
| `GET` | `/public/info` | Public open data endpoint | None | `200 OK` |
| `POST` | `/auth/signup` | Register a new user in Supabase | None | `201 Created`<br>`400 Bad Request` |
| `POST` | `/auth/login` | Authenticate user & receive JWT tokens | None | `200 OK`<br>`400 Bad Request`<br>`401 Unauthorized`<br>`429 Too Many Requests` |
| `POST` | `/auth/refresh` | Exchange refresh token for fresh access token | None | `200 OK`<br>`400 Bad Request`<br>`401 Unauthorized` |
| `POST` | `/auth/logout` | Revoke session & invalidate tokens | `Authorization: Bearer <token>` | `204 No Content`<br>`401 Unauthorized` |
| `GET` | `/protected/profile` | Retrieve authenticated user's profile | `Authorization: Bearer <token>` | `200 OK`<br>`401 Unauthorized` |
| `GET` | `/protected/dashboard`| Reusable guard verification endpoint | `Authorization: Bearer <token>` | `200 OK`<br>`401 Unauthorized` |
| `GET` | `/protected/admin` | Role-based administrative dashboard | `Authorization: Bearer <token>` | `200 OK`<br>`401 Unauthorized`<br>`403 Forbidden` |

---

## 🔑 Environment Configuration & Secrets

> [!CAUTION]
> **Never commit your `.env` file to Git.** The `.gitignore` in this repository strictly ignores `.env`. Git history contains zero secret keys. Use `.env.example` as a template.

### 1. Create a free Supabase project
1. Navigate to [supabase.com](https://supabase.com) and create a project (e.g., `FlyRank-Auth`).
2. Go to **Project Settings $\to$ API** and copy:
   - **Project URL**
   - **anon key** (`public` key — safe for client/app usage).
   *(Never use the `service_role` key here as it bypasses all Row Level Security).*
3. Under **Authentication $\to$ Providers $\to$ Email**, switch **"Confirm email" OFF** for rapid local practice testing.

### 2. Configure Local `.env`
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Populate the values inside `.env`:
```env
# Supabase Configuration
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_KEY=your_supabase_anon_public_key_here

# Server Configuration
PORT=8000
HOST=0.0.0.0

# Rate Limiting Guard
RATE_LIMIT_FAILED_ATTEMPTS=5
RATE_LIMIT_WINDOW_SECONDS=300
```

---

## ⚡ Quickstart (Run in Under 2 Minutes)

### Prerequisites
- Python 3.10 or higher
- Git

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/shazilahmed/flyrank-a4-auth.git
cd flyrank-a4-auth
pip install -r requirements.txt
```

### 2. Start the API Server
```bash
uvicorn app.main:app --reload --port 8000
```
Console output confirms successful startup:
```text
INFO:     Started server process
INFO:     flyrank_auth: Server running and connected to Supabase
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

---

## 📖 Interactive Swagger UI (`/docs`)

FastAPI exposes an automated OpenAPI documentation page with full Bearer Token authorization support at:
`http://localhost:8000/docs`

### Using the Padlock ("Authorize") in Swagger UI:
1. Open `http://localhost:8000/docs` in your browser.
2. Note the visible **padlock icons** next to `/protected/profile`, `/protected/dashboard`, `/protected/admin`, and `/auth/logout`.
3. Click the green **"Authorize"** button at the top-right.
4. Paste the `access_token` string obtained from `/auth/login` (no need to type "Bearer ", Swagger adds it automatically).
5. Click **Authorize** $\to$ **Close**.
6. Expand `GET /protected/profile` and click **Try it out** $\to$ **Execute**.
7. Observe status code `200 OK` with your account details directly in the browser!

---

## 🧪 Testing & Verification Suite

The repository contains an exhaustive test suite with **40 test cases** verifying all stages, status codes, token variations, and security boundaries.

### Run All Tests
```bash
python -m pytest -v
```

### Test Coverage Summary:
- **`tests/test_stage1_auth.py`** (8 tests): Missing email/password validation (400), blank whitespace fields (400), valid user creation (201), duplicate registration handling (400), invalid password login (401), and token generation (200).
- **`tests/test_stage2_3_gates.py`** (5 tests): Public route access (200), missing token rejection (401), malformed header rejection (401), cryptographic signature verification (200), and tampered token rejection (401).
- **`tests/test_stage4_middleware_logout.py`** (6 tests): Guard reusability on dashboard (200 / 401), authenticated logout lifecycle (204 No Content), unauthenticated logout rejection (401).
- **`tests/test_swagger.py`** (2 tests): Verification of OpenAPI `HTTPBearer` security scheme configuration and padlock schema attachment.
- **`tests/test_extras.py`** (8 tests): Administrative 403 Forbidden checks, admin access grant, refresh token rotation, and brute-force lockout triggers (429).
- **`tests/test_difficult_edge_cases.py`** (11 tests): Case-insensitivity (`bearer`, `BEARER`), extra token whitespace, basic auth confusion attacks, corrupted JSON payloads, non-string data types, client IP isolation, and method not allowed (405).

---

## 🔒 Security & Auth Deep Dives

### 1. 401 Unauthorized vs. 403 Forbidden
- **`401 Unauthorized` ("Who are you?")**: The user failed authentication. Either no token was provided, the header was malformed, or the token was forged, tampered with, or expired. The server does not know who is calling.
- **`403 Forbidden` ("I know you, and no.")**: The user successfully authenticated (valid JWT, known user identity), but their identity or role does not have authorization to access this specific resource (e.g., non-admin calling `/protected/admin`).

### 2. Why Access Tokens are Short-Lived
Access tokens are stateless credentials. Because servers do not query a database session table on every microservice request, a stolen access token cannot be immediately invalidated until it expires. Keeping access token lifespans short (e.g., 15–60 minutes) strictly limits the window of opportunity for an attacker if a token is intercepted. The `refresh_token` lives securely to acquire new access tokens seamlessly.

### 3. Why Login Rate Limiting is Mandatory
Authentication endpoints (`/auth/login`) are the primary target for automated credential stuffing and dictionary attacks. Without rate limiting, attackers can fire thousands of password guesses per second. Our in-memory sliding-window limiter isolates attacker IPs and returns `429 Too Many Requests` after 5 failed attempts, safeguarding user credentials.

### 4. The Reality of Stateless JWT Logout
Because JWTs are self-contained and cryptographically signed, any server possessing the public key or secret will consider a JWT valid until its `exp` timestamp elapses. "Instant logout" in pure stateless JWT architectures requires either:
1. Calling the Identity Provider (`supabase.auth.sign_out()`) to invalidate refresh sessions.
2. Maintaining a centralized token revocation blocklist / Redis cache for remaining token lifespans.

---

## 🤖 Stage 7: The AI Rematch ("AI vs Me")

In Stage 7, an independent prompt was provided to an LLM in quarantine (`ai-version/app.py`) to build the same API without seeing this codebase.

### AI Implementation Flaws & Critical Differences:
1. **Header Parsing Vulnerability**:
   - *AI Code*: Performed naive `request.headers.get("Authorization").split(" ")[1]` without checking array length or whitespace. An incoming `Authorization: Bearer` or `Authorization: InvalidHeader` raised an unhandled `IndexError`, causing an internal `500 Internal Server Error` instead of a clean `401 {"error": "Access token required"}`.
   - *Our Implementation*: Uses defensive parsing with explicit validation for scheme, length, and non-empty token string.
2. **Missing Input Validation & Status Codes**:
   - *AI Code*: Defaulted to FastAPI Pydantic schema validation which responds with HTTP `422 Unprocessable Entity` containing verbose stack objects. The assignment strictly required `400 Bad Request` with `{"error": "..."}`.
   - *Our Implementation*: Implements custom FastAPI exception handlers and input cleaners ensuring strict compliance with `400` status codes.
3. **Leaked Error Traces & Missing Error Trapping**:
   - *AI Code*: Did not catch Supabase `AuthApiError` specifically, letting database and SDK traces leak directly into client responses.
   - *Our Implementation*: Traps Supabase auth errors cleanly, logging security events internally while returning sanitized, standardized error JSON to clients.
