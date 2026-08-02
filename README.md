# Secure Password Manager — Backend

FastAPI backend for the Secure Password Manager: user authentication and an encrypted password vault, built with bcrypt (login) + JWT (sessions) + AES-256-GCM (stored credentials).

## Tech Stack

- **FastAPI** — REST API framework
- **SQLite** — local file-based database (`password_manager.db`, auto-created on first run)
- **bcrypt** (via `passlib`) — one-way hashing for user login passwords
- **AES-256-GCM** (via `cryptography`) — two-way encryption for stored site passwords, so they can be decrypted and shown back to the user
- **JWT** (via `python-jose`) — stateless auth tokens for protected routes
- **python-dotenv** — loads secrets from `.env`

> Note: `auth.py` and `crypto.py` both include pure-Python fallback implementations (PBKDF2 for hashing, hand-written AES-CTR+HMAC for encryption) in case `passlib`/`cryptography` aren't installed. In normal setup, the real `bcrypt` and `cryptography` libraries are used — the fallbacks exist only for environments where those packages fail to install.

## Project Structure

```
backend/
├── main.py           # FastAPI app, all routes (auth, entries, utils)
├── auth.py           # password hashing (bcrypt) + JWT create/decode
├── crypto.py          # AES-256-GCM encrypt/decrypt for stored passwords
├── database.py        # SQLite connection + table creation (users, entries)
├── models.py           # data models
├── schemas.py           # Pydantic request/response schemas
├── pw_util.py            # password strength scoring + password generator
├── server.py              # fallback server runner
├── requirements.txt
├── .env.example            # template for required environment variables
├── .env                     # actual secrets — NEVER commit this
├── .aes_key                  # fallback local AES key file — NEVER commit this
└── test_*.py                  # test scripts for auth, crypto, CRUD, full flow
```

## Setup

**1. Create a virtual environment and install dependencies**
```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt --break-system-packages
```

**2. Configure environment variables**

Copy `.env.example` to `.env` and fill in real values:
```bash
copy .env.example .env
```

Required variables:
| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Signs JWT tokens — use a long random string |
| `ALGORITHM` | JWT signing algorithm (`HS256`) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | JWT session length (default `60`) |
| `DATABASE_URL` | SQLite path (default `sqlite:///./password_manager.db`) |
| `ENCRYPTION_KEY` | 32-byte AES key (64-char hex string) used to encrypt/decrypt stored passwords |

**Never commit `.env` or `.aes_key`** — both hold live secrets. Both are excluded in `.gitignore`.

**3. Run the server**
```bash
python main.py
```
or
```bash
uvicorn main:app --reload
```

The API runs at `http://localhost:8000`. Interactive docs (Swagger UI) are auto-generated at `http://localhost:8000/docs`.

## API Endpoints

**Auth**
| Method | Route | Description |
|---|---|---|
| POST | `/auth/register` | Create a new user (email + password, min 6 chars) |
| POST | `/auth/login` | Log in, returns a JWT bearer token |
| GET | `/auth/me` | Returns the current authenticated user (requires token) |

**Vault Entries** (all require `Authorization: Bearer <token>`)
| Method | Route | Description |
|---|---|---|
| POST | `/entries` | Add a new entry — password is encrypted before saving |
| GET | `/entries?q=search` | List entries (optionally filtered by site name/username) — passwords returned masked |
| GET | `/entries/{id}` | Get one entry with the password **decrypted** |
| PUT | `/entries/{id}` | Update site name, username, and/or password |
| DELETE | `/entries/{id}` | Delete an entry |

**Utilities**
| Method | Route | Description |
|---|---|---|
| POST | `/utils/password-strength` | Score a password's strength |
| POST | `/utils/generate-password` | Generate a random strong password (configurable length/character sets) |

## Security Notes

- Login passwords are **hashed** with bcrypt — never stored or logged in plaintext, and not recoverable.
- Vault passwords are **encrypted** with AES-256-GCM — recoverable only via `/entries/{id}` by the entry's owner, verified through JWT.
- Every `/entries` route filters by the authenticated user's ID — one user cannot read or modify another user's entries.
- The AES key is loaded from `ENCRYPTION_KEY` in `.env` (or falls back to a locally generated `.aes_key` file if unset). This is a known simplification: in a production password manager, the encryption key would typically be derived from the user's own master password client-side, so the server itself never has access to it. Worth mentioning as a deliberate scope trade-off if asked in an interview.

## Testing

Run the included test scripts to verify each layer independently:
```bash
python test_auth.py          # bcrypt hashing + JWT create/verify
python test_encryption.py    # AES encrypt/decrypt round-trip
python test_crud.py          # entries CRUD + user isolation
python test_all_phases.py    # end-to-end flow
```
! [image alt](https://github.com/2023btechcsectisshaunakpatel-ops/Secure-Password-Manager/blob/f4c94d74e4ef096aba0bce84b4ff97d5409fd6bf/Screenshot%202026-07-31%20231726.png)

! [image alt](https://github.com/2023btechcsectisshaunakpatel-ops/Secure-Password-Manager/blob/98e577dbef244e2d4c0e07d3a8f4b96239b83e4d/Screenshot%202026-07-31%20231744.png)

! [image alt](https://github.com/2023btechcsectisshaunakpatel-ops/Secure-Password-Manager/blob/3c5344096be390716771fcb9c20271485a0fa8f4/Screenshot%202026-07-31%20231800.png)

! [image alt](https://github.com/2023btechcsectisshaunakpatel-ops/Secure-Password-Manager/blob/e93ed0307a63359dbfdabf9ab939db5e1668c1fe/Screenshot%202026-07-31%20231814.png)
