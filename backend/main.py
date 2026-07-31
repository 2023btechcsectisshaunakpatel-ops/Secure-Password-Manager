import sys
import json
from pathlib import Path

# Add backend directory to path
sys.path.append(str(Path(__file__).parent))

from database import init_db, get_db_connection
from auth import hash_password, verify_password, create_access_token, decode_access_token

# Initialize database
init_db()

# Check FastAPI
try:
    from fastapi import FastAPI, HTTPException, Depends, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.security import OAuth2PasswordBearer
    from schemas import UserCreate, UserLogin, UserResponse, Token, EntryCreate, EntryUpdate, EntryResponse, EntryDetailResponse
    from crypto import encrypt, decrypt
    from pw_util import calculate_password_strength, generate_secure_password
    from typing import List, Optional
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

if HAS_FASTAPI:
    app = FastAPI(
        title="Secure Password Manager API",
        description="Password Vault API with bcrypt/PBKDF2 auth and AES-256 encrypted credential storage",
        version="1.0.0"
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

    def get_current_user(token: str = Depends(oauth2_scheme)):
        payload = decode_access_token(token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload

    @app.post("/auth/register", status_code=status.HTTP_201_CREATED)
    def register(user_data: UserCreate):
        email = user_data.email.strip().lower()
        password = user_data.password

        if not email or "@" not in email:
            raise HTTPException(status_code=400, detail="Invalid email address")
        if not password or len(password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="Email already registered")

        hashed_pwd = hash_password(password)
        cursor.execute("INSERT INTO users (email, hashed_password) VALUES (?, ?)", (email, hashed_pwd))
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return {
            "id": user_id,
            "email": email,
            "message": "User registered successfully"
        }

    @app.post("/auth/login", response_model=Token)
    def login(user_data: UserLogin):
        email = user_data.email.strip().lower()
        password = user_data.password

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, hashed_password FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            raise HTTPException(status_code=401, detail="Invalid email or password")

        user_id, user_email, hashed_pwd = row["id"], row["email"], row["hashed_password"]

        if not verify_password(password, hashed_pwd):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        access_token = create_access_token(data={"sub": user_email, "user_id": user_id})
        return {"access_token": access_token, "token_type": "bearer"}

    @app.get("/auth/me")
    def read_users_me(current_user: dict = Depends(get_current_user)):
        return {"user": current_user}

    @app.post("/utils/password-strength")
    def analyze_password_strength(data: dict):
        pwd = str(data.get("password", ""))
        return calculate_password_strength(pwd)

    @app.post("/utils/generate-password")
    def generate_password(data: dict):
        length = int(data.get("length", 16))
        use_uppercase = bool(data.get("use_uppercase", True))
        use_lowercase = bool(data.get("use_lowercase", True))
        use_digits = bool(data.get("use_digits", True))
        use_symbols = bool(data.get("use_symbols", True))

        gen_pwd = generate_secure_password(length, use_uppercase, use_lowercase, use_digits, use_symbols)
        return {
            "password": gen_pwd,
            "strength": calculate_password_strength(gen_pwd)
        }

    @app.post("/entries", status_code=status.HTTP_201_CREATED, response_model=EntryResponse)
    def create_entry(entry: EntryCreate, current_user: dict = Depends(get_current_user)):
        site_name = entry.site_name.strip()
        site_username = entry.site_username.strip()
        raw_password = entry.password

        if not site_name or not site_username or not raw_password:
            raise HTTPException(status_code=400, detail="All fields are required")

        enc_pwd, nonce = encrypt(raw_password)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO entries (user_id, site_name, site_username, encrypted_password, nonce)
            VALUES (?, ?, ?, ?, ?)
        """, (current_user["user_id"], site_name, site_username, enc_pwd, nonce))
        entry_id = cursor.lastrowid
        conn.commit()

        cursor.execute("SELECT created_at, updated_at FROM entries WHERE id = ?", (entry_id,))
        row = cursor.fetchone()
        conn.close()

        return EntryResponse(
            id=entry_id,
            site_name=site_name,
            site_username=site_username,
            masked_password="••••••••",
            created_at=str(row["created_at"]) if row else None,
            updated_at=str(row["updated_at"]) if row else None
        )

    @app.get("/entries", response_model=List[EntryResponse])
    def list_entries(q: Optional[str] = None, current_user: dict = Depends(get_current_user)):
        conn = get_db_connection()
        cursor = conn.cursor()

        if q and q.strip():
            query_term = f"%{q.strip().lower()}%"
            cursor.execute("""
                SELECT id, site_name, site_username, created_at, updated_at
                FROM entries
                WHERE user_id = ? AND (LOWER(site_name) LIKE ? OR LOWER(site_username) LIKE ?)
                ORDER BY id DESC
            """, (current_user["user_id"], query_term, query_term))
        else:
            cursor.execute("""
                SELECT id, site_name, site_username, created_at, updated_at
                FROM entries
                WHERE user_id = ?
                ORDER BY id DESC
            """, (current_user["user_id"],))

        rows = cursor.fetchall()
        conn.close()

        return [
            EntryResponse(
                id=r["id"],
                site_name=r["site_name"],
                site_username=r["site_username"],
                masked_password="••••••••",
                created_at=str(r["created_at"]),
                updated_at=str(r["updated_at"])
            ) for r in rows
        ]

    @app.get("/entries/{entry_id}", response_model=EntryDetailResponse)
    def get_entry(entry_id: int, current_user: dict = Depends(get_current_user)):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, site_name, site_username, encrypted_password, nonce, created_at, updated_at
            FROM entries
            WHERE id = ? AND user_id = ?
        """, (entry_id, current_user["user_id"]))
        row = cursor.fetchone()
        conn.close()

        if not row:
            raise HTTPException(status_code=404, detail="Entry not found or access denied")

        decrypted_pwd = decrypt(row["encrypted_password"], row["nonce"])

        return EntryDetailResponse(
            id=row["id"],
            site_name=row["site_name"],
            site_username=row["site_username"],
            password=decrypted_pwd,
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"])
        )

    @app.put("/entries/{entry_id}", response_model=EntryResponse)
    def update_entry(entry_id: int, entry_update: EntryUpdate, current_user: dict = Depends(get_current_user)):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM entries WHERE id = ? AND user_id = ?", (entry_id, current_user["user_id"]))
        if not cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=404, detail="Entry not found or access denied")

        updates = []
        params = []

        if entry_update.site_name is not None and entry_update.site_name.strip():
            updates.append("site_name = ?")
            params.append(entry_update.site_name.strip())

        if entry_update.site_username is not None and entry_update.site_username.strip():
            updates.append("site_username = ?")
            params.append(entry_update.site_username.strip())

        if entry_update.password is not None and entry_update.password:
            enc_pwd, nonce = encrypt(entry_update.password)
            updates.append("encrypted_password = ?")
            params.append(enc_pwd)
            updates.append("nonce = ?")
            params.append(nonce)

        if not updates:
            conn.close()
            raise HTTPException(status_code=400, detail="No fields to update")

        updates.append("updated_at = CURRENT_TIMESTAMP")
        params.append(entry_id)
        params.append(current_user["user_id"])

        query = f"UPDATE entries SET {', '.join(updates)} WHERE id = ? AND user_id = ?"
        cursor.execute(query, tuple(params))
        conn.commit()

        cursor.execute("SELECT id, site_name, site_username, created_at, updated_at FROM entries WHERE id = ?", (entry_id,))
        row = cursor.fetchone()
        conn.close()

        return EntryResponse(
            id=row["id"],
            site_name=row["site_name"],
            site_username=row["site_username"],
            masked_password="••••••••",
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"])
        )

    @app.delete("/entries/{entry_id}")
    def delete_entry(entry_id: int, current_user: dict = Depends(get_current_user)):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM entries WHERE id = ? AND user_id = ?", (entry_id, current_user["user_id"]))
        rows = cursor.rowcount
        conn.commit()
        conn.close()

        if rows == 0:
            raise HTTPException(status_code=404, detail="Entry not found or access denied")

        return {"message": f"Entry {entry_id} deleted successfully"}

else:
    app = None

if __name__ == "__main__":
    if HAS_FASTAPI:
        import uvicorn
        uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
    else:
        from server import run_server
        run_server()
