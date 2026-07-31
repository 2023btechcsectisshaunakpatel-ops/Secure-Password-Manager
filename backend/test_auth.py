import sys
import os
import json
import sqlite3
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from database import init_db, get_db_connection
from auth import hash_password, verify_password, create_access_token, decode_access_token

def run_tests():
    print("=" * 60)
    print("🧪 RUNNING PHASE 1 AUTHENTICATION & SECURITY TESTS")
    print("=" * 60)

    # 1. Initialize DB
    init_db()
    print("✅ 1. Database initialized and 'users' table verified.")

    # Clean up test user if exists
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE email = ?", ("testuser@example.com",))
    conn.commit()

    # 2. Test Password Hashing (bcrypt / PBKDF2)
    raw_password = "MySecretPassword123!"
    hashed = hash_password(raw_password)
    print(f"✅ 2. Password hashed successfully.")
    print(f"   Raw Password: '{raw_password}'")
    print(f"   Hashed Value: '{hashed[:30]}...'")

    assert raw_password not in hashed, "CRITICAL ERROR: Plaintext password found in hash!"
    assert verify_password(raw_password, hashed) is True, "Password verification failed for correct password!"
    assert verify_password("WrongPassword123", hashed) is False, "Password verification passed for WRONG password!"
    print("✅ 3. Password verification logic passed (correct -> True, wrong -> False).")

    # 3. Test Register Flow & Database Persistence
    cursor.execute("INSERT INTO users (email, hashed_password) VALUES (?, ?)", ("testuser@example.com", hashed))
    user_id = cursor.lastrowid
    conn.commit()

    cursor.execute("SELECT id, email, hashed_password FROM users WHERE email = ?", ("testuser@example.com",))
    db_row = cursor.fetchone()
    conn.close()

    assert db_row is not None, "User not found in DB!"
    assert db_row["hashed_password"] == hashed, "Database hash mismatch!"
    assert raw_password not in db_row["hashed_password"], "Plaintext password stored in DB!"
    print(f"✅ 4. User registered and stored in SQLite database. User ID: {user_id}")

    # 4. Test JWT Token Generation & Verification
    token = create_access_token(data={"sub": "testuser@example.com", "user_id": user_id})
    print(f"✅ 5. JWT Token generated: {token[:25]}...")

    payload = decode_access_token(token)
    assert payload is not None, "Failed to decode valid JWT!"
    assert payload["sub"] == "testuser@example.com", f"Payload 'sub' mismatch: {payload.get('sub')}"
    assert payload["user_id"] == user_id, f"Payload 'user_id' mismatch: {payload.get('user_id')}"
    print(f"✅ 6. JWT Token decoded and verified successfully. Subject: {payload['sub']}")

    # 5. Invalid Token Test
    invalid_token = token[:-5] + "XXXXX"
    invalid_payload = decode_access_token(invalid_token)
    assert invalid_payload is None, "Tampered JWT was accepted!"
    print("✅ 7. Tampered JWT signature rejection verified.")

    print("=" * 60)
    print("🎉 ALL PHASE 1 AUTHENTICATION TESTS PASSED PERFECTLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
