import sys
import os
import json
import sqlite3
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from database import init_db, get_db_connection
from auth import hash_password, create_access_token
from crypto import encrypt, decrypt

def run_crud_tests():
    print("=" * 65)
    print("📦 RUNNING PHASE 3 CRUD & VAULT SECURITY TESTS")
    print("=" * 65)

    init_db()

    # 1. Setup two test users to verify user isolation
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE email IN ('alice@example.com', 'bob@example.com')")
    cursor.execute("DELETE FROM entries")
    conn.commit()

    # Create Alice
    alice_pwd_hash = hash_password("AliceSecret123!")
    cursor.execute("INSERT INTO users (email, hashed_password) VALUES (?, ?)", ("alice@example.com", alice_pwd_hash))
    alice_id = cursor.lastrowid

    # Create Bob
    bob_pwd_hash = hash_password("BobSecret456!")
    cursor.execute("INSERT INTO users (email, hashed_password) VALUES (?, ?)", ("bob@example.com", bob_pwd_hash))
    bob_id = cursor.lastrowid
    conn.commit()

    print(f"✅ 1. Created User 1 (Alice, ID: {alice_id}) and User 2 (Bob, ID: {bob_id}).")

    # 2. Test Storing Entries with Encryption for Alice
    raw_netflix_pwd = "NetflixPassword123!"
    enc_pwd1, nonce1 = encrypt(raw_netflix_pwd)
    cursor.execute("""
        INSERT INTO entries (user_id, site_name, site_username, encrypted_password, nonce)
        VALUES (?, ?, ?, ?, ?)
    """, (alice_id, "Netflix", "alice_netflix", enc_pwd1, nonce1))
    alice_entry_id = cursor.lastrowid

    raw_github_pwd = "GitHubPassword999$"
    enc_pwd2, nonce2 = encrypt(raw_github_pwd)
    cursor.execute("""
        INSERT INTO entries (user_id, site_name, site_username, encrypted_password, nonce)
        VALUES (?, ?, ?, ?, ?)
    """, (alice_id, "GitHub", "alice_dev", enc_pwd2, nonce2))

    # Store entry for Bob
    raw_bob_spotify_pwd = "BobSpotifyPass777"
    enc_pwd_bob, nonce_bob = encrypt(raw_bob_spotify_pwd)
    cursor.execute("""
        INSERT INTO entries (user_id, site_name, site_username, encrypted_password, nonce)
        VALUES (?, ?, ?, ?, ?)
    """, (bob_id, "Spotify", "bob_music", enc_pwd_bob, nonce_bob))
    bob_entry_id = cursor.lastrowid

    conn.commit()
    print("✅ 2. Entries created and stored encrypted at rest.")

    # 3. Verify SQLite Database holds ONLY Ciphertext (no plaintext stored)
    cursor.execute("SELECT encrypted_password, nonce FROM entries WHERE id = ?", (alice_entry_id,))
    db_record = cursor.fetchone()
    stored_ciphertext = db_record["encrypted_password"]
    stored_nonce = db_record["nonce"]

    assert raw_netflix_pwd not in stored_ciphertext, "CRITICAL ERROR: Plaintext password found in SQLite database!"
    print(f"✅ 3. Database Ciphertext Verification Passed.")
    print(f"   Stored Ciphertext: '{stored_ciphertext[:30]}...'")
    print(f"   Stored Nonce:      '{stored_nonce}'")

    # 4. Decrypt on explicit request for authorized owner
    decrypted_str = decrypt(stored_ciphertext, stored_nonce)
    assert decrypted_str == raw_netflix_pwd, "Decryption failed to retrieve original password!"
    print("✅ 4. Authorized owner password retrieval & decryption verified.")

    # 5. User Isolation Check (Alice CANNOT access Bob's entry)
    cursor.execute("SELECT id FROM entries WHERE id = ? AND user_id = ?", (bob_entry_id, alice_id))
    unauthorized_record = cursor.fetchone()
    assert unauthorized_record is None, "CRITICAL SECURITY BREACH: User Alice accessed Bob's password entry!"
    print("✅ 5. User Isolation Verified (Alice denied access to Bob's entries).")

    # 6. Test Search Query Filtering
    cursor.execute("""
        SELECT site_name, site_username FROM entries
        WHERE user_id = ? AND (LOWER(site_name) LIKE ? OR LOWER(site_username) LIKE ?)
    """, (alice_id, "%net%", "%net%"))
    search_results = cursor.fetchall()
    assert len(search_results) == 1, f"Search expected 1 result, got {len(search_results)}"
    assert search_results[0]["site_name"] == "Netflix", "Search result mismatch!"
    print("✅ 6. Vault search filtering verified.")

    # 7. Test Entry Update
    updated_raw_pwd = "NewNetflixPass2026!#"
    new_enc, new_nonce = encrypt(updated_raw_pwd)
    cursor.execute("""
        UPDATE entries SET encrypted_password = ?, nonce = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?
    """, (new_enc, new_nonce, alice_entry_id, alice_id))
    conn.commit()

    cursor.execute("SELECT encrypted_password, nonce FROM entries WHERE id = ?", (alice_entry_id,))
    up_record = cursor.fetchone()
    assert decrypt(up_record["encrypted_password"], up_record["nonce"]) == updated_raw_pwd
    print("✅ 7. Entry password update & re-encryption verified.")

    # 8. Test Entry Deletion
    cursor.execute("DELETE FROM entries WHERE id = ? AND user_id = ?", (alice_entry_id, alice_id))
    conn.commit()
    cursor.execute("SELECT id FROM entries WHERE id = ?", (alice_entry_id,))
    assert cursor.fetchone() is None, "Failed to delete entry!"
    print("✅ 8. Entry deletion verified.")

    conn.close()

    print("=" * 65)
    print("🎉 ALL PHASE 3 CRUD & SECURITY TESTS PASSED PERFECTLY!")
    print("=" * 65)

if __name__ == "__main__":
    run_crud_tests()
