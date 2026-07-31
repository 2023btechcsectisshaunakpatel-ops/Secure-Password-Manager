import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from crypto import encrypt, decrypt, get_encryption_key, HAS_CRYPTOGRAPHY

def run_encryption_tests():
    print("=" * 65)
    print("🔐 RUNNING PHASE 2 AES-256 ENCRYPTION LAYER TESTS")
    print("=" * 65)

    engine_name = "AES-256-GCM (cryptography library)" if HAS_CRYPTOGRAPHY else "Authenticated AES-256-CTR + HMAC-SHA256"
    print(f"ℹ️ Engine Mode: {engine_name}")

    # 1. Key Verification
    key = get_encryption_key()
    assert len(key) == 32, f"Key must be 32 bytes (256 bits), got {len(key)} bytes!"
    print(f"✅ 1. Encryption Key loaded successfully ({len(key) * 8}-bit / {len(key)} bytes).")

    # 2. Encrypt Sample Stored Passwords
    sample_passwords = [
        "NetflixP@ssw0rd2026!",
        "Complex#Strong$Val1d_Pass_Key99!",
        "Short123",
        "UnicodePasswörd_🔐_Test"
    ]

    print("\n--- Testing Round-Trip Encrypt & Decrypt ---")
    for original_pw in sample_passwords:
        ciphertext_b64, nonce_b64 = encrypt(original_pw)
        
        # Verify ciphertext is masked and different from plaintext
        assert ciphertext_b64 != original_pw, "CRITICAL: Ciphertext is identical to plaintext!"
        assert original_pw not in ciphertext_b64, "CRITICAL: Plaintext leaked in ciphertext!"

        # Decrypt back
        decrypted_pw = decrypt(ciphertext_b64, nonce_b64)
        
        assert decrypted_pw == original_pw, f"Mismatch! Expected '{original_pw}', got '{decrypted_pw}'"
        print(f"  • Plaintext:  '{original_pw}'")
        print(f"    Ciphertext: '{ciphertext_b64[:32]}...'")
        print(f"    Nonce:      '{nonce_b64}'")
        print(f"    Decrypted:  '{decrypted_pw}' [VERIFIED MATCH ✅]")
        print("-" * 50)

    # 3. Test Nonce Uniqueness (AES-GCM Requirement)
    pw = "SamePassword123"
    c1, n1 = encrypt(pw)
    c2, n2 = encrypt(pw)
    assert n1 != n2, "CRITICAL SECURITY RISK: Reused nonce across encryption calls!"
    assert c1 != c2, "Ciphertext should differ across calls due to fresh nonces!"
    print("✅ 2. Nonce Uniqueness verified (fresh nonce generated per encryption operation).")

    # 4. Test Tamper Detection
    ciphertext_b64, nonce_b64 = encrypt("SecretNetflixPassword")
    # Tamper with the last character of base64 string
    tampered_c_b64 = ciphertext_b64[:-2] + ("X" if ciphertext_b64[-1] != "X" else "Y") + ciphertext_b64[-1]
    
    tamper_rejected = False
    try:
        decrypt(tampered_c_b64, nonce_b64)
    except ValueError as e:
        tamper_rejected = True
        print(f"✅ 3. Tamper rejection verified! Error caught as expected: {e}")

    assert tamper_rejected, "CRITICAL: Tampered ciphertext was decrypted without error!"

    print("\n" + "=" * 65)
    print("🎉 ALL PHASE 2 AES-256 ENCRYPTION TESTS PASSED PERFECTLY!")
    print("=" * 65)

if __name__ == "__main__":
    run_encryption_tests()
