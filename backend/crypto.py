import os
import base64
import secrets
import hashlib
import hmac
from pathlib import Path

# Load env variables
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).parent / ".env")
except ImportError:
    pass

# Try importing cryptography
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

def get_encryption_key() -> bytes:
    """
    Retrieve or derive a 32-byte (256-bit) AES key from environment variable ENCRYPTION_KEY.
    Returns 32 raw bytes.
    """
    key_str = os.getenv("ENCRYPTION_KEY", "").strip()
    if key_str:
        # Check if 64-char hex string
        if len(key_str) == 64:
            try:
                return bytes.fromhex(key_str)
            except ValueError:
                pass
        # Check if base64 encoded
        try:
            decoded = base64.b64decode(key_str)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass
        # Fallback: hash the string to produce exactly 32 bytes
        return hashlib.sha256(key_str.encode('utf-8')).digest()

    # Check for local fallback key file
    key_file = Path(__file__).parent / ".aes_key"
    if key_file.exists():
        try:
            with open(key_file, "rb") as f:
                key = f.read()
                if len(key) == 32:
                    return key
        except Exception:
            pass

    # Generate new random 32-byte key and persist locally
    new_key = secrets.token_bytes(32)
    try:
        with open(key_file, "wb") as f:
            f.write(new_key)
    except Exception:
        pass
    return new_key


# =====================================================================
# Pure Python AES-256 Engine (Fallback when 'cryptography' is missing)
# =====================================================================

SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p

def _key_expansion(key: bytes):
    w = list(key)
    for i in range(8, 60):
        temp = w[(i - 1) * 4: i * 4]
        if i % 8 == 0:
            temp = [SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
            temp[0] ^= RCON[i // 8]
        elif i % 8 == 4:
            temp = [SBOX[x] for x in temp]
        for j in range(4):
            w.append(w[(i - 8) * 4 + j] ^ temp[j])
    return [w[i * 16:(i + 1) * 16] for i in range(15)]

def _aes_encrypt_block(block: bytes, round_keys):
    state = list(block)
    for i in range(16):
        state[i] ^= round_keys[0][i]

    for r in range(1, 14):
        # SubBytes
        state = [SBOX[b] for b in state]
        # ShiftRows
        state = [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11]
        ]
        # MixColumns
        new_state = [0] * 16
        for c in range(4):
            col = state[c*4 : c*4+4]
            new_state[c*4 + 0] = _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]
            new_state[c*4 + 1] = col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]
            new_state[c*4 + 2] = col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)
            new_state[c*4 + 3] = _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2)
        state = new_state
        # AddRoundKey
        for i in range(16):
            state[i] ^= round_keys[r][i]

    # Final round
    state = [SBOX[b] for b in state]
    state = [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11]
    ]
    for i in range(16):
        state[i] ^= round_keys[14][i]

    return bytes(state)

def _aes_ctr_xcrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """AES-256 CTR mode encryption/decryption."""
    round_keys = _key_expansion(key)
    out = bytearray()
    counter = 1
    
    for i in range(0, len(data), 16):
        counter_block = nonce[:12] + counter.to_bytes(4, byteorder='big')
        keystream = _aes_encrypt_block(counter_block, round_keys)
        chunk = data[i : i + 16]
        for j in range(len(chunk)):
            out.append(chunk[j] ^ keystream[j])
        counter += 1

    return bytes(out)


# =====================================================================
# Main Encryption & Decryption APIs
# =====================================================================

def encrypt(plaintext: str, key: bytes = None) -> tuple[str, str]:
    """
    Encrypts a plaintext string using AES-256-GCM (or AES-256 CTR + HMAC-SHA256 fallback).
    
    Returns:
        tuple[str, str]: (ciphertext_b64, nonce_b64)
    """
    if not plaintext:
        raise ValueError("Plaintext to encrypt cannot be empty")

    if key is None:
        key = get_encryption_key()

    plaintext_bytes = plaintext.encode('utf-8')

    if HAS_CRYPTOGRAPHY:
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)  # 96-bit nonce for AES-GCM
        ciphertext_raw = aesgcm.encrypt(nonce, plaintext_bytes, None)
        ciphertext_b64 = base64.b64encode(ciphertext_raw).decode('utf-8')
        nonce_b64 = base64.b64encode(nonce).decode('utf-8')
        return ciphertext_b64, nonce_b64

    # Fallback: Authenticated AES-256-CTR with HMAC-SHA256
    nonce = secrets.token_bytes(12)
    ctr_ciphertext = _aes_ctr_xcrypt(key, nonce, plaintext_bytes)
    
    # Authenticate ciphertext + nonce using HMAC-SHA256 (32 bytes tag)
    mac_key = hashlib.sha256(key + b"HMAC-AUTHENTICATION-KEY").digest()
    tag = hmac.new(mac_key, nonce + ctr_ciphertext, hashlib.sha256).digest()

    full_payload = ctr_ciphertext + tag
    ciphertext_b64 = base64.b64encode(full_payload).decode('utf-8')
    nonce_b64 = base64.b64encode(nonce).decode('utf-8')

    return ciphertext_b64, nonce_b64


def decrypt(ciphertext_b64: str, nonce_b64: str, key: bytes = None) -> str:
    """
    Decrypts a base64 ciphertext and nonce back to the original plaintext string.
    
    Returns:
        str: Decrypted plaintext password
    """
    if not ciphertext_b64 or not nonce_b64:
        raise ValueError("Ciphertext and nonce are required for decryption")

    if key is None:
        key = get_encryption_key()

    try:
        ciphertext_raw = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
    except Exception as e:
        raise ValueError(f"Invalid base64 encoding in ciphertext or nonce: {e}")

    if HAS_CRYPTOGRAPHY:
        try:
            aesgcm = AESGCM(key)
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_raw, None)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed or data tampered: {e}")

    # Fallback: Authenticated AES-256-CTR verification & decryption
    if len(ciphertext_raw) < 32:
        raise ValueError("Invalid ciphertext length")

    ctr_ciphertext = ciphertext_raw[:-32]
    tag = ciphertext_raw[-32:]

    mac_key = hashlib.sha256(key + b"HMAC-AUTHENTICATION-KEY").digest()
    expected_tag = hmac.new(mac_key, nonce + ctr_ciphertext, hashlib.sha256).digest()

    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Decryption failed: MAC verification failed (data tampered or wrong key)")

    decrypted_bytes = _aes_ctr_xcrypt(key, nonce, ctr_ciphertext)
    return decrypted_bytes.decode('utf-8')
