import os
import json
import time
import base64
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from pathlib import Path

# Load env variables
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).parent / ".env")
except ImportError:
    pass

SECRET_KEY = os.getenv("SECRET_KEY", "secret_jwt_key_32_bytes_long_secure_token_key_change_me")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

# Check passlib / bcrypt
try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    HAS_PASSLIB = True
except ImportError:
    HAS_PASSLIB = False

# Check python-jose or PyJWT
try:
    from jose import jwt, JWTError
    HAS_JOSE = True
except ImportError:
    try:
        import jwt
        JWTError = jwt.PyJWTError
        HAS_JOSE = True
    except ImportError:
        HAS_JOSE = False

def hash_password(password: str) -> str:
    """Hash password with bcrypt if available, else PBKDF2-HMAC-SHA256."""
    if HAS_PASSLIB:
        return pwd_context.hash(password)
    
    # Fallback to standard library PBKDF2 with salt
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return f"pbkdf2:sha256:100000${base64.b64encode(salt).decode('utf-8')}${base64.b64encode(dk).decode('utf-8')}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash."""
    if HAS_PASSLIB and not hashed_password.startswith("pbkdf2:"):
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except Exception:
            pass

    if hashed_password.startswith("pbkdf2:"):
        try:
            parts = hashed_password.split("$")
            if len(parts) == 3:
                algo_info, salt_b64, dk_b64 = parts
                iterations = int(algo_info.split(":")[2])
                salt = base64.b64decode(salt_b64)
                target_dk = base64.b64decode(dk_b64)
                test_dk = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt, iterations)
                return hmac.compare_digest(test_dk, target_dk)
        except Exception:
            return False

    if HAS_PASSLIB:
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except Exception:
            return False

    return False

def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def _base64url_decode(s: str) -> bytes:
    padding = '=' * (4 - (len(s) % 4))
    return base64.urlsafe_b64decode(s + padding)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Generate JWT Token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": int(expire.timestamp())})

    if HAS_JOSE:
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    # Pure Python JWT implementation (HS256)
    header = {"alg": "HS256", "typ": "JWT"}
    header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
    payload_json = json.dumps(to_encode, separators=(',', ':')).encode('utf-8')

    segments = [
        _base64url_encode(header_json),
        _base64url_encode(payload_json)
    ]
    signing_input = ".".join(segments).encode('utf-8')
    signature = hmac.new(SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
    segments.append(_base64url_encode(signature))

    return ".".join(segments)

def decode_access_token(token: str) -> Optional[dict]:
    """Decode and verify JWT Token."""
    if HAS_JOSE:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except Exception:
            return None

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        
        header_b64, payload_b64, signature_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        expected_sig = hmac.new(SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
        actual_sig = _base64url_decode(signature_b64)

        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        payload_bytes = _base64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode('utf-8'))

        exp = payload.get("exp")
        if exp and time.time() > exp:
            return None

        return payload
    except Exception:
        return None
