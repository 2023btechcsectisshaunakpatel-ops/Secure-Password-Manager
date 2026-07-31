import secrets
import string
import math
from typing import Dict, Any, List

def calculate_password_strength(password: str) -> Dict[str, Any]:
    """
    Evaluates password strength based on entropy, length, character diversity, and patterns.
    Returns score (0-4), score_percent (0-100), label, and feedback.
    """
    if not password:
        return {
            "score": 0,
            "score_percent": 0,
            "label": "Very Weak",
            "feedback": ["Password cannot be empty"],
            "has_lowercase": False,
            "has_uppercase": False,
            "has_digits": False,
            "has_symbols": False,
            "length": 0
        }

    length = len(password)
    has_lowercase = any(c in string.ascii_lowercase for c in password)
    has_uppercase = any(c in string.ascii_uppercase for c in password)
    has_digits = any(c in string.digits for c in password)
    has_symbols = any(c in string.punctuation or not c.isalnum() for c in password)

    charset_size = 0
    if has_lowercase: charset_size += 26
    if has_uppercase: charset_size += 26
    if has_digits: charset_size += 10
    if has_symbols: charset_size += 32

    # Entropy calculation: length * log2(charset_size)
    entropy = length * math.log2(charset_size) if charset_size > 0 else 0

    feedback: List[str] = []
    if length < 8:
        feedback.append("Use at least 8 characters (12+ recommended)")
    if not has_uppercase:
        feedback.append("Add uppercase letters (A-Z)")
    if not has_lowercase:
        feedback.append("Add lowercase letters (a-z)")
    if not has_digits:
        feedback.append("Add numbers (0-9)")
    if not has_symbols:
        feedback.append("Add special symbols (!@#$%^&*)")

    # Score rating based on entropy
    if entropy < 28 or length < 6:
        score = 0
        label = "Very Weak"
        score_percent = max(10, min(25, int(entropy)))
    elif entropy < 36 or length < 8:
        score = 1
        label = "Weak"
        score_percent = 35
    elif entropy < 52:
        score = 2
        label = "Fair"
        score_percent = 55
    elif entropy < 70:
        score = 3
        label = "Strong"
        score_percent = 80
    else:
        score = 4
        label = "Very Strong"
        score_percent = 100

    if not feedback:
        feedback.append("Great password! Extremely strong.")

    return {
        "score": score,
        "score_percent": score_percent,
        "label": label,
        "entropy": round(entropy, 1),
        "feedback": feedback,
        "has_lowercase": has_lowercase,
        "has_uppercase": has_uppercase,
        "has_digits": has_digits,
        "has_symbols": has_symbols,
        "length": length
    }


def generate_secure_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True
) -> str:
    """
    Generates a cryptographically secure random password using Python's 'secrets' module (CSPRNG).
    Guarantees inclusion of enabled character sets.
    """
    if length < 4:
        length = 4
    if length > 128:
        length = 128

    pools: List[str] = []
    guaranteed_chars: List[str] = []

    if use_lowercase:
        pools.append(string.ascii_lowercase)
        guaranteed_chars.append(secrets.choice(string.ascii_lowercase))
    if use_uppercase:
        pools.append(string.ascii_uppercase)
        guaranteed_chars.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        pools.append(string.digits)
        guaranteed_chars.append(secrets.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        pools.append(symbols)
        guaranteed_chars.append(secrets.choice(symbols))

    # Default fallback if no pool chosen
    if not pools:
        pools.append(string.ascii_lowercase + string.digits)
        guaranteed_chars.append(secrets.choice(string.ascii_lowercase))

    all_chars = "".join(pools)
    remaining_length = length - len(guaranteed_chars)

    random_chars = [secrets.choice(all_chars) for _ in range(max(0, remaining_length))]
    password_list = guaranteed_chars + random_chars

    # Cryptographically shuffle password
    secrets.SystemRandom().shuffle(password_list)
    return "".join(password_list)
