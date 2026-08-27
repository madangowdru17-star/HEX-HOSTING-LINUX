"""
Password hashing.

Uses Werkzeug's generate_password_hash/check_password_hash (PBKDF2-SHA256
with a per-password random salt, or scrypt on newer Werkzeug) so we avoid
pulling in extra native-compiled dependencies like bcrypt while still
getting a salted, slow, industry-standard KDF. If you prefer bcrypt/argon2
in your deployment, swap the two functions below — nothing else in the
app needs to change.
"""
from werkzeug.security import generate_password_hash, check_password_hash

_HASH_METHOD = "pbkdf2:sha256:260000"


def hash_password(plain: str) -> str:
    return generate_password_hash(plain, method=_HASH_METHOD)


def verify_password(plain: str, stored: str) -> bool:
    if not stored or not plain:
        return False
    try:
        return check_password_hash(stored, plain)
    except Exception:
        return False


def is_hashed(value: str) -> bool:
    return bool(value) and value.startswith(("pbkdf2:", "scrypt:"))


PASSWORD_MIN_LENGTH = 8


def password_policy_errors(pwd: str):
    errors = []
    if not pwd or len(pwd) < PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {PASSWORD_MIN_LENGTH} characters.")
    if pwd and pwd.strip() == "":
        errors.append("Password cannot be blank.")
    if pwd and not any(c.isdigit() for c in pwd):
        errors.append("Password must contain at least one number.")
    if pwd and not any(c.isalpha() for c in pwd):
        errors.append("Password must contain at least one letter.")
    return errors
