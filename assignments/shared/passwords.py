from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError


def hash_password(password: str) -> str:
    """Transform a plaintext password into a secure storable hash using Argon2id.
    
    Args:
        password: The plaintext password to hash.
        
    Returns:
        A secure hash string that can be stored in the database.
    """
    hasher = PasswordHasher()
    return hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a login password against a stored Argon2id hash.
    
    Args:
        password: The plaintext password provided at login.
        stored_hash: The hash stored in the database.
        
    Returns:
        True if the password matches the hash, False otherwise.
        Fails closed: returns False for malformed hashes or mismatches.
    """
    hasher = PasswordHasher()
    try:
        hasher.verify(stored_hash, password)
        return True
    except (InvalidHash, VerifyMismatchError):
        return False
