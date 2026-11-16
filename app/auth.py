"""Small authentication module used for the DevOps TP N°3."""
from __future__ import annotations

import time
from typing import Any

MAX_ATTEMPTS = 3
LOCKOUT_SECONDS = 300

# username -> stored password value
users: dict[str, str] = {}

# username -> number of consecutive failed attempts
attempts: dict[str, int] = {}

# username -> Unix timestamp at which the lockout expires
blocked_until: dict[str, float] = {}

GENERIC_ERROR = "Identifiants incorrects"


def _valid_username(username: Any) -> bool:
    if not isinstance(username, str):
        return False
    if not (3 <= len(username) <= 32):
        return False
    return all(ch.isalnum() or ch in "._-" for ch in username)


def _valid_password(password: Any) -> bool:
    return isinstance(password, str) and 12 <= len(password) <= 128


import hashlib
import secrets


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16).hex()

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        600000
    )

    return f"pbkdf2_sha256${600000}${salt}${hashed.hex()}"




def _verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, iterations, salt, stored_hash = encoded_hash.split("$")

        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations)

        if iterations <= 0 or iterations > 10000000:
            return False

        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt),
            iterations
        )

        return secrets.compare_digest(
            new_hash.hex(),
            stored_hash
        )

    except (ValueError, TypeError):
        return False


def register_user(username: Any, password: Any) -> bool:
    """Register a user. Return False for invalid or duplicate credentials."""
    if not _valid_username(username) or not _valid_password(password):
        return False
    if username in users:
        return False

    users[username] = _hash_password(password)
    attempts.pop(username, None)
    blocked_until.pop(username, None)
    return True



def authenticate(username: Any, password: Any) -> dict[str, Any]:
    """Authenticate a user and return a result dictionary."""

    if not _valid_username(username) or not isinstance(password, str):
        return {"success": False, "message": GENERIC_ERROR}

    now = time.time()

    # Check whether the account is locked
    if username in blocked_until:
        if blocked_until[username] > now:
            return {"success": False, "message": GENERIC_ERROR}

        # Lockout expired: reset attempts
        blocked_until.pop(username, None)
        attempts.pop(username, None)

    # Get stored password hash
    encoded_hash = users.get(username)

    if encoded_hash is None:
        return {"success": False, "message": GENERIC_ERROR}

    # Verify password
    if not _verify_password(password, encoded_hash):
        _record_failure(username, now)
        return {"success": False, "message": GENERIC_ERROR}

    # Successful authentication
    attempts.pop(username, None)
    blocked_until.pop(username, None)

    return {
        "success": True,
        "message": "Connexion reussie"
    }


def _record_failure(username: str, now: float) -> None:
    attempts[username] = attempts.get(username, 0) + 1

    if attempts[username] >= MAX_ATTEMPTS:
        blocked_until[username] = now + LOCKOUT_SECONDS


def reset_attempts() -> None:
    """Clear lockout state. Intended for tests and controlled administration."""
    attempts.clear()
    blocked_until.clear()


def reset_state() -> None:
    """Clear all in-memory state. Intended for isolated automated tests."""
    users.clear()
    reset_attempts()
