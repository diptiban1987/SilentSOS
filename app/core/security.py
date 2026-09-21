"""Security primitives: Argon2id password hashing, JWT access tokens,
opaque rotating refresh tokens, device API keys.

Design notes
------------
* Passwords  — argon2-cffi PasswordHasher (Argon2id, memory-hard).
* Access JWT — HS256, short lived (default 15 min), carries sub/role/jti.
* Refresh    — 48-byte urlsafe random, stored ONLY as SHA-256, single-use
               (rotated on every refresh), revocable per-user.
* Device key — `ssos_` + 32-byte urlsafe random, stored ONLY as SHA-256.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from app.core.config import get_settings

_settings = get_settings()
_ph = PasswordHasher()  # argon2id defaults are production-grade

JWT_ALGORITHM = "HS256"
REFRESH_COOKIE_NAME = "ssos_refresh"


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_entropy_ok(password: str) -> bool:
    """Minimum policy: >=12 chars with upper, lower and digit."""
    if len(password) < 12:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    return has_upper and has_lower and has_digit


# --------------------------------------------------------------------------- #
# JWT access tokens
# --------------------------------------------------------------------------- #
def create_access_token(user_id: int, role: str) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=_settings.ACCESS_TOKEN_MINUTES)
    payload = {
        "sub": str(user_id),
        "role": role,
        "typ": "access",
        "jti": uuid.uuid4().hex,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, _settings.SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token, exp


class TokenError(Exception):
    """Raised when an access token is invalid/expired/wrong type."""


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            _settings.SECRET_KEY,
            algorithms=[JWT_ALGORITHM],  # exact allowlist — no alg confusion
            options={"require": ["exp", "sub", "typ"]},
        )
    except jwt.PyJWTError as exc:  # expired, bad signature, malformed…
        raise TokenError(str(exc)) from exc
    if payload.get("typ") != "access":
        raise TokenError("wrong token type")
    return payload


# --------------------------------------------------------------------------- #
# Refresh tokens (opaque, hashed at rest, single-use rotation)
# --------------------------------------------------------------------------- #
def new_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def refresh_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=_settings.REFRESH_TOKEN_DAYS)


# --------------------------------------------------------------------------- #
# Device API keys
# --------------------------------------------------------------------------- #
def new_device_key() -> str:
    return f"ssos_{secrets.token_urlsafe(32)}"


def hash_device_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Cookie helpers (refresh token transport)
# --------------------------------------------------------------------------- #
def refresh_cookie_kwargs() -> dict:
    return {
        "key": REFRESH_COOKIE_NAME,
        "httponly": True,
        "secure": _settings.is_prod,
        "samesite": "lax",
        "path": "/api/v1/auth",
        "max_age": _settings.REFRESH_TOKEN_DAYS * 24 * 3600,
    }


def clear_refresh_cookie_kwargs() -> dict:
    return {
        "key": REFRESH_COOKIE_NAME,
        "httponly": True,
        "secure": _settings.is_prod,
        "samesite": "lax",
        "path": "/api/v1/auth",
        "max_age": 0,
    }
