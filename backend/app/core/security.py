"""JWT authentication, Argon2 password hashing, and role-based access control."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from pydantic import BaseModel

from app.core.config import Settings


class UserRole(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    PRIVACY_OFFICER = "privacy_officer"
    ADMIN = "admin"


class TokenPayload(BaseModel):
    sub: str
    user_id: str
    role: UserRole
    exp: int
    iat: int


class AuthenticationError(Exception):
    """Raised when credentials or JWT tokens are invalid or expired."""


_password_hasher = PasswordHasher()


def hash_password(plain_password: str) -> str:
    """Hash a password using Argon2id."""
    return _password_hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against an Argon2id hash."""
    try:
        return _password_hasher.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False


def create_access_token(
    *,
    subject: str,
    user_id: str,
    role: UserRole | str,
    settings: Settings,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed HS256 JWT containing user identity and role claims."""
    now = datetime.now(UTC)
    expire = now + (expires_delta or timedelta(minutes=settings.jwt_access_token_expire_minutes))
    payload = {
        "sub": subject,
        "user_id": user_id,
        "role": UserRole(role).value,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str, settings: Settings) -> TokenPayload:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "user_id", "role", "exp", "iat"]},
        )
        return TokenPayload(**payload)
    except Exception as exc:
        raise AuthenticationError("Invalid or expired authentication token") from exc
