import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import HTTPException

ISSUER = "zerotrustai-local"


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310000).hex()
    return f"{salt}${digest}"


def check_password(password: str, encoded: str) -> bool:
    salt, expected = encoded.split("$", 1)
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310000).hex()
    return hmac.compare_digest(actual, expected)


def issue_token(secret: str, subject: str, role: str, audience: str) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": subject,
            "role": role,
            "iss": ISSUER,
            "aud": audience,
            "iat": now,
            "exp": now + timedelta(minutes=15),
            "jti": secrets.token_hex(16),
        },
        secret,
        algorithm="HS256",
    )


def verify_token(header: str | None, secret: str, audience: str) -> dict:
    if not header or not header.startswith("Bearer "):
        raise HTTPException(401, "Bearer token required", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = jwt.decode(
            header[7:],
            secret,
            algorithms=["HS256"],
            audience=audience,
            issuer=ISSUER,
            options={"require": ["sub", "role", "exp", "iat", "iss", "aud", "jti"]},
        )
        if not isinstance(claims["sub"], str) or not isinstance(claims["role"], str):
            raise jwt.InvalidTokenError("Invalid identity claims")
        return claims
    except jwt.InvalidTokenError as exc:
        raise HTTPException(401, "Invalid or expired token") from exc
