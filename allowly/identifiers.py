from __future__ import annotations

import base64
import hashlib
import hmac

EMAIL_HMAC_VERSION = "v1"
EMAIL_HMAC_PREFIX = "email_hmac"


def normalize_email(email: str) -> str:
    """Normalize an email address for Allowly's local identifier helper."""
    normalized = email.strip().lower()
    if not normalized:
        raise ValueError("email must not be empty")
    return normalized


def from_email(email: str, *, pepper: str | bytes, version: str = EMAIL_HMAC_VERSION) -> str:
    """Return a stable opaque user_id derived locally from an email address.

    The raw email and pepper never leave the customer's application.
    """
    if version != EMAIL_HMAC_VERSION:
        raise ValueError("unsupported email identifier version")

    key = _pepper_bytes(pepper)
    message = normalize_email(email).encode("utf-8")
    digest = hmac.new(key, message, hashlib.sha256).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"{EMAIL_HMAC_PREFIX}:{version}:{encoded}"


def _pepper_bytes(pepper: str | bytes) -> bytes:
    if isinstance(pepper, str):
        encoded = pepper.encode("utf-8")
    elif isinstance(pepper, bytes):
        encoded = pepper
    else:
        raise TypeError("pepper must be str or bytes")
    if not encoded:
        raise ValueError("pepper must not be empty")
    return encoded


__all__ = [
    "EMAIL_HMAC_PREFIX",
    "EMAIL_HMAC_VERSION",
    "from_email",
    "normalize_email",
]
