"""Allowly-native agent credentials for the existing agent-token header."""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
import re
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Invalid Allowly agent credential")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Invalid Allowly agent credential") from exc
    if _b64url(decoded) != value:
        raise ValueError("Invalid Allowly agent credential")
    return decoded


class NativeAgentCredential:
    """Sign a short-lived agent token from a locally stored enrollment key.

    Pass ``credential.token`` as ``agent_token_supplier`` to ``Allowly``.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        if data.get("version") != 1 or data.get("provider") != "allowly":
            raise ValueError("Invalid Allowly agent credential")
        for field in ("workspace_id", "agent_id", "binding_id", "key_id"):
            value = data.get(field)
            if not isinstance(value, str) or not value:
                raise ValueError("Invalid Allowly agent credential")
            setattr(self, field, value)
        jwk = data.get("private_key_jwk")
        if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise ValueError("Invalid Allowly agent credential")
        private_value, public_value = jwk.get("d"), jwk.get("x")
        if not isinstance(private_value, str) or not isinstance(public_value, str):
            raise ValueError("Invalid Allowly agent credential")
        private_bytes = _decode(private_value)
        if len(private_bytes) != 32 or len(_decode(public_value)) != 32:
            raise ValueError("Invalid Allowly agent credential")
        self._key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        actual_public = self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        if actual_public != _decode(public_value):
            raise ValueError("Invalid Allowly agent credential")

    @classmethod
    def from_json(cls, value: str) -> NativeAgentCredential:
        parsed = json.loads(value)
        if not isinstance(parsed, dict):
            raise ValueError("Invalid Allowly agent credential")
        return cls(parsed)

    @classmethod
    def from_file(cls, path: str | Path) -> NativeAgentCredential:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    def token(self) -> str:
        now = int(time.time())
        header = _b64url(json.dumps(
            {"alg": "EdDSA", "typ": "JWT", "kid": self.key_id}, separators=(",", ":"),
        ).encode("utf-8"))
        claims = _b64url(json.dumps({
            "iss": "allowly-agent",
            "aud": self.workspace_id,
            "sub": self.agent_id,
            "bid": self.binding_id,
            "iat": now,
            "nbf": now,
            "exp": now + 60,
        }, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header}.{claims}".encode("ascii")
        return f"{header}.{claims}.{_b64url(self._key.sign(signing_input))}"
