import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from allowly import NativeAgentCredential


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_native_credential_signs_short_lived_bound_token() -> None:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    credential = NativeAgentCredential({
        "version": 1,
        "provider": "allowly",
        "workspace_id": "ws_123",
        "agent_id": "agent_123",
        "binding_id": "bind_123",
        "key_id": "key_123",
        "private_key_jwk": {"kty": "OKP", "crv": "Ed25519", "x": _encode(public), "d": _encode(private)},
    })

    first, second, third = credential.token().split(".")
    assert json.loads(_decode(first)) == {"alg": "EdDSA", "typ": "JWT", "kid": "key_123"}
    claims = json.loads(_decode(second))
    assert {key: claims[key] for key in ("iss", "aud", "sub", "bid")} == {
        "iss": "allowly-agent", "aud": "ws_123", "sub": "agent_123", "bid": "bind_123",
    }
    assert claims["exp"] - claims["iat"] == 60
    key.public_key().verify(_decode(third), f"{first}.{second}".encode("ascii"))


def test_native_credential_rejects_mismatched_key() -> None:
    first = Ed25519PrivateKey.generate()
    second = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="Invalid Allowly agent credential"):
        NativeAgentCredential({
            "version": 1, "provider": "allowly", "workspace_id": "ws", "agent_id": "agent",
            "binding_id": "binding", "key_id": "key",
            "private_key_jwk": {
                "kty": "OKP", "crv": "Ed25519",
                "x": _encode(first.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
                "d": _encode(second.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())),
            },
        })


def test_native_credential_rejects_noncanonical_private_key_encoding() -> None:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    private = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption(),
    )
    with pytest.raises(ValueError, match="Invalid Allowly agent credential"):
        NativeAgentCredential({
            "version": 1, "provider": "allowly", "workspace_id": "ws", "agent_id": "agent",
            "binding_id": "binding", "key_id": "key",
            "private_key_jwk": {
                "kty": "OKP", "crv": "Ed25519", "x": _encode(public), "d": _encode(private) + "!",
            },
        })
