from __future__ import annotations

import base64
import hashlib
import json

import httpx
import pytest
import respx
from allowly_receipt_format import canonicalize
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from allowly import Allowly, AllowlyProtocolError
from allowly.verify import (
    SEAL_PROFILE,
    SealInputError,
    hash_seal_json,
    load_keys_from_json,
    verify_seal_json,
)


BASE = "https://api.example.com"
RECORD_SHA256 = "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
PENDING_RECEIPT = {
    "status": "pending",
    "receipt_id": "rcp_abc",
    "ready_at_estimate": "2026-04-21T14:32:18.482Z",
    "url": f"{BASE}/v1/receipts/rcp_abc",
}
SIGNED_RECEIPT = {
    "schema_version": "4",
    "receipt_id": "rcp_abc",
    "action": "record.seal",
    "signature": "signature",
}


@respx.mock
@pytest.mark.asyncio
async def test_seal_hashes_locally_posts_only_digest_and_polls() -> None:
    posted: dict = {}

    def seal_handler(request: httpx.Request) -> httpx.Response:
        posted.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "request_id": "req_123",
                "profile": SEAL_PROFILE,
                "record_sha256": RECORD_SHA256,
                "decision": "allow",
                "reason": "authorization_granted_action_active",
                "receipt": PENDING_RECEIPT,
            },
        )

    post = respx.post(f"{BASE}/v1/seal").mock(side_effect=seal_handler)
    get = respx.get(f"{BASE}/v1/receipts/rcp_abc").mock(
        return_value=httpx.Response(
            200,
            json={"status": "signed", "receipt": SIGNED_RECEIPT},
        )
    )
    async with Allowly(api_key="test-key", base_url=BASE) as client:
        result = await client.seal(
            '{"b":2,"a":1}',
            request_id="req_123",
            metadata={"source": "workflow"},
            poll_interval=0.001,
        )

    assert result.record_sha256 == RECORD_SHA256
    assert result.receipt == SIGNED_RECEIPT
    assert posted == {
        "request_id": "req_123",
        "profile": SEAL_PROFILE,
        "record_sha256": RECORD_SHA256,
        "metadata": {"source": "workflow"},
    }
    assert post.call_count == 1
    assert get.call_count == 1


@respx.mock
@pytest.mark.asyncio
async def test_seal_value_returns_immediately_signed_receipt() -> None:
    route = respx.post(f"{BASE}/v1/seal").mock(
        return_value=httpx.Response(
            200,
            json={
                "request_id": "req_value",
                "profile": SEAL_PROFILE,
                "record_sha256": RECORD_SHA256,
                "decision": "allow",
                "reason": "authorization_granted_action_active",
                "receipt": {"status": "signed", "receipt": SIGNED_RECEIPT},
            },
        )
    )
    async with Allowly(api_key="test-key", base_url=BASE) as client:
        result = await client.seal_value(
            {"b": 2, "a": 1},
            request_id="req_value",
        )

    assert result.receipt == SIGNED_RECEIPT
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_seal_rejects_ambiguous_json_before_network() -> None:
    async with Allowly(api_key="test-key", base_url=BASE) as client:
        with pytest.raises(SealInputError) as exc_info:
            await client.seal('{"a":1,"\\u0061":2}', request_id="req_bad")
    assert exc_info.value.code == "duplicate_key"


@respx.mock
@pytest.mark.asyncio
async def test_seal_rejects_response_binding_mismatch() -> None:
    respx.post(f"{BASE}/v1/seal").mock(
        return_value=httpx.Response(
            200,
            json={
                "request_id": "req_other",
                "profile": SEAL_PROFILE,
                "record_sha256": RECORD_SHA256,
                "decision": "allow",
                "reason": "authorization_granted_action_active",
                "receipt": {"status": "signed", "receipt": SIGNED_RECEIPT},
            },
        )
    )
    async with Allowly(api_key="test-key", base_url=BASE) as client:
        with pytest.raises(AllowlyProtocolError, match="request_id does not match"):
            await client.seal('{"a":1,"b":2}', request_id="req_expected")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def test_verify_seal_reports_signature_and_record_match_separately() -> None:
    raw_json = '{"b":2,"a":1}'
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(32))
    public_key = private_key.public_key().public_bytes_raw()
    payload = {
        "schema_version": "4",
        "receipt_id": "rcp_seal",
        "workspace_id": "ws_test",
        "issued_at": "2026-04-21T14:32:17.482Z",
        "decision": "allow",
        "reason": "authorization_granted_action_active",
        "user_id": "allowly:seal",
        "agent_id": "allowly.seal",
        "action": "record.seal",
        "resource": None,
        "context": {
            "seal_profile": SEAL_PROFILE,
            "record_sha256": hash_seal_json(raw_json),
        },
        "authorization_id": "auth_seal",
        "engine_version": "2026-04-17.1",
        "alg": "Ed25519",
        "key_id": "seal-key/v1",
    }
    receipt = {**payload, "signature": _b64url(private_key.sign(canonicalize(payload)))}
    keys = load_keys_from_json(
        {
            "workspace_id": "ws_test",
            "keys": [
                {
                    "key_id": "seal-key/v1",
                    "alg": "Ed25519",
                    "public_key": _b64url(public_key),
                    "public_key_fingerprint": (
                        f"sha256:{hashlib.sha256(public_key).hexdigest()}"
                    ),
                    "active_from": "2026-01-01T00:00:00.000Z",
                    "active_until": None,
                }
            ],
        }
    )

    matched = verify_seal_json(
        raw_json,
        receipt,
        keys,
        expected_workspace_id="ws_test",
    )
    mismatched = verify_seal_json(
        '{"a":2}',
        receipt,
        keys,
        expected_workspace_id="ws_test",
    )
    invalid_signature = verify_seal_json(
        raw_json,
        {**receipt, "signature": "A" * 86},
        keys,
        expected_workspace_id="ws_test",
    )

    assert (matched.signature_verified, matched.record_matches, matched.failure_reason) == (
        True,
        True,
        None,
    )
    assert (
        mismatched.signature_verified,
        mismatched.record_matches,
        mismatched.failure_reason,
    ) == (True, False, "record_mismatch")
    assert (
        invalid_signature.signature_verified,
        invalid_signature.record_matches,
        invalid_signature.failure_reason,
    ) == (False, False, "receipt_verification_failed")
