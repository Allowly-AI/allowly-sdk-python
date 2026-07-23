from __future__ import annotations

import hashlib

import httpx
import pytest

from allowly.verify import (
    VerificationError,
    clear_keys_doc_cache,
    fetch_keys_doc,
    load_keys_from_json,
    verify_receipt,
)


VALID_DOC = {
    "workspace_id": "ws_1",
    "keys": [
        {
            "key_id": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
            "alg": "Ed25519",
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "active_from": "2026-01-01T00:00:00.000Z",
            "active_until": None,
        }
    ],
}

V2_DOC = {
    "workspace_id": "ws_test",
    "keys": [
        {
            "key_id": "test-key/v1",
            "alg": "Ed25519",
            "public_key": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "active_from": "2026-01-01T00:00:00.000Z",
            "active_until": None,
        }
    ],
}

V2_RECEIPT = {
    "schema_version": "3",
    "receipt_id": "rcp_01HXZMINIMAL0000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T14:32:17.482Z",
    "decision": "allow",
    "reason": "authorization_granted_action_active",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "action": "outreach.send",
    "resource": "edge:emp_8821:conn_9f2a",
    "context": {},
    "authorization_id": "auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",
    "engine_version": "2026-04-17.1",
    "alg": "Ed25519",
    "key_id": "test-key/v1",
    "signature": "O98ntdo49t38E6a2M-19qjaC-2TzTw8tYqOn-fsUAYzfyf0dWTx9uje9NQlkvCl-fP68o_ATkBSW3mpyguoODQ",
}


@pytest.fixture(autouse=True)
def _clear_cache():
    clear_keys_doc_cache()


def _client_for(body: str | bytes, status_code: int = 200) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, content=body)

    transport = httpx.MockTransport(handler)
    return httpx.Client(transport=transport)


def test_fetch_keys_doc_rejects_non_https():
    with pytest.raises(VerificationError, match="HTTPS"):
        fetch_keys_doc("ws_1", base_url="http://localhost:8000")


def test_fetch_keys_doc_caches_for_five_minutes():
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, json=VALID_DOC)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    first = fetch_keys_doc("ws_1", base_url="https://api.example.com", client=client)
    second = fetch_keys_doc("ws_1", base_url="https://api.example.com", client=client)

    assert first == VALID_DOC
    assert second == VALID_DOC
    assert calls["count"] == 1


def test_fetch_keys_doc_enforces_hash_pin():
    body = httpx.Response(200, json=VALID_DOC).content
    client = _client_for(body)
    expected_sha256 = hashlib.sha256(body).hexdigest()

    assert fetch_keys_doc(
        "ws_1",
        base_url="https://api.example.com",
        expected_sha256=expected_sha256,
        client=client,
    ) == VALID_DOC


def test_verify_receipt_requires_and_forwards_workspace_binding(monkeypatch):
    with pytest.raises(TypeError, match="expected_workspace_id"):
        verify_receipt({}, [])  # type: ignore[call-arg]

    seen = {}

    def verifier(receipt, public_keys, **kwargs):
        seen.update(kwargs)

    monkeypatch.setattr("allowly.verify._verify_receipt", verifier)
    verify_receipt({}, [], expected_workspace_id="ws_1")
    assert seen["expected_workspace_id"] == "ws_1"


def test_verify_v2_receipt_with_signed_algorithm_and_key_id():
    keys = load_keys_from_json(V2_DOC)

    verify_receipt(V2_RECEIPT, keys, expected_workspace_id="ws_test")


def test_fetch_keys_doc_encodes_workspace_id():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.raw_path
        return httpx.Response(200, json={**VALID_DOC, "workspace_id": "ws/1"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    fetch_keys_doc("ws/1", base_url="https://api.example.com", client=client)
    assert seen["path"] == b"/v1/workspaces/ws%2F1/keys"


def test_fetch_keys_doc_rejects_workspace_id_mismatch():
    body = httpx.Response(200, json={**VALID_DOC, "workspace_id": "ws_other"}).text
    client = _client_for(body)

    with pytest.raises(VerificationError, match="workspace_id mismatch"):
        fetch_keys_doc("ws_1", base_url="https://api.example.com", client=client)


def test_zero_ttl_bypasses_stale_cache():
    """cache_ttl_seconds=0 must not reuse an entry cached with a longer TTL."""
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, json=VALID_DOC)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    fetch_keys_doc("ws_1", base_url="https://api.example.com", cache_ttl_seconds=300, client=client)
    fetch_keys_doc("ws_1", base_url="https://api.example.com", cache_ttl_seconds=0, client=client)

    assert calls["count"] == 2


def test_returned_doc_is_isolated_from_cache():
    """Mutating the returned doc must not corrupt the cached copy."""
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, json=VALID_DOC)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    first = fetch_keys_doc("ws_1", base_url="https://api.example.com", client=client)
    first["keys"].clear()

    second = fetch_keys_doc("ws_1", base_url="https://api.example.com", client=client)
    assert calls["count"] == 1
    assert len(second["keys"]) == 1


def test_load_keys_from_json_rejects_malformed_doc():
    with pytest.raises(VerificationError):
        load_keys_from_json(
            {
                "workspace_id": "ws_1",
                "keys": [{**VALID_DOC["keys"][0], "public_key": "not-base64url??"}],
            }
        )


def test_fetch_keys_doc_default_client_path(monkeypatch):
    calls = {"count": 0, "closed": 0}

    class FakeClient:
        def __init__(self, *, timeout: float):
            assert timeout == 10.0

        def get(self, url: str) -> httpx.Response:
            calls["count"] += 1
            return httpx.Response(200, json=VALID_DOC, request=httpx.Request("GET", url))

        def close(self) -> None:
            calls["closed"] += 1

    monkeypatch.setattr(httpx, "Client", FakeClient)
    assert fetch_keys_doc("ws_1", base_url="https://api.example.com") == VALID_DOC
    assert calls == {"count": 1, "closed": 1}


def test_fetch_keys_doc_wraps_httpx_errors(monkeypatch):
    class FakeClient:
        def __init__(self, *, timeout: float):
            pass

        def get(self, url: str) -> httpx.Response:
            raise httpx.ConnectError("boom")

        def close(self) -> None:
            pass

    monkeypatch.setattr(httpx, "Client", FakeClient)
    with pytest.raises(VerificationError, match="failed to fetch keys document"):
        fetch_keys_doc("ws_1", base_url="https://api.example.com")
