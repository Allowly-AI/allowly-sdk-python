from __future__ import annotations

import hashlib

import httpx
import pytest

from allowly.verify import (
    VerificationError,
    clear_keys_doc_cache,
    fetch_keys_doc,
    load_keys_from_json,
)


VALID_DOC = {
    "workspace_id": "ws_1",
    "keys": [
        {
            "key_id": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
            "alg": "Ed25519",
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "active_from": "2026-01-01T00:00:00Z",
            "active_until": None,
        }
    ],
}


@pytest.fixture(autouse=True)
def _clear_cache():
    clear_keys_doc_cache()


def _client_for(body: str, status_code: int = 200) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, text=body)

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
    body = httpx.Response(200, json=VALID_DOC).text
    client = _client_for(body)
    expected_sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()

    assert fetch_keys_doc(
        "ws_1",
        base_url="https://api.example.com",
        expected_sha256=expected_sha256,
        client=client,
    ) == VALID_DOC


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
