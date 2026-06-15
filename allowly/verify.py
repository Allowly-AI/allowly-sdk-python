"""Offline Ed25519 receipt verification.

Wraps the receipt-format reference verifier. No network call needed —
fetch the workspace public keys once, cache them, verify locally forever.

    from allowly.verify import fetch_keys_doc, verify_receipt, load_keys_from_json

    keys_doc = fetch_keys_doc(workspace_id)
    keys = load_keys_from_json(keys_doc)
    verify_receipt(signed_receipt, keys)  # raises VerificationError if invalid
"""
from __future__ import annotations

import hashlib
import httpx
import json
import time
from typing import Any

# Offline verification is powered by the published reference verifier,
# allowly-receipt-format (import path allowly_receipt_format). It ships as an
# optional extra so the core SDK stays dependency-light:
#     pip install 'allowly[verifier]'
def _import_verifier():
    try:
        from allowly_receipt_format import (
            verify_receipt,
            load_keys_from_json,
            VerificationError,
            PublicKey,
        )
        return verify_receipt, load_keys_from_json, VerificationError, PublicKey
    except ImportError as exc:
        raise ImportError(
            "Receipt verification requires the allowly-receipt-format package. "
            "Install the verifier extra: pip install 'allowly[verifier]'"
        ) from exc


verify_receipt, _load_keys_from_json, VerificationError, PublicKey = _import_verifier()

DEFAULT_BASE_URL = "https://api.allowly.ai"
DEFAULT_KEYS_DOC_CACHE_TTL_SECONDS = 300
_keys_doc_cache: dict[tuple[str, str | None], tuple[float, dict[str, Any]]] = {}


def load_keys_from_json(doc: dict[str, Any]) -> list[PublicKey]:
    try:
        return _load_keys_from_json(doc)
    except VerificationError:
        raise
    except Exception as exc:
        raise VerificationError(str(exc)) from exc


def fetch_keys_doc(
    workspace_id: str,
    *,
    base_url: str = DEFAULT_BASE_URL,
    cache_ttl_seconds: int = DEFAULT_KEYS_DOC_CACHE_TTL_SECONDS,
    expected_sha256: str | None = None,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    base_url = base_url.rstrip("/")
    url = f"{base_url}/v1/workspaces/{workspace_id}/keys"
    if not url.startswith("https://"):
        raise VerificationError(f"keys document URL must use HTTPS: {url}")

    cache_key = (url, expected_sha256, cache_ttl_seconds)
    cached = _keys_doc_cache.get(cache_key)
    now = time.time()
    if cached and cached[0] > now:
        import copy
        return copy.deepcopy(cached[1])

    owns_client = client is None
    if client is None:
        client = httpx.Client(timeout=10.0)
    try:
        resp = client.get(url)
        resp.raise_for_status()
        body = resp.text
    except httpx.HTTPError as exc:
        raise VerificationError(f"failed to fetch keys document: {exc}") from exc
    finally:
        if owns_client:
            client.close()

    if expected_sha256 is not None:
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        if digest.lower() != expected_sha256.lower():
            raise VerificationError("keys document SHA-256 hash did not match expected pin")

    try:
        doc = json.loads(body)
    except json.JSONDecodeError as exc:
        raise VerificationError("keys document was not valid JSON") from exc
    if isinstance(doc, dict) and doc.get("workspace_id") != workspace_id:
        raise VerificationError(
            f"keys document workspace_id mismatch: got {doc.get('workspace_id')!r}, want {workspace_id!r}"
        )

    load_keys_from_json(doc)
    _keys_doc_cache[cache_key] = (now + cache_ttl_seconds, doc)
    import copy
    return copy.deepcopy(doc)


def clear_keys_doc_cache() -> None:
    _keys_doc_cache.clear()


__all__ = [
    "verify_receipt",
    "load_keys_from_json",
    "fetch_keys_doc",
    "clear_keys_doc_cache",
    "VerificationError",
    "PublicKey",
]
