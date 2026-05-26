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
import sys
import os
import time
from typing import Any

# Allow importing the reference verifier from the receipt-format repo when running
# inside the monorepo. In a standalone install, the verifier ships as allowly.verifier.
def _import_verifier():
    try:
        from allowly._verifier import verify_receipt, load_keys_from_json, VerificationError, PublicKey
        return verify_receipt, load_keys_from_json, VerificationError, PublicKey
    except ImportError:
        pass

    # Fallback: look for the receipt-format verifier relative to this workspace.
    _repo_verifier = os.path.join(
        os.path.dirname(__file__), "..", "..",
        "allowly-receipt-format", "verifiers", "python",
    )
    if os.path.isdir(_repo_verifier):
        sys.path.insert(0, _repo_verifier)
        from verifier import verify_receipt, load_keys_from_json, VerificationError, PublicKey  # type: ignore
        return verify_receipt, load_keys_from_json, VerificationError, PublicKey

    raise ImportError(
        "Receipt verifier not found. Install allowly with the verifier extra: "
        "pip install 'allowly[verifier]'"
    )


_verify_receipt, _load_keys_from_json, VerificationError, PublicKey = _import_verifier()

DEFAULT_BASE_URL = "https://api.allowly.ai"
DEFAULT_KEYS_DOC_CACHE_TTL_SECONDS = 300
_keys_doc_cache: dict[tuple[str, str | None], tuple[float, dict[str, Any]]] = {}


def load_keys_from_json(doc: dict[str, Any]) -> list[PublicKey]:
    _validate_keys_doc(doc)
    return _load_keys_from_json(doc)


def verify_receipt(*args: Any, **kwargs: Any) -> Any:
    return _verify_receipt(*args, **kwargs)


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

    load_keys_from_json(doc)
    _keys_doc_cache[cache_key] = (now + cache_ttl_seconds, doc)
    import copy
    return copy.deepcopy(doc)


def clear_keys_doc_cache() -> None:
    _keys_doc_cache.clear()


def _validate_keys_doc(doc: dict[str, Any]) -> None:
    if not isinstance(doc, dict):
        raise VerificationError("key document must be an object")
    workspace_id = doc.get("workspace_id")
    if not isinstance(workspace_id, str) or not workspace_id:
        raise VerificationError("key document workspace_id must be a non-empty string")
    keys = doc.get("keys")
    if not isinstance(keys, list):
        raise VerificationError("key document keys must be an array")

    for i, key in enumerate(keys):
        if not isinstance(key, dict):
            raise VerificationError(f"keys[{i}] must be an object")
        for field in ("key_id", "alg", "public_key", "active_from"):
            value = key.get(field)
            if not isinstance(value, str) or not value:
                raise VerificationError(f"keys[{i}].{field} must be a non-empty string")
        if key["alg"] != "Ed25519":
            raise VerificationError(f'keys[{i}].alg must be "Ed25519"')
        active_until = key.get("active_until")
        if active_until is not None and not isinstance(active_until, str):
            raise VerificationError(f"keys[{i}].active_until must be string or null")
        try:
            raw = _b64url_decode(key["public_key"])
        except Exception as exc:
            raise VerificationError(f"keys[{i}].public_key is not valid base64url") from exc
        if len(raw) != 32:
            raise VerificationError(
                f"keys[{i}].public_key must decode to 32 bytes, got {len(raw)}"
            )


def _b64url_decode(value: str) -> bytes:
    import base64

    padded = value + "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


__all__ = [
    "verify_receipt",
    "load_keys_from_json",
    "fetch_keys_doc",
    "clear_keys_doc_cache",
    "VerificationError",
    "PublicKey",
]
