"""Verify resolution notifications and manage their workspace setup endpoint."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from datetime import datetime
import hashlib
import hmac
import json
import math
import re
import time
from typing import TYPE_CHECKING, Any

from .error import AllowlyProtocolError
from .types import (
    ResolutionWebhookConfig, ResolutionWebhookData, ResolutionWebhookDeliveries,
    ResolutionWebhookDelivery, ResolutionWebhookEvent, ResolutionWebhookSecret,
)

if TYPE_CHECKING:
    from .client import Allowly

_PATH = "/v1/setup/resolution-webhook"
_EVENT_TYPES = {"confirmation.resolved", "escalation.resolved"}
_ERROR_CODES = {
    "unsafe_url", "dns_error", "timeout", "transport_error", "request_too_large",
    "response_too_large", "invalid_headers", "http_error", "expired", "attempts_exhausted",
    "endpoint_disabled", "endpoint_changed", "endpoint_gone", "workspace_closed",
}


def _base64_32(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", value):
        raise AllowlyProtocolError("webhook key or signature must be canonical 32-byte base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except binascii.Error:
        raise AllowlyProtocolError("invalid webhook base64") from None
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise AllowlyProtocolError("webhook key or signature must be canonical 32-byte base64")
    return decoded


def _signing_key(secret: str) -> bytes:
    if not isinstance(secret, str) or not secret.startswith("whsec_"):
        raise AllowlyProtocolError("signing_secret must use the whsec_ profile")
    return _base64_32(secret[6:])


def verify_resolution_webhook(
    raw_body: bytes, headers: Mapping[str, str], *, signing_secret: str,
    expected_workspace_id: str, now: float | None = None,
) -> ResolutionWebhookEvent:
    """Authenticate exact UTF-8 bytes, then validate the event. `now` is Unix seconds.

    Persist event IDs to prevent duplicate processing. This notification is not
    execution permission or a portable signed receipt; run a fresh GET and check.
    """
    if not isinstance(raw_body, bytes) or not 0 < len(raw_body) <= 16 * 1024:
        raise AllowlyProtocolError("raw_body must be bytes of at most 16 KiB")
    if not isinstance(expected_workspace_id, str) or not expected_workspace_id:
        raise AllowlyProtocolError("expected_workspace_id must come from trusted configuration")
    key = _signing_key(signing_secret)
    if not isinstance(headers, Mapping):
        raise AllowlyProtocolError("webhook headers must be a mapping")
    signed_headers: dict[str, str] = {}
    for name, value in headers.items():
        normalized = name.lower() if isinstance(name, str) else ""
        if normalized not in {"webhook-id", "webhook-timestamp", "webhook-signature"}:
            continue
        if normalized in signed_headers or not isinstance(value, str) or not value:
            raise AllowlyProtocolError("webhook headers must be unique non-empty strings")
        limit = 1024 if normalized == "webhook-signature" else 128
        if len(value) > limit or any(not 0x20 <= ord(char) <= 0x7E for char in value):
            raise AllowlyProtocolError("webhook header exceeds its bounds or contains invalid characters")
        signed_headers[normalized] = value
    if len(signed_headers) != 3:
        raise AllowlyProtocolError("missing webhook signature headers")
    event_id = signed_headers["webhook-id"]
    timestamp = signed_headers["webhook-timestamp"]
    if not re.fullmatch(r"evt_[A-Za-z0-9_-]+", event_id) or not re.fullmatch(r"0|[1-9][0-9]{0,11}", timestamp):
        raise AllowlyProtocolError("invalid webhook ID or timestamp")
    current_time = time.time() if now is None else now
    if isinstance(current_time, bool) or not isinstance(current_time, (int, float)) or not math.isfinite(current_time):
        raise AllowlyProtocolError("now must be finite Unix seconds")
    if abs(current_time - int(timestamp)) > 300:
        raise AllowlyProtocolError("webhook timestamp is outside the 300-second tolerance")
    signatures = signed_headers["webhook-signature"].split()
    if not 1 <= len(signatures) <= 8:
        raise AllowlyProtocolError("webhook signature count exceeds its bounds")
    expected = hmac.digest(key, f"{event_id}.{timestamp}.".encode("ascii") + raw_body, hashlib.sha256)
    verified = False
    for signature in signatures:
        scheme, separator, encoded = signature.partition(",")
        if not separator or not encoded or "," in encoded or not re.fullmatch(r"[A-Za-z0-9]+", scheme):
            raise AllowlyProtocolError("malformed webhook signature header")
        if scheme == "v1":
            verified |= hmac.compare_digest(expected, _base64_32(encoded))
    if not verified:
        raise AllowlyProtocolError("webhook signature did not verify")
    try:
        raw = json.loads(raw_body.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise AllowlyProtocolError("webhook payload must be valid UTF-8 JSON with unique fields") from None
    body = _record(raw, {"id", "type", "timestamp", "workspace_id", "data"})
    if body["id"] != event_id or body["workspace_id"] != expected_workspace_id:
        raise AllowlyProtocolError("webhook event or workspace ID does not match")
    event_type = _event_type(body, "type")
    data = _record(body["data"], {"prompt_id", "status", "source_receipt_id", "resolution_receipt_id"})
    prompt_id = _identifier(data, "prompt_id", "cnf_" if event_type == "confirmation.resolved" else "esc_")
    status = _string(data, "status")
    if status not in {"approved", "rejected"}:
        raise AllowlyProtocolError("webhook status must be approved or rejected")
    source = _nullable_string(data, "source_receipt_id")
    if source is not None:
        _identifier(data, "source_receipt_id", "rcp_")
    return ResolutionWebhookEvent(
        id=event_id, type=event_type, timestamp=_timestamp(body, "timestamp"),
        workspace_id=expected_workspace_id,
        data=ResolutionWebhookData(prompt_id, status, source, _identifier(data, "resolution_receipt_id", "rcp_")),
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError("invalid JSON constant")


def _record(value: Any, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AllowlyProtocolError("webhook object fields do not match the contract")
    return value


def _string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise AllowlyProtocolError(f"webhook {key} must be a bounded non-empty string")
    return value


def _nullable_string(raw: dict[str, Any], key: str) -> str | None:
    if key not in raw:
        raise AllowlyProtocolError(f"webhook {key} must be present")
    return None if raw[key] is None else _string(raw, key)


def _identifier(raw: dict[str, Any], key: str, prefix: str) -> str:
    value = _string(raw, key)
    if len(value) > 128 or not re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9_-]+", value):
        raise AllowlyProtocolError(f"webhook {key} has an invalid ID prefix or format")
    return value


def _timestamp(raw: dict[str, Any], key: str) -> str:
    value = _string(raw, key)
    match = re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))", value)
    try:
        if match is None or (match[1] is not None and (int(match[1]) > 23 or int(match[2]) > 59)):
            raise ValueError()
        datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        raise AllowlyProtocolError(f"webhook {key} must be a valid timezone-aware timestamp") from None
    return value


def _nullable_timestamp(raw: dict[str, Any], key: str) -> str | None:
    return None if _nullable_string(raw, key) is None else _timestamp(raw, key)


def _event_type(raw: dict[str, Any], key: str) -> str:
    value = _string(raw, key)
    if value not in _EVENT_TYPES:
        raise AllowlyProtocolError("unknown resolution webhook event type")
    return value


class _ResolutionWebhookResource:
    """Setup/CLI credentials only. Runtime keys cannot manage this endpoint."""

    def __init__(self, client: Allowly) -> None:
        self._client = client

    async def get(self) -> ResolutionWebhookConfig:
        return _parse_config(await self._client._request("GET", _PATH))

    async def configure(self, url: str) -> ResolutionWebhookSecret:
        return _parse_secret(await self._client._request("PUT", _PATH, json={"url": url}))

    async def rotate(self) -> ResolutionWebhookSecret:
        return _parse_secret(await self._client._request("POST", f"{_PATH}/rotate"))

    async def disable(self) -> ResolutionWebhookConfig:
        return _parse_config(await self._client._request("DELETE", _PATH))

    async def deliveries(self) -> ResolutionWebhookDeliveries:
        raw = _record(await self._client._request("GET", f"{_PATH}/deliveries"), {"items"})
        if not isinstance(raw["items"], list) or len(raw["items"]) > 20:
            raise AllowlyProtocolError("webhook deliveries must contain at most 20 items")
        return ResolutionWebhookDeliveries([_parse_delivery(item) for item in raw["items"]])


def _parse_config(value: Any) -> ResolutionWebhookConfig:
    raw = _record(value, {"workspace_id", "endpoint_id", "url", "enabled", "credential_version", "created_at", "updated_at"})
    if not isinstance(raw["enabled"], bool):
        raise AllowlyProtocolError("webhook enabled must be a boolean")
    version = raw["credential_version"]
    if version is not None and (type(version) is not int or version < 1):
        raise AllowlyProtocolError("webhook credential_version must be a positive integer or null")
    config = ResolutionWebhookConfig(
        workspace_id=_string(raw, "workspace_id"), endpoint_id=_nullable_string(raw, "endpoint_id"),
        url=_nullable_string(raw, "url"), enabled=raw["enabled"], credential_version=version,
        created_at=_nullable_timestamp(raw, "created_at"), updated_at=_nullable_timestamp(raw, "updated_at"),
    )
    fields = (config.url, version, config.created_at, config.updated_at)
    if config.endpoint_id is None:
        if config.enabled or any(field is not None for field in fields):
            raise AllowlyProtocolError("missing webhook endpoint must have a disabled null configuration")
    elif any(field is None for field in fields):
        raise AllowlyProtocolError("configured webhook endpoint must include its URL, version and timestamps")
    return config


def _parse_secret(value: Any) -> ResolutionWebhookSecret:
    if not isinstance(value, dict) or "signing_secret" not in value:
        raise AllowlyProtocolError("webhook signing_secret must be present")
    secret = _string(value, "signing_secret")
    _signing_key(secret)
    config = _parse_config({key: item for key, item in value.items() if key != "signing_secret"})
    if config.endpoint_id is None:
        raise AllowlyProtocolError("webhook signing_secret requires a configured endpoint")
    return ResolutionWebhookSecret(**vars(config), signing_secret=secret)


def _parse_delivery(value: Any) -> ResolutionWebhookDelivery:
    raw = _record(value, {"event_id", "event_type", "status", "attempts", "created_at", "delivered_at", "last_error"})
    status = _string(raw, "status")
    if status not in {"pending", "delivered", "failed", "cancelled"}:
        raise AllowlyProtocolError("unknown webhook delivery status")
    attempts = raw["attempts"]
    if type(attempts) is not int or attempts < 0:
        raise AllowlyProtocolError("webhook attempts must be a non-negative integer")
    error = _nullable_string(raw, "last_error")
    if error is not None and error not in _ERROR_CODES:
        raise AllowlyProtocolError("unknown webhook delivery error code")
    delivered_at = _nullable_timestamp(raw, "delivered_at")
    if (status == "delivered") != (delivered_at is not None):
        raise AllowlyProtocolError("webhook delivered_at does not match delivery status")
    return ResolutionWebhookDelivery(
        event_id=_identifier(raw, "event_id", "evt_"), event_type=_event_type(raw, "event_type"),
        status=status, attempts=attempts, created_at=_timestamp(raw, "created_at"),
        delivered_at=delivered_at, last_error=error,
    )
