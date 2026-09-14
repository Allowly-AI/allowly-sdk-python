from __future__ import annotations

from typing import Any, cast
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

import httpx

from .error import AllowlyAPIError, AllowlyProtocolError, FieldError
from .types import SealWebhookDelivery, SealWebhookStatus

_SEAL_PROFILE = "allowly.seal.jcs-sha256.v1"


class SealWebhookClient:
    """Client for one private SEAL webhook URL.

    The URL is the only credential used by this client. Keep it out of logs,
    tickets, and source control.
    """

    def __init__(
        self,
        webhook_url: str,
        *,
        timeout: float = 10.0,
        dangerously_allow_insecure_url: bool = False,
    ) -> None:
        self._webhook_url, self._origin, self._query = _validate_webhook_url(
            webhook_url,
            dangerously_allow_insecure_url,
        )
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._http = httpx.AsyncClient(timeout=timeout, follow_redirects=False)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> SealWebhookClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    async def send(
        self,
        record_json: str | bytes,
        *,
        idempotency_key: str | None = None,
    ) -> SealWebhookDelivery:
        """Send one complete JSON record without an API key."""
        if not isinstance(record_json, (str, bytes)):
            raise TypeError("record_json must be str or bytes")
        headers = {"Content-Type": "application/json"}
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        raw = await self._request(
            "POST",
            self._webhook_url,
            content=record_json,
            headers=headers,
            expected_statuses={200, 202},
        )
        return _parse_delivery(raw)

    async def get_delivery(self, attempt_id: str) -> SealWebhookDelivery:
        """Get the current state of one delivery made through this webhook."""
        raw = await self._request(
            "GET",
            self._url(f"/v1/seal/webhooks/deliveries/{quote(attempt_id, safe='')}"),
            expected_statuses={200},
        )
        delivery = _parse_delivery(raw)
        if delivery.attempt_id != attempt_id:
            raise AllowlyProtocolError(
                "SEAL webhook response attempt_id does not match the request"
            )
        return delivery

    async def get_receipt(self, receipt_id: str) -> SealWebhookDelivery:
        """Get a delivery and its signed receipt through the private URL."""
        raw = await self._request(
            "GET",
            self._url(f"/v1/seal/webhooks/receipts/{quote(receipt_id, safe='')}"),
            expected_statuses={200},
        )
        delivery = _parse_delivery(raw)
        if delivery.receipt_id != receipt_id:
            raise AllowlyProtocolError(
                "SEAL webhook response receipt_id does not match the request"
            )
        return delivery

    async def get_keys(self) -> dict[str, Any]:
        """Fetch this webhook workspace's public verification-key document."""
        return _require_dict(
            await self._request(
                "GET",
                self._url("/v1/seal/webhooks/keys"),
                expected_statuses={200},
            ),
            "SEAL webhook keys response",
        )

    def _url(self, path: str) -> str:
        return f"{self._origin}{path}?{self._query}"

    async def _request(
        self,
        method: str,
        url: str,
        *,
        expected_statuses: set[int],
        **kwargs: Any,
    ) -> Any:
        try:
            response = await self._http.request(method, url, **kwargs)
        except httpx.TransportError:
            # A transport exception can include the credential-bearing URL.
            raise AllowlyProtocolError("SEAL webhook request failed") from None
        if response.is_success and response.status_code not in expected_statuses:
            raise AllowlyProtocolError(
                f"unexpected successful HTTP status: {response.status_code}"
            )
        try:
            data = response.json()
        except ValueError as exc:
            if response.is_success:
                raise AllowlyProtocolError(
                    "successful SEAL webhook response must be valid JSON"
                ) from exc
            data = {}
        if not response.is_success:
            error = data.get("error") if isinstance(data, dict) else None
            if isinstance(error, str):
                error = {"message": error}
            elif not isinstance(error, dict):
                error = {}
            raw_fields = error.get("fields")
            fields = [
                FieldError(
                    field=str(item.get("field", "")),
                    message=str(item.get("message", "")),
                )
                for item in (raw_fields if isinstance(raw_fields, list) else [])
                if isinstance(item, dict)
            ]
            raise AllowlyAPIError(
                status=response.status_code,
                code=error.get("code", "error"),
                message=error.get("message", "Unknown error"),
                fields=fields,
                retry_after_seconds=_parse_retry_after(
                    response.headers.get("Retry-After")
                ),
            )
        return data


def _validate_webhook_url(url: str, allow_insecure: bool) -> tuple[str, str, str]:
    if not isinstance(url, str):
        raise TypeError("webhook_url must be a string")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("webhook_url must be a valid HTTP or HTTPS URL")
    if parsed.scheme != "https" and not allow_insecure:
        raise ValueError("webhook_url must use HTTPS")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("webhook_url must not contain user info or a fragment")
    if parsed.path != "/v1/seal/webhooks":
        raise ValueError("webhook_url must use the SEAL webhook endpoint")
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    if len(query_items) != 1 or query_items[0][0] != "token" or not query_items[0][1]:
        raise ValueError("webhook_url must contain exactly one non-empty token")
    origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    query = urlencode({"token": query_items[0][1]})
    return f"{origin}{parsed.path}?{query}", origin, query


def _parse_delivery(value: Any) -> SealWebhookDelivery:
    raw = _require_dict(value, "SEAL webhook delivery response")
    raw_status = _require_str(raw, "status")
    allowed = {"received", "signing", "sealed", "rejected", "failed"}
    if raw_status not in allowed:
        raise AllowlyProtocolError(f"unknown SEAL webhook status: {raw_status!r}")
    status = cast(SealWebhookStatus, raw_status)
    profile = _require_str(raw, "profile")
    if profile != _SEAL_PROFILE:
        raise AllowlyProtocolError("SEAL webhook response has an unknown profile")
    receipt = _optional_dict(raw, "receipt")
    receipt_id = _optional_str(raw, "receipt_id")
    workspace_id = _require_str(raw, "workspace_id")
    if receipt is not None:
        if receipt_id is None or receipt.get("receipt_id") != receipt_id:
            raise AllowlyProtocolError("SEAL webhook receipt_id binding does not match")
        if receipt.get("workspace_id") != workspace_id:
            raise AllowlyProtocolError(
                "SEAL webhook workspace_id binding does not match"
            )
    return SealWebhookDelivery(
        attempt_id=_require_str(raw, "attempt_id"),
        workspace_id=workspace_id,
        status=status,
        received_at=_require_str(raw, "received_at"),
        updated_at=_require_str(raw, "updated_at"),
        profile=profile,
        record_sha256=_optional_str(raw, "record_sha256"),
        receipt_id=receipt_id,
        error_code=_optional_str(raw, "error_code"),
        status_url=_require_str(raw, "status_url"),
        receipt_url=_optional_str(raw, "receipt_url"),
        keys_url=_require_str(raw, "keys_url"),
        receipt=receipt,
    )


def _require_dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AllowlyProtocolError(f"{name} must be an object")
    return value


def _require_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise AllowlyProtocolError(
            f"SEAL webhook response {key} must be a non-empty string"
        )
    return value


def _optional_str(raw: dict[str, Any], key: str) -> str | None:
    if key not in raw or raw[key] is None:
        return None
    if not isinstance(raw[key], str):
        raise AllowlyProtocolError(
            f"SEAL webhook response {key} must be a string or null"
        )
    return raw[key]


def _optional_dict(raw: dict[str, Any], key: str) -> dict[str, Any] | None:
    if key not in raw or raw[key] is None:
        return None
    return _require_dict(raw[key], f"SEAL webhook response {key}")


def _parse_retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    return seconds if seconds >= 0 else None
