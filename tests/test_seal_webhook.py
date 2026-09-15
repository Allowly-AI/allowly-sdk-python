from __future__ import annotations

import httpx
import pytest
import respx

from allowly import AllowlyAPIError, AllowlyProtocolError, SealWebhookClient

BASE = "https://api.example.com"
TOKEN = "seal_w1_s001_test-token"
WEBHOOK_URL = f"{BASE}/v1/seal/webhooks?token={TOKEN}"


def _delivery(**overrides):
    body = {
        "attempt_id": "swd_attempt",
        "workspace_id": "ws_test",
        "status": "signing",
        "received_at": "2026-09-13T12:00:00Z",
        "updated_at": "2026-09-13T12:00:01Z",
        "profile": "allowly.seal.jcs-sha256.v1",
        "record_sha256": "a" * 64,
        "metadata": None,
        "receipt_id": "rcp_test",
        "error_code": None,
        "status_url": (f"{BASE}/v1/seal/webhooks/deliveries/swd_attempt?token={TOKEN}"),
        "receipt_url": (f"{BASE}/v1/seal/webhooks/receipts/rcp_test?token={TOKEN}"),
        "keys_url": f"{BASE}/v1/seal/webhooks/keys?token={TOKEN}",
        "receipt": None,
    }
    body.update(overrides)
    return body


@respx.mock
@pytest.mark.asyncio
async def test_send_posts_exact_json_without_api_key() -> None:
    raw = b'{"event":"created","amount":1.00}'
    details = {
        "type": "invoice",
        "reference": "INV-1042",
        "statement": "Approved for payment",
    }
    route = respx.post(WEBHOOK_URL).mock(
        return_value=httpx.Response(202, json=_delivery(metadata=details))
    )

    async with SealWebhookClient(WEBHOOK_URL) as webhook:
        result = await webhook.send(
            raw,
            idempotency_key="sender-event-7",
            type="invoice",
            reference="INV-1042",
            statement="Approved for payment",
        )

    assert result.attempt_id == "swd_attempt"
    assert result.status == "signing"
    assert result.metadata == details
    assert route.call_count == 1
    request = route.calls[0].request
    assert request.content == raw
    assert request.headers["content-type"] == "application/json"
    assert request.headers["idempotency-key"] == "sender-event-7"
    assert request.headers["allowly-seal-type"] == "invoice"
    assert request.headers["allowly-seal-reference"] == "INV-1042"
    assert request.headers["allowly-seal-statement"] == "Approved for payment"
    assert "authorization" not in request.headers


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [" leading", "trailing ", "café", "inside\tgap", "x" * 257],
)
async def test_send_rejects_invalid_detail_header_values(value: str) -> None:
    async with SealWebhookClient(WEBHOOK_URL) as webhook:
        with pytest.raises(ValueError):
            await webhook.send("{}", reference=value)


@respx.mock
@pytest.mark.asyncio
async def test_private_url_fetches_scoped_status_receipt_and_keys() -> None:
    signed_receipt = {
        "schema_version": "4",
        "receipt_id": "rcp_test",
        "workspace_id": "ws_test",
    }
    respx.get(f"{BASE}/v1/seal/webhooks/deliveries/swd_attempt?token={TOKEN}").mock(
        return_value=httpx.Response(200, json=_delivery())
    )
    respx.get(f"{BASE}/v1/seal/webhooks/receipts/rcp_test?token={TOKEN}").mock(
        return_value=httpx.Response(
            200,
            json=_delivery(status="sealed", receipt=signed_receipt),
        )
    )
    keys_route = respx.get(f"{BASE}/v1/seal/webhooks/keys?token={TOKEN}").mock(
        return_value=httpx.Response(
            200,
            json={"workspace_id": "ws_test", "keys": []},
        )
    )

    async with SealWebhookClient(WEBHOOK_URL) as webhook:
        status = await webhook.get_delivery("swd_attempt")
        receipt = await webhook.get_receipt("rcp_test")
        keys = await webhook.get_keys()

    assert status.status == "signing"
    assert receipt.receipt == signed_receipt
    assert keys == {"workspace_id": "ws_test", "keys": []}
    assert "authorization" not in keys_route.calls[0].request.headers


@respx.mock
@pytest.mark.asyncio
async def test_webhook_errors_keep_code_and_retry_after() -> None:
    respx.post(WEBHOOK_URL).mock(
        return_value=httpx.Response(
            429,
            json={
                "error": {
                    "code": "tier_rate_limit_exceeded",
                    "message": "Retry later",
                }
            },
            headers={"Retry-After": "2"},
        )
    )
    async with SealWebhookClient(WEBHOOK_URL) as webhook:
        with pytest.raises(AllowlyAPIError) as exc_info:
            await webhook.send("{}")
    assert exc_info.value.code == "tier_rate_limit_exceeded"
    assert exc_info.value.retry_after_seconds == 2
    assert TOKEN not in str(exc_info.value)


@respx.mock
@pytest.mark.asyncio
async def test_webhook_transport_error_does_not_expose_private_url() -> None:
    respx.post(WEBHOOK_URL).mock(
        side_effect=httpx.ConnectError(f"failed to connect to {WEBHOOK_URL}")
    )
    async with SealWebhookClient(WEBHOOK_URL) as webhook:
        with pytest.raises(AllowlyProtocolError) as exc_info:
            await webhook.send("{}")
    assert TOKEN not in str(exc_info.value)


@respx.mock
@pytest.mark.asyncio
async def test_webhook_rejects_mismatched_receipt_binding() -> None:
    respx.get(f"{BASE}/v1/seal/webhooks/receipts/rcp_test?token={TOKEN}").mock(
        return_value=httpx.Response(
            200,
            json=_delivery(
                status="sealed",
                receipt={
                    "schema_version": "4",
                    "receipt_id": "rcp_other",
                    "workspace_id": "ws_test",
                },
            ),
        )
    )
    async with SealWebhookClient(WEBHOOK_URL) as webhook:
        with pytest.raises(AllowlyProtocolError, match="receipt_id binding"):
            await webhook.get_receipt("rcp_test")


@respx.mock
@pytest.mark.asyncio
async def test_webhook_rejects_unknown_delivery_status() -> None:
    respx.post(WEBHOOK_URL).mock(
        return_value=httpx.Response(202, json=_delivery(status="unknown"))
    )
    async with SealWebhookClient(WEBHOOK_URL) as webhook:
        with pytest.raises(AllowlyProtocolError, match="unknown SEAL webhook status"):
            await webhook.send("{}")


@respx.mock
@pytest.mark.asyncio
async def test_webhook_defaults_missing_metadata_from_older_runtimes_to_none() -> None:
    body = _delivery()
    del body["metadata"]
    respx.post(WEBHOOK_URL).mock(return_value=httpx.Response(202, json=body))

    async with SealWebhookClient(WEBHOOK_URL) as webhook:
        delivery = await webhook.send("{}")

    assert delivery.metadata is None


@respx.mock
@pytest.mark.asyncio
async def test_webhook_recovers_signed_metadata_when_top_level_is_missing() -> None:
    signed_metadata = {
        "type": "invoice",
        "reference": "INV-1042",
        "statement": "Approved for payment",
    }
    body = _delivery(
        status="sealed",
        receipt={
            "schema_version": "4",
            "receipt_id": "rcp_test",
            "workspace_id": "ws_test",
            "context": {"seal_metadata": signed_metadata},
        },
    )
    del body["metadata"]
    respx.get(f"{BASE}/v1/seal/webhooks/receipts/rcp_test?token={TOKEN}").mock(
        return_value=httpx.Response(200, json=body)
    )

    async with SealWebhookClient(WEBHOOK_URL) as webhook:
        delivery = await webhook.get_receipt("rcp_test")

    assert delivery.metadata == signed_metadata


@respx.mock
@pytest.mark.asyncio
async def test_webhook_rejects_metadata_conflicting_with_signed_receipt() -> None:
    respx.get(f"{BASE}/v1/seal/webhooks/receipts/rcp_test?token={TOKEN}").mock(
        return_value=httpx.Response(
            200,
            json=_delivery(
                status="sealed",
                metadata={"reference": "UNSIGNED"},
                receipt={
                    "schema_version": "4",
                    "receipt_id": "rcp_test",
                    "workspace_id": "ws_test",
                    "context": {"seal_metadata": {"reference": "SIGNED"}},
                },
            ),
        )
    )

    async with SealWebhookClient(WEBHOOK_URL) as webhook:
        with pytest.raises(AllowlyProtocolError, match="metadata does not match"):
            await webhook.get_receipt("rcp_test")


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "metadata",
    [["not-an-object"], {"reference": 42}],
)
async def test_webhook_rejects_malformed_signed_metadata(metadata: object) -> None:
    respx.get(f"{BASE}/v1/seal/webhooks/receipts/rcp_test?token={TOKEN}").mock(
        return_value=httpx.Response(
            200,
            json=_delivery(
                status="sealed",
                receipt={
                    "schema_version": "4",
                    "receipt_id": "rcp_test",
                    "workspace_id": "ws_test",
                    "context": {"seal_metadata": metadata},
                },
            ),
        )
    )

    async with SealWebhookClient(WEBHOOK_URL) as webhook:
        with pytest.raises(AllowlyProtocolError, match="signed SEAL receipt metadata"):
            await webhook.get_receipt("rcp_test")


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("metadata", [["not-an-object"], {"reference": 42}])
async def test_webhook_rejects_malformed_present_metadata(metadata: object) -> None:
    respx.post(WEBHOOK_URL).mock(
        return_value=httpx.Response(202, json=_delivery(metadata=metadata))
    )

    async with SealWebhookClient(WEBHOOK_URL) as webhook:
        with pytest.raises(AllowlyProtocolError, match="metadata"):
            await webhook.send("{}")


@pytest.mark.parametrize(
    "url, message",
    [
        ("http://api.example.com/v1/seal/webhooks?token=x", "HTTPS"),
        ("https://api.example.com/v1/seal?token=x", "webhook endpoint"),
        ("https://api.example.com/v1/seal/webhooks", "exactly one"),
        ("https://api.example.com/v1/seal/webhooks?token=x&other=y", "exactly one"),
    ],
)
def test_webhook_url_validation(url: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        SealWebhookClient(url)


@pytest.mark.asyncio
async def test_local_webhook_requires_explicit_insecure_opt_in() -> None:
    client = SealWebhookClient(
        "http://localhost:8085/v1/seal/webhooks?token=local",
        dangerously_allow_insecure_url=True,
    )
    await client.aclose()
