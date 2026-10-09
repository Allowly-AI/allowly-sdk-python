import base64
import hashlib
import hmac
import json

import httpx
import pytest
import respx

from allowly import Allowly, AllowlyAPIError, AllowlyProtocolError, verify_resolution_webhook

KEY = bytes(range(32))
SECRET = "whsec_" + base64.b64encode(KEY).decode()
NOW = 1700000000
BASE = "https://api.example.com/v1/setup/resolution-webhook"
RAW = b'{"id":"evt_1","type":"confirmation.resolved","timestamp":"2023-11-14T22:13:00Z","workspace_id":"ws_test","data":{"prompt_id":"cnf_1","status":"approved","source_receipt_id":null,"resolution_receipt_id":"rcp_1"}}'
# Independently calculated with openssl dgst -sha256 -mac HMAC.
GOLDEN_SIGNATURE = "ccj9r4381eeqEORTlD4qdKOXeGA63FYeGAv62T9IPOI="


def _headers(raw=RAW, *, event_id="evt_1", timestamp=str(NOW)):
    signature = hmac.new(KEY, f"{event_id}.{timestamp}.".encode() + raw, hashlib.sha256).digest()
    return {
        "webhook-id": event_id, "webhook-timestamp": timestamp,
        "webhook-signature": "v1," + base64.b64encode(signature).decode(),
    }


def _verify(raw=RAW, headers=None, **options):
    return verify_resolution_webhook(
        raw, _headers(raw) if headers is None else headers,
        signing_secret=options.pop("signing_secret", SECRET),
        expected_workspace_id=options.pop("expected_workspace_id", "ws_test"),
        now=options.pop("now", NOW), **options,
    )


def test_cross_sdk_golden_signature_and_typed_fields():
    headers = _headers()
    assert headers["webhook-signature"] == "v1," + GOLDEN_SIGNATURE
    event = _verify(headers={name.title(): value for name, value in headers.items()})
    assert event.id == "evt_1"
    assert event.type == "confirmation.resolved"
    assert event.workspace_id == "ws_test"
    assert event.data.prompt_id == "cnf_1"
    assert event.data.source_receipt_id is None
    assert event.data.resolution_receipt_id == "rcp_1"


@pytest.mark.parametrize("kind", ["confirmation", "escalation"])
@pytest.mark.parametrize("status", ["approved", "rejected"])
def test_accepts_both_recorded_choices_and_event_types(kind, status):
    body = json.loads(RAW)
    body["type"] = f"{kind}.resolved"
    body["data"].update(prompt_id="cnf_1" if kind == "confirmation" else "esc_1", status=status, source_receipt_id="rcp_source")
    raw = json.dumps(body, indent=2).encode()
    event = _verify(raw)
    assert event.type == f"{kind}.resolved"
    assert event.data.status == status
    assert event.data.source_receipt_id == "rcp_source"


@pytest.mark.parametrize("offset", [-300, 0, 300])
def test_exact_tolerance_and_retry_bytes(offset):
    first = _verify(headers=_headers(timestamp=str(NOW + offset)))
    second = _verify(headers=_headers(timestamp=str(NOW + 10)), now=NOW + 10)
    assert first == second


@pytest.mark.parametrize("offset", [-301, 301])
def test_rejects_stale_and_future_attempts(offset):
    with pytest.raises(AllowlyProtocolError, match="tolerance"):
        _verify(headers=_headers(timestamp=str(NOW + offset)))


def test_verifies_all_v1_signatures_and_ignores_unknown_schemes():
    headers = _headers()
    wrong = base64.b64encode(b"x" * 32).decode()
    headers["webhook-signature"] = f"v2,unknown v1,{wrong} {headers['webhook-signature']}"
    assert _verify(headers=headers).id == "evt_1"


@pytest.mark.parametrize("secret", [
    "", SECRET[6:], SECRET.rstrip("="), SECRET + "=", "whsec_" + "_" * 43 + "=",
    "whsec_" + base64.b64encode(b"x" * 31).decode(), SECRET[:-2] + "9=",
])
def test_rejects_noncanonical_or_wrong_length_keys(secret):
    with pytest.raises(AllowlyProtocolError):
        _verify(signing_secret=secret)


@pytest.mark.parametrize("changes", [
    {"webhook-id": "evt_other"}, {"webhook-id": "evt_1.x"}, {"webhook-id": "evt_" + "x" * 129},
    {"webhook-timestamp": "01700000000"}, {"webhook-timestamp": "1700000000.0"},
    {"webhook-signature": "v1," + "A" * 44}, {"webhook-signature": "v2,unknown"},
    {"webhook-signature": "v1," + GOLDEN_SIGNATURE.rstrip("=")},
    {"webhook-signature": "v1," + GOLDEN_SIGNATURE[:-2] + "J="},
    {"webhook-signature": "v1," + GOLDEN_SIGNATURE + ",extra"},
    {"webhook-signature": " ".join(["v1," + GOLDEN_SIGNATURE] * 9)},
    {"webhook-signature": "x" * 1025}, {"webhook-timestamp": "1700000000\n"},
])
def test_rejects_invalid_or_tampered_headers(changes):
    with pytest.raises(AllowlyProtocolError):
        _verify(headers={**_headers(), **changes})


@pytest.mark.parametrize("key", ["webhook-id", "webhook-timestamp", "webhook-signature"])
def test_rejects_missing_and_ambiguous_headers(key):
    headers = _headers()
    value = headers.pop(key)
    with pytest.raises(AllowlyProtocolError):
        _verify(headers=headers)
    headers[key] = value
    headers[key.title()] = value
    with pytest.raises(AllowlyProtocolError):
        _verify(headers=headers)


def test_authenticates_before_json_parsing(monkeypatch):
    called = False
    def forbidden_parse(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("JSON parsed before authentication")
    monkeypatch.setattr("allowly.resolution_webhook.json.loads", forbidden_parse)
    with pytest.raises(AllowlyProtocolError, match="signature"):
        _verify(b"not JSON", headers=_headers())
    assert not called


@pytest.mark.parametrize("raw", [RAW + b" ", RAW.replace(b"approved", b"rejected")])
def test_rejects_changed_raw_bytes(raw):
    with pytest.raises(AllowlyProtocolError, match="signature"):
        _verify(raw, headers=_headers())


@pytest.mark.parametrize("raw", [
    b"[]", b"{", b"\xff", b"\xef\xbb\xbf" + RAW,
    RAW.replace(b'"id":"evt_1"', b'"id":"evt_other","id":"evt_1"'),
    RAW.replace(b'"id":"evt_1"', b'"\\u0069d":"evt_other","id":"evt_1"'),
    RAW.replace(b'"source_receipt_id":null', b'"source_receipt_id":null,"source_receipt_id":"rcp_other"'),
    RAW.replace(b"null", b"NaN"),
])
def test_rejects_authenticated_malformed_json(raw):
    with pytest.raises(AllowlyProtocolError):
        _verify(raw)


@pytest.mark.parametrize("field,value", [
    ("id", "evt_other"), ("type", "confirmation.created"), ("workspace_id", "ws_other"),
    ("timestamp", "2023-02-30T22:13:00Z"), ("timestamp", "2023-11-14T22:13:00"),
    ("data", None), ("resource", "private"),
])
def test_rejects_authenticated_invalid_event(field, value):
    body = json.loads(RAW)
    body[field] = value
    with pytest.raises(AllowlyProtocolError):
        _verify(json.dumps(body).encode())


@pytest.mark.parametrize("field,value", [
    ("prompt_id", "esc_1"), ("status", "pending"), ("source_receipt_id", "auth_1"),
    ("source_receipt_id", False), ("resolution_receipt_id", None),
    ("resolution_receipt_id", "rcp_"), ("nonce", "private"),
])
def test_rejects_authenticated_invalid_data(field, value):
    body = json.loads(RAW)
    body["data"][field] = value
    with pytest.raises(AllowlyProtocolError):
        _verify(json.dumps(body).encode())


@pytest.mark.parametrize("field", ["prompt_id", "status", "source_receipt_id", "resolution_receipt_id"])
def test_requires_all_data_fields_including_null_source(field):
    body = json.loads(RAW)
    del body["data"][field]
    with pytest.raises(AllowlyProtocolError):
        _verify(json.dumps(body).encode())


@pytest.mark.parametrize("raw", ["{}", b"", b"x" * (16 * 1024 + 1)])
def test_bounds_raw_body(raw):
    with pytest.raises(AllowlyProtocolError):
        _verify(raw, headers=_headers())


def test_accepts_exact_body_limit_and_eight_signature_entries():
    raw = RAW + b" " * (16 * 1024 - len(RAW))
    headers = _headers(raw)
    headers["webhook-signature"] = "v2,unknown " * 7 + headers["webhook-signature"]
    assert _verify(raw, headers=headers).id == "evt_1"


def test_requires_trusted_workspace_and_finite_clock():
    for options in [{"expected_workspace_id": "ws_other"}, {"expected_workspace_id": ""}, {"now": float("nan")}]:
        with pytest.raises(AllowlyProtocolError):
            _verify(**options)


def test_preserves_json_punctuation_inside_trusted_workspace_id():
    body = json.loads(RAW)
    body["workspace_id"] = 'ws_,"id":{},[]\\value'
    raw = json.dumps(body).encode()
    assert _verify(raw, expected_workspace_id=body["workspace_id"]).workspace_id == body["workspace_id"]


def _config(**overrides):
    return {
        "workspace_id": "ws_test", "endpoint_id": "rwh_1", "url": "https://customer.example/callback",
        "enabled": True, "credential_version": 1,
        "created_at": "2023-11-14T22:13:00Z", "updated_at": "2023-11-14T22:13:00Z", **overrides,
    }


@respx.mock
@pytest.mark.asyncio
async def test_setup_resource_methods_and_secret_privacy():
    routes = [
        respx.get(BASE).mock(return_value=httpx.Response(200, json=_config())),
        respx.put(BASE).mock(return_value=httpx.Response(200, json=_config(signing_secret=SECRET))),
        respx.post(BASE + "/rotate").mock(return_value=httpx.Response(200, json=_config(credential_version=2, signing_secret=SECRET))),
        respx.delete(BASE).mock(return_value=httpx.Response(200, json=_config(enabled=False))),
        respx.get(BASE + "/deliveries").mock(return_value=httpx.Response(200, json={"items": [{
            "event_id": "evt_1", "event_type": "confirmation.resolved", "status": "failed", "attempts": 1,
            "created_at": "2023-11-14T22:13:00Z", "delivered_at": None, "last_error": "endpoint_gone",
        }]})),
    ]
    async with Allowly("setup-key", base_url="https://api.example.com") as client:
        assert (await client.resolution_webhook.get()).workspace_id == "ws_test"
        configured = await client.resolution_webhook.configure("https://customer.example/callback")
        assert configured.signing_secret == SECRET
        assert SECRET not in repr(configured)
        assert (await client.resolution_webhook.rotate()).credential_version == 2
        assert not (await client.resolution_webhook.disable()).enabled
        assert (await client.resolution_webhook.deliveries()).items[0].last_error == "endpoint_gone"
    assert all(route.call_count == 1 for route in routes)
    assert all(route.calls[0].request.headers["authorization"] == "Bearer setup-key" for route in routes)
    assert json.loads(routes[1].calls[0].request.content) == {"url": "https://customer.example/callback"}


@respx.mock
@pytest.mark.asyncio
async def test_missing_endpoint_is_explicit_disabled_null_config():
    body = _config(endpoint_id=None, url=None, enabled=False, credential_version=None, created_at=None, updated_at=None)
    respx.get(BASE).mock(return_value=httpx.Response(200, json=body))
    async with Allowly("setup-key", base_url="https://api.example.com") as client:
        result = await client.resolution_webhook.get()
    assert result.endpoint_id is None
    assert result.credential_version is None


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("field", list(_config()))
async def test_config_requires_every_field(field):
    body = _config()
    del body[field]
    respx.get(BASE).mock(return_value=httpx.Response(200, json=body))
    async with Allowly("setup-key", base_url="https://api.example.com") as client:
        with pytest.raises(AllowlyProtocolError):
            await client.resolution_webhook.get()


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("overrides", [{"enabled": 1}, {"credential_version": True}, {"credential_version": 0}, {"created_at": "invalid"}, {"url": None}, {"signing_secret": SECRET}])
async def test_config_rejects_malformed_or_secret_bearing_get(overrides):
    respx.get(BASE).mock(return_value=httpx.Response(200, json=_config(**overrides)))
    async with Allowly("setup-key", base_url="https://api.example.com") as client:
        with pytest.raises(AllowlyProtocolError):
            await client.resolution_webhook.get()


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("status", [403, 404, 429, 503])
async def test_setup_errors_never_retry_or_fallback(status):
    route = respx.post(BASE + "/rotate").mock(return_value=httpx.Response(status, json={"error": {"code": "resolution_webhook_not_configured", "message": "Unavailable"}}))
    async with Allowly("setup-key", base_url="https://api.example.com") as client:
        with pytest.raises(AllowlyAPIError) as error:
            await client.resolution_webhook.rotate()
    assert error.value.status == status
    assert route.call_count == 1


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("secret", [None, "wrong-profile", SECRET.rstrip("="), False])
async def test_configure_requires_a_valid_current_signing_secret(secret):
    body = _config() if secret is None else _config(signing_secret=secret)
    respx.put(BASE).mock(return_value=httpx.Response(200, json=body))
    async with Allowly("setup-key", base_url="https://api.example.com") as client:
        with pytest.raises(AllowlyProtocolError):
            await client.resolution_webhook.configure("https://customer.example/callback")


def _delivery(**overrides):
    return {
        "event_id": "evt_1", "event_type": "confirmation.resolved", "status": "pending", "attempts": 0,
        "created_at": "2023-11-14T22:13:00Z", "delivered_at": None, "last_error": None, **overrides,
    }


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["pending", "delivered", "failed", "cancelled"])
async def test_delivery_statuses_and_bounded_history(status):
    item = _delivery(status=status, delivered_at="2023-11-14T22:14:00Z" if status == "delivered" else None)
    respx.get(BASE + "/deliveries").mock(return_value=httpx.Response(200, json={"items": [item] * 20}))
    async with Allowly("setup-key", base_url="https://api.example.com") as client:
        result = await client.resolution_webhook.deliveries()
    assert len(result.items) == 20
    assert result.items[0].status == status


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("body", [
    {"items": False}, {"items": [_delivery()] * 21},
    {"items": [_delivery(attempts=True)]}, {"items": [_delivery(event_type="unknown")]},
    {"items": [_delivery(last_error="https://private.example/secret")]},
    {"items": [_delivery(status="delivered")]},
    {"items": [_delivery(delivered_at="2023-11-14T22:14:00Z")]},
    {"items": [_delivery(url="https://private.example/")]},
    *[{"items": [{key: value for key, value in _delivery().items() if key != missing}]} for missing in _delivery()],
])
async def test_deliveries_reject_malformed_or_private_metadata(body):
    respx.get(BASE + "/deliveries").mock(return_value=httpx.Response(200, json=body))
    async with Allowly("setup-key", base_url="https://api.example.com") as client:
        with pytest.raises(AllowlyProtocolError):
            await client.resolution_webhook.deliveries()
