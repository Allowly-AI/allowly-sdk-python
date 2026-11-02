import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import Mock

import httpx
import pytest
import respx

from allowly import Allowly, AllowlyAPIError, AllowlyProtocolError, TextCheckResponse

BASE = "https://api.example.com"
REQUEST = "Reply to ticket:one with a refund of 0 dollars."


def response():
    return {
        "authorization_id": "auth_resolved", "engine_version": "sha256:" + "a" * 64,
        "results": {"ticket.reply": {"decision": "allow", "reason": "authorization_granted_action_active",
            "receipt": {"status": "pending", "receipt_id": "rcp_one", "ready_at_estimate": None,
                        "url": BASE + "/v1/receipts/rcp_one"}}},
        "parse": {"id": "parse_one", "agent_name": "Support agent",
            "policy_ref": {"policy_id": "support", "policy_version": 1, "definition_sha256": "b" * 64},
            "parsed_request": {"actions": ["ticket.reply"], "resource": "ticket:one", "context": {"amount_micros": 0}},
            "request_sha256": hashlib.sha256(REQUEST.encode()).hexdigest(),
            "model": "gemini-3.5-flash", "model_version": "version-one", "expires_at": "2026-11-01T00:00:00Z"},
    }


@respx.mock
@pytest.mark.asyncio
async def test_text_check_and_recheck_preserve_canonical_request_and_cost_zero():
    initial = respx.post(BASE + "/v1/agent-check/text").mock(return_value=httpx.Response(
        200, json=response(), headers={"X-Allowly-Billing-Warning": "near_quota"}))
    resumed = respx.post(BASE + "/v1/agent-check/text/parse_one").mock(return_value=httpx.Response(200, json=response()))
    async with Allowly("key", base_url=BASE) as client:
        parsed = await client.check_text_by_agent(agent_name="Support agent", request=REQUEST,
            idempotency_key="initial", estimated_cost_micros=0, session_id="session-one",
            client_timestamp=datetime(2026, 10, 31, tzinfo=timezone.utc))
        checked = await client.recheck_text_by_agent(agent_name="Support agent", parse_id=parsed.parse.id, idempotency_key="resume")
    assert isinstance(parsed, TextCheckResponse)
    assert parsed.parse.parsed_request == response()["parse"]["parsed_request"]
    assert checked.parse == parsed.parse
    assert checked.results["ticket.reply"].decision == "allow"
    assert parsed.billing_warning == "near_quota"
    assert json.loads(initial.calls[0].request.content) == {"agent_name": "Support agent", "request": REQUEST,
        "session_id": "session-one", "estimated_cost_micros": 0, "client_timestamp": "2026-10-31T00:00:00Z"}
    assert json.loads(resumed.calls[0].request.content) == {"agent_name": "Support agent"}
    assert initial.calls[0].request.headers["Idempotency-Key"] == "initial"
    assert resumed.calls[0].request.headers["Idempotency-Key"] == "resume"
    assert "X-Allowly-Agent-Token" not in initial.calls[0].request.headers
    assert initial.call_count == 1
    assert resumed.call_count == 1
    assert initial.calls[0].request.extensions["timeout"]["read"] == 35
    assert resumed.calls[0].request.extensions["timeout"]["read"] == 1


@respx.mock
@pytest.mark.asyncio
async def test_text_check_honors_explicit_short_timeout():
    route = respx.post(BASE + "/v1/agent-check/text").mock(return_value=httpx.Response(200, json=response()))
    async with Allowly("key", base_url=BASE) as client:
        await client.check_text_by_agent(agent_name="Support agent", request=REQUEST, idempotency_key="one", timeout_seconds=0.5)
    assert route.calls[0].request.extensions["timeout"]["read"] == 0.5


@pytest.mark.parametrize("edit", [
    lambda p: p.pop("parse"), lambda p: p["parse"].update(extra=True),
    lambda p: p["parse"].update(agent_name="Another agent"),
    lambda p: p["parse"].update(request_sha256="c" * 64),
    lambda p: p["parse"].update(expires_at="2026-02-30T00:00:00Z"),
    lambda p: p["parse"].update(model_version=None),
    lambda p: p["parse"]["policy_ref"].update(definition_sha256="bad"),
    lambda p: p["parse"]["parsed_request"].update(actions=["ticket.reply", "customer.delete"]),
    lambda p: (p["parse"]["parsed_request"].update(actions=["ticket.reply", "customer.delete"]),
               p["results"].update({"customer.delete": p["results"]["ticket.reply"]})),
    lambda p: p["parse"]["parsed_request"].update(resource=None),
    lambda p: p["parse"]["parsed_request"].update(context={"amount_micros": 2**53}),
    lambda p: p["parse"]["parsed_request"].update(context={"text": "x" * 4096}),
    lambda p: p["parse"]["parsed_request"].update(context={"nested": {"value": 1}}),
    lambda p: p["parse"]["parsed_request"].update(context={"nested": [[1]]}),
    lambda p: p["parse"]["parsed_request"].update(context={"text": "unsafe\x00text"}),
    lambda p: p["parse"]["parsed_request"].update(context={str(i): i for i in range(24)}),
    lambda p: p["parse"]["parsed_request"].update(extra=True),
    lambda p: p.update(authorization_id=" auth_other"),
    lambda p: p["results"].update({"customer.delete": p["results"]["ticket.reply"]}),
    lambda p: p["results"]["ticket.reply"].update(decision="maybe"),
    lambda p: p["results"]["ticket.reply"].update(receipt={"status": "unknown"}),
])
@respx.mock
@pytest.mark.asyncio
async def test_text_check_rejects_unbound_or_malformed_response_without_fallback(edit):
    payload = response()
    edit(payload)
    respx.post(BASE + "/v1/agent-check/text").mock(return_value=httpx.Response(200, json=payload))
    async with Allowly("key", base_url=BASE, fallback_by_action={"ticket.reply": "fail_open"}) as client:
        with pytest.raises(AllowlyProtocolError):
            await client.check_text_by_agent(agent_name="Support agent", request=REQUEST, idempotency_key="one")


@respx.mock
@pytest.mark.asyncio
async def test_recheck_rejects_different_parse_id():
    respx.post(BASE + "/v1/agent-check/text/parse_other").mock(return_value=httpx.Response(200, json=response()))
    async with Allowly("key", base_url=BASE) as client:
        with pytest.raises(AllowlyProtocolError):
            await client.recheck_text_by_agent(agent_name="Support agent", parse_id="parse_other", idempotency_key="one")


@pytest.mark.parametrize("method", ["initial", "recheck"])
@pytest.mark.parametrize("status,code", [(422, "text_parse_incomplete"), (429, "text_parse_quota_exceeded"),
                                       (503, "text_parser_busy"), (503, "text_parser_unavailable")])
@respx.mock
@pytest.mark.asyncio
async def test_text_check_propagates_api_errors_once(method, status, code):
    path = "/v1/agent-check/text" + ("/parse_one" if method == "recheck" else "")
    route = respx.post(BASE + path).mock(return_value=httpx.Response(status, json={"error": {
        "code": code, "message": "Check stopped", "fields": [{"field": "amount_micros", "message": "required"}]}}))
    async with Allowly("key", base_url=BASE, fallback_by_action={"ticket.reply": "fail_open"}) as client:
        with pytest.raises(AllowlyAPIError) as error:
            if method == "initial":
                await client.check_text_by_agent(agent_name="Support agent", request=REQUEST, idempotency_key="one")
            else:
                await client.recheck_text_by_agent(agent_name="Support agent", parse_id="parse_one", idempotency_key="one")
    assert error.value.status == status and error.value.code == code
    assert error.value.retry_after_seconds is None
    assert error.value.fields[0].field == "amount_micros"
    assert route.call_count == 1
    assert route.calls[0].request.method == "POST"


@pytest.mark.parametrize("method", ["initial", "recheck"])
@respx.mock
@pytest.mark.asyncio
async def test_text_check_never_falls_back_on_transport_or_calls_identity_supplier(method):
    path = "/v1/agent-check/text" + ("/parse_one" if method == "recheck" else "")
    route = respx.post(BASE + path).mock(side_effect=httpx.ConnectError("offline"))
    arguments = {"agent_name": "Support agent", "idempotency_key": "one",
                 **({"request": REQUEST} if method == "initial" else {"parse_id": "parse_one"})}
    async with Allowly("key", base_url=BASE, fallback_by_action={"ticket.reply": "fail_open"}) as client:
        call = client.check_text_by_agent if method == "initial" else client.recheck_text_by_agent
        with pytest.raises(httpx.ConnectError):
            await call(**arguments)
    supplier = Mock(return_value="identity")
    async with Allowly("key", base_url=BASE, agent_token_supplier=supplier) as client:
        call = client.check_text_by_agent if method == "initial" else client.recheck_text_by_agent
        with pytest.raises(ValueError, match="configured agent identity"):
            await call(**arguments)
    supplier.assert_not_called()
    assert route.call_count == 1


@pytest.mark.parametrize("text_request", [" ", "🙂" * 4097, "unsafe\x00text"])
@pytest.mark.asyncio
async def test_text_request_limit_counts_utf8_bytes(text_request):
    async with Allowly("key", base_url=BASE) as client:
        with pytest.raises(ValueError):
            await client.check_text_by_agent(agent_name="Support agent", request=text_request, idempotency_key="one")
