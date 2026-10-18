import copy
import json
from dataclasses import asdict

import httpx
import pytest

from allowly import Allowly, AllowlyAPIError, AllowlyProtocolError, ObserveEventStatus

REFERENCE = {"policy_id": "published", "policy_version": 1, "definition_sha256": "a" * 64}
EVENT = {"event_id": "operation:1", "agent_id": "agent_demo", "action": "email.send", "policy_ref": REFERENCE,
         "occurred_at": "2026-10-18T20:00:00Z", "reported_execution": "sent", "sources": {"body": "Fictional capture"}}
STATUS = {**{key: EVENT[key] for key in ("event_id", "agent_id", "action", "policy_ref", "reported_execution")},
          "mode": "observe", "intervention": "none", "processing_status": "pending", "assessment_status": "not_assessed",
          "signing_status": "unavailable", "observed_action_id": None, "assessment_id": None, "dashboard_url": None, "last_error": None}


async def client_with(respond):
    client = Allowly("runtime-key", base_url="https://api.test", fallback_by_action={"email.send": "fail_open"})
    await client._http.aclose()
    client._http = httpx.AsyncClient(base_url="https://api.test", headers={"Authorization": "Bearer runtime-key"}, transport=httpx.MockTransport(respond))
    return client


async def test_submit_and_get_use_runtime_auth_exact_status_and_frozen_snake_case_dataclass():
    calls = []
    def respond(request):
        calls.append(request)
        assert request.headers["Authorization"] == "Bearer runtime-key"
        if request.method == "POST":
            assert request.url.path == "/v1/observe/events"
            assert json.loads(request.content) == EVENT
            return httpx.Response(202, json=STATUS)
        assert request.url.raw_path == b"/v1/observe/events/operation%3A1"
        return httpx.Response(200, json={**STATUS, "processing_status": "complete", "assessment_status": "violation_detected", "signing_status": "signed", "assessment_id": "assessment_test", "observed_action_id": "action_test"})
    async with await client_with(respond) as client:
        result = await client.observe.submit(**copy.deepcopy(EVENT))
        assert isinstance(result, ObserveEventStatus)
        assert asdict(result) == STATUS
        final = await client.observe.get(EVENT["event_id"])
        assert final.assessment_status == "violation_detected"
    assert len(calls) == 2


@pytest.mark.parametrize("method,status", [("submit", 200), ("submit", 201), ("get", 202), ("get", 204)])
async def test_success_status_is_not_interchangeable(method, status):
    async with await client_with(lambda request: httpx.Response(status, json=STATUS)) as client:
        with pytest.raises(AllowlyProtocolError):
            await (client.observe.submit(**EVENT) if method == "submit" else client.observe.get(EVENT["event_id"]))


@pytest.mark.parametrize("change", [
    {"event_id": "other"}, {"agent_id": "other"}, {"action": "email.read"}, {"policy_ref": {**REFERENCE, "policy_version": 2}},
    {"reported_execution": "unknown"}, {"mode": "enforce"}, {"intervention": "deny"}, {"assessment_status": "allow"},
    {"sources": {"body": "must not leak"}}, {"policy_ref": {**REFERENCE, "policy_version": True}}, {"signing_status": None},
])
async def test_submit_rejects_unbound_or_malformed_success(change):
    async with await client_with(lambda request: httpx.Response(202, json={**STATUS, **change})) as client:
        with pytest.raises(AllowlyProtocolError):
            await client.observe.submit(**EVENT)


async def test_status_requires_nullable_fields_instead_of_defaulting_them():
    incomplete = {key: value for key, value in STATUS.items() if key != "assessment_id"}
    async with await client_with(lambda request: httpx.Response(200, json=incomplete)) as client:
        with pytest.raises(AllowlyProtocolError):
            await client.observe.get(EVENT["event_id"])


@pytest.mark.parametrize("change", [
    {"event_id": "../escape"}, {"sources": {"body": True}}, {"sources": {}}, {"sources": {"x" * 65: "text"}},
    {"sources": {"body": "x" * 40960}}, {"sources": {"body": "\0"}}, {"occurred_at": "2026-10-18T20:00:00"},
    {"policy_ref": {**REFERENCE, "policy_version": True}},
])
async def test_invalid_capture_is_rejected_before_network(change):
    def unexpected(request):
        pytest.fail("invalid input reached the API")
    async with await client_with(unexpected) as client:
        with pytest.raises(AllowlyProtocolError):
            await client.observe.submit(**{**EVENT, **change})


@pytest.mark.parametrize("response", ["timeout", "conflict", "invalid_json"])
async def test_no_automatic_retry_or_fail_open_for_ambiguous_report(response):
    calls = []
    def respond(request):
        calls.append(request)
        if response == "timeout":
            raise httpx.ReadTimeout("ambiguous", request=request)
        if response == "conflict":
            return httpx.Response(409, json={"error": {"code": "event_conflict", "message": "Different content"}})
        return httpx.Response(202, content=b"not-json")
    async with await client_with(respond) as client:
        with pytest.raises((httpx.ReadTimeout, AllowlyAPIError, AllowlyProtocolError)):
            await client.observe.submit(**EVENT)
    assert len(calls) == 1
