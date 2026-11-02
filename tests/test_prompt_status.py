import httpx
import pytest
import respx

from allowly import (
    Allowly, AllowlyProtocolError, ConfirmationStatus, ConfirmationStatusResponse,
    EscalationStatus, EscalationStatusResponse,
)

BASE = "https://api.example.com"


def test_released_names_alias_the_same_implementation():
    assert ConfirmationStatus is ConfirmationStatusResponse
    assert EscalationStatus is EscalationStatusResponse
    client = Allowly("key", base_url=BASE)
    for resource in (client.confirmations, client.escalations):
        assert resource.get.__func__ is resource.get_status.__func__


def payload(kind):
    value = {"authorization_id": "auth_original", "action": "github.read", "resource": None,
             "status": "pending", "expires_at": "2026-10-12T00:00:00Z", "resolved_at": None,
             "source_receipt_id": "rcp_original", "resolution_receipt_id": None, "authority_status": "none"}
    if kind == "confirm":
        value.update(confirmation_id="cnf_original", child_authorization_id=None, authority_expires_at=None)
    else:
        value.update(escalation_id="esc_original", consumed_at=None)
    return value


@pytest.mark.parametrize("kind", ["confirm", "escalate"])
@pytest.mark.parametrize("status", ["pending", "approved", "rejected", "expired", "unknown"])
@respx.mock
async def test_prompt_status_reads_typed_monitor_without_mutation(kind, status):
    value = payload(kind)
    value["status"] = status
    path = "/v1/confirmations/cnf_original/status" if kind == "confirm" else "/v1/escalations/esc_original"
    route = respx.get(BASE + path).mock(return_value=httpx.Response(200, json=value))
    async with Allowly("private-key", base_url=BASE) as client:
        resource = client.confirmations if kind == "confirm" else client.escalations
        result = await resource.get_status("cnf_original" if kind == "confirm" else "esc_original")
    assert isinstance(result, ConfirmationStatusResponse if kind == "confirm" else EscalationStatusResponse)
    assert result.status == status and result.source_receipt_id == "rcp_original"
    assert len(respx.calls) == 1 and route.calls.last.request.method == "GET"


@pytest.mark.parametrize("kind", ["confirm", "escalate"])
@pytest.mark.parametrize("field,bad", [("status", "allow"), ("authority_status", "allow"), ("resource", 42),
                                      ("source_receipt_id", False), ("resolved_at", []), ("expires_at", None)])
@respx.mock
async def test_prompt_status_rejects_malformed_shape(kind, field, bad):
    value = payload(kind)
    value[field] = bad
    path = "/v1/confirmations/cnf_original/status" if kind == "confirm" else "/v1/escalations/esc_original"
    respx.get(BASE + path).mock(return_value=httpx.Response(200, json=value))
    async with Allowly("key", base_url=BASE) as client:
        with pytest.raises(AllowlyProtocolError):
            await (client.confirmations if kind == "confirm" else client.escalations).get_status(
                "cnf_original" if kind == "confirm" else "esc_original")


@respx.mock
async def test_status_wrong_id_missing_binding_and_confirmation_consumed_are_refused():
    value = payload("confirm")
    route = respx.get(BASE + "/v1/confirmations/cnf_original/status")
    async with Allowly("key", base_url=BASE) as client:
        for bad in ({**value, "confirmation_id": "cnf_other"}, {**value, "authority_status": "consumed"},
                    {key: val for key, val in value.items() if key != "source_receipt_id"}):
            route.mock(return_value=httpx.Response(200, json=bad))
            with pytest.raises(AllowlyProtocolError):
                await client.confirmations.get_status("cnf_original")
        with pytest.raises(ValueError):
            await client.confirmations.get_status("bearer-nonce")


@respx.mock
async def test_escalation_consumed_and_legacy_null_evidence_are_not_permission():
    value = {**payload("escalate"), "status": "unknown", "authority_status": "consumed", "source_receipt_id": None}
    respx.get(BASE + "/v1/escalations/esc_original").mock(return_value=httpx.Response(200, json=value))
    async with Allowly("key", base_url=BASE) as client:
        result = await client.escalations.get_status("esc_original")
    assert result.status == "unknown" and result.authority_status == "consumed" and result.source_receipt_id is None


@respx.mock
async def test_readiness_strict_read_only_boolean():
    route = respx.get(BASE + "/readyz")
    async with Allowly("key", base_url=BASE) as client:
        for value, expected in [({"status": "ready"}, True), ({"status": "not_ready"}, False)]:
            route.mock(return_value=httpx.Response(200, json=value))
            assert await client.readiness() is expected
        route.mock(return_value=httpx.Response(200, json={}))
        with pytest.raises(AllowlyProtocolError):
            await client.readiness()


@pytest.mark.parametrize("kind", ["confirm", "escalate"])
@respx.mock
async def test_status_reconnects_once_after_remote_disconnect(kind):
    path = "/v1/confirmations/cnf_original/status" if kind == "confirm" else "/v1/escalations/esc_original"
    route = respx.get(BASE + path).mock(side_effect=[
        httpx.RemoteProtocolError("Server disconnected without sending a response"),
        httpx.Response(200, json=payload(kind)),
    ])
    async with Allowly("private-key", base_url=BASE) as client:
        resource = client.confirmations if kind == "confirm" else client.escalations
        result = await resource.get_status("cnf_original" if kind == "confirm" else "esc_original")
    assert result.status == "pending" and result.authority_status == "none"
    assert result.source_receipt_id == "rcp_original"
    assert route.call_count == 2
    assert [(call.request.method, call.request.url.path) for call in respx.calls] == [("GET", path)] * 2
    assert all(call.request.headers["authorization"] == "Bearer private-key" for call in route.calls)


@pytest.mark.parametrize("kind", ["confirm", "escalate"])
@respx.mock
async def test_status_disconnect_retry_is_bounded_without_check_fallback(kind):
    path = "/v1/confirmations/cnf_original/status" if kind == "confirm" else "/v1/escalations/esc_original"
    route = respx.get(BASE + path).mock(
        side_effect=httpx.RemoteProtocolError("connection closed"))
    async with Allowly("key", base_url=BASE, fallback_by_action={"github.read": "fail_open"}) as client:
        with pytest.raises(httpx.RemoteProtocolError):
            await (client.confirmations if kind == "confirm" else client.escalations).get_status(
                "cnf_original" if kind == "confirm" else "esc_original")
    assert route.call_count == 2
    assert all(call.request.method == "GET" for call in respx.calls)


@pytest.mark.parametrize("kind", ["confirm", "escalate"])
@respx.mock
async def test_reconnected_status_still_rejects_malformed_authority(kind):
    path = "/v1/confirmations/cnf_original/status" if kind == "confirm" else "/v1/escalations/esc_original"
    route = respx.get(BASE + path).mock(side_effect=[
        httpx.RemoteProtocolError("connection closed"),
        httpx.Response(200, json={**payload(kind), "authority_status": "allow"}),
    ])
    async with Allowly("key", base_url=BASE, fallback_by_action={"github.read": "fail_open"}) as client:
        with pytest.raises(AllowlyProtocolError):
            await (client.confirmations if kind == "confirm" else client.escalations).get_status(
                "cnf_original" if kind == "confirm" else "esc_original")
    assert route.call_count == 2
    assert all(call.request.method == "GET" for call in respx.calls)


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
@respx.mock
async def test_remote_disconnect_never_replays_mutating_requests(method):
    route = respx.request(method, BASE + "/v1/check").mock(side_effect=[
        httpx.RemoteProtocolError("response lost"), httpx.Response(200, json={}),
    ])
    async with Allowly("key", base_url=BASE) as client:
        with pytest.raises(httpx.RemoteProtocolError):
            await client._request(method, "/v1/check", json={"authorization_id": "auth_original"})
    assert route.call_count == 1


@respx.mock
async def test_check_remote_disconnect_is_not_replayed():
    route = respx.post(BASE + "/v1/check").mock(side_effect=[
        httpx.RemoteProtocolError("response lost"), httpx.Response(200, json={}),
    ])
    async with Allowly("key", base_url=BASE) as client:
        result = await client.check(authorization_id="auth_original", actions=["github.read"])
    assert route.call_count == 1
    assert result.results["github.read"].decision == "deny"
    assert result.results["github.read"].is_fallback


@respx.mock
async def test_named_check_remote_disconnect_is_not_replayed_or_allowed():
    route = respx.post(BASE + "/v1/agent-check").mock(side_effect=[
        httpx.RemoteProtocolError("response lost"), httpx.Response(200, json={}),
    ])
    async with Allowly("key", base_url=BASE, fallback_by_action={"github.read": "fail_open"}) as client:
        with pytest.raises(httpx.RemoteProtocolError):
            await client.check_by_agent(
                agent_name="review agent", actions=["github.read"],
                expected_policy_ref={"policy_id": "review", "policy_version": 1, "definition_sha256": "a" * 64},
            )
    assert route.call_count == 1
