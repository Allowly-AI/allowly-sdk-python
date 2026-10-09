import httpx
import pytest
import respx

from allowly import Allowly, AllowlyProtocolError, ConfirmationStatusResponse, EscalationStatusResponse

BASE = "https://api.example.com"


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
