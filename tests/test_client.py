import pytest
import httpx
import respx

from allowly import Allowly, AllowlyAPIError, AllowlyProtocolError

BASE = "https://api.example.com"

PENDING_RECEIPT = {
    "status": "pending",
    "receipt_id": "rcp_abc",
    "ready_at_estimate": "2026-04-21T14:32:18.482Z",
    "url": f"{BASE}/v1/receipts/rcp_abc",
}


@pytest.fixture
def client():
    return Allowly(api_key="test-key", base_url=BASE)


def test_client_rejects_insecure_base_url_by_default():
    with pytest.raises(ValueError, match="HTTPS"):
        Allowly(api_key="test-key", base_url="http://api.example.com")


def test_client_allows_insecure_base_url_with_explicit_opt_in():
    Allowly(
        api_key="test-key",
        base_url="http://localhost:8000",
        dangerously_allow_insecure_base_url=True,
    )


@respx.mock
@pytest.mark.asyncio
async def test_check_allow(client):
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "user_id": "u1",
        "agent_id": "a1",
        "authorization_id": "auth_1",
        "authorization_expires_at": "2026-12-31T00:00:00Z",
        "engine_version": "2026-04-19.1",
        "results": {
            "email.read": {
                "decision": "allow",
                "reason": "authorization_granted_action_active",
                "receipt": PENDING_RECEIPT,
            }
        },
    }))
    res = await client.check(authorization_id="auth_1", actions=["email.read"])
    item = res.results["email.read"]
    assert item.decision == "allow"
    assert item.is_fallback is False
    assert item.fallback_mode is None
    assert item.budget is None
    assert item.policy_eval is None
    assert item.receipt is not None
    assert item.receipt.receipt_id == "rcp_abc"
    assert item.receipt.status == "pending"


@respx.mock
@pytest.mark.asyncio
async def test_check_deny(client):
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_nope",
        "engine_version": "2026-04-19.1",
        "results": {
            "email.read": {
                "decision": "deny",
                "reason": "authorization_superseded",
                "superseded_by": "auth_new",
                "receipt": PENDING_RECEIPT,
            }
        },
    }))
    res = await client.check(authorization_id="auth_nope", actions=["email.read"])
    assert res.results["email.read"].decision == "deny"
    assert res.results["email.read"].reason == "authorization_superseded"
    assert res.results["email.read"].superseded_by == "auth_new"


@respx.mock
@pytest.mark.asyncio
async def test_check_confirm(client):
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_2",
        "authorization_expires_at": "2026-12-31T00:00:00Z",
        "engine_version": "2026-04-19.1",
        "results": {
            "email.send": {
                "decision": "confirm",
                "reason": "action_requires_user_confirmation",
                "confirm_nonce": "cnf_abc",
                "confirm_expires_at": "2026-04-20T00:15:00Z",
                "confirm_prompt_hint": "email.send",
                "receipt": PENDING_RECEIPT,
            }
        },
    }))
    res = await client.check(authorization_id="auth_2", actions=["email.send"])
    item = res.results["email.send"]
    assert item.decision == "confirm"
    assert item.confirm_nonce == "cnf_abc"  # type: ignore[union-attr]


@respx.mock
@pytest.mark.asyncio
async def test_check_parses_policy_eval(client):
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_policy",
        "authorization_expires_at": "2026-12-31T00:00:00Z",
        "engine_version": "2026-04-19.1",
        "results": {
            "hiring.publish_feedback": {
                "decision": "confirm",
                "reason": "condition_requires_user_confirmation",
                "confirm_nonce": "cnf_policy",
                "confirm_expires_at": "2026-04-20T00:15:00Z",
                "confirm_prompt_hint": "hiring.publish_feedback",
                "policy_eval": {
                    "matched_condition": {
                        "field": "checks_failed",
                        "op": "in",
                        "value": ["pii_detected", "tone_flag"],
                    },
                    "field_value": "pii_detected",
                },
                "receipt": PENDING_RECEIPT,
            }
        },
    }))
    res = await client.check(authorization_id="auth_policy", actions=["hiring.publish_feedback"])
    item = res.results["hiring.publish_feedback"]
    assert item.decision == "confirm"
    assert item.policy_eval is not None
    assert item.policy_eval.matched_condition is not None
    assert item.policy_eval.matched_condition.field == "checks_failed"
    assert item.policy_eval.matched_condition.op == "in"
    assert item.policy_eval.matched_condition.value == ["pii_detected", "tone_flag"]
    assert item.policy_eval.field_value == "pii_detected"


@respx.mock
@pytest.mark.asyncio
async def test_check_escalate(client):
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_esc",
        "authorization_expires_at": "2026-12-31T00:00:00Z",
        "engine_version": "2026-04-19.1",
        "results": {
            "candidate.delete": {
                "decision": "escalate",
                "reason": "escalation_required",
                "escalation_id": "esc_abc",
                "escalation_to": "compliance",
                "escalation_expires_at": "2026-04-21T17:00:00Z",
                "escalation": {
                    "escalation_id": "esc_abc",
                    "status": "pending",
                    "escalation_to": "compliance",
                    "expires_at": "2026-04-21T17:00:00Z",
                },
                "receipt": PENDING_RECEIPT,
            }
        },
    }))
    res = await client.check(authorization_id="auth_esc", actions=["candidate.delete"])
    item = res.results["candidate.delete"]
    assert item.decision == "escalate"
    assert item.escalation_id == "esc_abc"  # type: ignore[union-attr]
    assert item.escalation_to == "compliance"  # type: ignore[union-attr]
    assert item.escalation is not None
    assert item.escalation.status == "pending"


@respx.mock
@pytest.mark.asyncio
async def test_check_raises_on_401(client):
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(401, json={
        "error": {"code": "unauthorized", "message": "Invalid or revoked API key"}
    }))
    with pytest.raises(AllowlyAPIError) as exc_info:
        await client.check(authorization_id="auth_1", actions=["x"])
    assert exc_info.value.status == 401
    assert exc_info.value.code == "unauthorized"


@respx.mock
@pytest.mark.asyncio
async def test_check_sends_auth_header(client):
    route = respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_1",
        "engine_version": "2026-04-19.1",
        "results": {
            "x": {"decision": "deny", "reason": "authorization_not_found", "receipt": PENDING_RECEIPT}
        },
    }))
    await client.check(authorization_id="auth_1", actions=["x"])
    assert route.calls[0].request.headers["authorization"] == "Bearer test-key"


@respx.mock
@pytest.mark.asyncio
async def test_check_sends_idempotency_key(client):
    route = respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_1",
        "engine_version": "2026-04-19.1",
        "results": {
            "x": {"decision": "deny", "reason": "authorization_not_found", "receipt": PENDING_RECEIPT}
        },
    }))
    await client.check(authorization_id="auth_1", actions=["x"], idempotency_key="idem_1")
    assert route.calls[0].request.headers["idempotency-key"] == "idem_1"


@respx.mock
@pytest.mark.asyncio
async def test_check_sends_multi_action_v10_body(client):
    route = respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_1",
        "engine_version": "2026-04-19.1",
        "results": {
            "public.web.search": {"decision": "allow", "reason": "ok", "receipt": PENDING_RECEIPT},
            "public.page.read": {"decision": "deny", "reason": "action_not_in_authorization", "receipt": PENDING_RECEIPT},
        },
    }))
    res = await client.check(
        authorization_id="auth_1",
        actions=["public.web.search", "public.page.read"],
        resource="subject:s_123",
        estimated_cost_micros=12345,
        context={"stage": "filter3"},
    )
    import json
    body = json.loads(route.calls[0].request.content)
    assert body["actions"] == ["public.web.search", "public.page.read"]
    assert body["resource"] == "subject:s_123"
    assert body["estimated_cost_micros"] == 12345
    assert body["context"] == {"stage": "filter3"}
    assert res.results["public.web.search"].decision == "allow"
    assert res.results["public.page.read"].decision == "deny"


@respx.mock
@pytest.mark.asyncio
async def test_check_parses_budget_result(client):
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_1",
        "engine_version": "2026-04-19.1",
        "results": {
            "llm.enrich": {
                "decision": "allow",
                "reason": "authorization_granted_action_active",
                "receipt": PENDING_RECEIPT,
                "budget": {
                    "limit_micros": 1_000_000,
                    "spent_micros": 100_000,
                    "estimated_cost_micros": 25_000,
                    "spent_after_micros": 125_000,
                },
            }
        },
    }))
    res = await client.check(
        authorization_id="auth_1",
        actions=["llm.enrich"],
        estimated_cost_micros=25_000,
    )

    budget = res.results["llm.enrich"].budget
    assert budget is not None
    assert budget.limit_micros == 1_000_000
    assert budget.spent_micros == 100_000
    assert budget.estimated_cost_micros == 25_000
    assert budget.spent_after_micros == 125_000


@respx.mock
@pytest.mark.asyncio
async def test_check_rejects_malformed_budget(client):
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_1",
        "engine_version": "test",
        "results": {"llm.enrich": {
            "decision": "allow",
            "reason": "ok",
            "receipt": PENDING_RECEIPT,
            "budget": {"spent_micros": 1, "estimated_cost_micros": 1},
        }},
    }))

    with pytest.raises(AllowlyProtocolError, match="limit_micros"):
        await client.check(authorization_id="auth_1", actions=["llm.enrich"])


@respx.mock
@pytest.mark.asyncio
async def test_check_rejects_unknown_decision_even_with_fail_open():
    client = Allowly(
        api_key="test-key",
        base_url=BASE,
        fallback_by_action={"payments.send": "fail_open"},
    )
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_1",
        "engine_version": "test",
        "results": {
            "payments.send": {
                "decision": "future_value",
                "reason": "bad response",
                "receipt": PENDING_RECEIPT,
            }
        },
    }))

    with pytest.raises(AllowlyProtocolError, match="unknown check decision"):
        await client.check(authorization_id="auth_1", actions=["payments.send"])


@pytest.mark.asyncio
async def test_waiting_check_uses_server_wait_window(monkeypatch):
    client = Allowly(api_key="test-key", base_url=BASE)
    seen = {}

    async def request(method, path, **kwargs):
        seen["timeout"] = kwargs["timeout"]
        return {
            "authorization_id": "auth_1",
            "engine_version": "test",
            "results": {
                "x": {"decision": "allow", "reason": "ok", "receipt": PENDING_RECEIPT}
            },
        }

    monkeypatch.setattr(client, "_request", request)
    await client.check(authorization_id="auth_1", actions=["x"], wait=True)
    assert seen["timeout"] == 6.0


@respx.mock
@pytest.mark.asyncio
async def test_check_timeout_fail_open_returns_local_fallback():
    client = Allowly(
        api_key="test-key",
        base_url=BASE,
        check_timeout_ms=1,
        fallback_by_action={"public.web.search": "fail_open"},
    )
    respx.post(f"{BASE}/v1/check").mock(side_effect=httpx.ReadTimeout("slow"))

    res = await client.check(authorization_id="auth_1", actions=["public.web.search"])
    item = res.results["public.web.search"]

    assert item.decision == "allow"
    assert item.reason == "fallback_open_timeout"
    assert item.is_fallback is True
    assert item.fallback_mode == "fail_open"
    assert item.receipt is None
    assert item.budget is None
    assert res.authorization_id == "auth_1"
    assert res.engine_version == "sdk_fallback"


@respx.mock
@pytest.mark.asyncio
async def test_check_timeout_unmapped_action_uses_default_fail_closed():
    client = Allowly(api_key="test-key", base_url=BASE, check_timeout_ms=1)
    respx.post(f"{BASE}/v1/check").mock(side_effect=httpx.ReadTimeout("slow"))

    res = await client.check(authorization_id="auth_1", actions=["email.send"])
    item = res.results["email.send"]

    assert item.decision == "deny"
    assert item.reason == "fallback_closed_timeout"
    assert item.is_fallback is True
    assert item.fallback_mode == "fail_closed"
    assert item.receipt is None


@respx.mock
@pytest.mark.asyncio
async def test_check_connection_error_fail_open_returns_unreachable():
    client = Allowly(
        api_key="test-key",
        base_url=BASE,
        fallback_by_action={"public.web.search": "fail_open"},
    )
    respx.post(f"{BASE}/v1/check").mock(side_effect=httpx.ConnectError("offline"))

    res = await client.check(authorization_id="auth_1", actions=["public.web.search"])
    item = res.results["public.web.search"]

    assert item.decision == "allow"
    assert item.reason == "fallback_open_unreachable"
    assert item.is_fallback is True
    assert item.fallback_mode == "fail_open"
    assert item.receipt is None


@respx.mock
@pytest.mark.asyncio
async def test_check_5xx_fail_closed_returns_unreachable():
    client = Allowly(api_key="test-key", base_url=BASE)
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(503, json={
        "error": {"code": "unavailable", "message": "try again"}
    }))

    res = await client.check(authorization_id="auth_1", actions=["email.send"])
    item = res.results["email.send"]

    assert item.decision == "deny"
    assert item.reason == "fallback_closed_unreachable"
    assert item.is_fallback is True
    assert item.fallback_mode == "fail_closed"
    assert item.receipt is None


@respx.mock
@pytest.mark.asyncio
async def test_check_non_json_5xx_returns_unreachable():
    client = Allowly(api_key="test-key", base_url=BASE)
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(502, text="<html>bad gateway</html>"))

    res = await client.check(authorization_id="auth_1", actions=["email.send"])

    assert res.results["email.send"].reason == "fallback_closed_unreachable"


@respx.mock
@pytest.mark.asyncio
async def test_check_malformed_error_body_still_fails_closed():
    """A proxy 5xx whose error.fields is not a list must not crash the fallback."""
    client = Allowly(api_key="test-key", base_url=BASE)
    respx.post(f"{BASE}/v1/check").mock(
        return_value=httpx.Response(503, json={"error": {"fields": "boom"}})
    )

    res = await client.check(authorization_id="auth_1", actions=["email.send"])

    assert res.results["email.send"].reason == "fallback_closed_unreachable"


@respx.mock
@pytest.mark.asyncio
async def test_string_error_body_preserves_message(client):
    """LB shape {"error": "..."} must survive into AllowlyAPIError.message."""
    respx.post(f"{BASE}/v1/authorizations").mock(
        return_value=httpx.Response(400, json={"error": "upstream connect timeout"})
    )
    with pytest.raises(AllowlyAPIError) as exc_info:
        await client.authorizations.create(user_id="u1", actions=["email.read"])
    assert exc_info.value.status == 400
    assert "upstream connect timeout" in str(exc_info.value)


@respx.mock
@pytest.mark.asyncio
async def test_path_params_are_percent_encoded(client):
    """An id with reserved chars must not redirect the authenticated request."""
    route = respx.delete(
        f"{BASE}/v1/authorizations/..%2Fpolicies%2Fresearch_agent"
    ).mock(return_value=httpx.Response(200, json={
        "authorization_id": "x", "revoked_at": "t", "receipt": PENDING_RECEIPT,
    }))
    await client.authorizations.revoke("../policies/research_agent")
    assert route.called
    assert "/v1/policies/" not in str(route.calls[0].request.url)


@respx.mock
@pytest.mark.asyncio
async def test_check_mixed_action_fallback_modes():
    client = Allowly(
        api_key="test-key",
        base_url=BASE,
        fallback_by_action={
            "public.web.search": "fail_open",
            "email.send": "fail_closed",
        },
    )
    respx.post(f"{BASE}/v1/check").mock(side_effect=httpx.ConnectError("offline"))

    res = await client.check(
        authorization_id="auth_1",
        actions=["public.web.search", "email.send"],
    )

    assert res.results["public.web.search"].decision == "allow"
    assert res.results["public.web.search"].reason == "fallback_open_unreachable"
    assert res.results["email.send"].decision == "deny"
    assert res.results["email.send"].reason == "fallback_closed_unreachable"


@respx.mock
@pytest.mark.asyncio
async def test_check_429_does_not_fallback():
    client = Allowly(
        api_key="test-key",
        base_url=BASE,
        fallback_by_action={"public.web.search": "fail_open"},
    )
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(429, json={
        "error": {"code": "quota_exceeded", "message": "quota exceeded"}
    }))

    with pytest.raises(AllowlyAPIError) as exc_info:
        await client.check(authorization_id="auth_1", actions=["public.web.search"])
    assert exc_info.value.status == 429
    assert exc_info.value.code == "quota_exceeded"


@respx.mock
@pytest.mark.asyncio
async def test_fallback_results_are_not_cached():
    client = Allowly(
        api_key="test-key",
        base_url=BASE,
        fallback_by_action={"public.web.search": "fail_open"},
    )
    route = respx.post(f"{BASE}/v1/check").mock(side_effect=httpx.ConnectError("offline"))

    await client.check(authorization_id="auth_1", actions=["public.web.search"])
    await client.check(authorization_id="auth_1", actions=["public.web.search"])

    assert route.call_count == 2


@respx.mock
@pytest.mark.asyncio
async def test_settle_budget_sends_actual_cost_and_idempotency_key(client):
    route = respx.post(f"{BASE}/v1/budget-settlements").mock(return_value=httpx.Response(200, json={
        "check_receipt_id": "rcp_check",
        "authorization_id": "auth_1",
        "estimated_cost_micros": 30,
        "actual_cost_micros": 12,
        "delta_micros": -18,
        "spent_before_micros": 50,
        "spent_after_micros": 32,
        "receipt": PENDING_RECEIPT,
    }))

    res = await client.settle_budget(
        check_receipt_id="rcp_check",
        actual_cost_micros=12,
        idempotency_key="settle-1",
    )

    import json
    body = json.loads(route.calls[0].request.content)
    assert body == {"check_receipt_id": "rcp_check", "actual_cost_micros": 12}
    assert route.calls[0].request.headers["idempotency-key"] == "settle-1"
    assert res.authorization_id == "auth_1"
    assert res.delta_micros == -18
    assert res.receipt.status == "pending"


@respx.mock
@pytest.mark.asyncio
async def test_authorizations_create(client):
    respx.post(f"{BASE}/v1/authorizations").mock(return_value=httpx.Response(201, json={
        "authorization_id": "auth_new",
        "created_at": "2026-04-20T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "receipt": PENDING_RECEIPT,
    }))
    res = await client.authorizations.create(
        user_id="u1", agent_id="a1",
        actions=["email.read"],
        expires_at="2026-12-31T00:00:00Z",
    )
    assert res.authorization_id == "auth_new"
    assert res.receipt.status == "pending"


@respx.mock
@pytest.mark.asyncio
async def test_authorizations_create_with_budget(client):
    route = respx.post(f"{BASE}/v1/authorizations").mock(return_value=httpx.Response(201, json={
        "authorization_id": "auth_budget",
        "created_at": "2026-04-20T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "budget_limit_micros": 50_000_000,
        "budget_spent_micros": 0,
        "receipt": PENDING_RECEIPT,
    }))
    res = await client.authorizations.create(
        user_id="u1",
        agent_id="a1",
        actions=["llm.enrich"],
        budget_limit_micros=50_000_000,
    )
    import json
    body = json.loads(route.calls[0].request.content)
    assert body["budget_limit_micros"] == 50_000_000
    assert res.authorization_id == "auth_budget"
    assert res.budget_limit_micros == 50_000_000
    assert res.budget_spent_micros == 0


@respx.mock
@pytest.mark.asyncio
async def test_authorizations_create_with_escalation(client):
    route = respx.post(f"{BASE}/v1/authorizations").mock(return_value=httpx.Response(201, json={
        "authorization_id": "auth_esc",
        "created_at": "2026-04-20T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "requires_escalation_for": ["candidate.delete"],
        "requires_deny_for": ["email.send"],
        "escalation_targets": {"candidate.delete": "compliance"},
        "replaced_authorization_id": "auth_old",
        "revocation_receipt": PENDING_RECEIPT,
        "receipt": PENDING_RECEIPT,
    }))
    res = await client.authorizations.create(
        user_id="u1",
        agent_id="a1",
        actions=["candidate.delete", "email.send"],
        requires_escalation_for=["candidate.delete"],
        requires_deny_for=["email.send"],
        escalation_targets={"candidate.delete": "compliance"},
        idempotency_key="create-1",
    )
    import json
    body = json.loads(route.calls[0].request.content)
    assert body["requires_escalation_for"] == ["candidate.delete"]
    assert body["requires_deny_for"] == ["email.send"]
    assert body["escalation_targets"] == {"candidate.delete": "compliance"}
    assert route.calls[0].request.headers["idempotency-key"] == "create-1"
    assert res.requires_escalation_for == ["candidate.delete"]
    assert res.requires_deny_for == ["email.send"]
    assert res.escalation_targets == {"candidate.delete": "compliance"}
    assert res.replaced_authorization_id == "auth_old"
    assert res.revocation_receipt is not None


@respx.mock
@pytest.mark.asyncio
async def test_authorizations_create_no_session_id(client):
    """session_id must not be sent — it was removed in v6."""
    route = respx.post(f"{BASE}/v1/authorizations").mock(return_value=httpx.Response(201, json={
        "authorization_id": "auth_new",
        "created_at": "2026-04-20T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "receipt": PENDING_RECEIPT,
    }))
    await client.authorizations.create(
        user_id="u1", agent_id="a1",
        actions=["email.read"],
        expires_at="2026-12-31T00:00:00Z",
    )
    import json
    body = json.loads(route.calls[0].request.content)
    assert "session_id" not in body


@respx.mock
@pytest.mark.asyncio
async def test_authorizations_create_from_policy_id(client):
    route = respx.post(f"{BASE}/v1/authorizations").mock(return_value=httpx.Response(201, json={
        "authorization_id": "auth_policy",
        "policy_id": "research_agent",
        "created_at": "2026-04-20T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "receipt": PENDING_RECEIPT,
    }))
    res = await client.authorizations.create(
        user_id="subject:s_123",
        policy_id="research_agent",
        metadata={"source": "import"},
    )
    import json
    body = json.loads(route.calls[0].request.content)
    assert body["user_id"] == "subject:s_123"
    assert body["policy_id"] == "research_agent"
    assert body["agent_id"] is None
    assert body["actions"] is None
    assert body["metadata"] == {"source": "import"}
    assert res.authorization_id == "auth_policy"
    assert res.policy_id == "research_agent"


@respx.mock
@pytest.mark.asyncio
async def test_non_check_endpoint_5xx_does_not_fallback():
    client = Allowly(
        api_key="test-key",
        base_url=BASE,
        fallback_by_action={"email.read": "fail_open"},
    )
    respx.post(f"{BASE}/v1/authorizations").mock(return_value=httpx.Response(503, json={
        "error": {"code": "unavailable", "message": "try again"}
    }))

    with pytest.raises(AllowlyAPIError) as exc_info:
        await client.authorizations.create(user_id="u1", agent_id="a1", actions=["email.read"])
    assert exc_info.value.status == 503


@respx.mock
@pytest.mark.asyncio
async def test_authorizations_revoke(client):
    route = respx.delete(f"{BASE}/v1/authorizations/auth_123").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_123",
        "revoked_at": "2026-05-01T09:00:00Z",
        "receipt": PENDING_RECEIPT,
        "revoked_confirmations": ["auth_child"],
    }))
    res = await client.authorizations.revoke(
        "auth_123", revoked_by="user", idempotency_key="revoke-1"
    )
    assert res.authorization_id == "auth_123"
    assert res.receipt.status == "pending"
    assert res.revoked_confirmations == ["auth_child"]
    assert route.calls[0].request.headers["idempotency-key"] == "revoke-1"


@respx.mock
@pytest.mark.asyncio
async def test_authorizations_revoke_with_superseded_by(client):
    route = respx.delete(f"{BASE}/v1/authorizations/auth_123").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_123",
        "revoked_at": "2026-05-01T09:00:00Z",
        "receipt": PENDING_RECEIPT,
    }))
    await client.authorizations.revoke("auth_123", superseded_by="auth_456")
    import json
    body = json.loads(route.calls[0].request.content)
    assert body["superseded_by"] == "auth_456"


@respx.mock
@pytest.mark.asyncio
async def test_authorizations_create_with_replaces(client):
    route = respx.post(f"{BASE}/v1/authorizations").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_123",
        "created_at": "2026-05-01T09:00:00Z",
        "expires_at": "2026-05-31T09:00:00Z",
        "receipt": PENDING_RECEIPT,
    }))
    await client.authorizations.create(
        user_id="u1",
        agent_id="a1",
        actions=["email.read"],
        replaces="auth_001",
    )
    import json
    body = json.loads(route.calls[0].request.content)
    assert body["replaces"] == "auth_001"


@respx.mock
@pytest.mark.asyncio
async def test_confirmations_approve(client):
    route = respx.post(f"{BASE}/v1/confirmations/nonce123").mock(return_value=httpx.Response(200, json={
        "decision": "approved", "authorization_id": "auth_xyz", "expires_at": "2026-04-20T00:01:00Z",
    }))
    res = await client.confirmations.approve(
        "nonce123", approved=True, idempotency_key="confirm-1"
    )
    assert res.decision == "approved"
    assert res.authorization_id == "auth_xyz"
    assert route.calls[0].request.headers["idempotency-key"] == "confirm-1"


@respx.mock
@pytest.mark.asyncio
async def test_confirmations_denied(client):
    respx.post(f"{BASE}/v1/confirmations/nonce123").mock(return_value=httpx.Response(200, json={
        "decision": "denied_by_user",
    }))
    res = await client.confirmations.approve("nonce123", approved=False)
    assert res.decision == "denied_by_user"


@respx.mock
@pytest.mark.asyncio
async def test_escalations_approve(client):
    route = respx.post(f"{BASE}/v1/escalations/esc_abc/resolve").mock(return_value=httpx.Response(200, json={
        "escalation_id": "esc_abc",
        "status": "approved",
        "resolved_by": "compliance:1",
        "resolved_at": "2026-04-21T16:15:00Z",
        "receipt": PENDING_RECEIPT,
    }))
    res = await client.escalations.approve("esc_abc", resolved_by="compliance:1", note="ok")
    import json
    body = json.loads(route.calls[0].request.content)
    assert body == {"resolution": "approved", "resolved_by": "compliance:1", "note": "ok"}
    assert res.escalation_id == "esc_abc"
    assert res.status == "approved"
    assert res.receipt is not None
    assert res.receipt.status == "pending"


@respx.mock
@pytest.mark.asyncio
async def test_escalations_reject_idempotent_without_new_receipt(client):
    respx.post(f"{BASE}/v1/escalations/esc_abc/resolve").mock(return_value=httpx.Response(200, json={
        "escalation_id": "esc_abc",
        "status": "rejected",
        "resolved_by": "compliance:1",
        "resolved_at": "2026-04-21T16:15:00Z",
        "receipt": None,
    }))
    res = await client.escalations.reject("esc_abc", resolved_by="compliance:1")
    assert res.status == "rejected"
    assert res.receipt is None


@respx.mock
@pytest.mark.asyncio
async def test_receipts_get_pending(client):
    respx.get(f"{BASE}/v1/receipts/rcp_abc").mock(return_value=httpx.Response(200, json={
        "status": "pending",
        "receipt_id": "rcp_abc",
        "ready_at_estimate": "2026-04-21T14:32:18.482Z",
        "url": f"{BASE}/v1/receipts/rcp_abc",
    }))
    r = await client.receipts.get("rcp_abc")
    assert r.status == "pending"
    assert r.receipt_id == "rcp_abc"  # type: ignore[union-attr]


@respx.mock
@pytest.mark.asyncio
async def test_receipts_get_signed(client):
    signed = {
        "version": "1.1", "receipt_id": "rcp_abc", "decision": "allow",
        "alg": "Ed25519", "key_id": "k", "signature": "sig",
    }
    respx.get(f"{BASE}/v1/receipts/rcp_abc").mock(return_value=httpx.Response(200, json={
        "status": "signed",
        "receipt": signed,
    }))
    r = await client.receipts.get("rcp_abc")
    assert r.status == "signed"
    assert r.receipt == signed  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_receipt_polling_rejects_non_positive_limits(client):
    with pytest.raises(ValueError, match="poll_interval"):
        await client.receipts.fetch_signed("rcp_abc", poll_interval=0)
    with pytest.raises(ValueError, match="timeout"):
        await client.receipts.fetch_signed("rcp_abc", timeout=0)


@pytest.mark.asyncio
async def test_receipt_polling_timeout_includes_request_time(client, monkeypatch):
    import asyncio

    async def slow_get(receipt_id):
        await asyncio.sleep(1)

    monkeypatch.setattr(client.receipts, "get", slow_get)
    with pytest.raises(TimeoutError, match="not signed after"):
        await client.receipts.fetch_signed("rcp_abc", poll_interval=0.001, timeout=0.01)


@respx.mock
@pytest.mark.asyncio
async def test_receipts_reject_unknown_status(client):
    respx.get(f"{BASE}/v1/receipts/rcp_abc").mock(
        return_value=httpx.Response(200, json={"status": "lost"})
    )
    with pytest.raises(AllowlyProtocolError, match="receipt status"):
        await client.receipts.get("rcp_abc")


@pytest.mark.asyncio
async def test_client_async_context_closes_http_client():
    async with Allowly(api_key="test-key", base_url=BASE) as client:
        assert not client._http.is_closed
    assert client._http.is_closed
