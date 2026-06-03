import pytest
import httpx
import respx

from allowly import Allowly, AllowlyAPIError

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


# ---------------------------------------------------------------------------
# check()
# ---------------------------------------------------------------------------

@respx.mock
@pytest.mark.asyncio
async def test_check_allow(client):
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "user_id": "u1",
        "agent_id": "a1",
        "authorization_id": "auth_1",
        "authorization_expires_at": "2026-12-31T00:00:00Z",
        "policy_version": "2026-04-19.1",
        "results": {
            "email.read": {
                "decision": "allow",
                "reason": "authorization_granted_scope_active",
                "receipt": PENDING_RECEIPT,
            }
        },
    }))
    res = await client.check(authorization_id="auth_1", scopes=["email.read"])
    item = res.results["email.read"]
    assert item.decision == "allow"
    assert item.is_fallback is False
    assert item.fallback_mode is None
    assert item.budget is None
    assert item.receipt is not None
    assert item.receipt.receipt_id == "rcp_abc"
    assert item.receipt.status == "pending"


@respx.mock
@pytest.mark.asyncio
async def test_check_deny(client):
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_nope",
        "policy_version": "2026-04-19.1",
        "results": {
            "email.read": {
                "decision": "deny",
                "reason": "authorization_not_found",
                "receipt": PENDING_RECEIPT,
            }
        },
    }))
    res = await client.check(authorization_id="auth_nope", scopes=["email.read"])
    assert res.results["email.read"].decision == "deny"
    assert res.results["email.read"].reason == "authorization_not_found"


@respx.mock
@pytest.mark.asyncio
async def test_check_confirm(client):
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_2",
        "authorization_expires_at": "2026-12-31T00:00:00Z",
        "policy_version": "2026-04-19.1",
        "results": {
            "email.send": {
                "decision": "confirm",
                "reason": "scope_requires_user_confirmation",
                "confirm_nonce": "cnf_abc",
                "confirm_expires_at": "2026-04-20T00:15:00Z",
                "confirm_prompt_hint": "email.send",
                "receipt": PENDING_RECEIPT,
            }
        },
    }))
    res = await client.check(authorization_id="auth_2", scopes=["email.send"])
    item = res.results["email.send"]
    assert item.decision == "confirm"
    assert item.confirm_nonce == "cnf_abc"  # type: ignore[union-attr]


@respx.mock
@pytest.mark.asyncio
async def test_check_raises_on_401(client):
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(401, json={
        "error": {"code": "unauthorized", "message": "Invalid or revoked API key"}
    }))
    with pytest.raises(AllowlyAPIError) as exc_info:
        await client.check(authorization_id="auth_1", scopes=["x"])
    assert exc_info.value.status == 401
    assert exc_info.value.code == "unauthorized"


@respx.mock
@pytest.mark.asyncio
async def test_check_sends_auth_header(client):
    route = respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_1",
        "policy_version": "2026-04-19.1",
        "results": {
            "x": {"decision": "deny", "reason": "authorization_not_found", "receipt": PENDING_RECEIPT}
        },
    }))
    await client.check(authorization_id="auth_1", scopes=["x"])
    assert route.calls[0].request.headers["authorization"] == "Bearer test-key"


@respx.mock
@pytest.mark.asyncio
async def test_check_sends_multi_scope_v10_body(client):
    route = respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_1",
        "policy_version": "2026-04-19.1",
        "results": {
            "public.web.search": {"decision": "allow", "reason": "ok", "receipt": PENDING_RECEIPT},
            "public.page.read": {"decision": "deny", "reason": "scope_not_authorized", "receipt": PENDING_RECEIPT},
        },
    }))
    res = await client.check(
        authorization_id="auth_1",
        scopes=["public.web.search", "public.page.read"],
        resource="subject:s_123",
        estimated_cost_micros=12345,
        context={"stage": "filter3"},
    )
    import json
    body = json.loads(route.calls[0].request.content)
    assert body["scopes"] == ["public.web.search", "public.page.read"]
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
        "policy_version": "2026-04-19.1",
        "results": {
            "llm.enrich": {
                "decision": "allow",
                "reason": "authorization_granted_scope_active",
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
        scopes=["llm.enrich"],
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
async def test_check_timeout_fail_open_returns_local_fallback():
    client = Allowly(
        api_key="test-key",
        base_url=BASE,
        check_timeout_ms=1,
        fallback_by_scope={"public.web.search": "fail_open"},
    )
    respx.post(f"{BASE}/v1/check").mock(side_effect=httpx.ReadTimeout("slow"))

    res = await client.check(authorization_id="auth_1", scopes=["public.web.search"])
    item = res.results["public.web.search"]

    assert item.decision == "allow"
    assert item.reason == "fallback_open_timeout"
    assert item.is_fallback is True
    assert item.fallback_mode == "fail_open"
    assert item.receipt is None
    assert item.budget is None
    assert res.authorization_id == "auth_1"
    assert res.policy_version == "sdk_fallback"


@respx.mock
@pytest.mark.asyncio
async def test_check_timeout_unmapped_scope_uses_default_fail_closed():
    client = Allowly(api_key="test-key", base_url=BASE, check_timeout_ms=1)
    respx.post(f"{BASE}/v1/check").mock(side_effect=httpx.ReadTimeout("slow"))

    res = await client.check(authorization_id="auth_1", scopes=["email.send"])
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
        fallback_by_scope={"public.web.search": "fail_open"},
    )
    respx.post(f"{BASE}/v1/check").mock(side_effect=httpx.ConnectError("offline"))

    res = await client.check(authorization_id="auth_1", scopes=["public.web.search"])
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

    res = await client.check(authorization_id="auth_1", scopes=["email.send"])
    item = res.results["email.send"]

    assert item.decision == "deny"
    assert item.reason == "fallback_closed_unreachable"
    assert item.is_fallback is True
    assert item.fallback_mode == "fail_closed"
    assert item.receipt is None


@respx.mock
@pytest.mark.asyncio
async def test_check_mixed_scope_fallback_modes():
    client = Allowly(
        api_key="test-key",
        base_url=BASE,
        fallback_by_scope={
            "public.web.search": "fail_open",
            "email.send": "fail_closed",
        },
    )
    respx.post(f"{BASE}/v1/check").mock(side_effect=httpx.ConnectError("offline"))

    res = await client.check(
        authorization_id="auth_1",
        scopes=["public.web.search", "email.send"],
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
        fallback_by_scope={"public.web.search": "fail_open"},
    )
    respx.post(f"{BASE}/v1/check").mock(return_value=httpx.Response(429, json={
        "error": {"code": "quota_exceeded", "message": "quota exceeded"}
    }))

    with pytest.raises(AllowlyAPIError) as exc_info:
        await client.check(authorization_id="auth_1", scopes=["public.web.search"])
    assert exc_info.value.status == 429
    assert exc_info.value.code == "quota_exceeded"


@respx.mock
@pytest.mark.asyncio
async def test_fallback_results_are_not_cached():
    client = Allowly(
        api_key="test-key",
        base_url=BASE,
        fallback_by_scope={"public.web.search": "fail_open"},
    )
    route = respx.post(f"{BASE}/v1/check").mock(side_effect=httpx.ConnectError("offline"))

    await client.check(authorization_id="auth_1", scopes=["public.web.search"])
    await client.check(authorization_id="auth_1", scopes=["public.web.search"])

    assert route.call_count == 2


# ---------------------------------------------------------------------------
# authorizations.create()
# ---------------------------------------------------------------------------

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
        scopes=["email.read"],
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
        scopes=["llm.enrich"],
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
        scopes=["email.read"],
        expires_at="2026-12-31T00:00:00Z",
    )
    import json
    body = json.loads(route.calls[0].request.content)
    assert "session_id" not in body


@respx.mock
@pytest.mark.asyncio
async def test_authorizations_create_from_bundle_id(client):
    route = respx.post(f"{BASE}/v1/authorizations").mock(return_value=httpx.Response(201, json={
        "authorization_id": "auth_bundle",
        "bundle_id": "research_agent",
        "created_at": "2026-04-20T00:00:00Z",
        "expires_at": "2026-12-31T00:00:00Z",
        "receipt": PENDING_RECEIPT,
    }))
    res = await client.authorizations.create(
        user_id="subject:s_123",
        bundle_id="research_agent",
        metadata={"source": "import"},
    )
    import json
    body = json.loads(route.calls[0].request.content)
    assert body["user_id"] == "subject:s_123"
    assert body["bundle_id"] == "research_agent"
    assert body["agent_id"] is None
    assert body["scopes"] is None
    assert body["metadata"] == {"source": "import"}
    assert res.authorization_id == "auth_bundle"
    assert res.bundle_id == "research_agent"


@respx.mock
@pytest.mark.asyncio
async def test_non_check_endpoint_5xx_does_not_fallback():
    client = Allowly(
        api_key="test-key",
        base_url=BASE,
        fallback_by_scope={"email.read": "fail_open"},
    )
    respx.post(f"{BASE}/v1/authorizations").mock(return_value=httpx.Response(503, json={
        "error": {"code": "unavailable", "message": "try again"}
    }))

    with pytest.raises(AllowlyAPIError) as exc_info:
        await client.authorizations.create(user_id="u1", agent_id="a1", scopes=["email.read"])
    assert exc_info.value.status == 503


# ---------------------------------------------------------------------------
# authorizations.revoke()
# ---------------------------------------------------------------------------

@respx.mock
@pytest.mark.asyncio
async def test_authorizations_revoke(client):
    respx.delete(f"{BASE}/v1/authorizations/auth_123").mock(return_value=httpx.Response(200, json={
        "authorization_id": "auth_123",
        "revoked_at": "2026-05-01T09:00:00Z",
        "receipt": PENDING_RECEIPT,
    }))
    res = await client.authorizations.revoke("auth_123", revoked_by="user")
    assert res.authorization_id == "auth_123"
    assert res.receipt.status == "pending"


# ---------------------------------------------------------------------------
# confirmations.approve()
# ---------------------------------------------------------------------------

@respx.mock
@pytest.mark.asyncio
async def test_confirmations_approve(client):
    respx.post(f"{BASE}/v1/confirmations/nonce123").mock(return_value=httpx.Response(200, json={
        "decision": "approved", "authorization_id": "auth_xyz", "expires_at": "2026-04-20T00:01:00Z",
    }))
    res = await client.confirmations.approve("nonce123", approved=True)
    assert res.decision == "approved"
    assert res.authorization_id == "auth_xyz"


@respx.mock
@pytest.mark.asyncio
async def test_confirmations_denied(client):
    respx.post(f"{BASE}/v1/confirmations/nonce123").mock(return_value=httpx.Response(200, json={
        "decision": "denied_by_user",
    }))
    res = await client.confirmations.approve("nonce123", approved=False)
    assert res.decision == "denied_by_user"


# ---------------------------------------------------------------------------
# receipts.get()
# ---------------------------------------------------------------------------

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
        "version": "1.0", "receipt_id": "rcp_abc", "decision": "allow",
        "signature": {"alg": "Ed25519", "key_id": "k", "value": "sig"},
    }
    respx.get(f"{BASE}/v1/receipts/rcp_abc").mock(return_value=httpx.Response(200, json={
        "status": "signed",
        "receipt": signed,
    }))
    r = await client.receipts.get("rcp_abc")
    assert r.status == "signed"
    assert r.receipt == signed  # type: ignore[union-attr]
