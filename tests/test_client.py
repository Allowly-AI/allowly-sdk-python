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
        context={"stage": "filter3"},
    )
    import json
    body = json.loads(route.calls[0].request.content)
    assert body["scopes"] == ["public.web.search", "public.page.read"]
    assert body["resource"] == "subject:s_123"
    assert body["context"] == {"stage": "filter3"}
    assert res.results["public.web.search"].decision == "allow"
    assert res.results["public.page.read"].decision == "deny"


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
