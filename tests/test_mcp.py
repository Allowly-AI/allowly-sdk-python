"""Real FastMCP dispatch test for Allowly middleware."""
import inspect
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from allowly.mcp import AllowlyMCPMiddleware, MCPCheckInput


def _response(decision: str):
    action = SimpleNamespace(decision=decision, reason=f"test_{decision}")
    return SimpleNamespace(results={"read_email": action})


def test_middleware_has_no_argument_identity_escape_hatch():
    assert "allow_user_id_argument" not in inspect.signature(
        AllowlyMCPMiddleware
    ).parameters


@pytest.mark.asyncio
async def test_fastmcp_ignores_caller_controlled_user_id_without_user_id_fn():
    authorization_lookups = []
    mcp = FastMCP("test")

    @mcp.tool()
    def read_email(user_id: str) -> str:
        return f"email for {user_id}"

    def authorization_id_for(user_id):
        authorization_lookups.append(user_id)
        return "auth_1"

    middleware = AllowlyMCPMiddleware(
        api_key="test-key",
        authorization_id_fn=authorization_id_for,
    )
    mcp.add_middleware(middleware)

    try:
        async with Client(mcp) as client:
            with pytest.raises(ToolError, match="authorization_not_found"):
                await client.call_tool("read_email", {"user_id": "attacker"})
    finally:
        await middleware.aclose()

    assert authorization_lookups == []


@pytest.mark.asyncio
async def test_fastmcp_enforces_allow_and_deny():
    calls = 0
    mcp = FastMCP("test")

    @mcp.tool()
    def read_email() -> str:
        nonlocal calls
        calls += 1
        return "email content"

    def trusted_user(context):
        assert context.fastmcp_context is not None
        return "u1"

    middleware = AllowlyMCPMiddleware(
        api_key="test-key",
        authorization_id_fn=lambda user_id: "auth_1" if user_id else None,
        user_id_fn=trusted_user,
    )
    mcp.add_middleware(middleware)
    check = AsyncMock(side_effect=[_response("allow"), _response("deny")])

    try:
        with patch.object(middleware.client, "check", check):
            async with Client(mcp) as client:
                result = await client.call_tool("read_email", {})
                assert result.content[0].text == "email content"
                with pytest.raises(ToolError, match="decision.*deny"):
                    await client.call_tool("read_email", {})
        assert calls == 1
        assert check.await_count == 2
    finally:
        await middleware.aclose()


@pytest.mark.asyncio
async def test_fastmcp_confirm_payload_carries_expiry():
    mcp = FastMCP("test")

    @mcp.tool()
    def read_email() -> str:
        return "email content"

    middleware = AllowlyMCPMiddleware(
        api_key="test-key",
        authorization_id_fn=lambda user_id: "auth_1",
        user_id_fn=lambda context: "u1",
    )
    mcp.add_middleware(middleware)
    action = SimpleNamespace(
        decision="confirm",
        reason="action_requires_user_confirmation",
        confirm_nonce="cnf_1",
        confirm_expires_at="2026-07-29T12:00:00.000Z",
        confirm_prompt_hint="read_email",
    )
    check = AsyncMock(return_value=SimpleNamespace(results={"read_email": action}))

    try:
        with patch.object(middleware.client, "check", check):
            async with Client(mcp) as client:
                with pytest.raises(ToolError) as err:
                    await client.call_tool("read_email", {})
    finally:
        await middleware.aclose()

    payload = json.loads(str(err.value))
    assert payload["confirm_nonce"] == "cnf_1"
    assert payload["confirm_expires_at"] == "2026-07-29T12:00:00.000Z"


@pytest.mark.asyncio
async def test_fastmcp_maps_only_explicit_policy_input_and_agent_token():
    mcp = FastMCP("test")

    @mcp.tool()
    def send_email(thread_id: str, recipient_domain: str, secret_body: str) -> str:
        return "sent"

    async def trusted_token(context):
        assert context.request is not None
        assert context.fastmcp_context is not None
        return "trusted-jwt"

    async def check_input(context):
        return MCPCheckInput(
            action="email.send",
            resource=f"gmail:thread:{context.arguments['thread_id']}",
            context={"recipient_domain": context.arguments["recipient_domain"]},
            client_timestamp="2026-09-24T20:01:02.123Z",
            estimated_cost_micros=0,
            idempotency_key="send-123",
        )

    middleware = AllowlyMCPMiddleware(
        api_key="test-key",
        authorization_id_fn=lambda user_id: "auth_1" if user_id == "u1" else None,
        user_id_fn=lambda context: "u1",
        agent_token_fn=trusted_token,
        check_input_fn=check_input,
    )
    mcp.add_middleware(middleware)
    check = AsyncMock(
        return_value=SimpleNamespace(results={"email.send": _response("allow").results["read_email"]})
    )

    try:
        with patch.object(middleware.client, "check", check):
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "send_email",
                    {
                        "thread_id": "abc",
                        "recipient_domain": "example.com",
                        "secret_body": "not policy context",
                    },
                )
                assert result.content[0].text == "sent"
    finally:
        await middleware.aclose()

    check.assert_awaited_once_with(
        authorization_id="auth_1",
        actions=["email.send"],
        resource="gmail:thread:abc",
        context={"recipient_domain": "example.com"},
        client_timestamp="2026-09-24T20:01:02.123Z",
        estimated_cost_micros=0,
        idempotency_key="send-123",
        agent_token="trusted-jwt",
    )
    assert "secret_body" not in repr(check.await_args.kwargs)
    assert "not policy context" not in repr(check.await_args.kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("supplied", [None, "", "   "])
async def test_fastmcp_invalid_configured_agent_token_fails_closed(supplied):
    mcp = FastMCP("test")

    @mcp.tool()
    def read_email() -> str:
        return "email content"

    middleware = AllowlyMCPMiddleware(
        api_key="test-key",
        authorization_id_fn=lambda user_id: "auth_1",
        user_id_fn=lambda context: "u1",
        agent_token_fn=lambda context: supplied,
    )
    mcp.add_middleware(middleware)
    check = AsyncMock(return_value=_response("allow"))

    try:
        with patch.object(middleware.client, "check", check):
            async with Client(mcp) as client:
                with pytest.raises(ToolError, match="agent_token_not_found"):
                    await client.call_tool("read_email", {})
    finally:
        await middleware.aclose()

    check.assert_not_awaited()


@pytest.mark.asyncio
async def test_fastmcp_agent_token_callback_error_is_safe_and_fails_closed():
    mcp = FastMCP("test")

    @mcp.tool()
    def read_email() -> str:
        return "email content"

    def broken_token(context):
        raise RuntimeError("leaked-secret")

    middleware = AllowlyMCPMiddleware(
        api_key="test-key",
        authorization_id_fn=lambda user_id: "auth_1",
        user_id_fn=lambda context: "u1",
        agent_token_fn=broken_token,
    )
    mcp.add_middleware(middleware)

    try:
        async with Client(mcp) as client:
            with pytest.raises(ToolError) as caught:
                await client.call_tool("read_email", {})
    finally:
        await middleware.aclose()

    assert "agent_token_unavailable" in str(caught.value)
    assert "leaked-secret" not in str(caught.value)
