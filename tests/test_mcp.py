"""Real FastMCP dispatch test for Allowly middleware."""
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from allowly.mcp import AllowlyMCPMiddleware


def _response(decision: str):
    action = SimpleNamespace(decision=decision, reason=f"test_{decision}")
    return SimpleNamespace(results={"read_email": action})


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
