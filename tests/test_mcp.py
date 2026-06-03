"""Tests for AllowlyMCPMiddleware — both FastMCP and low-level Server patterns."""
from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

# Stub the mcp package so tests run without it installed
if "mcp" not in sys.modules:
    _mcp = ModuleType("mcp")
    _mcp_types = ModuleType("mcp.types")

    class _TextContent:
        def __init__(self, *, type, text):
            self.type = type
            self.text = text

    class _CallToolResult:
        def __init__(self, *, content, isError=False):
            self.content = content
            self.isError = isError

    _mcp_types.TextContent = _TextContent
    _mcp_types.CallToolResult = _CallToolResult
    sys.modules["mcp"] = _mcp
    sys.modules["mcp.types"] = _mcp_types

import pytest

from allowly import AllowlyMCPMiddleware
from allowly.types import (
    CheckResponse,
    ReceiptEnvelopePending,
    ScopeCheckResultAllow,
    ScopeCheckResultConfirm,
    ScopeCheckResultDeny,
    ScopeCheckResultEscalate,
)

BASE = "https://api.example.com"

PENDING = ReceiptEnvelopePending(
    status="pending",
    receipt_id="rcp_abc",
    ready_at_estimate="2026-04-21T14:32:18.482Z",
    url=f"{BASE}/v1/receipts/rcp_abc",
)


def _authorization_id_fn(user_id: str) -> str | None:
    return "auth_1" if user_id else None


def _response(scope: str, result) -> CheckResponse:
    return CheckResponse(
        user_id="u1",
        agent_id="gmail-tools",
        authorization_id="auth_1",
        authorization_expires_at="2026-12-31T00:00:00Z",
        policy_version="2026-04-19.1",
        results={scope: result},
    )


def _allow_response(scope: str = "read_email") -> CheckResponse:
    return _response(scope, ScopeCheckResultAllow(decision="allow", reason="authorization_granted_scope_active", receipt=PENDING))


def _deny_response(scope: str = "send_email") -> CheckResponse:
    return _response(scope, ScopeCheckResultDeny(decision="deny", reason="authorization_not_found", receipt=PENDING))


def _confirm_response(scope: str = "send_email") -> CheckResponse:
    return _response(
        scope,
        ScopeCheckResultConfirm(
            decision="confirm",
            reason="scope_requires_user_confirmation",
            receipt=PENDING,
            confirm_nonce="cnf_abc",
            confirm_expires_at="2026-04-20T00:15:00Z",
            confirm_prompt_hint="email.send",
        ),
    )


def _escalate_response(scope: str = "delete_candidate") -> CheckResponse:
    return _response(
        scope,
        ScopeCheckResultEscalate(
            decision="escalate",
            reason="escalation_required",
            receipt=PENDING,
            escalation_id="esc_abc",
            escalation_to="compliance",
            escalation_expires_at="2026-04-21T17:00:00Z",
        ),
    )


# ---------------------------------------------------------------------------
# Low-level Server wrapping
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_wrap_allows_tool_call():
    server = MagicMock()
    original_call = AsyncMock(return_value={"text": "email content"})
    server.call_tool = original_call

    middleware = AllowlyMCPMiddleware.wrap(
        server, api_key="test-key", authorization_id_fn=_authorization_id_fn
    )

    with patch.object(middleware.client, "check", AsyncMock(return_value=_allow_response())):
        result = await server.call_tool("read_email", {"user_id": "u1", "thread_id": "t1"})

    original_call.assert_awaited_once_with("read_email", {"user_id": "u1", "thread_id": "t1"})
    assert result == {"text": "email content"}


@pytest.mark.asyncio
async def test_wrap_blocks_tool_call_on_deny():
    server = MagicMock()
    original_call = AsyncMock(return_value={"text": "should not reach"})
    server.call_tool = original_call

    middleware = AllowlyMCPMiddleware.wrap(
        server, api_key="test-key", authorization_id_fn=_authorization_id_fn
    )

    with patch.object(middleware.client, "check", AsyncMock(return_value=_deny_response())):
        result = await server.call_tool("send_email", {"user_id": "u1"})

    original_call.assert_not_awaited()
    assert result["decision"] == "deny"
    assert result["reason"] == "authorization_not_found"


@pytest.mark.asyncio
async def test_wrap_missing_user_id_denies():
    server = MagicMock()
    original_call = AsyncMock(return_value={})
    server.call_tool = original_call

    middleware = AllowlyMCPMiddleware.wrap(
        server, api_key="test-key", authorization_id_fn=_authorization_id_fn
    )

    check_mock = AsyncMock(return_value=_allow_response())
    with patch.object(middleware.client, "check", check_mock):
        result = await server.call_tool("read_email", {})

    check_mock.assert_not_awaited()
    original_call.assert_not_awaited()
    assert result["decision"] == "deny"


@pytest.mark.asyncio
async def test_wrap_check_called_with_authorization_id():
    server = MagicMock()
    server.call_tool = AsyncMock(return_value={})

    middleware = AllowlyMCPMiddleware.wrap(
        server, api_key="test-key", authorization_id_fn=_authorization_id_fn
    )

    check_mock = AsyncMock(return_value=_allow_response())
    with patch.object(middleware.client, "check", check_mock):
        await server.call_tool("read_email", {"user_id": "u1"})

    check_mock.assert_awaited_once_with(authorization_id="auth_1", scopes=["read_email"])


# ---------------------------------------------------------------------------
# FastMCP on_call_tool hook
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fastmcp_allows_tool_call():
    middleware = AllowlyMCPMiddleware(api_key="test-key", authorization_id_fn=_authorization_id_fn)

    context = MagicMock()
    context.message.name = "read_email"
    context.message.arguments = {"user_id": "u1", "thread_id": "t1"}

    call_next = AsyncMock(return_value="tool result")

    with patch.object(middleware.client, "check", AsyncMock(return_value=_allow_response())):
        result = await middleware.on_call_tool(context, call_next)

    call_next.assert_awaited_once_with(context)
    assert result == "tool result"


@pytest.mark.asyncio
async def test_fastmcp_blocks_tool_call_on_deny():
    middleware = AllowlyMCPMiddleware(api_key="test-key", authorization_id_fn=_authorization_id_fn)

    context = MagicMock()
    context.message.name = "send_email"
    context.message.arguments = {"user_id": "u1"}

    call_next = AsyncMock()

    with patch.object(middleware.client, "check", AsyncMock(return_value=_deny_response())):
        result = await middleware.on_call_tool(context, call_next)

    call_next.assert_not_awaited()
    assert result.isError is True
    assert result.content[0].text == "authorization_not_found"


@pytest.mark.asyncio
async def test_fastmcp_confirm_returns_nonce():
    middleware = AllowlyMCPMiddleware(api_key="test-key", authorization_id_fn=_authorization_id_fn)

    context = MagicMock()
    context.message.name = "send_email"
    context.message.arguments = {"user_id": "u1"}

    call_next = AsyncMock()

    with patch.object(middleware.client, "check", AsyncMock(return_value=_confirm_response())):
        result = await middleware.on_call_tool(context, call_next)

    call_next.assert_not_awaited()
    assert result.isError is True
    import json
    payload = json.loads(result.content[0].text)
    assert payload["decision"] == "confirm"
    assert payload["confirm_nonce"] == "cnf_abc"
    assert payload["confirm_prompt_hint"] == "email.send"


@pytest.mark.asyncio
async def test_fastmcp_escalate_returns_escalation_payload():
    middleware = AllowlyMCPMiddleware(api_key="test-key", authorization_id_fn=_authorization_id_fn)

    context = MagicMock()
    context.message.name = "delete_candidate"
    context.message.arguments = {"user_id": "u1"}

    call_next = AsyncMock()

    with patch.object(middleware.client, "check", AsyncMock(return_value=_escalate_response())):
        result = await middleware.on_call_tool(context, call_next)

    call_next.assert_not_awaited()
    assert result.isError is True
    import json
    payload = json.loads(result.content[0].text)
    assert payload["decision"] == "escalate"
    assert payload["escalation_id"] == "esc_abc"
    assert payload["escalation_to"] == "compliance"


@pytest.mark.asyncio
async def test_wrap_confirm_returns_nonce():
    server = MagicMock()
    original_call = AsyncMock(return_value={})
    server.call_tool = original_call

    middleware = AllowlyMCPMiddleware.wrap(
        server, api_key="test-key", authorization_id_fn=_authorization_id_fn
    )

    with patch.object(middleware.client, "check", AsyncMock(return_value=_confirm_response())):
        result = await server.call_tool("send_email", {"user_id": "u1"})

    original_call.assert_not_awaited()
    assert result["decision"] == "confirm"
    assert result["confirm_nonce"] == "cnf_abc"


@pytest.mark.asyncio
async def test_wrap_escalate_returns_escalation_payload():
    server = MagicMock()
    original_call = AsyncMock(return_value={})
    server.call_tool = original_call

    middleware = AllowlyMCPMiddleware.wrap(
        server, api_key="test-key", authorization_id_fn=_authorization_id_fn
    )

    with patch.object(middleware.client, "check", AsyncMock(return_value=_escalate_response())):
        result = await server.call_tool("delete_candidate", {"user_id": "u1"})

    original_call.assert_not_awaited()
    assert result["decision"] == "escalate"
    assert result["escalation_id"] == "esc_abc"
    assert result["escalation_to"] == "compliance"
