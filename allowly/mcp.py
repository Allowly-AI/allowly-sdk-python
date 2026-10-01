"""Allowly middleware for FastMCP 3.x servers.

Usage:
    from fastmcp import FastMCP

    mcp = FastMCP("my-server")
    mcp.add_middleware(AllowlyMCPMiddleware(
        api_key="allowly_l1_s001_...",
        user_id_fn=trusted_user_id,
        authorization_id_fn=lambda user_id: db.get_authorization_id(user_id),
    ))
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Awaitable, Callable, Optional, Union

import mcp.types as mt
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult

from allowly.client import Allowly


AuthorizationIdResult = Optional[str]
AuthorizationIdFn = Callable[[str], Union[AuthorizationIdResult, Awaitable[AuthorizationIdResult]]]
UserIdResult = Optional[str]


@dataclass(frozen=True)
class MCPAuthorizationContext:
    tool_name: str
    arguments: dict[str, Any]
    request: Any | None = None
    fastmcp_context: Any | None = None


UserIdFn = Callable[[MCPAuthorizationContext], Union[UserIdResult, Awaitable[UserIdResult]]]


@dataclass(frozen=True)
class MCPCheckInput:
    """Trusted policy fields selected for one MCP tool request.

    Tool arguments are available to ``check_input_fn`` for explicit mapping,
    but the middleware never copies them into policy input automatically.
    """

    action: str | None = None
    resource: str | None = None
    context: dict[str, Any] | None = None
    client_timestamp: datetime | str | None = None
    estimated_cost_micros: int | None = None
    idempotency_key: str | None = None


AgentTokenResult = Optional[str]
AgentTokenFn = Callable[
    [MCPAuthorizationContext],
    Union[AgentTokenResult, Awaitable[AgentTokenResult]],
]
CheckInputFn = Callable[
    [MCPAuthorizationContext],
    Union[MCPCheckInput, Awaitable[MCPCheckInput]],
]


class AllowlyMCPMiddleware(Middleware):
    """Gate every FastMCP tool call through Allowly.

    ``user_id_fn`` must resolve identity from trusted host context, not
    caller-controlled tool arguments. ``authorization_id_fn`` is then called with
    that trusted user ID and must return the corresponding Allowly authorization
    ID. Both callbacks may be sync or async. If either returns ``None`` the check
    is denied immediately.
    """

    def __init__(
        self,
        api_key: str,
        authorization_id_fn: AuthorizationIdFn,
        *,
        base_url: Optional[str] = None,
        user_id_fn: UserIdFn | None = None,
        agent_token_fn: AgentTokenFn | None = None,
        check_input_fn: CheckInputFn | None = None,
    ) -> None:
        kwargs: dict[str, Any] = {}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = Allowly(api_key, **kwargs)
        self.authorization_id_fn = authorization_id_fn
        self.user_id_fn = user_id_fn
        self.agent_token_fn = agent_token_fn
        self.check_input_fn = check_input_fn

    async def aclose(self) -> None:
        await self.client.aclose()

    async def _resolve_authorization_id(self, context: MCPAuthorizationContext) -> Optional[str]:
        user_id = await self._resolve_user_id(context)
        if not user_id:
            return None
        result = self.authorization_id_fn(user_id)
        if hasattr(result, "__await__"):
            return await result  # type: ignore[return-value]
        return result  # type: ignore[return-value]

    async def _resolve_user_id(self, context: MCPAuthorizationContext) -> Optional[str]:
        if self.user_id_fn is not None:
            result = self.user_id_fn(context)
            if hasattr(result, "__await__"):
                return await result  # type: ignore[return-value]
            return result  # type: ignore[return-value]
        return None

    async def _resolve_agent_token(
        self, context: MCPAuthorizationContext
    ) -> Optional[str]:
        if self.agent_token_fn is None:
            return None
        try:
            result = self.agent_token_fn(context)
            token = await result if hasattr(result, "__await__") else result
        except Exception:
            raise ToolError("agent_token_unavailable") from None
        if not isinstance(token, str) or not token.strip():
            raise ToolError("agent_token_not_found")
        return token

    async def _resolve_check_input(
        self, context: MCPAuthorizationContext
    ) -> MCPCheckInput:
        if self.check_input_fn is None:
            return MCPCheckInput()
        try:
            result = self.check_input_fn(context)
            resolved = await result if hasattr(result, "__await__") else result
        except Exception:
            raise ToolError("check_input_unavailable") from None
        if not isinstance(resolved, MCPCheckInput):
            raise ToolError("check_input_invalid")
        return resolved

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """FastMCP hook — called before every tool execution."""
        name = context.message.name
        args = context.message.arguments or {}
        auth_context = MCPAuthorizationContext(
            tool_name=name,
            arguments=args,
            request=context.message,
            fastmcp_context=context.fastmcp_context,
        )
        authorization_id = await self._resolve_authorization_id(auth_context)
        if authorization_id is None:
            raise ToolError("authorization_not_found")

        check_input = await self._resolve_check_input(auth_context)
        action = check_input.action if check_input.action is not None else name
        if not isinstance(action, str) or not action.strip():
            raise ToolError("check_action_invalid")
        agent_token = await self._resolve_agent_token(auth_context)
        result = await self.client.check(
            authorization_id=authorization_id,
            actions=[action],
            resource=check_input.resource,
            context=check_input.context,
            client_timestamp=check_input.client_timestamp,
            estimated_cost_micros=check_input.estimated_cost_micros,
            idempotency_key=check_input.idempotency_key,
            agent_token=agent_token,
        )
        action_result = result.results.get(action)
        if action_result is None:
            raise ToolError("missing_result")
        if action_result.decision == "allow":
            return await call_next(context)
        raise ToolError(json.dumps(_decision_payload(action_result)))


def _decision_payload(action: Any) -> dict[str, Any]:
    if action.decision == "confirm":
        return {
            "decision": "confirm",
            "reason": action.reason,
            "confirm_nonce": action.confirm_nonce,
            "confirm_expires_at": action.confirm_expires_at,
            "confirm_prompt_hint": action.confirm_prompt_hint,
        }
    if action.decision == "escalate":
        return {
            "decision": "escalate",
            "reason": action.reason,
            "escalation_id": action.escalation_id,
            "escalation_to": action.escalation_to,
            "escalation_expires_at": action.escalation_expires_at,
        }
    return {"decision": action.decision, "reason": action.reason}
