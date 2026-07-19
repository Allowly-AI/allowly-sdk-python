"""Allowly middleware for FastMCP 2.x servers.

Usage:
    from fastmcp import FastMCP

    mcp = FastMCP("my-server")
    mcp.add_middleware(AllowlyMCPMiddleware(
        api_key="allowly_l1_s001_...",
        user_id_fn=lambda context: context.fastmcp_context.session.user_id,
        authorization_id_fn=lambda user_id: db.get_authorization_id(user_id),
    ))
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional, Union

import mcp.types as mt
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.tool import ToolResult

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
        allow_user_id_argument: bool = False,
    ) -> None:
        kwargs: dict[str, Any] = {}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = Allowly(api_key, **kwargs)
        self.authorization_id_fn = authorization_id_fn
        self.user_id_fn = user_id_fn
        self.allow_user_id_argument = allow_user_id_argument

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
        if self.allow_user_id_argument:
            user_id = context.arguments.get("user_id")
            return user_id if isinstance(user_id, str) and user_id else None
        return None

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
            fastmcp_context=context.fastmcp_context,
        )
        authorization_id = await self._resolve_authorization_id(auth_context)
        if authorization_id is None:
            raise ToolError("authorization_not_found")

        result = await self.client.check(authorization_id=authorization_id, actions=[name])
        action_result = result.results[name]
        if action_result.decision == "allow":
            return await call_next(context)
        raise ToolError(json.dumps(_decision_payload(action_result)))


def _decision_payload(action: Any) -> dict[str, Any]:
    if action.decision == "confirm":
        return {
            "decision": "confirm",
            "reason": action.reason,
            "confirm_nonce": action.confirm_nonce,
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
