"""Allowly middleware for MCP servers.

Supports both FastMCP and low-level mcp.server.Server.

FastMCP usage:
    mcp = FastMCP("my-server")
    mcp.add_middleware(AllowlyMCPMiddleware(
        api_key="allowly_l1_s001_...",
        user_id_fn=lambda context: context.fastmcp_context.session.user_id,
        authorization_id_fn=lambda user_id: db.get_authorization_id(user_id),
    ))

Low-level Server usage:
    server = Server("my-server")
    AllowlyMCPMiddleware.wrap(
        server,
        api_key="allowly_l1_s001_...",
        user_id_fn=lambda context: trusted_current_user_id(),
        authorization_id_fn=lambda user_id: db.get_authorization_id(user_id),
    )
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional, Union

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


class AllowlyMCPMiddleware:
    """Gate every tool call on an MCP server through Allowly.

    Works with both FastMCP (via ``on_call_tool`` middleware hook) and the
    low-level ``mcp.server.Server`` (via :meth:`wrap`).

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

    # ------------------------------------------------------------------
    # FastMCP middleware protocol
    # ------------------------------------------------------------------

    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        """FastMCP hook — called before every tool execution."""
        from mcp.types import CallToolResult, TextContent

        name: str = context.message.name
        args: dict[str, Any] = context.message.arguments or {}

        auth_context = MCPAuthorizationContext(
            tool_name=name,
            arguments=args,
            fastmcp_context=context,
        )
        authorization_id = await self._resolve_authorization_id(auth_context)
        if authorization_id is None:
            return CallToolResult(
                content=[TextContent(type="text", text="authorization_not_found")],
                isError=True,
            )

        result = await self.client.check(authorization_id=authorization_id, actions=[name])
        action_result = result.results[name]

        if action_result.decision == "allow":
            return await call_next(context)

        if action_result.decision == "confirm":
            import json
            payload = json.dumps({
                "decision": "confirm",
                "reason": action_result.reason,
                "confirm_nonce": action_result.confirm_nonce,
                "confirm_prompt_hint": action_result.confirm_prompt_hint,
            })
            return CallToolResult(
                content=[TextContent(type="text", text=payload)],
                isError=True,
            )

        if action_result.decision == "escalate":
            import json
            payload = json.dumps({
                "decision": "escalate",
                "reason": action_result.reason,
                "escalation_id": action_result.escalation_id,
                "escalation_to": action_result.escalation_to,
                "escalation_expires_at": action_result.escalation_expires_at,
            })
            return CallToolResult(
                content=[TextContent(type="text", text=payload)],
                isError=True,
            )

        return CallToolResult(
            content=[TextContent(type="text", text=action_result.reason)],
            isError=True,
        )

    # ------------------------------------------------------------------
    # Low-level mcp.server.Server wrapper
    # ------------------------------------------------------------------

    @classmethod
    def wrap(
        cls,
        server: Any,
        *,
        api_key: str,
        authorization_id_fn: AuthorizationIdFn,
        base_url: Optional[str] = None,
        user_id_fn: UserIdFn | None = None,
        allow_user_id_argument: bool = False,
    ) -> "AllowlyMCPMiddleware":
        """Wrap a low-level ``mcp.server.Server`` instance.

        Monkey-patches ``server.call_tool`` so every tool call is checked
        against Allowly before execution.

        Returns the middleware instance in case further configuration is needed.
        """
        middleware = cls(
            api_key,
            authorization_id_fn,
            base_url=base_url,
            user_id_fn=user_id_fn,
            allow_user_id_argument=allow_user_id_argument,
        )
        original_call = server.call_tool

        async def _checked_call(name: str, arguments: Optional[dict[str, Any]]) -> Any:
            args = arguments or {}

            auth_context = MCPAuthorizationContext(tool_name=name, arguments=args)
            authorization_id = await middleware._resolve_authorization_id(auth_context)
            if authorization_id is None:
                return {"decision": "deny", "reason": "authorization_not_found"}

            result = await middleware.client.check(authorization_id=authorization_id, actions=[name])
            action_result = result.results[name]

            if action_result.decision == "allow":
                return await original_call(name, arguments)

            if action_result.decision == "confirm":
                return {
                    "decision": "confirm",
                    "reason": action_result.reason,
                    "confirm_nonce": action_result.confirm_nonce,
                    "confirm_prompt_hint": action_result.confirm_prompt_hint,
                }

            if action_result.decision == "escalate":
                return {
                    "decision": "escalate",
                    "reason": action_result.reason,
                    "escalation_id": action_result.escalation_id,
                    "escalation_to": action_result.escalation_to,
                    "escalation_expires_at": action_result.escalation_expires_at,
                }

            return {"decision": action_result.decision, "reason": action_result.reason}

        server.call_tool = _checked_call
        return middleware
