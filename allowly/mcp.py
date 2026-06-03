"""Allowly middleware for MCP servers.

Supports both FastMCP and low-level mcp.server.Server.

FastMCP usage:
    mcp = FastMCP("my-server")
    mcp.add_middleware(AllowlyMCPMiddleware(
        api_key="allowly_live_...",
        authorization_id_fn=lambda user_id: db.get_authorization_id(user_id),
    ))

Low-level Server usage:
    server = Server("my-server")
    AllowlyMCPMiddleware.wrap(
        server,
        api_key="allowly_live_...",
        authorization_id_fn=lambda user_id: db.get_authorization_id(user_id),
    )
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable, Optional, Union

from allowly.client import Allowly


AuthorizationIdResult = Optional[str]
AuthorizationIdFn = Callable[[str], Union[AuthorizationIdResult, Awaitable[AuthorizationIdResult]]]


class AllowlyMCPMiddleware:
    """Gate every tool call on an MCP server through Allowly.

    Works with both FastMCP (via ``on_call_tool`` middleware hook) and the
    low-level ``mcp.server.Server`` (via :meth:`wrap`).

    ``authorization_id_fn`` is called with the ``user_id`` from the tool arguments
    and must return the corresponding Allowly authorization ID. It may be sync or async.
    If it returns ``None`` the check is denied immediately.
    """

    def __init__(
        self,
        api_key: str,
        authorization_id_fn: AuthorizationIdFn,
        *,
        base_url: Optional[str] = None,
    ) -> None:
        kwargs: dict[str, Any] = {}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = Allowly(api_key, **kwargs)
        self.authorization_id_fn = authorization_id_fn

    async def _resolve_authorization_id(self, user_id: str) -> Optional[str]:
        result = self.authorization_id_fn(user_id)
        if hasattr(result, "__await__"):
            return await result  # type: ignore[return-value]
        return result  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # FastMCP middleware protocol
    # ------------------------------------------------------------------

    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        """FastMCP hook — called before every tool execution."""
        from mcp.types import CallToolResult, TextContent

        name: str = context.message.name
        args: dict[str, Any] = context.message.arguments or {}
        user_id: str = args.get("user_id") or ""

        authorization_id = await self._resolve_authorization_id(user_id)
        if authorization_id is None:
            return CallToolResult(
                content=[TextContent(type="text", text="authorization_not_found")],
                isError=True,
            )

        result = await self.client.check(authorization_id=authorization_id, scopes=[name])
        scope_result = result.results[name]

        if scope_result.decision == "allow":
            return await call_next(context)

        if scope_result.decision == "confirm":
            import json
            payload = json.dumps({
                "decision": "confirm",
                "reason": scope_result.reason,
                "confirm_nonce": scope_result.confirm_nonce,
                "confirm_prompt_hint": scope_result.confirm_prompt_hint,
            })
            return CallToolResult(
                content=[TextContent(type="text", text=payload)],
                isError=True,
            )

        if scope_result.decision == "escalate":
            import json
            payload = json.dumps({
                "decision": "escalate",
                "reason": scope_result.reason,
                "escalation_id": scope_result.escalation_id,
                "escalation_to": scope_result.escalation_to,
                "escalation_expires_at": scope_result.escalation_expires_at,
            })
            return CallToolResult(
                content=[TextContent(type="text", text=payload)],
                isError=True,
            )

        return CallToolResult(
            content=[TextContent(type="text", text=scope_result.reason)],
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
    ) -> "AllowlyMCPMiddleware":
        """Wrap a low-level ``mcp.server.Server`` instance.

        Monkey-patches ``server.call_tool`` so every tool call is checked
        against Allowly before execution.

        Returns the middleware instance in case further configuration is needed.
        """
        middleware = cls(api_key, authorization_id_fn, base_url=base_url)
        original_call = server.call_tool

        async def _checked_call(name: str, arguments: Optional[dict[str, Any]]) -> Any:
            args = arguments or {}
            user_id: str = args.get("user_id") or ""

            authorization_id = await middleware._resolve_authorization_id(user_id)
            if authorization_id is None:
                return {"decision": "deny", "reason": "authorization_not_found"}

            result = await middleware.client.check(authorization_id=authorization_id, scopes=[name])
            scope_result = result.results[name]

            if scope_result.decision == "allow":
                return await original_call(name, arguments)

            if scope_result.decision == "confirm":
                return {
                    "decision": "confirm",
                    "reason": scope_result.reason,
                    "confirm_nonce": scope_result.confirm_nonce,
                    "confirm_prompt_hint": scope_result.confirm_prompt_hint,
                }

            if scope_result.decision == "escalate":
                return {
                    "decision": "escalate",
                    "reason": scope_result.reason,
                    "escalation_id": scope_result.escalation_id,
                    "escalation_to": scope_result.escalation_to,
                    "escalation_expires_at": scope_result.escalation_expires_at,
                }

            return {"decision": scope_result.decision, "reason": scope_result.reason}

        server.call_tool = _checked_call
        return middleware
