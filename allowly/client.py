from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx

from .error import AllowlyAPIError, FieldError
from .types import (
    CheckResponse,
    ConfirmationApproveResponse,
    AuthorizationCreateResponse,
    AuthorizationRevokeResponse,
    ReceiptEnvelopePending,
    ReceiptEnvelopeSigned,
    ReceiptEnvelope,
    ScopeEntry,
    FallbackMode,
    ScopeCheckResultAllow,
    ScopeCheckResultConfirm,
    ScopeCheckResultDeny,
)

DEFAULT_BASE_URL = "https://api.allowly.ai"


class Allowly:
    """Allowly API client.

    Usage::

        allowly = Allowly(api_key="allowly_live_...")
        result = await allowly.check(authorization_id="auth_...", scopes=["email.send"])
        if result.results["email.send"].decision == "allow":
            ...
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 10.0,
        check_timeout_ms: int = 1000,
        default_fallback: FallbackMode = "fail_closed",
        fallback_by_scope: dict[str, FallbackMode] | None = None,
    ) -> None:
        self._api_key = api_key
        if check_timeout_ms <= 0:
            raise ValueError("check_timeout_ms must be positive")
        self._check_timeout = check_timeout_ms / 1000
        self._default_fallback = _validate_fallback_mode(default_fallback)
        self._fallback_by_scope = {
            scope: _validate_fallback_mode(mode)
            for scope, mode in (fallback_by_scope or {}).items()
        }
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )
        self.authorizations = _AuthorizationsResource(self)
        self.confirmations = _ConfirmationsResource(self)
        self.receipts = _ReceiptsResource(self)

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        resp = await self._http.request(method, path, **kwargs)
        if resp.status_code == 204:
            return None
        data = resp.json()
        if not resp.is_success:
            err = data.get("error", {})
            fields = [FieldError(field=f["field"], message=f["message"]) for f in err.get("fields", [])]
            raise AllowlyAPIError(
                status=resp.status_code,
                code=err.get("code", "error"),
                message=err.get("message", "Unknown error"),
                fields=fields,
            )
        return data

    async def check(
        self,
        *,
        authorization_id: str,
        scopes: list[str],
        resource: str | None = None,
        session_id: str | None = None,
        context: dict[str, Any] | None = None,
        wait: bool = False,
    ) -> CheckResponse:
        """Check whether an authorization permits each requested scope."""
        path = "/v1/check" + ("?wait=true" if wait else "")
        body = {
            "authorization_id": authorization_id,
            "scopes": scopes,
            "resource": resource,
            "session_id": session_id,
            "context": context or {},
        }
        try:
            raw = await self._request("POST", path, json=body, timeout=self._check_timeout)
        except httpx.TimeoutException:
            return self._fallback_check_response(
                authorization_id=authorization_id,
                scopes=scopes,
                failure="timeout",
            )
        except httpx.TransportError:
            return self._fallback_check_response(
                authorization_id=authorization_id,
                scopes=scopes,
                failure="unreachable",
            )
        except AllowlyAPIError as exc:
            if exc.status >= 500:
                return self._fallback_check_response(
                    authorization_id=authorization_id,
                    scopes=scopes,
                    failure="unreachable",
                )
            raise
        return _parse_check_response(raw)

    def _fallback_mode_for_scope(self, scope: str) -> FallbackMode:
        return self._fallback_by_scope.get(scope, self._default_fallback)

    def _fallback_check_response(
        self,
        *,
        authorization_id: str,
        scopes: list[str],
        failure: str,
    ) -> CheckResponse:
        results = {}
        for scope in scopes:
            mode = self._fallback_mode_for_scope(scope)
            decision = "allow" if mode == "fail_open" else "deny"
            reason = f"fallback_{'open' if mode == 'fail_open' else 'closed'}_{failure}"
            base = {
                "decision": decision,
                "reason": reason,
                "receipt": None,
                "is_fallback": True,
                "fallback_mode": mode,
            }
            if decision == "allow":
                results[scope] = ScopeCheckResultAllow(**base)
            else:
                results[scope] = ScopeCheckResultDeny(**base)
        return CheckResponse(
            authorization_id=authorization_id,
            user_id=None,
            agent_id=None,
            authorization_expires_at=None,
            policy_version="sdk_fallback",
            results=results,
        )


class _AuthorizationsResource:
    def __init__(self, client: Allowly) -> None:
        self._client = client

    async def create(
        self,
        *,
        user_id: str,
        agent_id: str | None = None,
        scopes: list[ScopeEntry] | list[str] | None = None,
        expires_at: datetime | str | None = None,
        bundle_id: str | None = None,
        requires_confirm_for: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuthorizationCreateResponse:
        expires_iso = expires_at.isoformat() if isinstance(expires_at, datetime) else expires_at
        scope_list = [
            {"name": s, "constraints": {}} if isinstance(s, str)
            else {"name": s.name, "constraints": s.constraints}
            for s in (scopes or [])
        ] if scopes is not None else None
        raw = await self._client._request("POST", "/v1/authorizations", json={
            "user_id": user_id,
            "agent_id": agent_id,
            "bundle_id": bundle_id,
            "scopes": scope_list,
            "requires_confirm_for": requires_confirm_for or [],
            "expires_at": expires_iso,
            "metadata": metadata or {},
        })
        return AuthorizationCreateResponse(
            authorization_id=raw["authorization_id"],
            created_at=raw["created_at"],
            expires_at=raw["expires_at"],
            receipt=_parse_pending_envelope(raw["receipt"]),
            bundle_id=raw.get("bundle_id"),
        )

    async def revoke(
        self,
        authorization_id: str,
        *,
        revoked_by: str | None = None,
        notes: str | None = None,
    ) -> AuthorizationRevokeResponse:
        body: dict[str, Any] = {}
        if revoked_by:
            body["revoked_by"] = revoked_by
        if notes:
            body["notes"] = notes
        raw = await self._client._request(
            "DELETE", f"/v1/authorizations/{authorization_id}", json=body or None
        )
        return AuthorizationRevokeResponse(
            authorization_id=raw["authorization_id"],
            revoked_at=raw["revoked_at"],
            receipt=_parse_pending_envelope(raw["receipt"]),
        )


class _ConfirmationsResource:
    def __init__(self, client: Allowly) -> None:
        self._client = client

    async def approve(
        self,
        nonce: str,
        *,
        approved: bool,
        ttl_seconds: int = 60,
    ) -> ConfirmationApproveResponse:
        raw = await self._client._request("POST", f"/v1/confirmations/{nonce}", json={
            "approved": approved,
            "ttl_seconds": ttl_seconds,
        })
        return ConfirmationApproveResponse(
            decision=raw["decision"],
            authorization_id=raw.get("authorization_id"),
            expires_at=raw.get("expires_at"),
        )


class _ReceiptsResource:
    def __init__(self, client: Allowly) -> None:
        self._client = client

    async def get(self, receipt_id: str) -> ReceiptEnvelope:
        """Fetch a receipt. Returns a pending or signed envelope."""
        raw = await self._client._request("GET", f"/v1/receipts/{receipt_id}")
        return _parse_receipt_envelope(raw)

    async def fetch_signed(
        self,
        receipt_id: str,
        *,
        poll_interval: float = 1.0,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Poll until the receipt is signed, then return the full signed receipt dict.

        Raises TimeoutError if signing doesn't complete within `timeout` seconds.
        """
        import asyncio
        elapsed = 0.0
        while elapsed < timeout:
            envelope = await self.get(receipt_id)
            if isinstance(envelope, ReceiptEnvelopeSigned):
                return envelope.receipt
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
        raise TimeoutError(f"Receipt {receipt_id} not signed after {timeout}s")


def _parse_pending_envelope(raw: dict[str, Any]) -> ReceiptEnvelopePending:
    return ReceiptEnvelopePending(
        status="pending",
        receipt_id=raw["receipt_id"],
        ready_at_estimate=raw["ready_at_estimate"],
        url=raw["url"],
    )


def _parse_receipt_envelope(raw: dict[str, Any]) -> ReceiptEnvelope:
    if raw.get("status") == "signed":
        return ReceiptEnvelopeSigned(status="signed", receipt=raw["receipt"])
    return ReceiptEnvelopePending(
        status="pending",
        receipt_id=raw["receipt_id"],
        ready_at_estimate=raw.get("ready_at_estimate", ""),
        url=raw.get("url", ""),
    )


def _validate_fallback_mode(mode: str) -> FallbackMode:
    if mode not in {"fail_open", "fail_closed"}:
        raise ValueError("fallback mode must be 'fail_open' or 'fail_closed'")
    return mode  # type: ignore[return-value]


def _parse_check_response(raw: dict[str, Any]) -> CheckResponse:
    # The API returns a map keyed by requested scope. Preserve those keys so
    # callers can safely handle mixed allow/deny/confirm results in one check.
    results = {}
    for scope, item in raw["results"].items():
        base = dict(
            decision=item["decision"],
            reason=item["reason"],
            receipt=_parse_receipt_envelope(item["receipt"]),
            is_fallback=bool(item.get("is_fallback", False)),
            fallback_mode=item.get("fallback_mode"),
        )
        if item["decision"] == "deny":
            results[scope] = ScopeCheckResultDeny(**base)
        elif item["decision"] == "confirm":
            results[scope] = ScopeCheckResultConfirm(
                **base,
                confirm_nonce=item.get("confirm_nonce", ""),
                confirm_expires_at=item.get("confirm_expires_at", ""),
                confirm_prompt_hint=item.get("confirm_prompt_hint", ""),
            )
        else:
            results[scope] = ScopeCheckResultAllow(**base)
    return CheckResponse(
        user_id=raw.get("user_id", ""),
        agent_id=raw.get("agent_id", ""),
        authorization_id=raw.get("authorization_id", ""),
        authorization_expires_at=raw.get("authorization_expires_at", ""),
        policy_version=raw.get("policy_version", ""),
        results=results,
    )
