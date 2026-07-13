from __future__ import annotations

from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from .error import AllowlyAPIError, FieldError
from .types import (
    CheckResponse,
    ConfirmationApproveResponse,
    AuthorizationCreateResponse,
    AuthorizationRevokeResponse,
    BudgetInfo,
    EscalationInfo,
    EscalationResolveResponse,
    PolicyConditionEvidence,
    PolicyEvalInfo,
    ReceiptEnvelopePending,
    ReceiptEnvelopeSigned,
    ReceiptEnvelope,
    ActionEntry,
    FallbackMode,
    ActionCheckResultAllow,
    ActionCheckResultConfirm,
    ActionCheckResultDeny,
    ActionCheckResultEscalate,
)

DEFAULT_BASE_URL = "https://api.allowly.ai"


class Allowly:
    """Allowly API client.

    Usage::

        allowly = Allowly(api_key="allowly_l1_s001_...")
        result = await allowly.check(authorization_id="auth_...", actions=["email.send"])
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
        fallback_by_action: dict[str, FallbackMode] | None = None,
        dangerously_allow_insecure_base_url: bool = False,
    ) -> None:
        self._api_key = api_key
        base_url = _validate_base_url(base_url, dangerously_allow_insecure_base_url)
        if check_timeout_ms <= 0:
            raise ValueError("check_timeout_ms must be positive")
        self._check_timeout = check_timeout_ms / 1000
        self._default_fallback = _validate_fallback_mode(default_fallback)
        self._fallback_by_action = {
            action: _validate_fallback_mode(mode)
            for action, mode in (fallback_by_action or {}).items()
        }
        self._http = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )
        self.authorizations = _AuthorizationsResource(self)
        self.confirmations = _ConfirmationsResource(self)
        self.escalations = _EscalationsResource(self)
        self.receipts = _ReceiptsResource(self)

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        resp = await self._http.request(method, path, **kwargs)
        if resp.status_code == 204:
            return None
        try:
            data = resp.json()
        except ValueError:
            if resp.is_success:
                raise
            data = {}
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
        actions: list[str],
        resource: str | None = None,
        session_id: str | None = None,
        estimated_cost_micros: int | None = None,
        context: dict[str, Any] | None = None,
        wait: bool = False,
        idempotency_key: str | None = None,
    ) -> CheckResponse:
        """Check whether an authorization permits each requested action."""
        path = "/v1/check" + ("?wait=true" if wait else "")
        body = {
            "authorization_id": authorization_id,
            "actions": actions,
            "resource": resource,
            "session_id": session_id,
            "estimated_cost_micros": estimated_cost_micros,
            "context": context or {},
        }
        try:
            headers = {"Idempotency-Key": idempotency_key} if idempotency_key is not None else None
            raw = await self._request("POST", path, json=body, timeout=self._check_timeout, headers=headers)
        except httpx.TimeoutException:
            return self._fallback_check_response(
                authorization_id=authorization_id,
                actions=actions,
                failure="timeout",
            )
        except httpx.TransportError:
            return self._fallback_check_response(
                authorization_id=authorization_id,
                actions=actions,
                failure="unreachable",
            )
        except AllowlyAPIError as exc:
            if exc.status >= 500:
                return self._fallback_check_response(
                    authorization_id=authorization_id,
                    actions=actions,
                    failure="unreachable",
                )
            raise
        return _parse_check_response(raw)

    def _fallback_mode_for_action(self, action: str) -> FallbackMode:
        return self._fallback_by_action.get(action, self._default_fallback)

    def _fallback_check_response(
        self,
        *,
        authorization_id: str,
        actions: list[str],
        failure: str,
    ) -> CheckResponse:
        results = {}
        for action in actions:
            mode = self._fallback_mode_for_action(action)
            decision = "allow" if mode == "fail_open" else "deny"
            reason = f"fallback_{'open' if mode == 'fail_open' else 'closed'}_{failure}"
            base = {
                "decision": decision,
                "reason": reason,
                "receipt": None,
                "is_fallback": True,
                "fallback_mode": mode,
                "budget": None,
                "escalation": None,
                "policy_eval": None,
            }
            if decision == "allow":
                results[action] = ActionCheckResultAllow(**base)
            else:
                results[action] = ActionCheckResultDeny(**base)
        return CheckResponse(
            authorization_id=authorization_id,
            user_id=None,
            agent_id=None,
            authorization_expires_at=None,
            engine_version="sdk_fallback",
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
        actions: list[ActionEntry] | list[str] | None = None,
        expires_at: datetime | str | None = None,
        policy_id: str | None = None,
        requires_confirm_for: list[str] | None = None,
        requires_escalation_for: list[str] | None = None,
        escalation_targets: dict[str, str] | None = None,
        budget_limit_micros: int | None = None,
        replaces: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuthorizationCreateResponse:
        expires_iso = expires_at.isoformat() if isinstance(expires_at, datetime) else expires_at
        action_list = [
            {"name": s, "constraints": {}} if isinstance(s, str)
            else {"name": s.name, "constraints": s.constraints}
            for s in (actions or [])
        ] if actions is not None else None
        raw = await self._client._request("POST", "/v1/authorizations", json={
            "user_id": user_id,
            "agent_id": agent_id,
            "policy_id": policy_id,
            "actions": action_list,
            "requires_confirm_for": requires_confirm_for or [],
            "requires_escalation_for": requires_escalation_for or [],
            "escalation_targets": escalation_targets or {},
            "budget_limit_micros": budget_limit_micros,
            "expires_at": expires_iso,
            "replaces": replaces,
            "metadata": metadata or {},
        })
        return AuthorizationCreateResponse(
            authorization_id=raw["authorization_id"],
            created_at=raw["created_at"],
            expires_at=raw["expires_at"],
            receipt=_parse_pending_envelope(raw["receipt"]),
            policy_id=raw.get("policy_id"),
            requires_confirm_for=raw.get("requires_confirm_for", []),
            requires_escalation_for=raw.get("requires_escalation_for", []),
            escalation_targets=raw.get("escalation_targets", {}),
            budget_limit_micros=raw.get("budget_limit_micros"),
            budget_spent_micros=raw.get("budget_spent_micros"),
        )

    async def revoke(
        self,
        authorization_id: str,
        *,
        revoked_by: str | None = None,
        superseded_by: str | None = None,
        notes: str | None = None,
    ) -> AuthorizationRevokeResponse:
        body: dict[str, Any] = {}
        if revoked_by:
            body["revoked_by"] = revoked_by
        if superseded_by:
            body["superseded_by"] = superseded_by
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


class _EscalationsResource:
    def __init__(self, client: Allowly) -> None:
        self._client = client

    async def resolve(
        self,
        escalation_id: str,
        *,
        resolution: str,
        resolved_by: str,
        note: str | None = None,
    ) -> EscalationResolveResponse:
        raw = await self._client._request("POST", f"/v1/escalations/{escalation_id}/resolve", json={
            "resolution": resolution,
            "resolved_by": resolved_by,
            "note": note,
        })
        receipt = raw.get("receipt")
        return EscalationResolveResponse(
            escalation_id=raw["escalation_id"],
            status=raw["status"],
            resolved_by=raw.get("resolved_by"),
            resolved_at=raw.get("resolved_at"),
            receipt=_parse_pending_envelope(receipt) if receipt is not None else None,
        )

    async def approve(
        self,
        escalation_id: str,
        *,
        resolved_by: str,
        note: str | None = None,
    ) -> EscalationResolveResponse:
        return await self.resolve(
            escalation_id,
            resolution="approved",
            resolved_by=resolved_by,
            note=note,
        )

    async def reject(
        self,
        escalation_id: str,
        *,
        resolved_by: str,
        note: str | None = None,
    ) -> EscalationResolveResponse:
        return await self.resolve(
            escalation_id,
            resolution="rejected",
            resolved_by=resolved_by,
            note=note,
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


def _validate_base_url(base_url: str, allow_insecure: bool) -> str:
    normalized = base_url.rstrip("/")
    parsed = urlparse(normalized)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("base_url must be a valid URL")
    if parsed.scheme != "https" and not allow_insecure:
        raise ValueError("base_url must use HTTPS")
    return normalized


def _parse_check_response(raw: dict[str, Any]) -> CheckResponse:
    # The API returns a map keyed by requested action. Preserve those keys so
    # callers can safely handle mixed allow/deny/confirm/escalate results in one check.
    results = {}
    for action, item in raw["results"].items():
        base = dict(
            decision=item["decision"],
            reason=item["reason"],
            receipt=_parse_receipt_envelope(item["receipt"]),
            is_fallback=bool(item.get("is_fallback", False)),
            fallback_mode=item.get("fallback_mode"),
            budget=_parse_budget_info(item.get("budget")),
            escalation=_parse_escalation_info(item.get("escalation")),
            policy_eval=_parse_policy_eval(item.get("policy_eval")),
        )
        if item["decision"] == "deny":
            results[action] = ActionCheckResultDeny(**base, superseded_by=item.get("superseded_by"))
        elif item["decision"] == "confirm":
            results[action] = ActionCheckResultConfirm(
                **base,
                confirm_nonce=item.get("confirm_nonce", ""),
                confirm_expires_at=item.get("confirm_expires_at", ""),
                confirm_prompt_hint=item.get("confirm_prompt_hint", ""),
            )
        elif item["decision"] == "escalate":
            results[action] = ActionCheckResultEscalate(
                **base,
                escalation_id=item.get("escalation_id", ""),
                escalation_to=item.get("escalation_to"),
                escalation_expires_at=item.get("escalation_expires_at"),
            )
        else:
            results[action] = ActionCheckResultAllow(**base)
    return CheckResponse(
        user_id=raw.get("user_id", ""),
        agent_id=raw.get("agent_id", ""),
        authorization_id=raw.get("authorization_id", ""),
        authorization_expires_at=raw.get("authorization_expires_at", ""),
        engine_version=raw.get("engine_version", ""),
        results=results,
    )


def _parse_budget_info(raw: Any) -> BudgetInfo | None:
    if raw is None:
        return None
    return BudgetInfo(
        limit_micros=raw["limit_micros"],
        spent_micros=raw["spent_micros"],
        estimated_cost_micros=raw["estimated_cost_micros"],
        spent_after_micros=raw.get("spent_after_micros"),
    )


def _parse_escalation_info(raw: Any) -> EscalationInfo | None:
    if raw is None:
        return None
    return EscalationInfo(
        escalation_id=raw["escalation_id"],
        status=raw["status"],
        escalation_to=raw.get("escalation_to"),
        expires_at=raw.get("expires_at"),
    )


def _parse_policy_eval(raw: Any) -> PolicyEvalInfo | None:
    if raw is None:
        return None
    matched = raw.get("matched_condition")
    return PolicyEvalInfo(
        matched_condition=(
            PolicyConditionEvidence(
                field=matched["field"],
                op=matched["op"],
                value=matched["value"],
            )
            if isinstance(matched, dict)
            else None
        ),
        field_value=raw.get("field_value"),
    )
