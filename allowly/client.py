from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from .error import AllowlyAPIError, AllowlyProtocolError, FieldError
from .types import (
    CheckResponse,
    ConfirmationApproveResponse,
    AuthorizationCreateResponse,
    AuthorizationRevokeResponse,
    BudgetInfo,
    BudgetSettlementResponse,
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
        edge_token: str | None = None,
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
        # edge_token fills the X-Allowly-Edge-Token header that Cloudflare adds
        # for public traffic. Local/direct deployments (e.g. the documented
        # local Caddy endpoint) must supply it themselves — typically from
        # ALLOWLY_EDGE_TOKEN. Never sent unless explicitly provided.
        headers = {"Authorization": f"Bearer {api_key}"}
        if edge_token is not None:
            headers["X-Allowly-Edge-Token"] = edge_token
        self._http = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
        )
        self.authorizations = _AuthorizationsResource(self)
        self.confirmations = _ConfirmationsResource(self)
        self.escalations = _EscalationsResource(self)
        self.receipts = _ReceiptsResource(self)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> Allowly:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        data, _ = await self._request_with_headers(method, path, **kwargs)
        return data

    async def _request_with_headers(
        self, method: str, path: str, **kwargs: Any
    ) -> tuple[Any, httpx.Headers]:
        resp = await self._http.request(method, path, **kwargs)
        if resp.status_code == 204:
            return None, resp.headers
        try:
            data = resp.json()
        except ValueError:
            if resp.is_success:
                raise
            data = {}
        if not resp.is_success:
            err = data.get("error") if isinstance(data, dict) else None
            if isinstance(err, str):
                err = {"message": err}
            elif not isinstance(err, dict):
                err = {}
            raw_fields = err.get("fields")
            fields = [
                FieldError(field=str(f.get("field", "")), message=str(f.get("message", "")))
                for f in (raw_fields if isinstance(raw_fields, list) else [])
                if isinstance(f, dict)
            ]
            raise AllowlyAPIError(
                status=resp.status_code,
                code=err.get("code", "error"),
                message=err.get("message", "Unknown error"),
                fields=fields,
                retry_after_seconds=_parse_retry_after(resp.headers.get("Retry-After")),
            )
        return data, resp.headers

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
            timeout = max(self._check_timeout, 6.0) if wait else self._check_timeout
            raw, response_headers = await self._request_with_headers(
                "POST", path, json=body, timeout=timeout, headers=headers
            )
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
        response = _parse_check_response(raw)
        response.billing_warning = response_headers.get("X-Allowly-Billing-Warning")
        return response

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

    async def settle_budget(
        self,
        *,
        check_receipt_id: str,
        actual_cost_micros: int,
        idempotency_key: str | None = None,
    ) -> BudgetSettlementResponse:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key is not None else None
        raw = await self._request(
            "POST",
            "/v1/budget-settlements",
            json={
                "check_receipt_id": check_receipt_id,
                "actual_cost_micros": actual_cost_micros,
            },
            headers=headers,
        )
        return _parse_budget_settlement_response(raw)


class _AuthorizationsResource:
    def __init__(self, client: Allowly) -> None:
        self._client = client

    async def create(
        self,
        *,
        user_id: str,
        policy_id: str | None = None,
        expires_at: datetime | str | None = None,
        agent_id: str | None = None,
        actions: list[ActionEntry] | list[str] | None = None,
        requires_confirm_for: list[str] | None = None,
        requires_escalation_for: list[str] | None = None,
        requires_deny_for: list[str] | None = None,
        escalation_targets: dict[str, str] | None = None,
        budget_limit_micros: int | None = None,
        replaces: str | None = None,
        metadata: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> AuthorizationCreateResponse:
        """Create an authorization for a user.

        Canonical flow: pass ``policy_id`` referencing a reusable agent policy.
        Inline flow (``agent_id`` + ``actions``, no ``policy_id``) is for
        prototyping and ad-hoc per-user grants. Exactly one of the two shapes
        must be used.
        """
        expires_iso = expires_at.isoformat() if isinstance(expires_at, datetime) else expires_at
        action_list = [
            {"name": s, "constraints": {}} if isinstance(s, str)
            else {"name": s.name, "constraints": s.constraints}
            for s in (actions or [])
        ] if actions is not None else None
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key is not None else None
        raw, response_headers = await self._client._request_with_headers("POST", "/v1/authorizations", json={
            "user_id": user_id,
            "agent_id": agent_id,
            "policy_id": policy_id,
            "actions": action_list,
            "requires_confirm_for": requires_confirm_for or [],
            "requires_escalation_for": requires_escalation_for or [],
            "requires_deny_for": requires_deny_for or [],
            "escalation_targets": escalation_targets or {},
            "budget_limit_micros": budget_limit_micros,
            "expires_at": expires_iso,
            "replaces": replaces,
            "metadata": metadata or {},
        }, headers=headers)
        revocation_receipt = raw.get("revocation_receipt")
        return AuthorizationCreateResponse(
            authorization_id=raw["authorization_id"],
            created_at=raw["created_at"],
            expires_at=raw["expires_at"],
            receipt=_parse_pending_envelope(raw["receipt"]),
            policy_id=raw.get("policy_id"),
            requires_confirm_for=raw.get("requires_confirm_for", []),
            requires_escalation_for=raw.get("requires_escalation_for", []),
            requires_deny_for=raw.get("requires_deny_for", []),
            escalation_targets=raw.get("escalation_targets", {}),
            budget_limit_micros=raw.get("budget_limit_micros"),
            budget_spent_micros=raw.get("budget_spent_micros"),
            replaced_authorization_id=raw.get("replaced_authorization_id"),
            revocation_receipt=(
                _parse_pending_envelope(revocation_receipt)
                if revocation_receipt is not None
                else None
            ),
            billing_warning=response_headers.get("X-Allowly-Billing-Warning"),
        )

    async def revoke(
        self,
        authorization_id: str,
        *,
        revoked_by: str | None = None,
        superseded_by: str | None = None,
        notes: str | None = None,
        idempotency_key: str | None = None,
    ) -> AuthorizationRevokeResponse:
        body: dict[str, Any] = {}
        if revoked_by:
            body["revoked_by"] = revoked_by
        if superseded_by:
            body["superseded_by"] = superseded_by
        if notes:
            body["notes"] = notes
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key is not None else None
        raw = await self._client._request(
            "DELETE", f"/v1/authorizations/{quote(authorization_id, safe='')}", json=body or None, headers=headers
        )
        return AuthorizationRevokeResponse(
            authorization_id=raw["authorization_id"],
            revoked_at=raw["revoked_at"],
            receipt=_parse_pending_envelope(raw["receipt"]),
            revoked_confirmations=raw.get("revoked_confirmations", []),
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
        idempotency_key: str | None = None,
    ) -> ConfirmationApproveResponse:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key is not None else None
        raw = await self._client._request("POST", f"/v1/confirmations/{quote(nonce, safe='')}", json={
            "approved": approved,
            "ttl_seconds": ttl_seconds,
        }, headers=headers)
        decision = _require_str(raw, "decision")
        if decision not in {"approved", "denied_by_user"}:
            raise AllowlyProtocolError(f"unknown confirmation decision: {decision!r}")
        return ConfirmationApproveResponse(
            decision=decision,
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
        raw = await self._client._request("POST", f"/v1/escalations/{quote(escalation_id, safe='')}/resolve", json={
            "resolution": resolution,
            "resolved_by": resolved_by,
            "note": note,
        })
        status = _require_str(raw, "status")
        if status not in {"approved", "rejected"}:
            raise AllowlyProtocolError(f"unknown escalation status: {status!r}")
        receipt = raw.get("receipt")
        return EscalationResolveResponse(
            escalation_id=raw["escalation_id"],
            status=status,
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
        raw = await self._client._request("GET", f"/v1/receipts/{quote(receipt_id, safe='')}")
        return _parse_receipt_envelope(raw)

    async def fetch_signed(
        self,
        receipt_id: str,
        *,
        poll_interval: float = 1.0,
        timeout: float = 120.0,
    ) -> dict[str, Any]:
        """Poll until the receipt is signed, then return the full signed receipt dict.

        The default timeout covers the signer's once-per-minute batch tick plus
        scheduling/cold-start allowance; valid service behavior can take just
        over a minute. Raises TimeoutError if signing doesn't complete within
        `timeout` seconds.
        """
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        if timeout <= 0:
            raise ValueError("timeout must be positive")

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while (remaining := deadline - loop.time()) > 0:
            try:
                envelope = await asyncio.wait_for(self.get(receipt_id), timeout=remaining)
            except asyncio.TimeoutError:
                break
            if isinstance(envelope, ReceiptEnvelopeSigned):
                return envelope.receipt
            await asyncio.sleep(min(poll_interval, max(0, deadline - loop.time())))
        raise TimeoutError(f"Receipt {receipt_id} not signed after {timeout}s")


def _parse_pending_envelope(raw: Any) -> ReceiptEnvelopePending:
    raw = _require_dict(raw, "pending receipt envelope")
    if raw.get("status") != "pending":
        raise AllowlyProtocolError("receipt status must be 'pending'")
    return ReceiptEnvelopePending(
        status="pending",
        receipt_id=_optional_str(raw, "receipt_id"),
        ready_at_estimate=_optional_str(raw, "ready_at_estimate"),
        url=_optional_str(raw, "url"),
    )


def _parse_receipt_envelope(raw: Any) -> ReceiptEnvelope:
    raw = _require_dict(raw, "receipt envelope")
    if raw.get("status") == "pending":
        return _parse_pending_envelope(raw)
    if raw.get("status") == "signed":
        return ReceiptEnvelopeSigned(
            status="signed",
            receipt=_require_dict(raw.get("receipt"), "signed receipt"),
        )
    raise AllowlyProtocolError("receipt status must be 'pending' or 'signed'")


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


def _parse_retry_after(value: str | None) -> float | None:
    # Allowly only emits integer-seconds Retry-After; tolerate floats, ignore
    # HTTP-date and garbage rather than raising inside error handling.
    if value is None:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    return seconds if seconds >= 0 else None


def _parse_check_response(raw: dict[str, Any]) -> CheckResponse:
    # The API returns a map keyed by requested action. Preserve those keys so
    # callers can safely handle mixed allow/deny/confirm/escalate results in one check.
    raw = _require_dict(raw, "check response")
    result_items = _require_dict(raw.get("results"), "check results")
    results = {}
    for action, raw_item in result_items.items():
        if not isinstance(action, str):
            raise AllowlyProtocolError("check result action must be a string")
        item = _require_dict(raw_item, f"check result {action!r}")
        decision = _require_str(item, "decision")
        if decision not in {"allow", "deny", "confirm", "escalate"}:
            raise AllowlyProtocolError(f"unknown check decision: {decision!r}")
        base = dict(
            decision=decision,
            reason=_require_str(item, "reason"),
            receipt=_parse_receipt_envelope(item.get("receipt")),
            is_fallback=bool(item.get("is_fallback", False)),
            fallback_mode=item.get("fallback_mode"),
            budget=_parse_budget_info(item.get("budget")),
            escalation=_parse_escalation_info(item.get("escalation")),
            policy_eval=_parse_policy_eval(item.get("policy_eval")),
        )
        if decision == "allow":
            results[action] = ActionCheckResultAllow(**base)
        elif decision == "deny":
            results[action] = ActionCheckResultDeny(**base, superseded_by=item.get("superseded_by"))
        elif decision == "confirm":
            results[action] = ActionCheckResultConfirm(
                **base,
                confirm_nonce=_require_str(item, "confirm_nonce"),
                confirm_expires_at=_require_str(item, "confirm_expires_at"),
                confirm_prompt_hint=_require_str(item, "confirm_prompt_hint"),
            )
        else:
            results[action] = ActionCheckResultEscalate(
                **base,
                escalation_id=_require_str(item, "escalation_id"),
                escalation_to=_optional_str(item, "escalation_to"),
                escalation_expires_at=_optional_str(item, "escalation_expires_at"),
            )
    return CheckResponse(
        user_id=_optional_str(raw, "user_id"),
        agent_id=_optional_str(raw, "agent_id"),
        authorization_id=_require_str(raw, "authorization_id"),
        authorization_expires_at=_optional_str(raw, "authorization_expires_at"),
        engine_version=_require_str(raw, "engine_version"),
        results=results,
    )


def _require_dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AllowlyProtocolError(f"{name} must be an object")
    return value


def _require_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise AllowlyProtocolError(f"{key} must be a string")
    return value


def _require_int(raw: dict[str, Any], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise AllowlyProtocolError(f"{key} must be an integer")
    return value


def _optional_str(raw: dict[str, Any], key: str) -> str | None:
    value = raw.get(key)
    if value is not None and not isinstance(value, str):
        raise AllowlyProtocolError(f"{key} must be a string or null")
    return value


def _parse_budget_info(raw: Any) -> BudgetInfo | None:
    if raw is None:
        return None
    raw = _require_dict(raw, "budget")
    return BudgetInfo(
        limit_micros=_require_int(raw, "limit_micros"),
        spent_micros=_require_int(raw, "spent_micros"),
        estimated_cost_micros=_require_int(raw, "estimated_cost_micros"),
        spent_after_micros=(
            _require_int(raw, "spent_after_micros")
            if raw.get("spent_after_micros") is not None
            else None
        ),
    )


def _parse_budget_settlement_response(raw: Any) -> BudgetSettlementResponse:
    raw = _require_dict(raw, "budget settlement response")
    return BudgetSettlementResponse(
        check_receipt_id=_require_str(raw, "check_receipt_id"),
        authorization_id=_require_str(raw, "authorization_id"),
        estimated_cost_micros=_require_int(raw, "estimated_cost_micros"),
        actual_cost_micros=_require_int(raw, "actual_cost_micros"),
        delta_micros=_require_int(raw, "delta_micros"),
        spent_before_micros=_require_int(raw, "spent_before_micros"),
        spent_after_micros=_require_int(raw, "spent_after_micros"),
        receipt=_parse_receipt_envelope(raw.get("receipt")),
    )


def _parse_escalation_info(raw: Any) -> EscalationInfo | None:
    if raw is None:
        return None
    raw = _require_dict(raw, "escalation")
    return EscalationInfo(
        escalation_id=_require_str(raw, "escalation_id"),
        status=_require_str(raw, "status"),
        escalation_to=_optional_str(raw, "escalation_to"),
        expires_at=_optional_str(raw, "expires_at"),
    )


def _parse_policy_eval(raw: Any) -> PolicyEvalInfo | None:
    if raw is None:
        return None
    raw = _require_dict(raw, "policy evaluation")
    matched = raw.get("matched_condition")
    if matched is not None:
        matched = _require_dict(matched, "matched policy condition")
    return PolicyEvalInfo(
        matched_condition=(
            PolicyConditionEvidence(
                field=_require_str(matched, "field"),
                op=_require_str(matched, "op"),
                value=matched.get("value"),
            )
            if matched is not None
            else None
        ),
        field_value=raw.get("field_value"),
    )
