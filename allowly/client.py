from __future__ import annotations

import asyncio
from dataclasses import asdict
from datetime import datetime
import inspect
import re
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import quote, urlparse

import httpx

from .error import AllowlyAPIError, AllowlyProtocolError, FieldError
from .resolution_webhook import _ResolutionWebhookResource
from .types import (
    CheckResponse,
    CustomExecutableCreateRequest,
    EnabledExecutableResponse,
    ExecutableOperation,
    ExecutableCapabilities,
    ExecutableEvidenceCapability,
    ConfirmationApproveResponse,
    ConfirmationStatusResponse,
    EscalationStatusResponse,
    ConfirmationStatus,
    AuthorizationCreateResponse,
    AuthorizationRevokeResponse,
    BudgetInfo,
    BudgetSettlementResponse,
    EscalationInfo,
    EscalationResolveResponse,
    EscalationStatus,
    ExecutionDownstream,
    ExecutionRequestDescriptor,
    ExecutionReview,
    ExecutionResponse,
    ExecutionStatus,
    OutcomeEvidence,
    PolicyConditionEvidence,
    PolicyEvalInfo,
    ReceiptEnvelopePending,
    ReceiptEnvelopeSigned,
    ReceiptEnvelope,
    ReceiptAcknowledgmentCaller,
    ReceiptAcknowledgmentResponse,
    SealResponse,
    ActionEntry,
    FallbackMode,
    ActionCheckResultAllow,
    ActionCheckResultConfirm,
    ActionCheckResultDeny,
    ActionCheckResultEscalate,
)

DEFAULT_BASE_URL = "https://api.allowly.ai"

AgentTokenSupplier = Callable[[], str | Awaitable[str]]

if TYPE_CHECKING:
    from .execution import LocalExecutionResult


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
        fallback_by_action: dict[str, FallbackMode] | None = None,
        dangerously_allow_insecure_base_url: bool = False,
        edge_token: str | None = None,
        agent_token: str | None = None,
        agent_token_supplier: AgentTokenSupplier | None = None,
    ) -> None:
        self._api_key = api_key
        self._edge_token = edge_token
        self._agent_token = agent_token
        self._agent_token_supplier = agent_token_supplier
        base_url = _validate_base_url(base_url, dangerously_allow_insecure_base_url)
        if check_timeout_ms <= 0:
            raise ValueError("check_timeout_ms must be positive")
        self._check_timeout = check_timeout_ms / 1000
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
        self.resolution_webhook = _ResolutionWebhookResource(self)

    async def create_custom_executable(
        self, request: CustomExecutableCreateRequest,
    ) -> EnabledExecutableResponse:
        """Create one immutable customer-defined operation using a setup credential."""
        raw = await self._request(
            "POST", "/v1/setup/custom-executables",
            json=asdict(request), expected_success_status=201,
        )
        return _parse_custom_executable_response(raw)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def readiness(self) -> bool:
        """Read runtime readiness. This is not an authorization decision."""
        raw = _require_dict(await self._request("GET", "/readyz"), "readiness response")
        return _require_str(raw, "status") == "ready"

    async def __aenter__(self) -> Allowly:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        data, _ = await self._request_with_headers(method, path, **kwargs)
        return data

    async def _request_with_headers(
        self,
        method: str,
        path: str,
        *,
        expected_success_status: int | tuple[int, ...] = 200,
        **kwargs: Any,
    ) -> tuple[Any, httpx.Headers]:
        request_headers = kwargs.get("headers")
        request_agent_token = (
            request_headers.get("X-Allowly-Agent-Token")
            if isinstance(request_headers, dict)
            else None
        )

        sensitive_values = [
            value
            for value in (self._api_key, self._edge_token, request_agent_token)
            if isinstance(value, str) and value
        ]

        def safe_error_text(value: Any, fallback: str) -> str:
            rendered = value if isinstance(value, str) else fallback
            for sensitive_value in sensitive_values:
                rendered = rendered.replace(sensitive_value, "[REDACTED]")
            return rendered

        resp = await self._http.request(method, path, **kwargs)
        expected_statuses = (
            (expected_success_status,)
            if isinstance(expected_success_status, int)
            else expected_success_status
        )
        if resp.is_success and resp.status_code not in expected_statuses:
            raise AllowlyProtocolError(
                f"expected HTTP {' or '.join(str(status) for status in expected_statuses)}, "
                f"got {resp.status_code}"
            )
        if resp.status_code == 204:
            return None, resp.headers
        try:
            data = resp.json()
        except ValueError as exc:
            if resp.is_success:
                raise AllowlyProtocolError(
                    "successful response body must be valid JSON"
                ) from exc
            data = {}
        if not resp.is_success:
            err = data.get("error") if isinstance(data, dict) else None
            if isinstance(err, str):
                err = {"message": err}
            elif not isinstance(err, dict):
                err = {}
            raw_fields = err.get("fields")
            fields = [
                FieldError(
                    field=safe_error_text(f.get("field"), ""),
                    message=safe_error_text(f.get("message"), ""),
                )
                for f in (raw_fields if isinstance(raw_fields, list) else [])
                if isinstance(f, dict)
            ]
            raise AllowlyAPIError(
                status=resp.status_code,
                code=safe_error_text(err.get("code"), "error"),
                message=safe_error_text(err.get("message"), "Unknown error"),
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
        client_timestamp: datetime | str | None = None,
        agent_token: str | None = None,
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
        if client_timestamp is not None:
            body["client_timestamp"] = _client_timestamp(client_timestamp)
        headers = await self._identity_headers(
            agent_token,
            idempotency_key=idempotency_key,
        )
        identity_enabled = bool(headers and "X-Allowly-Agent-Token" in headers)
        try:
            timeout = max(self._check_timeout, 6.0) if wait else self._check_timeout
            raw, response_headers = await asyncio.wait_for(
                self._request_with_headers(
                    "POST",
                    path,
                    json=body,
                    timeout=timeout,
                    headers=headers,
                ),
                timeout=timeout,
            )
        except (asyncio.TimeoutError, httpx.TimeoutException):
            return self._fallback_check_response(
                authorization_id=authorization_id,
                actions=actions,
                failure="timeout",
                force_fail_closed=identity_enabled,
            )
        except (httpx.DecodingError, httpx.TransportError):
            return self._fallback_check_response(
                authorization_id=authorization_id,
                actions=actions,
                failure="unreachable",
                force_fail_closed=identity_enabled,
            )
        except AllowlyAPIError as exc:
            if exc.code == "identity_verification_unavailable":
                raise
            if exc.status == 408:
                return self._fallback_check_response(
                    authorization_id=authorization_id,
                    actions=actions,
                    failure="timeout",
                    force_fail_closed=identity_enabled,
                )
            if exc.status >= 500:
                return self._fallback_check_response(
                    authorization_id=authorization_id,
                    actions=actions,
                    failure="unreachable",
                    force_fail_closed=identity_enabled,
                )
            raise
        response = _parse_check_response(
            raw,
            expected_authorization_id=authorization_id,
            expected_actions=actions,
        )
        response.billing_warning = response_headers.get("X-Allowly-Billing-Warning")
        return response

    async def _identity_headers(
        self,
        agent_token: str | None,
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, str] | None:
        headers: dict[str, str] = {}
        effective_agent_token: str | None = agent_token
        if effective_agent_token is None and self._agent_token_supplier is not None:
            supplied = self._agent_token_supplier()
            effective_agent_token = await supplied if inspect.isawaitable(supplied) else supplied
            if not isinstance(effective_agent_token, str) or not effective_agent_token.strip():
                raise ValueError("agent token supplier must return a non-empty string")
        elif effective_agent_token is None:
            effective_agent_token = self._agent_token
        if effective_agent_token is not None:
            if not isinstance(effective_agent_token, str) or not effective_agent_token.strip():
                raise ValueError("agent token must be a non-empty string")
            headers["X-Allowly-Agent-Token"] = effective_agent_token
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        return headers or None

    def _fallback_check_response(
        self,
        *,
        authorization_id: str,
        actions: list[str],
        failure: str,
        force_fail_closed: bool = False,
    ) -> CheckResponse:
        results = {}
        for action in actions:
            mode: FallbackMode = (
                "fail_closed"
                if force_fail_closed
                else self._fallback_by_action.get(action, "fail_closed")
            )
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

    async def get_execution(
        self,
        operation_id: str,
        *,
        agent_token: str | None = None,
    ) -> ExecutionResponse:
        raw = await self._request(
            "GET",
            f"/v1/executions/{quote(operation_id, safe='')}",
            headers=await self._identity_headers(agent_token),
        )
        response = _parse_execution_response(raw)
        if response.operation_id != operation_id:
            raise AllowlyProtocolError(
                "execution response does not match the requested operation"
            )
        return response

    async def prepare_execution(
        self, *, operation_id: str, authorization_id: str,
        enabled_executable_id: str, catalog_operation_id: str, action: str,
        http_request: dict[str, Any], policy_input: dict[str, Any],
        client_timestamp: datetime | str, idempotency_key: str,
        evidence_mode: str = "receipt", agent_token: str | None = None,
    ) -> ExecutionResponse:
        """Approve a customer-side execution remotely; this never sends to the provider."""
        raw = await self._request(
            "POST", "/v1/execute", expected_success_status=(200, 201),
            headers=await self._identity_headers(agent_token, idempotency_key=idempotency_key),
            json={"operation_id": operation_id,
                  "authorization_id": authorization_id,
                  "enabled_executable_id": enabled_executable_id,
                  "catalog_operation_id": catalog_operation_id, "action": action,
                  "http_request": http_request, "policy_input": policy_input,
                  "evidence_mode": evidence_mode,
                  "client_timestamp": _client_timestamp(client_timestamp)},
        )
        result = _parse_execution_response(raw)
        if (result.operation_id != operation_id or result.destination_id != enabled_executable_id
                or result.action != action
                or result.request_descriptor.authorization_id != authorization_id):
            raise AllowlyProtocolError("execution approval does not match the requested operation")
        return result

    async def continue_execution(
        self, operation_id: str, *, execution_request: dict[str, Any],
        review_id: str, source_receipt_id: str, idempotency_key: str,
        agent_token: str | None = None,
    ) -> ExecutionResponse:
        """Continue the original waiting operation; never send provider bytes here."""
        if (not isinstance(execution_request, dict)
                or execution_request.get("operation_id") != operation_id
                or not review_id or not source_receipt_id or not idempotency_key):
            raise ValueError("continuation requires the original operation and review binding")
        request = {**execution_request,
                   "client_timestamp": _client_timestamp(execution_request.get("client_timestamp"))}
        raw = await self._request(
            "POST", f"/v1/executions/{quote(operation_id, safe='')}/continue",
            json={"execution_request": request, "review_id": review_id,
                  "source_receipt_id": source_receipt_id},
            headers=await self._identity_headers(agent_token, idempotency_key=idempotency_key),
            expected_success_status=(200, 201),
        )
        result = _parse_execution_response(raw)
        if (result.operation_id != operation_id
                or result.destination_id != request.get("enabled_executable_id")
                or result.action != request.get("action")
                or result.request_descriptor.authorization_id != request.get("authorization_id")):
            raise AllowlyProtocolError("execution continuation does not match the requested operation")
        return result

    async def claim_execution_dispatch(
        self, operation_id: str, *, approval_sha256: str, agent_token: str | None = None,
    ) -> dict[str, Any]:
        raw = await self._request(
            "POST", f"/v1/executions/{quote(operation_id, safe='')}/dispatch",
            json={"approval_sha256": approval_sha256},
            headers=await self._identity_headers(agent_token),
        )
        if (not isinstance(raw, dict) or raw.get("operation_id") != operation_id
                or raw.get("approval_sha256") != approval_sha256
                or raw.get("dispatch_state") != "claimed"):
            raise AllowlyProtocolError("invalid execution dispatch claim")
        return raw

    async def get_execution_witness_token(
        self, operation_id: str, *, approval_sha256: str, agent_token: str | None = None,
    ) -> dict[str, Any]:
        raw = await self._request(
            "POST", f"/v1/executions/{quote(operation_id, safe='')}/witness-session-token",
            json={"approval_sha256": approval_sha256},
            headers=await self._identity_headers(agent_token),
        )
        if not isinstance(raw, dict) or raw.get("approval_sha256") != approval_sha256:
            raise AllowlyProtocolError("invalid execution witness admission")
        return raw

    async def report_execution_outcome(
        self, operation_id: str, *, outcome: dict[str, Any], idempotency_key: str,
        agent_token: str | None = None,
    ) -> ExecutionResponse:
        raw = await self._request(
            "POST", f"/v1/executions/{quote(operation_id, safe='')}/outcome",
            json=outcome, headers=await self._identity_headers(agent_token, idempotency_key=idempotency_key),
            expected_success_status=(200, 201),
        )
        result = _parse_execution_response(raw)
        if result.operation_id != operation_id or result.approval_sha256 != outcome.get("approval_sha256"):
            raise AllowlyProtocolError("execution outcome does not match the requested operation")
        return result

    async def execute_http(
        self, url: str, *, operation_id: str, authorization_id: str,
        enabled_executable_id: str, catalog_operation_id: str, action: str,
        method: str = "GET", headers: dict[str, str] | None = None, body: str = "",
        evidence_mode: Literal["receipt", "witnessed"] = "receipt",
        policy_input: dict[str, Any] | None = None,
        storage_dir: str = ".allowly/executions", agent_token: str | None = None,
        native_binary: str | None = None, trusted_notary_key: str | None = None,
        timeout: float = 30.0,
    ) -> LocalExecutionResult:
        """Remotely authorize, then execute locally. See allowly.execution.execute_http."""
        from .execution import execute_http
        return await execute_http(
            self, url, operation_id=operation_id, authorization_id=authorization_id,
            enabled_executable_id=enabled_executable_id, catalog_operation_id=catalog_operation_id,
            action=action, method=method, headers=headers, body=body,
            evidence_mode=evidence_mode, policy_input=policy_input, storage_dir=storage_dir,
            agent_token=agent_token, native_binary=native_binary,
            trusted_notary_key=trusted_notary_key, timeout=timeout,
        )

    async def continue_http_execution(
        self, url: str, *, operation_id: str, authorization_id: str,
        enabled_executable_id: str, catalog_operation_id: str, action: str,
        method: str = "GET", headers: dict[str, str] | None = None, body: str = "",
        evidence_mode: Literal["receipt", "witnessed"] = "receipt",
        policy_input: dict[str, Any] | None = None,
        storage_dir: str = ".allowly/executions", agent_token: str | None = None,
        native_binary: str | None = None, trusted_notary_key: str | None = None,
        timeout: float = 30.0,
    ) -> LocalExecutionResult:
        """Continue a saved review with the same private request and operation ID."""
        from .execution import continue_http_execution
        return await continue_http_execution(
            self, url, operation_id=operation_id, authorization_id=authorization_id,
            enabled_executable_id=enabled_executable_id, catalog_operation_id=catalog_operation_id,
            action=action, method=method, headers=headers, body=body,
            evidence_mode=evidence_mode, policy_input=policy_input, storage_dir=storage_dir,
            agent_token=agent_token, native_binary=native_binary,
            trusted_notary_key=trusted_notary_key, timeout=timeout,
        )

    async def flush_execution_outcome(self, operation_dir: str, *, agent_token: str | None = None) -> ExecutionResponse:
        """Retry only a saved outcome report; never repeat the provider request."""
        from .execution import flush_execution_outcome
        return await flush_execution_outcome(self, operation_dir, agent_token=agent_token)

    async def acknowledge_receipt(
        self,
        *,
        receipt_id: str,
        receipt_sha256: str,
        client_timestamp: datetime | str,
        idempotency_key: str,
        agent_token: str | None = None,
    ) -> ReceiptAcknowledgmentResponse:
        raw = await self._request(
            "POST",
            f"/v1/receipts/{quote(receipt_id, safe='')}/acknowledgments",
            json={
                "receipt_sha256": receipt_sha256,
                "client_timestamp": _client_timestamp(client_timestamp),
            },
            headers=await self._identity_headers(
                agent_token,
                idempotency_key=idempotency_key,
            ),
            expected_success_status=(200, 201),
        )
        response = _parse_receipt_acknowledgment_response(raw)
        if response.receipt_id != receipt_id:
            raise AllowlyProtocolError(
                "receipt acknowledgment response does not match the requested receipt"
            )
        return response

    async def get_receipt_acknowledgment(
        self,
        receipt_id: str,
        acknowledgment_id: str,
        *,
        agent_token: str | None = None,
    ) -> ReceiptAcknowledgmentResponse:
        """Retrieve or repair one stored receipt acknowledgment."""
        raw = await self._request(
            "GET",
            (
                f"/v1/receipts/{quote(receipt_id, safe='')}/acknowledgments/"
                f"{quote(acknowledgment_id, safe='')}"
            ),
            headers=await self._identity_headers(agent_token),
        )
        response = _parse_receipt_acknowledgment_response(raw)
        if (
            response.receipt_id != receipt_id
            or response.acknowledgment_id != acknowledgment_id
        ):
            raise AllowlyProtocolError(
                "receipt acknowledgment response does not match the requested acknowledgment"
            )
        return response

    async def seal(
        self,
        record_json: str | bytes,
        *,
        request_id: str,
        metadata: dict[str, str] | None = None,
        poll_interval: float = 1.0,
        timeout: float = 120.0,
    ) -> SealResponse:
        """Hash strict raw JSON locally, create a SEAL, and wait for its receipt."""
        from .verify import hash_seal_json

        return await self._seal_digest(
            hash_seal_json(record_json),
            request_id=request_id,
            metadata=metadata,
            poll_interval=poll_interval,
            timeout=timeout,
        )

    async def seal_value(
        self,
        record: Any,
        *,
        request_id: str,
        metadata: dict[str, str] | None = None,
        poll_interval: float = 1.0,
        timeout: float = 120.0,
    ) -> SealResponse:
        """Seal a parsed JSON value after duplicate keys and spellings are lost."""
        from .verify import hash_seal_value

        return await self._seal_digest(
            hash_seal_value(record),
            request_id=request_id,
            metadata=metadata,
            poll_interval=poll_interval,
            timeout=timeout,
        )

    async def _seal_digest(
        self,
        record_sha256: str,
        *,
        request_id: str,
        metadata: dict[str, str] | None,
        poll_interval: float,
        timeout: float,
    ) -> SealResponse:
        from .verify import SEAL_PROFILE

        if not isinstance(request_id, str) or not request_id:
            raise ValueError("request_id must be a non-empty string")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        clean_metadata = _validate_seal_metadata(metadata)
        body: dict[str, Any] = {
            "request_id": request_id,
            "profile": SEAL_PROFILE,
            "record_sha256": record_sha256,
        }
        if clean_metadata is not None:
            body["metadata"] = clean_metadata

        raw = _require_dict(
            await self._request("POST", "/v1/seal", json=body),
            "seal response",
        )
        if _require_str(raw, "request_id") != request_id:
            raise AllowlyProtocolError("seal response request_id does not match the request")
        if _require_str(raw, "profile") != SEAL_PROFILE:
            raise AllowlyProtocolError("seal response profile does not match the request")
        if _require_str(raw, "record_sha256") != record_sha256:
            raise AllowlyProtocolError("seal response record_sha256 does not match the request")
        workspace_id = _require_str(raw, "workspace_id")
        if not workspace_id:
            raise AllowlyProtocolError("seal response workspace_id must be non-empty")
        decision = _require_str(raw, "decision")
        if decision != "allow":
            raise AllowlyProtocolError("seal response decision must be 'allow'")
        reason = _require_str(raw, "reason")
        envelope = _parse_receipt_envelope(raw.get("receipt"))
        pending_receipt_id = (
            None if isinstance(envelope, ReceiptEnvelopeSigned) else envelope.receipt_id
        )
        receipt = envelope.receipt if isinstance(envelope, ReceiptEnvelopeSigned) else (
            await self.receipts.fetch_signed(
                envelope.receipt_id,
                poll_interval=poll_interval,
                timeout=timeout,
            )
        )
        _validate_seal_receipt(
            receipt,
            record_sha256=record_sha256,
            expected_workspace_id=workspace_id,
            expected_receipt_id=pending_receipt_id,
        )
        return SealResponse(
            request_id=request_id,
            workspace_id=workspace_id,
            profile=SEAL_PROFILE,
            record_sha256=record_sha256,
            decision="allow",
            reason=reason,
            receipt=receipt,
        )


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
        if policy_id is not None:
            if agent_id is not None or actions is not None:
                raise ValueError("policy_id cannot be combined with agent_id or actions")
            decision_overrides = {
                "requires_confirm_for": requires_confirm_for,
                "requires_escalation_for": requires_escalation_for,
                "requires_deny_for": requires_deny_for,
                "escalation_targets": escalation_targets,
            }
            for field_name, value in decision_overrides.items():
                if value is not None:
                    raise ValueError(f"policy_id cannot be combined with {field_name}")
        else:
            if agent_id is None or actions is None:
                raise ValueError(
                    "provide either policy_id or inline agent_id and actions"
                )
            if expires_at is None:
                raise ValueError("expires_at is required for inline authorizations")

        expires_iso = expires_at.isoformat() if isinstance(expires_at, datetime) else expires_at
        body: dict[str, Any] = {
            "user_id": user_id,
            "metadata": metadata or {},
        }
        if expires_iso is not None:
            body["expires_at"] = expires_iso
        if budget_limit_micros is not None:
            body["budget_limit_micros"] = budget_limit_micros
        if replaces is not None:
            body["replaces"] = replaces
        if policy_id is not None:
            body["policy_id"] = policy_id
        else:
            assert agent_id is not None and actions is not None
            body.update({
                "agent_id": agent_id,
                "actions": [
                    {"name": action, "constraints": {}}
                    if isinstance(action, str)
                    else {"name": action.name, "constraints": action.constraints,
                          **({"executable_operations": [asdict(grant) for grant in action.executable_operations]}
                             if action.executable_operations else {})}
                    for action in actions
                ],
                "requires_confirm_for": requires_confirm_for or [],
                "requires_escalation_for": requires_escalation_for or [],
                "requires_deny_for": requires_deny_for or [],
                "escalation_targets": escalation_targets or {},
            })

        headers = {"Idempotency-Key": idempotency_key} if idempotency_key is not None else None
        raw, response_headers = await self._client._request_with_headers(
            "POST",
            "/v1/authorizations",
            json=body,
            headers=headers,
            expected_success_status=201,
        )
        raw = _require_dict(raw, "authorization create response")
        revocation_receipt = raw.get("revocation_receipt")
        return AuthorizationCreateResponse(
            authorization_id=_require_str(raw, "authorization_id"),
            created_at=_require_str(raw, "created_at"),
            expires_at=_require_str(raw, "expires_at"),
            receipt=_parse_pending_envelope(raw["receipt"]),
            policy_id=_optional_str(raw, "policy_id"),
            requires_confirm_for=_require_str_list(raw, "requires_confirm_for"),
            requires_escalation_for=_require_str_list(
                raw, "requires_escalation_for"
            ),
            requires_deny_for=_require_str_list(raw, "requires_deny_for"),
            escalation_targets=_require_str_map(raw, "escalation_targets"),
            budget_limit_micros=raw.get("budget_limit_micros"),
            budget_spent_micros=raw.get("budget_spent_micros"),
            replaced_authorization_id=raw.get("replaced_authorization_id"),
            revocation_receipt=(
                _parse_pending_envelope(revocation_receipt)
                if revocation_receipt is not None
                else None
            ),
            authorization_provenance=(
                _require_dict(raw["authorization_provenance"], "authorization provenance")
                if raw.get("authorization_provenance") is not None
                else None
            ),
            billing_warning=response_headers.get("X-Allowly-Billing-Warning"),
        )

    async def revoke(
        self,
        authorization_id: str,
        *,
        revoked_by: str | None = None,
        notes: str | None = None,
        idempotency_key: str | None = None,
    ) -> AuthorizationRevokeResponse:
        body: dict[str, Any] = {}
        if revoked_by:
            body["revoked_by"] = revoked_by
        if notes:
            body["notes"] = notes
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key is not None else None
        raw = await self._client._request(
            "DELETE",
            f"/v1/authorizations/{quote(authorization_id, safe='')}",
            json=body or None,
            headers=headers,
        )
        return AuthorizationRevokeResponse(
            authorization_id=_require_str(raw, "authorization_id"),
            revoked_at=_require_str(raw, "revoked_at"),
            receipt=_parse_pending_envelope(raw.get("receipt")),
            revoked_confirmations=_require_str_list(raw, "revoked_confirmations"),
        )


class _ConfirmationsResource:
    def __init__(self, client: Allowly) -> None:
        self._client = client

    async def get_status(self, confirmation_id: str) -> ConfirmationStatusResponse:
        """Read an opaque confirmation monitor ID, never its bearer nonce."""
        _validate_prompt_id(confirmation_id, "cnf_")
        raw = await self._client._request("GET", f"/v1/confirmations/{quote(confirmation_id, safe='')}/status")
        return _parse_confirmation_status(raw, confirmation_id)

    get = get_status

    async def approve(
        self,
        nonce: str,
        *,
        approved: bool,
        ttl_seconds: int = 60,
        idempotency_key: str | None = None,
    ) -> ConfirmationApproveResponse:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key is not None else None
        raw = await self._client._request(
            "POST",
            f"/v1/confirmations/{quote(nonce, safe='')}",
            json={
                "approved": approved,
                "ttl_seconds": ttl_seconds,
            },
            headers=headers,
        )
        decision = _require_str(raw, "decision")
        if decision not in {"approved", "not_approved", "denied_by_user"}:
            raise AllowlyProtocolError(f"unknown confirmation decision: {decision!r}")
        if decision == "approved":
            authorization_id = _require_str(raw, "authorization_id")
            expires_at = _require_str(raw, "expires_at")
        else:
            authorization_id = _require_null(raw, "authorization_id")
            expires_at = _require_null(raw, "expires_at")
        return ConfirmationApproveResponse(
            decision=decision,
            authorization_id=authorization_id,
            expires_at=expires_at,
            receipt=(
                _parse_pending_envelope(raw["receipt"])
                if raw.get("receipt") is not None
                else None
            ),
        )


class _EscalationsResource:
    def __init__(self, client: Allowly) -> None:
        self._client = client

    async def get_status(self, escalation_id: str) -> EscalationStatusResponse:
        """Read the recorded choice and current grant lifecycle without a Check."""
        _validate_prompt_id(escalation_id, "esc_")
        raw = await self._client._request("GET", f"/v1/escalations/{quote(escalation_id, safe='')}")
        return _parse_escalation_status(raw, escalation_id)

    get = get_status

    async def resolve(
        self,
        escalation_id: str,
        *,
        resolution: str,
        resolved_by: str,
        note: str | None = None,
    ) -> EscalationResolveResponse:
        raw = await self._client._request(
            "POST",
            f"/v1/escalations/{quote(escalation_id, safe='')}/resolve",
            json={
                "resolution": resolution,
                "resolved_by": resolved_by,
                "note": note,
            },
        )
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
        raw = await self._client._request(
            "GET",
            f"/v1/receipts/{quote(receipt_id, safe='')}",
        )
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
            retry_delay = poll_interval
            try:
                envelope = await asyncio.wait_for(self.get(receipt_id), timeout=remaining)
            except asyncio.TimeoutError:
                break
            except httpx.TransportError:
                pass
            except AllowlyAPIError as exc:
                if exc.status not in {408, 429} and not 500 <= exc.status <= 599:
                    raise
                if exc.retry_after_seconds is not None:
                    retry_delay = exc.retry_after_seconds
            else:
                if isinstance(envelope, ReceiptEnvelopeSigned):
                    if _require_str(envelope.receipt, "receipt_id") != receipt_id:
                        raise AllowlyProtocolError(
                            "signed receipt_id does not match the requested receipt"
                        )
                    return envelope.receipt
            await asyncio.sleep(
                min(retry_delay, max(0, deadline - loop.time()))
            )
        raise TimeoutError(f"Receipt {receipt_id} not signed after {timeout}s")


def _validate_prompt_id(value: str, prefix: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9_-]{1,256}", value):
        raise ValueError(f"prompt ID must be an opaque {prefix} monitor ID")


def _parse_custom_executable_response(value: Any) -> EnabledExecutableResponse:
    raw = _require_dict(value, "enabled executable")

    def flag(record: dict[str, Any], key: str) -> bool:
        if not isinstance(record.get(key), bool):
            raise AllowlyProtocolError(f"{key} must be a boolean")
        return record[key]

    def capability(
        value: Any, source: Literal["customer_reported", "independent_allowly_witness"],
    ) -> ExecutableEvidenceCapability:
        record = _require_dict(value, "executable evidence capability")
        if record.get("evidence_source") != source:
            raise AllowlyProtocolError("invalid executable evidence source")
        return ExecutableEvidenceCapability(
            available=flag(record, "available"), evidence_source=source,
            profile=_optional_str(record, "profile"), reason=_optional_str(record, "reason"),
            api_request_match_verification=_optional_str(record, "api_request_match_verification"),
        )

    if (raw.get("credential_location") != "customer_runtime"
            or raw.get("connection_status") != "not_verified"):
        raise AllowlyProtocolError("invalid executable credential location or connection status")
    operations_raw = raw.get("operations")
    if (not isinstance(operations_raw, list) or len(operations_raw) != 1
            or _require_int(raw, "operation_count") != 1):
        raise AllowlyProtocolError("a custom executable must contain exactly one operation")
    provider_id = _require_str(raw, "provider_id")
    operations = []
    for value in operations_raw:
        operation = _require_dict(value, "executable operation")
        capabilities = _require_dict(operation.get("capabilities"), "executable capabilities")
        fingerprint = _require_str(operation, "definition_fingerprint")
        if (operation.get("provider_id") != provider_id
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", fingerprint)):
            raise AllowlyProtocolError("invalid executable operation identity or fingerprint")
        operations.append(ExecutableOperation(
            provider_id=provider_id, operation_id=_require_str(operation, "operation_id"),
            label=_require_str(operation, "label"), method=_require_str(operation, "method"),
            path=_require_str(operation, "path"), effect=_require_str(operation, "effect"),
            request_content_type=_optional_str(operation, "request_content_type"),
            required_headers=_require_str_list(operation, "required_headers"),
            status=_require_str(operation, "status"), definition_fingerprint=fingerprint,
            capabilities=ExecutableCapabilities(
                customer_reported_receipt=capability(capabilities.get("customer_reported_receipt"), "customer_reported"),
                tls_witness=capability(capabilities.get("tls_witness"), "independent_allowly_witness"),
            ),
            allowly_live_tested=flag(operation, "allowly_live_tested"),
            tls_witness_tested=flag(operation, "tls_witness_tested"),
        ))
    return EnabledExecutableResponse(
        enabled_executable_id=_require_str(raw, "enabled_executable_id"), provider_id=provider_id,
        provider_name=_require_str(raw, "provider_name"), category=_require_str(raw, "category"),
        origin=_require_str(raw, "origin"), catalog_revision=_require_str(raw, "catalog_revision"),
        status=_require_str(raw, "status"), credential_location="customer_runtime",
        connection_status="not_verified", allowly_live_tested=flag(raw, "allowly_live_tested"),
        tls_witness_tested=flag(raw, "tls_witness_tested"), operations=operations,
        operation_count=1, enabled_at=_require_str(raw, "enabled_at"),
        disabled_at=_optional_str(raw, "disabled_at"),
    )


def _parse_pending_envelope(raw: Any) -> ReceiptEnvelopePending:
    raw = _require_dict(raw, "pending receipt envelope")
    if raw.get("status") != "pending":
        raise AllowlyProtocolError("receipt status must be 'pending'")
    return ReceiptEnvelopePending(
        status="pending",
        receipt_id=_require_str(raw, "receipt_id"),
        ready_at_estimate=_optional_str(raw, "ready_at_estimate"),
        url=_require_str(raw, "url"),
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


def _validate_seal_metadata(metadata: dict[str, str] | None) -> dict[str, str] | None:
    if metadata is None:
        return None
    if not isinstance(metadata, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in metadata.items()
    ):
        raise ValueError("metadata must be an object of string values")
    return dict(metadata)


def _validate_fallback_mode(mode: str) -> FallbackMode:
    if mode not in {"fail_open", "fail_closed"}:
        raise ValueError("fallback mode must be 'fail_open' or 'fail_closed'")
    return mode  # type: ignore[return-value]


def _validate_base_url(base_url: str, allow_insecure: bool) -> str:
    normalized = base_url.rstrip("/")
    parsed = urlparse(normalized)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("base_url must be a valid URL")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("base_url must use HTTP or HTTPS")
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


def _parse_check_response(
    raw: dict[str, Any],
    *,
    expected_authorization_id: str,
    expected_actions: list[str],
) -> CheckResponse:
    # The API returns a map keyed by requested action. Preserve those keys so
    # callers can safely handle mixed allow/deny/confirm/escalate results in one check.
    raw = _require_dict(raw, "check response")
    authorization_id = _require_str(raw, "authorization_id")
    if authorization_id != expected_authorization_id:
        raise AllowlyProtocolError(
            "check response authorization_id does not match the request"
        )
    result_items = _require_dict(raw.get("results"), "check results")
    expected_action_set = set(expected_actions)
    actual_action_set = set(result_items)
    if actual_action_set != expected_action_set:
        raise AllowlyProtocolError(
            "check response result actions do not match the request"
        )
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
            is_fallback=False,
            fallback_mode=None,
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
                confirmation_id=_optional_confirmation_id(item),
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
        authorization_id=authorization_id,
        authorization_expires_at=_optional_str(raw, "authorization_expires_at"),
        engine_version=_require_str(raw, "engine_version"),
        results=results,
    )


def _require_dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AllowlyProtocolError(f"{name} must be an object")
    return value


def _optional_confirmation_id(raw: dict[str, Any]) -> str | None:
    value = _optional_str(raw, "confirmation_id")
    if value is not None and not re.fullmatch(r"cnf_[A-Za-z0-9_-]+", value):
        raise AllowlyProtocolError("confirmation_id must be an opaque cnf_ ID")
    return value


def _status_nullable_str(raw: dict[str, Any], key: str) -> str | None:
    if key not in raw:
        raise AllowlyProtocolError(f"{key} must be present as a string or null")
    value = _optional_str(raw, key)
    if value == "" and key != "resource":
        raise AllowlyProtocolError(f"{key} must be non-empty or null")
    return value


def _status_timestamp(raw: dict[str, Any], key: str, *, nullable: bool = False) -> str | None:
    value = _status_nullable_str(raw, key) if nullable else _require_str(raw, key)
    if value is None:
        return None
    match = re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))", value
    )
    if match is None or (match[1] is not None and (int(match[1]) > 23 or int(match[2]) > 59)):
        raise AllowlyProtocolError(f"{key} must be a valid timezone-aware timestamp")
    try:
        return _client_timestamp(value)
    except ValueError as exc:
        raise AllowlyProtocolError(f"{key} must be a valid timezone-aware timestamp") from exc


def _parse_prompt_status(raw: dict[str, Any]) -> dict[str, Any]:
    status = _require_str(raw, "status")
    if status not in {"pending", "approved", "rejected", "expired", "unknown"}:
        raise AllowlyProtocolError(f"unknown prompt status: {status!r}")
    authorization_id = _require_str(raw, "authorization_id")
    action = _require_str(raw, "action")
    if not authorization_id or not action:
        raise AllowlyProtocolError("status authorization_id and action must be non-empty")
    resolved_at = _status_timestamp(raw, "resolved_at", nullable=True)
    if status in {"pending", "expired"} and resolved_at is not None:
        raise AllowlyProtocolError("unresolved prompt resolved_at must be null")
    return dict(
        authorization_id=authorization_id,
        action=action,
        resource=_status_nullable_str(raw, "resource"),
        status=status,
        expires_at=_status_timestamp(raw, "expires_at"),
        resolved_at=resolved_at,
        source_receipt_id=_status_nullable_str(raw, "source_receipt_id"),
        resolution_receipt_id=_status_nullable_str(raw, "resolution_receipt_id"),
    )


def _parse_confirmation_status(value: Any, expected_id: str) -> ConfirmationStatus:
    raw = _require_dict(value, "confirmation status")
    confirmation_id = _require_str(raw, "confirmation_id")
    if confirmation_id != expected_id:
        raise AllowlyProtocolError("confirmation_id does not match the request")
    base = _parse_prompt_status(raw)
    authority = _require_str(raw, "authority_status")
    if authority not in {"none", "available", "expired", "revoked", "unknown"}:
        raise AllowlyProtocolError(f"unknown confirmation authority_status: {authority!r}")
    child_id = _status_nullable_str(raw, "child_authorization_id")
    authority_expiry = _status_timestamp(raw, "authority_expires_at", nullable=True)
    if authority == "available" and (
        base["status"] != "approved" or child_id is None or authority_expiry is None
    ):
        raise AllowlyProtocolError("available confirmation authority requires an approved choice and child grant")
    if base["status"] == "rejected" and authority != "none":
        raise AllowlyProtocolError("rejected confirmation authority_status must be none")
    return ConfirmationStatus(
        **base, confirmation_id=confirmation_id, child_authorization_id=child_id,
        authority_status=authority, authority_expires_at=authority_expiry,
    )


def _parse_escalation_status(value: Any, expected_id: str) -> EscalationStatus:
    raw = _require_dict(value, "escalation status")
    escalation_id = _require_str(raw, "escalation_id")
    if escalation_id != expected_id:
        raise AllowlyProtocolError("escalation_id does not match the request")
    base = _parse_prompt_status(raw)
    authority = _require_str(raw, "authority_status")
    if authority not in {"none", "available", "expired", "revoked", "consumed", "unknown"}:
        raise AllowlyProtocolError(f"unknown escalation authority_status: {authority!r}")
    if authority == "available" and base["status"] != "approved":
        raise AllowlyProtocolError("available escalation authority requires an approved choice")
    if base["status"] == "rejected" and authority != "none":
        raise AllowlyProtocolError("rejected escalation authority_status must be none")
    return EscalationStatus(
        **base, escalation_id=escalation_id, authority_status=authority,
        consumed_at=_status_timestamp(raw, "consumed_at", nullable=True),
    )


def _validate_seal_receipt(
    receipt: dict[str, Any],
    *,
    record_sha256: str,
    expected_workspace_id: str,
    expected_receipt_id: str | None,
) -> None:
    from .verify import SEAL_ACTION, SEAL_AGENT_ID, SEAL_PROFILE, SEAL_USER_ID

    receipt_id = _require_str(receipt, "receipt_id")
    if not receipt_id:
        raise AllowlyProtocolError("seal receipt_id must be non-empty")
    if expected_receipt_id is not None and receipt_id != expected_receipt_id:
        raise AllowlyProtocolError("seal receipt_id does not match the pending receipt")
    expected_fields = {
        "schema_version": "4",
        "action": SEAL_ACTION,
        "decision": "allow",
        "agent_id": SEAL_AGENT_ID,
        "user_id": SEAL_USER_ID,
        "alg": "Ed25519",
    }
    for key, expected in expected_fields.items():
        if _require_str(receipt, key) != expected:
            raise AllowlyProtocolError(f"seal receipt {key} does not match the request")
    if _require_str(receipt, "workspace_id") != expected_workspace_id:
        raise AllowlyProtocolError("seal receipt workspace_id does not match the response")
    for key in ("key_id", "signature"):
        if not _require_str(receipt, key):
            raise AllowlyProtocolError(f"seal receipt {key} must be non-empty")
    context = _require_dict(receipt.get("context"), "seal receipt context")
    if _require_str(context, "seal_profile") != SEAL_PROFILE:
        raise AllowlyProtocolError("seal receipt profile does not match the request")
    if _require_str(context, "record_sha256") != record_sha256:
        raise AllowlyProtocolError("seal receipt record_sha256 does not match the request")


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


def _require_str_list(raw: dict[str, Any], key: str) -> list[str]:
    value = raw.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise AllowlyProtocolError(f"{key} must be an array of strings")
    return value


def _require_str_map(raw: dict[str, Any], key: str) -> dict[str, str]:
    value = raw.get(key)
    if not isinstance(value, dict) or any(
        not isinstance(map_key, str) or not isinstance(map_value, str)
        for map_key, map_value in value.items()
    ):
        raise AllowlyProtocolError(f"{key} must be an object of string values")
    return value


def _optional_str(raw: dict[str, Any], key: str) -> str | None:
    value = raw.get(key)
    if value is not None and not isinstance(value, str):
        raise AllowlyProtocolError(f"{key} must be a string or null")
    return value


def _require_null(raw: dict[str, Any], key: str) -> None:
    if key not in raw or raw[key] is not None:
        raise AllowlyProtocolError(f"{key} must be null")
    return None


def _client_timestamp(value: datetime | str) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("client_timestamp must include a timezone")
        rendered = value.isoformat()
        return rendered[:-6] + "Z" if rendered.endswith("+00:00") else rendered
    if not isinstance(value, str) or not value:
        raise ValueError("client_timestamp must be a non-empty timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise ValueError("client_timestamp must be a valid timezone-aware timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("client_timestamp must include a timezone")
    return value


def _parse_execution_response(raw: Any) -> ExecutionResponse:
    body = _require_dict(raw, "execution response")
    operation_id = _require_str(body, "operation_id")
    destination_id = _require_str(body, "destination_id")
    action = _require_str(body, "action")
    status = _require_str(body, "status")
    allowed_statuses: set[ExecutionStatus] = {
        "approved",
        "denied",
        "confirmation_required",
        "escalation_required",
        "waiting_for_review",
        "succeeded",
        "failed",
        "unknown",
    }
    if status not in allowed_statuses:
        raise AllowlyProtocolError(f"invalid execution status: {status!r}")
    decision = _require_str(body, "decision")
    if decision not in {"allow", "deny", "confirm", "escalate"}:
        raise AllowlyProtocolError(f"invalid execution decision: {decision!r}")
    review_raw = body.get("review")
    review = None
    if review_raw is not None:
        review_body = _require_dict(review_raw, "execution review")
        kind = _require_str(review_body, "kind")
        if kind not in {"confirm", "escalate"}:
            raise AllowlyProtocolError("invalid execution review kind")
        review = ExecutionReview(
            kind=kind, id=_require_str(review_body, "id"),
            source_receipt_id=_require_str(review_body, "source_receipt_id"),
            expires_at=_require_str(review_body, "expires_at"),
        )
        if (not review.id.startswith("cnf_" if kind == "confirm" else "esc_")
                or not review.source_receipt_id):
            raise AllowlyProtocolError("invalid execution review binding")
    if status == "waiting_for_review":
        envelope = _parse_receipt_envelope(body.get("decision_receipt"))
        receipt_id = envelope.receipt_id if isinstance(envelope, ReceiptEnvelopePending) else envelope.receipt.get("receipt_id")
        if (review is None or decision != review.kind or review.source_receipt_id != receipt_id
                or body.get("approval") is not None or body.get("approval_sha256") is not None
                or body.get("downstream") is not None or body.get("decision_state") != "not_allowed"
                or body.get("target_state") != "not_started" or body.get("evidence_state") != "pending"):
            raise AllowlyProtocolError("waiting execution has an invalid review binding")
    downstream_raw = body.get("downstream")
    downstream = None
    if downstream_raw is not None:
        downstream_body = _require_dict(downstream_raw, "execution downstream")
        source = _require_str(downstream_body, "source")
        if source != "customer_runtime":
            raise AllowlyProtocolError(f"invalid execution downstream source: {source!r}")
        http_status = downstream_body.get("http_status")
        if http_status is not None and (isinstance(http_status, bool) or not isinstance(http_status, int)):
            raise AllowlyProtocolError("execution downstream http_status must be an integer or null")
        response_fingerprint = downstream_body.get("response_fingerprint")
        if response_fingerprint is not None and not isinstance(response_fingerprint, str):
            raise AllowlyProtocolError(
                "execution downstream response_fingerprint must be a string or null"
            )
        response_fingerprint_scope = _require_str(
            downstream_body, "response_fingerprint_scope"
        )
        if response_fingerprint_scope not in {"complete", "unavailable"}:
            raise AllowlyProtocolError(
                "invalid execution downstream response_fingerprint_scope: "
                f"{response_fingerprint_scope!r}"
            )
        result = _require_dict(downstream_body.get("result"), "execution downstream result")
        business_completion = _require_str(downstream_body, "business_completion")
        if business_completion != "not_verified":
            raise AllowlyProtocolError(
                f"invalid execution downstream business_completion: {business_completion!r}"
            )
        downstream = ExecutionDownstream(
            source=source,
            http_status=http_status,
            response_fingerprint=response_fingerprint,
            response_fingerprint_scope=response_fingerprint_scope,
            result=result,
            business_completion="not_verified",
        )
    evidence_raw = body.get("outcome_evidence")
    evidence = _parse_outcome_evidence(evidence_raw) if evidence_raw is not None else None
    fingerprint_profile = _require_str(body, "request_fingerprint_profile")
    if fingerprint_profile != "allowly.execution.request.v1":
        raise AllowlyProtocolError(
            f"invalid execution request fingerprint profile: {fingerprint_profile!r}"
        )
    descriptor_body = _require_dict(body.get("request_descriptor"), "execution request descriptor")
    descriptor_method = _require_str(descriptor_body, "method")
    if descriptor_method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise AllowlyProtocolError(
            f"invalid execution request descriptor method: {descriptor_method!r}"
        )
    raw_headers = descriptor_body.get("headers")
    if not isinstance(raw_headers, list):
        raise AllowlyProtocolError("execution request descriptor headers must be an array")
    headers = []
    for item in raw_headers:
        header = _require_dict(item, "execution request header")
        headers.append({
            "name": _require_str(header, "name"),
            "value_sha256": _require_str(header, "value_sha256"),
        })
    request_descriptor = ExecutionRequestDescriptor(
        operation_id=_require_str(descriptor_body, "operation_id"),
        authorization_id=_require_str(descriptor_body, "authorization_id"),
        destination_id=_require_str(descriptor_body, "destination_id"),
        action=_require_str(descriptor_body, "action"),
        method=descriptor_method,
        origin=_require_str(descriptor_body, "origin"),
        path=_require_str(descriptor_body, "path"),
        query=_require_str(descriptor_body, "query"),
        headers=headers,
        body_sha256=_require_str(descriptor_body, "body_sha256"),
        body_size=_require_int(descriptor_body, "body_size"),
        content_type=_optional_str(descriptor_body, "content_type"),
    )
    if (
        request_descriptor.operation_id != operation_id
        or request_descriptor.destination_id != destination_id
        or request_descriptor.action != action
    ):
        raise AllowlyProtocolError(
            "execution request descriptor does not match the response"
        )
    return ExecutionResponse(
        operation_id=operation_id,
        status=status,
        decision=decision,
        reason=_require_str(body, "reason"),
        destination_id=destination_id,
        action=action,
        request_fingerprint_profile="allowly.execution.request.v1",
        request_fingerprint=_require_str(body, "request_fingerprint"),
        request_descriptor=request_descriptor,
        decision_receipt=_parse_receipt_envelope(body.get("decision_receipt")),
        downstream=downstream,
        outcome_evidence=evidence,
        confirmation_id=_optional_str(body, "confirmation_id"),
        review=review,
        confirm_nonce=_optional_str(body, "confirm_nonce"),
        confirm_expires_at=_optional_str(body, "confirm_expires_at"),
        confirm_prompt_hint=_optional_str(body, "confirm_prompt_hint"),
        escalation_id=_optional_str(body, "escalation_id"),
        escalation_expires_at=_optional_str(body, "escalation_expires_at"),
        escalation_to=_optional_str(body, "escalation_to"),
        escalation=_parse_escalation_info(body.get("escalation")),
        effective_evidence_mode=_optional_str(body, "effective_evidence_mode"),
        approval=body.get("approval"),
        approval_sha256=_optional_str(body, "approval_sha256"),
        approval_expires_at=_optional_str(body, "approval_expires_at"),
        decision_state=_optional_str(body, "decision_state"),
        target_state=_optional_str(body, "target_state"),
        evidence_state=_optional_str(body, "evidence_state"),
        witness_session=body.get("witness_session"),
    )


def _parse_outcome_evidence(raw: Any) -> OutcomeEvidence:
    body = _require_dict(raw, "outcome evidence")
    profile = _require_str(body, "profile")
    if profile != "allowly.seal.jcs-sha256.v1":
        raise AllowlyProtocolError(f"invalid outcome evidence profile: {profile!r}")
    receipt_raw = body.get("receipt")
    evidence_error = body.get("evidence_error")
    if evidence_error not in {None, "unavailable"}:
        raise AllowlyProtocolError(
            f"invalid outcome evidence error: {evidence_error!r}"
        )
    return OutcomeEvidence(
        profile="allowly.seal.jcs-sha256.v1",
        record=_require_dict(body.get("record"), "outcome evidence record"),
        record_sha256=_require_str(body, "record_sha256"),
        receipt=(
            _parse_receipt_envelope(receipt_raw)
            if receipt_raw is not None
            else None
        ),
        evidence_error=evidence_error,
    )


def _parse_receipt_acknowledgment_response(raw: Any) -> ReceiptAcknowledgmentResponse:
    body = _require_dict(raw, "receipt acknowledgment response")
    caller_body = _require_dict(body.get("caller"), "receipt acknowledgment caller")
    caller_kind = _require_str(caller_body, "kind")
    if caller_kind != "workspace_runtime_key":
        raise AllowlyProtocolError(f"invalid receipt acknowledgment caller kind: {caller_kind!r}")
    agent_identity_raw = caller_body.get("agent_identity")
    return ReceiptAcknowledgmentResponse(
        acknowledgment_id=_require_str(body, "acknowledgment_id"),
        receipt_id=_require_str(body, "receipt_id"),
        receipt_sha256=_require_str(body, "receipt_sha256"),
        client_timestamp=_require_str(body, "client_timestamp"),
        received_at=_require_str(body, "received_at"),
        caller=ReceiptAcknowledgmentCaller(
            kind="workspace_runtime_key",
            api_key_id=_require_str(caller_body, "api_key_id"),
            agent_identity=(
                _require_dict(agent_identity_raw, "receipt acknowledgment agent identity")
                if agent_identity_raw is not None
                else None
            ),
        ),
        evidence=_parse_outcome_evidence(body.get("evidence")),
    )


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
