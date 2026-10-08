from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Union

Decision = Literal["allow", "deny", "confirm", "escalate"]
FallbackMode = Literal["fail_open", "fail_closed"]
SealWebhookStatus = Literal["received", "signing", "sealed", "rejected", "failed"]


@dataclass
class CustomExecutableCreateRequest:
    """One public HTTPS operation. Headers contain names, never credential values."""

    name: str
    url: str
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    request_content_type: Literal["application/json", "application/x-www-form-urlencoded"] | None = None
    required_headers: list[str] = field(default_factory=list)


@dataclass
class ExecutableEvidenceCapability:
    available: bool
    evidence_source: Literal["customer_reported", "independent_allowly_witness"]
    profile: str | None
    reason: str | None
    api_request_match_verification: str | None


@dataclass
class ExecutableCapabilities:
    customer_reported_receipt: ExecutableEvidenceCapability
    tls_witness: ExecutableEvidenceCapability


@dataclass
class ExecutableOperation:
    provider_id: str
    operation_id: str
    label: str
    method: str
    path: str
    effect: str
    request_content_type: str | None
    required_headers: list[str]
    status: str
    definition_fingerprint: str
    capabilities: ExecutableCapabilities
    allowly_live_tested: bool
    tls_witness_tested: bool


@dataclass
class EnabledExecutableResponse:
    enabled_executable_id: str
    provider_id: str
    provider_name: str
    category: str
    origin: str
    catalog_revision: str
    status: str
    credential_location: Literal["customer_runtime"]
    connection_status: Literal["not_verified"]
    allowly_live_tested: bool
    tls_witness_tested: bool
    operations: list[ExecutableOperation]
    operation_count: int
    enabled_at: str
    disabled_at: str | None


ExecutionStatus = Literal[
    "approved",
    "denied",
    "confirmation_required",
    "escalation_required",
    "succeeded",
    "failed",
    "unknown",
]


@dataclass
class ReceiptEnvelopePending:
    status: Literal["pending"]
    receipt_id: str
    ready_at_estimate: str | None
    url: str


@dataclass
class ReceiptEnvelopeSigned:
    status: Literal["signed"]
    receipt: dict[str, Any]


ReceiptEnvelope = Union[ReceiptEnvelopePending, ReceiptEnvelopeSigned]


@dataclass
class SealResponse:
    request_id: str
    workspace_id: str
    profile: str
    record_sha256: str
    decision: Literal["allow"]
    reason: str
    receipt: dict[str, Any]


@dataclass
class SealWebhookDelivery:
    attempt_id: str
    workspace_id: str
    status: SealWebhookStatus
    received_at: str
    updated_at: str
    profile: Literal["allowly.seal.jcs-sha256.v1"]
    record_sha256: str | None
    metadata: dict[str, str] | None
    receipt_id: str | None
    error_code: str | None
    status_url: str
    receipt_url: str | None
    keys_url: str
    receipt: dict[str, Any] | None


@dataclass
class BudgetInfo:
    limit_micros: int
    spent_micros: int
    estimated_cost_micros: int
    spent_after_micros: int | None = None


@dataclass
class BudgetSettlementResponse:
    check_receipt_id: str
    authorization_id: str
    estimated_cost_micros: int
    actual_cost_micros: int
    delta_micros: int
    spent_before_micros: int
    spent_after_micros: int
    receipt: ReceiptEnvelope


@dataclass
class ExecutionDownstream:
    source: Literal["customer_runtime"]
    http_status: int | None
    response_fingerprint: str | None
    response_fingerprint_scope: Literal["complete", "unavailable"]
    result: dict[str, Any]
    business_completion: Literal["not_verified"]


@dataclass
class OutcomeEvidence:
    profile: Literal["allowly.seal.jcs-sha256.v1"]
    record: dict[str, Any]
    record_sha256: str
    receipt: ReceiptEnvelope | None
    evidence_error: Literal["unavailable"] | None = None


@dataclass
class ExecutionRequestDescriptor:
    operation_id: str
    authorization_id: str
    destination_id: str
    action: str
    method: str
    origin: str
    path: str
    query: str
    headers: list[dict[str, str]]
    body_sha256: str
    body_size: int
    content_type: str | None


@dataclass
class ExecutionResponse:
    operation_id: str
    status: ExecutionStatus
    decision: Decision
    reason: str
    destination_id: str
    action: str
    request_fingerprint_profile: Literal["allowly.execution.request.v1"]
    request_fingerprint: str
    request_descriptor: ExecutionRequestDescriptor
    decision_receipt: ReceiptEnvelope
    downstream: ExecutionDownstream | None = None
    outcome_evidence: OutcomeEvidence | None = None
    confirm_nonce: str | None = None
    confirm_expires_at: str | None = None
    confirm_prompt_hint: str | None = None
    escalation_id: str | None = None
    escalation_expires_at: str | None = None
    escalation_to: str | None = None
    escalation: EscalationInfo | None = None
    effective_evidence_mode: Literal["receipt", "witnessed"] | None = None
    approval: dict[str, Any] | None = None
    approval_sha256: str | None = None
    approval_expires_at: str | None = None
    decision_state: Literal["allowed", "not_allowed"] | None = None
    target_state: Literal["not_started", "response_observed", "unknown"] | None = None
    evidence_state: str | None = None
    witness_session: dict[str, Any] | None = None


@dataclass
class ReceiptAcknowledgmentCaller:
    kind: Literal["workspace_runtime_key"]
    api_key_id: str
    agent_identity: dict[str, Any] | None = None


@dataclass
class ReceiptAcknowledgmentResponse:
    acknowledgment_id: str
    receipt_id: str
    receipt_sha256: str
    client_timestamp: str
    received_at: str
    caller: ReceiptAcknowledgmentCaller
    evidence: OutcomeEvidence


@dataclass
class EscalationInfo:
    escalation_id: str
    status: str
    escalation_to: str | None = None
    expires_at: str | None = None


@dataclass
class PolicyConditionEvidence:
    field: str
    op: str
    value: str | int | bool | None | list[str | int | bool | None]


@dataclass
class PolicyEvalInfo:
    matched_condition: PolicyConditionEvidence | None
    field_value: str | int | bool | None


@dataclass(kw_only=True)
class ActionCheckResultBase:
    decision: Decision
    reason: str
    receipt: ReceiptEnvelope | None
    is_fallback: bool = False
    fallback_mode: FallbackMode | None = None
    budget: BudgetInfo | None = None
    escalation: EscalationInfo | None = None
    policy_eval: PolicyEvalInfo | None = None


@dataclass
class ActionCheckResultAllow(ActionCheckResultBase):
    decision: Literal["allow"]


@dataclass
class ActionCheckResultDeny(ActionCheckResultBase):
    decision: Literal["deny"]
    superseded_by: str | None = None


@dataclass(kw_only=True)
class ActionCheckResultConfirm(ActionCheckResultBase):
    decision: Literal["confirm"]
    confirm_nonce: str
    confirm_expires_at: str
    confirm_prompt_hint: str


@dataclass(kw_only=True)
class ActionCheckResultEscalate(ActionCheckResultBase):
    decision: Literal["escalate"]
    escalation_id: str
    escalation_to: str | None = None
    escalation_expires_at: str | None = None


ActionCheckResult = Union[
    ActionCheckResultAllow,
    ActionCheckResultDeny,
    ActionCheckResultConfirm,
    ActionCheckResultEscalate,
]


@dataclass
class CheckResponse:
    authorization_id: str
    user_id: str | None
    agent_id: str | None
    authorization_expires_at: str | None
    engine_version: str
    results: dict[str, ActionCheckResult]
    #: X-Allowly-Billing-Warning response header, when the workspace is close
    #: to a quota/payment boundary. Surface it to operators.
    billing_warning: str | None = None


@dataclass
class ExecutableOperationGrant:
    enabled_executable_id: str
    provider_id: str
    operation_id: str
    catalog_revision: str
    definition_fingerprint: str
    minimum_evidence_mode: Literal["receipt", "witnessed"] = "receipt"


@dataclass
class ActionEntry:
    name: str
    constraints: dict[str, Any] = field(default_factory=dict)
    executable_operations: list[ExecutableOperationGrant] = field(default_factory=list)


@dataclass
class AuthorizationCreateResponse:
    authorization_id: str
    created_at: str
    expires_at: str
    receipt: ReceiptEnvelopePending
    requires_confirm_for: list[str]
    requires_escalation_for: list[str]
    requires_deny_for: list[str]
    escalation_targets: dict[str, str]
    policy_id: str | None = None
    budget_limit_micros: int | None = None
    budget_spent_micros: int | None = None
    replaced_authorization_id: str | None = None
    revocation_receipt: ReceiptEnvelopePending | None = None
    authorization_provenance: dict[str, Any] | None = None
    #: X-Allowly-Billing-Warning response header, when present.
    billing_warning: str | None = None


@dataclass
class AuthorizationRevokeResponse:
    authorization_id: str
    revoked_at: str
    receipt: ReceiptEnvelopePending
    revoked_confirmations: list[str] = field(default_factory=list)


@dataclass
class ConfirmationApproveResponse:
    decision: Literal["approved", "not_approved", "denied_by_user"]
    authorization_id: str | None = None
    expires_at: str | None = None
    receipt: ReceiptEnvelopePending | None = None


@dataclass
class EscalationResolveResponse:
    escalation_id: str
    status: Literal["approved", "rejected"]
    resolved_by: str | None = None
    resolved_at: str | None = None
    receipt: ReceiptEnvelopePending | None = None
