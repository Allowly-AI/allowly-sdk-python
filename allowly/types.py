from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Union


Decision = Literal["allow", "deny", "confirm", "escalate"]
FallbackMode = Literal["fail_open", "fail_closed"]


@dataclass
class ReceiptEnvelopePending:
    status: Literal["pending"]
    receipt_id: str | None
    ready_at_estimate: str | None
    url: str | None


@dataclass
class ReceiptEnvelopeSigned:
    status: Literal["signed"]
    receipt: dict[str, Any]


ReceiptEnvelope = Union[ReceiptEnvelopePending, ReceiptEnvelopeSigned]


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


@dataclass
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


@dataclass
class ActionCheckResultConfirm(ActionCheckResultBase):
    decision: Literal["confirm"]
    confirm_nonce: str = ""
    confirm_expires_at: str = ""
    confirm_prompt_hint: str = ""


@dataclass
class ActionCheckResultEscalate(ActionCheckResultBase):
    decision: Literal["escalate"]
    escalation_id: str = ""
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
class ActionEntry:
    name: str
    constraints: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthorizationCreateResponse:
    authorization_id: str
    created_at: str
    expires_at: str
    receipt: ReceiptEnvelopePending
    policy_id: str | None = None
    requires_confirm_for: list[str] = field(default_factory=list)
    requires_escalation_for: list[str] = field(default_factory=list)
    requires_deny_for: list[str] = field(default_factory=list)
    escalation_targets: dict[str, str] = field(default_factory=dict)
    budget_limit_micros: int | None = None
    budget_spent_micros: int | None = None
    replaced_authorization_id: str | None = None
    revocation_receipt: ReceiptEnvelopePending | None = None
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
    decision: Literal["approved", "denied_by_user"]
    authorization_id: str | None = None
    expires_at: str | None = None


@dataclass
class EscalationResolveResponse:
    escalation_id: str
    status: Literal["approved", "rejected"]
    resolved_by: str | None = None
    resolved_at: str | None = None
    receipt: ReceiptEnvelopePending | None = None
