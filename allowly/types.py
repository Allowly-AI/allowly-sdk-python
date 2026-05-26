from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Union


Decision = Literal["allow", "deny", "confirm"]


@dataclass
class CheckRequest:
    authorization_id: str
    scopes: list[str]
    resource: str | None = None
    session_id: str | None = None
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReceiptEnvelopePending:
    status: Literal["pending"]
    receipt_id: str
    ready_at_estimate: str
    url: str


@dataclass
class ReceiptEnvelopeSigned:
    status: Literal["signed"]
    receipt: dict[str, Any]


ReceiptEnvelope = Union[ReceiptEnvelopePending, ReceiptEnvelopeSigned]


@dataclass
class ScopeCheckResultBase:
    decision: Decision
    reason: str
    receipt: ReceiptEnvelope


@dataclass
class ScopeCheckResultAllow(ScopeCheckResultBase):
    decision: Literal["allow"]


@dataclass
class ScopeCheckResultDeny(ScopeCheckResultBase):
    decision: Literal["deny"]


@dataclass
class ScopeCheckResultConfirm(ScopeCheckResultBase):
    decision: Literal["confirm"]
    confirm_nonce: str = ""
    confirm_expires_at: str = ""
    confirm_prompt_hint: str = ""


ScopeCheckResult = Union[ScopeCheckResultAllow, ScopeCheckResultDeny, ScopeCheckResultConfirm]


@dataclass
class CheckResponse:
    authorization_id: str
    user_id: str | None
    agent_id: str | None
    authorization_expires_at: str | None
    policy_version: str
    results: dict[str, ScopeCheckResult]


@dataclass
class ScopeEntry:
    name: str
    constraints: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthorizationCreateRequest:
    user_id: str
    agent_id: str | None = None
    scopes: list[ScopeEntry] | None = None
    expires_at: datetime | str | None = None
    bundle_id: str | None = None
    requires_confirm_for: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthorizationCreateResponse:
    authorization_id: str
    created_at: str
    expires_at: str
    receipt: ReceiptEnvelopePending
    bundle_id: str | None = None


@dataclass
class AuthorizationRevokeResponse:
    authorization_id: str
    revoked_at: str
    receipt: ReceiptEnvelopePending


@dataclass
class ConfirmationApproveRequest:
    approved: bool
    ttl_seconds: int = 60


@dataclass
class ConfirmationApproveResponse:
    decision: Literal["approved", "denied_by_user"]
    authorization_id: str | None = None
    expires_at: str | None = None
