from __future__ import annotations

from importlib import import_module

from .client import Allowly
from .error import AllowlyAPIError, FieldError
from .types import (
    CheckResponse,
    ConfirmationApproveResponse,
    AuthorizationCreateResponse,
    AuthorizationRevokeResponse,
    BudgetInfo,
    Decision,
    EscalationInfo,
    EscalationResolveResponse,
    FallbackMode,
    ReceiptEnvelope,
    ReceiptEnvelopePending,
    ReceiptEnvelopeSigned,
    ScopeEntry,
)

__all__ = [
    "Allowly",
    "AllowlyMCPMiddleware",
    "AllowlyAPIError",
    "FieldError",
    "VerificationError",
    "identifiers",
    "PublicKey",
    "fetch_keys_doc",
    "clear_keys_doc_cache",
    "load_keys_from_json",
    "verify_receipt",
    "CheckResponse",
    "BudgetInfo",
    "EscalationInfo",
    "EscalationResolveResponse",
    "AuthorizationCreateResponse",
    "AuthorizationRevokeResponse",
    "ConfirmationApproveResponse",
    "ReceiptEnvelope",
    "ReceiptEnvelopePending",
    "ReceiptEnvelopeSigned",
    "ScopeEntry",
    "Decision",
    "FallbackMode",
]


def __getattr__(name: str):
    if name == "identifiers":
        return import_module(".identifiers", __name__)

    if name == "AllowlyMCPMiddleware":
        from .mcp import AllowlyMCPMiddleware

        return AllowlyMCPMiddleware

    if name in {
        "VerificationError",
        "PublicKey",
        "fetch_keys_doc",
        "clear_keys_doc_cache",
        "load_keys_from_json",
        "verify_receipt",
    }:
        from . import verify as verify_module

        return getattr(verify_module, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
