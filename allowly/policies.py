"""Strict retained policy JSON and setup transport. No policy interpreter."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, TYPE_CHECKING
from urllib.parse import quote

from allowly_receipt_format import VerificationError, canonicalize
from allowly_receipt_format.evidence import validate_policy_definition as _validate_definition

from .error import AllowlyProtocolError
from .types import (PolicyDefinition, PolicyReference, PolicyResponse, PolicyListResponse,
                    PolicyPreviewResponse, PolicyPublishResponse, PolicyEvalInfo, ProvisionalPolicyResult)

if TYPE_CHECKING:
    from .client import Allowly

MAX_SAFE_INTEGER = 2**53 - 1


def _document(value: Any, name: str, limit: int = 65_536) -> dict:
    if type(value) is not dict:
        raise AllowlyProtocolError(f"{name} must be an object")
    try:
        encoded = canonicalize(value)
        if len(encoded) > limit:
            raise ValueError("document exceeds its canonical byte limit")
        return json.loads(encoded)
    except (VerificationError, ValueError, TypeError, UnicodeError, RecursionError):
        raise AllowlyProtocolError(f"{name} must be bounded canonical JSON with safe integers") from None


def _keys(value: Any, required: set[str], name: str, optional: set[str] = frozenset()) -> dict:
    if type(value) is not dict or not required <= value.keys() or value.keys() - required - optional:
        raise AllowlyProtocolError(f"{name} has missing or unknown fields")
    return value


def _text(value: Any, name: str, maximum: int = 128) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise AllowlyProtocolError(f"{name} must be a nonempty bounded string")
    return value


def _integer(value: Any, name: str, minimum: int = 1, maximum: int = MAX_SAFE_INTEGER) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise AllowlyProtocolError(f"{name} must be a bounded safe integer")
    return value


def _strings(value: Any, name: str, maximum: int, length: int = 128) -> list[str]:
    if type(value) is not list or not 1 <= len(value) <= maximum:
        raise AllowlyProtocolError(f"{name} must be a nonempty bounded string array")
    for item in value:
        _text(item, name, length)
    if len(set(value)) != len(value):
        raise AllowlyProtocolError(f"{name} must contain unique strings")
    return value


def _target(decision: Any, target: Any) -> None:
    if type(decision) is not str or decision not in {"allow", "deny", "confirm", "escalate"}:
        raise AllowlyProtocolError("policy decision is unsupported")
    if decision in {"allow", "deny"}:
        if target is not None:
            raise AllowlyProtocolError("allow and deny require a null target")
    elif decision == "confirm":
        if target != "agent_owner":
            raise AllowlyProtocolError("confirm target must be agent_owner")
    elif (type(target) is not str or not target.startswith("member:")
          or not target[7:].strip() or len(target[7:]) > 128):
        raise AllowlyProtocolError("escalate target must be member:<account_user_id>")


def parse_policy_reference(value: Any) -> PolicyReference:
    raw = _keys(_document(value, "policy_ref"), {"policy_id", "policy_version", "definition_sha256"}, "policy_ref")
    _text(raw["policy_id"], "policy_ref.policy_id")
    _integer(raw["policy_version"], "policy_ref.policy_version")
    if type(raw["definition_sha256"]) is not str or len(raw["definition_sha256"]) != 64 or any(c not in "0123456789abcdef" for c in raw["definition_sha256"]):
        raise AllowlyProtocolError("policy_ref.definition_sha256 must be lowercase hex SHA-256")
    return raw


def validate_policy_definition(value: Any) -> PolicyDefinition:
    raw = _document(value, "definition")
    try:
        _validate_definition(raw)
    except (ValueError, TypeError, KeyError):
        raise AllowlyProtocolError("definition has invalid policy or evidence fields") from None
    return raw


def definition_digest(definition: PolicyDefinition) -> str:
    return hashlib.sha256(canonicalize(definition)).hexdigest()


def parse_policy_evaluation(value: Any) -> PolicyEvalInfo:
    raw = _keys(_document(value, "policy_eval", 32_768), {"input_sha256", "result"}, "policy_eval")
    digest = raw["input_sha256"]
    if type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise AllowlyProtocolError("policy_eval.input_sha256 must be lowercase hex SHA-256")
    result = _keys(raw["result"], {"profile", "status", "decision", "target", "matched_rule_id", "evaluated_fields"}, "policy_eval.result")
    if result["profile"] != "allowly.basic.v1" or result["status"] != "ok":
        raise AllowlyProtocolError("policy_eval result profile or status is unsupported")
    _target(result["decision"], result["target"])
    if result["matched_rule_id"] is not None:
        _text(result["matched_rule_id"], "matched_rule_id")
    if type(result["evaluated_fields"]) is not dict:
        raise AllowlyProtocolError("evaluated_fields must be an object")
    for key in result["evaluated_fields"]:
        _text(key, "evaluated field")
    if result["matched_rule_id"] is None and result["evaluated_fields"]:
        raise AllowlyProtocolError("action-level result must have empty evaluated_fields")
    return PolicyEvalInfo(input_sha256=digest, result=ProvisionalPolicyResult(**result))


def _parse_policy(value: Any) -> PolicyResponse:
    raw = _keys(value, {"policy_ref", "definition"}, "policy response", {"description", "created_by", "created_at", "deleted_at"})
    reference, definition = parse_policy_reference(raw["policy_ref"]), validate_policy_definition(raw["definition"])
    if reference["definition_sha256"] != definition_digest(definition):
        raise AllowlyProtocolError("policy_ref definition digest does not match retained definition")
    optional = {}
    for key in ("description", "created_by", "created_at", "deleted_at"):
        value = raw.get(key)
        if value is not None and type(value) is not str:
            raise AllowlyProtocolError(f"{key} must be a string or null")
        optional[key] = value
    return PolicyResponse(policy_ref=reference, definition=definition, **optional)


class _PoliciesResource:
    def __init__(self, client: Allowly) -> None:
        self._client = client

    async def create(self, *, policy_id: str, definition: PolicyDefinition, description: str | None = None,
                     previous_policy_ref: PolicyReference | None = None, idempotency_key: str | None = None) -> PolicyResponse:
        body = self._body(policy_id, definition, description, previous_policy_ref)
        raw = await self._client._request("POST", "/v1/policies", json=body,
            headers={"Idempotency-Key": idempotency_key} if idempotency_key is not None else None,
            expected_success_status=201)
        response = _parse_policy(raw)
        if response.policy_ref["policy_id"] != policy_id or response.definition != body_definition(body):
            raise AllowlyProtocolError("created policy does not match the submitted definition")
        return response

    async def get(self, policy_id: str) -> PolicyResponse:
        response = _parse_policy(await self._client._request("GET", f"/v1/policies/{quote(_text(policy_id, 'policy_id'), safe='')}"))
        if response.policy_ref["policy_id"] != policy_id:
            raise AllowlyProtocolError("policy response does not match the requested logical ID")
        return response

    async def list(self, *, limit: int = 100, cursor: str | None = None) -> PolicyListResponse:
        _integer(limit, "limit", maximum=100)
        raw = _keys(await self._client._request("GET", "/v1/policies", params={"limit": limit, **({"cursor": cursor} if cursor is not None else {})}),
                    {"items", "has_more"}, "policy list", {"next_cursor"})
        if type(raw["items"]) is not list or type(raw["has_more"]) is not bool or (raw.get("next_cursor") is not None and type(raw["next_cursor"]) is not str):
            raise AllowlyProtocolError("policy list has invalid pagination fields")
        return PolicyListResponse(items=[_parse_policy(item) for item in raw["items"]], has_more=raw["has_more"], next_cursor=raw.get("next_cursor"))

    async def archive(self, policy_id: str, *, idempotency_key: str | None = None) -> None:
        await self._client._request("DELETE", f"/v1/policies/{quote(_text(policy_id, 'policy_id'), safe='')}",
            headers={"Idempotency-Key": idempotency_key} if idempotency_key is not None else None, expected_success_status=204)

    async def preview(self, *, definition: PolicyDefinition, action: str, context: dict[str, Any]) -> PolicyPreviewResponse:
        definition = validate_policy_definition(definition)
        _text(action, "action", 64)
        selected = next((entry["policy"] for entry in definition["actions"] if entry["policy"]["action"] == action), None)
        if selected is None:
            raise ValueError("preview action must be declared in the complete definition")
        context = _document(context, "context", 4096)
        input_sha256 = hashlib.sha256(canonicalize({"policy": selected, "action": action, "context": context})).hexdigest()
        raw = _keys(await self._client._request("POST", "/v1/setup/policies/preview", json={"definition": definition, "action": action, "context": context}),
                    {"provisional", "definition_sha256", "action", "policy_eval"}, "preview response")
        if raw["provisional"] is not True or raw["action"] != action or raw["definition_sha256"] != definition_digest(definition):
            raise AllowlyProtocolError("preview response does not match the submitted provisional definition")
        evaluation = parse_policy_evaluation(raw["policy_eval"])
        if evaluation.input_sha256 != input_sha256:
            raise AllowlyProtocolError("preview input commitment does not match the submitted policy and context")
        return PolicyPreviewResponse(provisional=True, definition_sha256=raw["definition_sha256"], action=action, policy_eval=evaluation)

    async def publish(self, *, policy_id: str, definition: PolicyDefinition, idempotency_key: str,
                      description: str | None = None, previous_policy_ref: PolicyReference | None = None) -> PolicyPublishResponse:
        _text(idempotency_key, "idempotency_key")
        body = self._body(policy_id, definition, description, previous_policy_ref)
        raw = _keys(await self._client._request("POST", "/v1/setup/policies/publish", json=body,
            headers={"Idempotency-Key": idempotency_key}, expected_success_status=201),
            {"policy_ref", "agent_id", "created_by", "created_at", "authorization_migrations", "archived_policy_ids", "revoked_confirmation_count"}, "publish response")
        reference = parse_policy_reference(raw["policy_ref"])
        if reference["policy_id"] != policy_id or reference["definition_sha256"] != definition_digest(body_definition(body)) or raw["agent_id"] != body["agent_id"]:
            raise AllowlyProtocolError("published policy does not match the submitted definition")
        if type(raw["authorization_migrations"]) is not list or type(raw["archived_policy_ids"]) is not list:
            raise AllowlyProtocolError("publish summary lists are invalid")
        for migration in raw["authorization_migrations"]:
            _keys(migration, {"user_id", "previous_authorization_id", "authorization_id"}, "authorization migration")
            for key in migration:
                _text(migration[key], key)
        for value in raw["archived_policy_ids"]:
            _text(value, "archived_policy_id")
        _integer(raw["revoked_confirmation_count"], "revoked_confirmation_count", minimum=0)
        return PolicyPublishResponse(**{**raw, "policy_ref": reference, "created_by": _text(raw["created_by"], "created_by", 256), "created_at": _text(raw["created_at"], "created_at")})

    @staticmethod
    def _body(policy_id: str, definition: PolicyDefinition, description: str | None, previous_policy_ref: PolicyReference | None) -> dict:
        _text(policy_id, "policy_id")
        if not re.fullmatch(r"[a-z0-9_-]+", policy_id):
            raise ValueError("policy_id must use lowercase letters, digits, underscore or hyphen")
        if description is not None and (type(description) is not str or len(description) > 2048):
            raise ValueError("description must be a bounded string")
        return {**validate_policy_definition(definition), "policy_id": policy_id,
                **({"description": description} if description is not None else {}),
                **({"previous_policy_ref": parse_policy_reference(previous_policy_ref)} if previous_policy_ref is not None else {})}


def body_definition(body: dict) -> PolicyDefinition:
    return {key: body[key] for key in ("profile", "agent_id", "actions", "default_expiry_days")}
