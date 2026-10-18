"""Report captured action strings; never grants permission or retries a send."""
from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from allowly_receipt_format.evidence import validate_mapping

from .error import AllowlyProtocolError
from .policies import _document, _keys, _text, parse_policy_reference
from .types import ObserveEventStatus, ObserveReportedExecution, PolicyReference

if TYPE_CHECKING:
    from .client import Allowly

_EVENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_STATUS_FIELDS = {
    "event_id", "agent_id", "action", "policy_ref", "mode", "intervention", "reported_execution",
    "processing_status", "assessment_status", "signing_status", "observed_action_id", "assessment_id",
    "dashboard_url", "last_error",
}
_EXECUTION = {"accepted", "sent", "failed", "unknown"}


def _event_id(value: Any) -> str:
    if type(value) is not str or _EVENT_ID.fullmatch(value) is None:
        raise AllowlyProtocolError("event_id must be 1 to 128 safe ASCII characters")
    return value


def _choice(value: Any, choices: set[str], name: str) -> str:
    if type(value) is not str or value not in choices:
        raise AllowlyProtocolError(f"{name} is unsupported")
    return value


def _status(value: Any, event_id: str, event: dict | None = None) -> ObserveEventStatus:
    raw = _keys(_document(value, "Observe status", 16 * 1024), _STATUS_FIELDS, "Observe status")
    _event_id(raw["event_id"])
    _text(raw["agent_id"], "agent_id")
    _text(raw["action"], "action", 64)
    raw["policy_ref"] = parse_policy_reference(raw["policy_ref"])
    _choice(raw["mode"], {"observe"}, "mode")
    _choice(raw["intervention"], {"none"}, "intervention")
    _choice(raw["reported_execution"], _EXECUTION, "reported_execution")
    _choice(raw["processing_status"], {"pending", "processing", "complete", "failed"}, "processing_status")
    _choice(raw["assessment_status"], {"not_assessed", "no_violation_found", "violation_detected", "insufficient_evidence"}, "assessment_status")
    _choice(raw["signing_status"], {"unavailable", "pending", "signed"}, "signing_status")
    for name, limit in (("observed_action_id", 128), ("assessment_id", 128), ("dashboard_url", 2048), ("last_error", 128)):
        if raw[name] is not None:
            _text(raw[name], name, limit)
    if raw["event_id"] != event_id or (event is not None and any(
        raw[name] != event[name] for name in ("agent_id", "action", "policy_ref", "reported_execution")
    )):
        raise AllowlyProtocolError("Observe response does not match the submitted event")
    return ObserveEventStatus(**raw)


class _ObserveResource:
    def __init__(self, client: Allowly):
        self._client = client

    async def submit(
        self, *, event_id: str, agent_id: str, action: str, policy_ref: PolicyReference,
        occurred_at: str, reported_execution: ObserveReportedExecution, sources: dict[str, str],
    ) -> ObserveEventStatus:
        event = _document({
            "event_id": _event_id(event_id), "agent_id": _text(agent_id, "agent_id"),
            "action": _text(action, "action", 64), "policy_ref": parse_policy_reference(policy_ref),
            "occurred_at": occurred_at, "reported_execution": _choice(reported_execution, _EXECUTION, "reported_execution"),
            "sources": sources,
        }, "Observe event", 40 * 1024)
        try:
            if type(occurred_at) is not str or "T" not in occurred_at:
                raise ValueError()
            occurred = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
            if occurred.tzinfo is None or occurred.utcoffset() is None:
                raise ValueError()
            if type(event["sources"]) is not dict or any(type(value) is not str or "\0" in value for value in event["sources"].values()):
                raise ValueError()
            validate_mapping({"observation_name": action, "sources": {
                name: "/input/sources/" + name.replace("~", "~0").replace("/", "~1") for name in event["sources"]
            }, "execution_pointer": "/output/reported_execution", "mapping_version": "allowly.observe.event.v1"})
        except (ValueError, TypeError, AttributeError):
            raise AllowlyProtocolError("Observe requires an aware timestamp and 1 to 32 bounded string sources") from None
        raw = await self._client._request("POST", "/v1/observe/events", json=event, expected_success_status=202)
        return _status(raw, event_id, event)

    async def get(self, event_id: str) -> ObserveEventStatus:
        raw = await self._client._request("GET", f"/v1/observe/events/{quote(_event_id(event_id), safe='')}", expected_success_status=200)
        return _status(raw, event_id)
