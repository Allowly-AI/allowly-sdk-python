"""Delivery verification wakes a saved job; status/Continue still gate dispatch."""

import json

import httpx
import pytest
import respx

from allowly import Allowly, AllowlyAPIError, AllowlyProtocolError, verify_resolution_webhook
from test_execution import BASE, URL, PARAMS, OBSERVED
from test_execution_continuation import review_runtime
from test_resolution_webhook import NOW, SECRET, _headers


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["confirm", "escalate"])
@pytest.mark.parametrize("case", ["approved", "rejected", "wrong_source", "wrong_workspace", "pending", "api_rejected"])
async def test_verified_callback_only_wakes_original_saved_execution(tmp_path, monkeypatch, kind, case):
    sends = []
    monkeypatch.setattr("allowly.execution._provider_send", lambda *args: sends.append(args) or OBSERVED)

    def continue_response(request, seen):
        if case == "api_rejected":
            return httpx.Response(409, json={"error": {"code": "execution_review_not_available", "message": "Rejected"}})
        from test_execution import approval_response
        seen["approved"] = approval_response(json.loads(request.content)["execution_request"])
        return httpx.Response(201, json=seen["approved"])

    with respx.mock as mock:
        seen, continuation, _ = review_runtime(mock, kind, continuation=continue_response)
        async with Allowly("runtime-key", base_url=BASE) as client:
            pending = await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
            review = pending.execution.review
            event_type = "confirmation.resolved" if kind == "confirm" else "escalation.resolved"
            body = {"id": "evt_execution", "type": event_type,
                    "timestamp": "2023-11-14T22:13:00Z", "workspace_id": "ws_other" if case == "wrong_workspace" else "ws_1",
                    "data": {"prompt_id": review.id, "status": "rejected" if case == "rejected" else "approved",
                             "source_receipt_id": "rcp_other" if case == "wrong_source" else review.source_receipt_id,
                             "resolution_receipt_id": "rcp_resolution"}}
            raw = json.dumps(body).encode()
            status = {"authorization_id": PARAMS["authorization_id"], "action": PARAMS["action"], "resource": None,
                      "status": "pending" if case == "pending" else "approved", "expires_at": review.expires_at,
                      "resolved_at": None, "source_receipt_id": review.source_receipt_id,
                      "resolution_receipt_id": "rcp_resolution", "authority_status": "none" if case == "pending" else "available"}
            if kind == "confirm":
                status.update(confirmation_id=review.id, child_authorization_id="auth_child", authority_expires_at=review.expires_at)
                status_url = BASE + f"/v1/confirmations/{review.id}/status"
            else:
                status.update(escalation_id=review.id, consumed_at=None)
                status_url = BASE + f"/v1/escalations/{review.id}"
            status_route = mock.get(status_url).mock(return_value=httpx.Response(200, json=status))

            async def receive():
                # This is caller-owned job selection, not a new SDK permission path.
                event = verify_resolution_webhook(raw, _headers(raw, event_id=body["id"]),
                                                  signing_secret=SECRET, expected_workspace_id="ws_1", now=NOW)
                if event.type != event_type or event.data.prompt_id != review.id or event.data.source_receipt_id != review.source_receipt_id:
                    raise ValueError("Callback does not match the saved job")
                if event.data.status != "approved":
                    return None
                resource = client.confirmations if kind == "confirm" else client.escalations
                current = await resource.get_status(review.id)
                if current.status != "approved" or current.authority_status != "available":
                    return None
                if current.authorization_id != PARAMS["authorization_id"] or current.action != PARAMS["action"] or current.source_receipt_id != review.source_receipt_id:
                    raise ValueError("Status does not match the saved job")
                return await client.continue_http_execution(URL, **PARAMS, storage_dir=str(tmp_path))

            assert not sends and not seen["dispatch"]
            if case == "wrong_workspace":
                with pytest.raises(AllowlyProtocolError, match="workspace"):
                    await receive()
            elif case == "wrong_source":
                with pytest.raises(ValueError, match="saved job"):
                    await receive()
            elif case == "api_rejected":
                with pytest.raises(AllowlyAPIError) as denied:
                    await receive()
                assert denied.value.code == "execution_review_not_available"
            else:
                completed = await receive()
                assert (completed is not None) == (case == "approved")

    if case == "approved":
        assert completed.execution.operation_id == PARAMS["operation_id"]
        assert seen["continue"][0]["body"] == {"execution_request": seen["prepare"][0], "review_id": review.id,
                                                "source_receipt_id": review.source_receipt_id}
        assert len(sends) == len(seen["dispatch"]) == len(seen["outcome"]) == 1
    else:
        assert not sends and not seen["dispatch"] and not seen["outcome"]
        assert continuation.call_count == (1 if case == "api_rejected" else 0)
        assert status_route.call_count == (1 if case in {"pending", "api_rejected"} else 0)
