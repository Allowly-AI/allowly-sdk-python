import asyncio
import hashlib
import inspect
import json

import httpx
import pytest
import respx

from allowly import Allowly, AllowlyAPIError, AllowlyProtocolError, ExecutionRecoveryRequired
from allowly.execution import _read, _request, _save
from test_execution import BASE, URL, PARAMS, OBSERVED, approval_response, runtime


def waiting(response, kind="confirm"):
    prefix = "cnf_" if kind == "confirm" else "esc_"
    response.update(status="waiting_for_review", decision=kind, approval=None,
                    approval_sha256=None, decision_state="not_allowed",
                    review={"kind": kind, "id": prefix + "review1", "source_receipt_id": "rcp_1",
                            "expires_at": "2099-01-01T00:00:00Z"})
    response["confirmation_id" if kind == "confirm" else "escalation_id"] = prefix + "review1"
    if kind == "confirm":
        response["confirm_nonce"] = "private-review-bearer"


def review_runtime(mock, kind="confirm", *, continuation=None, dispatch=None):
    seen, outcome = runtime(mock, mutate=lambda response: waiting(response, kind))
    seen["continue"] = []

    async def proceed(request):
        intent = json.loads(request.content)
        seen["continue"].append({"body": intent, "key": request.headers["idempotency-key"]})
        if continuation is not None:
            response = continuation(request, seen)
            return await response if inspect.isawaitable(response) else response
        response = approval_response(intent["execution_request"])
        seen["approved"] = response
        return httpx.Response(200, json=response)

    route = mock.post(BASE + "/v1/executions/refund-123/continue").mock(side_effect=proceed)
    if dispatch is not None:
        mock.post(BASE + "/v1/executions/refund-123/dispatch").mock(side_effect=dispatch)
    return seen, route, outcome


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["confirm", "escalate"])
async def test_wait_restart_continue_same_request_claims_once(tmp_path, monkeypatch, kind):
    sends = []
    monkeypatch.setattr("allowly.execution._provider_send", lambda *args: sends.append(args) or OBSERVED)
    with respx.mock as mock:
        seen, _, _ = review_runtime(mock, kind)
        async with Allowly("runtime-secret", base_url=BASE) as client:
            pending = await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
            assert pending.execution.status == "waiting_for_review"
            assert pending.execution.review.kind == kind
            assert not sends and not seen["dispatch"]
            waiting_state = _read(tmp_path / hashlib.sha256(b"refund-123").hexdigest() / "journal.json")
            assert waiting_state["authorization"]["confirm_nonce"] is None
            assert "private-review-bearer" not in json.dumps(waiting_state)
        async with Allowly("runtime-secret", base_url=BASE) as restarted:
            complete = await restarted.continue_http_execution(URL, **PARAMS, storage_dir=str(tmp_path))
            with pytest.raises(ExecutionRecoveryRequired):
                await restarted.continue_http_execution(URL, **PARAMS, storage_dir=str(tmp_path))
    assert complete.execution.status == "succeeded"
    assert len(sends) == len(seen["dispatch"]) == len(seen["outcome"]) == 1
    assert seen["continue"][0]["body"]["execution_request"] == seen["prepare"][0]
    assert seen["continue"][0]["body"]["source_receipt_id"] == "rcp_1"
    journal = _read(tmp_path / hashlib.sha256(b"refund-123").hexdigest() / "journal.json")
    assert journal["phase"] == "complete"
    for secret in ("runtime-secret", "private-token", PARAMS["body"]):
        assert secret not in json.dumps(journal)
        assert secret not in json.dumps(seen)


@pytest.mark.asyncio
async def test_pending_continuation_can_retry_after_approval(tmp_path, monkeypatch):
    sends = []
    monkeypatch.setattr("allowly.execution._provider_send", lambda *args: sends.append(1) or OBSERVED)
    def still_waiting(request, seen):
        return httpx.Response(200, json=seen["approved"])
    with respx.mock as mock:
        seen, route, _ = review_runtime(mock, continuation=still_waiting)
        async with Allowly("key", base_url=BASE) as client:
            await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
            waiting_result = await client.continue_http_execution(URL, **PARAMS, storage_dir=str(tmp_path))
            assert waiting_result.execution.status == "waiting_for_review" and not sends
            def approved(request):
                body = json.loads(request.content)
                seen["continue"].append({"body": body, "key": request.headers["idempotency-key"]})
                seen["approved"] = approval_response(body["execution_request"])
                return httpx.Response(200, json=seen["approved"])
            route.mock(side_effect=approved)
            await client.continue_http_execution(URL, **PARAMS, storage_dir=str(tmp_path))
    assert len(sends) == 1
    assert seen["continue"][0] == seen["continue"][1]


@pytest.mark.asyncio
async def test_new_review_epoch_updates_binding_and_continuation_key(tmp_path, monkeypatch):
    sends = []
    monkeypatch.setattr("allowly.execution._provider_send", lambda *args: sends.append(1) or OBSERVED)
    def next_epoch(request, seen):
        if len(seen["continue"]) == 1:
            response = json.loads(json.dumps(seen["approved"]))
            response["review"].update(id="cnf_next", source_receipt_id="rcp_next")
            response["confirmation_id"] = "cnf_next"
            response["decision_receipt"].update(receipt_id="rcp_next", url=BASE + "/v1/receipts/rcp_next")
            return httpx.Response(200, json=response)
        seen["approved"] = approval_response(json.loads(request.content)["execution_request"])
        return httpx.Response(200, json=seen["approved"])
    with respx.mock as mock:
        seen, _, _ = review_runtime(mock, continuation=next_epoch)
        async with Allowly("key", base_url=BASE) as client:
            await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
            pending = await client.continue_http_execution(URL, **PARAMS, storage_dir=str(tmp_path))
            assert pending.execution.review.id == "cnf_next" and not sends
            await client.continue_http_execution(URL, **PARAMS, storage_dir=str(tmp_path))
    assert len(sends) == len(seen["dispatch"]) == 1
    assert seen["continue"][0]["key"] != seen["continue"][1]["key"]
    assert seen["continue"][1]["body"]["review_id"] == "cnf_next"
    assert seen["continue"][1]["body"]["source_receipt_id"] == "rcp_next"


@pytest.mark.asyncio
async def test_lost_continue_response_reuses_saved_intent(tmp_path, monkeypatch):
    sends = []
    monkeypatch.setattr("allowly.execution._provider_send", lambda *args: sends.append(1) or OBSERVED)
    def lost(request, seen):
        seen["approved"] = approval_response(json.loads(request.content)["execution_request"])
        raise httpx.ReadError("response lost")
    with respx.mock as mock:
        seen, route, _ = review_runtime(mock, continuation=lost)
        async with Allowly("key", base_url=BASE) as client:
            await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
            with pytest.raises(httpx.ReadError):
                await client.continue_http_execution(URL, **PARAMS, storage_dir=str(tmp_path))
            assert not sends
        route.mock(return_value=httpx.Response(200, json=seen["approved"]))
        async with Allowly("key", base_url=BASE) as restarted:
            await restarted.continue_http_execution(URL, **PARAMS, storage_dir=str(tmp_path))
    assert len(sends) == len(seen["dispatch"]) == 1
    assert route.calls[0].request.content == route.calls[1].request.content
    assert route.calls[0].request.headers["idempotency-key"] == route.calls[1].request.headers["idempotency-key"]


@pytest.mark.asyncio
@pytest.mark.parametrize("changed", ["body", "headers", "policy_input", "authorization_id", "evidence_mode", "url", "timestamp"])
async def test_changed_request_fails_before_api_and_provider(tmp_path, monkeypatch, changed):
    monkeypatch.setattr("allowly.execution._provider_send", lambda *args: pytest.fail("provider called"))
    with respx.mock as mock:
        seen, route, _ = review_runtime(mock)
        async with Allowly("key", base_url=BASE) as client:
            result = await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
            args, url = dict(PARAMS), URL
            if changed == "body": args[changed] = '{"amount":26}'
            elif changed == "headers": args[changed] = {**PARAMS["headers"], "Authorization": "different"}
            elif changed == "policy_input": args[changed] = {"context": {"amount": 26}}
            elif changed == "authorization_id": args[changed] = "auth_other"
            elif changed == "evidence_mode": args[changed] = "witnessed"
            elif changed == "url": url = URL + "?other=1"
            else:
                path = tmp_path / hashlib.sha256(b"refund-123").hexdigest() / "journal.json"
                state = _read(path)
                state["client_timestamp"] = "2026-01-01T00:00:00Z"
                _save(path, state)
            with pytest.raises(AllowlyProtocolError, match="differs"):
                await client.continue_http_execution(url, **args, storage_dir=str(tmp_path))
    assert not route.called and not seen["dispatch"]


@pytest.mark.asyncio
@pytest.mark.parametrize("cause", ["rejected", "expired", "revoked"])
async def test_review_unavailable_never_claims_or_sends(tmp_path, monkeypatch, cause):
    monkeypatch.setattr("allowly.execution._provider_send", lambda *args: pytest.fail("provider called"))
    def unavailable(request, seen):
        return httpx.Response(409, json={"error": {"code": "execution_review_not_available", "message": cause}})
    with respx.mock as mock:
        seen, _, _ = review_runtime(mock, continuation=unavailable)
        async with Allowly("key", base_url=BASE) as client:
            await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
            with pytest.raises(AllowlyAPIError) as error:
                await client.continue_http_execution(URL, **PARAMS, storage_dir=str(tmp_path))
            assert error.value.code == "execution_review_not_available"
    assert not seen["dispatch"] and not seen["outcome"]


@pytest.mark.asyncio
async def test_ambiguous_dispatch_can_only_report_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr("allowly.execution._provider_send", lambda *args: pytest.fail("provider called"))
    def claim_lost(request):
        raise httpx.ReadError("claim response lost")
    with respx.mock as mock:
        seen, _, _ = review_runtime(mock, dispatch=claim_lost)
        async with Allowly("key", base_url=BASE) as client:
            await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
            with pytest.raises(httpx.ReadError):
                await client.continue_http_execution(URL, **PARAMS, storage_dir=str(tmp_path))
            with pytest.raises(ExecutionRecoveryRequired):
                await client.continue_http_execution(URL, **PARAMS, storage_dir=str(tmp_path))
            folder = tmp_path / hashlib.sha256(b"refund-123").hexdigest()
            result = await client.flush_execution_outcome(str(folder))
            assert result.status == "unknown"
    assert len(seen["continue"]) == 1


@pytest.mark.asyncio
async def test_local_lock_rejects_concurrent_continuation(tmp_path, monkeypatch):
    monkeypatch.setattr("allowly.execution._provider_send", lambda *args: OBSERVED)
    admitted, release = asyncio.Event(), asyncio.Event()
    async def proceed(request, seen):
        admitted.set()
        await release.wait()
        seen["approved"] = approval_response(json.loads(request.content)["execution_request"])
        return httpx.Response(200, json=seen["approved"])
    with respx.mock as mock:
        seen, _, _ = review_runtime(mock, continuation=proceed)
        async with Allowly("key", base_url=BASE) as client:
            await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
            first = asyncio.create_task(client.continue_http_execution(URL, **PARAMS, storage_dir=str(tmp_path)))
            await admitted.wait()
            try:
                with pytest.raises(ExecutionRecoveryRequired):
                    await client.continue_http_execution(URL, **PARAMS, storage_dir=str(tmp_path))
            finally:
                release.set()
            await first
    assert len(seen["continue"]) == len(seen["dispatch"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("phase,version", [("prepared", 2), ("authorized", 1), ("waiting_for_review", 1), ("unknown", 2)])
async def test_ineligible_or_legacy_journal_is_not_reopened(tmp_path, monkeypatch, phase, version):
    monkeypatch.setattr("allowly.execution._provider_send", lambda *args: pytest.fail("provider called"))
    with respx.mock as mock:
        seen, route, _ = review_runtime(mock)
        async with Allowly("key", base_url=BASE) as client:
            result = await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
            path = tmp_path / hashlib.sha256(b"refund-123").hexdigest() / "journal.json"
            state = _read(path)
            state.update(phase=phase, version=version)
            _save(path, state)
            with pytest.raises(ExecutionRecoveryRequired):
                await client.continue_http_execution(URL, **PARAMS, storage_dir=str(tmp_path))
    assert not route.called and not seen["dispatch"]


@pytest.mark.asyncio
async def test_low_level_continue_sends_original_request_and_identity_only():
    descriptor, _ = _request(URL, PARAMS["method"], PARAMS["headers"], PARAMS["body"])
    request = {key: PARAMS[key] for key in ("operation_id", "authorization_id", "enabled_executable_id", "catalog_operation_id", "action")}
    request.update(http_request=descriptor, policy_input={}, evidence_mode="receipt",
                   client_timestamp="2026-10-09T00:00:00Z")
    response = approval_response(request)
    waiting(response)
    with respx.mock as mock:
        route = mock.post(BASE + "/v1/executions/refund-123/continue").mock(return_value=httpx.Response(200, json=response))
        async with Allowly("runtime-secret", base_url=BASE) as client:
            result = await client.continue_execution("refund-123", execution_request=request,
                                                       review_id="cnf_review1", source_receipt_id="rcp_1",
                                                       idempotency_key="continue-key", agent_token="agent-secret")
    sent = route.calls[0].request
    assert json.loads(sent.content) == {"execution_request": request, "review_id": "cnf_review1", "source_receipt_id": "rcp_1"}
    assert sent.headers["idempotency-key"] == "continue-key"
    assert sent.headers["x-allowly-agent-token"] == "agent-secret"
    assert result.confirmation_id == result.review.id == "cnf_review1"
    assert "private-token" not in sent.content.decode()


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", ["missing", "source", "kind", "id", "allow", "approval", "hash", "target", "decision_state", "evidence"])
async def test_invalid_waiting_response_never_creates_dispatch(tmp_path, monkeypatch, invalid):
    monkeypatch.setattr("allowly.execution._provider_send", lambda *args: pytest.fail("provider called"))
    with respx.mock as mock:
        def malformed(response):
            waiting(response)
            if invalid == "missing": response.pop("review")
            elif invalid == "source": response["review"]["source_receipt_id"] = "rcp_other"
            elif invalid == "kind": response["review"]["kind"] = "allow"
            elif invalid == "id": response["review"]["id"] = "nonce-not-review-id"
            elif invalid == "allow": response["decision"] = "allow"
            elif invalid == "approval": response["approval"] = {"unexpected": True}
            elif invalid == "hash": response["approval_sha256"] = "sha256:" + "0" * 64
            elif invalid == "target": response["target_state"] = "unknown"
            elif invalid == "decision_state": response["decision_state"] = "allowed"
            else: response["evidence_state"] = "customer_reported"
        seen, _ = runtime(mock, mutate=malformed)
        async with Allowly("key", base_url=BASE) as client:
            with pytest.raises(AllowlyProtocolError):
                await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
    assert not seen["dispatch"]
