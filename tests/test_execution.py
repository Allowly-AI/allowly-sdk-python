import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from allowly import Allowly, AllowlyProtocolError, ExecutionRecoveryRequired, complete_execution_evidence
from allowly.execution import _notary_fingerprint, _provider_send, _request, _save, _witness_files
from allowly.verify import hash_seal_value

BASE = "https://api.example.com"
URL = "https://billing.example.com/v1/refunds"
PARAMS = dict(operation_id="refund-123", authorization_id="auth_1", enabled_executable_id="exe_1",
              catalog_operation_id="billing.refunds.create", action="billing.refund",
              method="POST", headers={"Authorization": "Bearer private-token", "Content-Type": "application/json"},
              body='{"amount":25}')
OBSERVED = {"status": 201, "headers": {}, "body": '{"id":"refund-123"}', "body_bytes": 19,
            "body_sha256": "sha256:" + hashlib.sha256(b'{"id":"refund-123"}').hexdigest()}


def approval_response(payload, evidence_mode=None):
    now = datetime.now(timezone.utc)
    descriptor = {"profile": "allowly.execution.approval.v1", "workspace_id": "ws_1",
                  "operation_id": payload["operation_id"], "authorization_id": payload["authorization_id"],
                  "agent_id": "agent_1", "action": payload["action"],
                  "executable": {"enabled_executable_id": payload["enabled_executable_id"], "catalog_operation_id": payload["catalog_operation_id"]},
                  "request": {**payload["http_request"], "provider_idempotency": {"kind": "none"}},
                  "policy_input_sha256": "sha256:" + hash_seal_value(payload["policy_input"]),
                  "evidence_mode": evidence_mode or payload["evidence_mode"],
                  "issued_at": (now - timedelta(seconds=1)).isoformat(), "expires_at": (now + timedelta(minutes=5)).isoformat()}
    return {"operation_id": payload["operation_id"], "destination_id": payload["enabled_executable_id"],
            "action": payload["action"], "status": "approved", "decision": "allow", "reason": "allowed",
            "request_fingerprint_profile": "allowly.execution.request.v1", "request_fingerprint": "sha256:" + "1" * 64,
            "request_descriptor": {"operation_id": payload["operation_id"], "authorization_id": payload["authorization_id"],
                                   "destination_id": payload["enabled_executable_id"], "action": payload["action"],
                                   **{k: payload["http_request"][k] for k in (
                                       "method", "origin", "path", "query", "headers",
                                       "body_sha256", "body_size", "content_type",
                                   )}},
            "decision_receipt": {"status": "pending", "receipt_id": "rcp_1", "ready_at_estimate": None, "url": BASE + "/v1/receipts/rcp_1"},
            "effective_evidence_mode": descriptor["evidence_mode"],
            "approval": descriptor, "approval_sha256": "sha256:" + hash_seal_value(descriptor),
            "approval_expires_at": descriptor["expires_at"], "decision_state": "allowed", "target_state": "not_started", "evidence_state": "pending"}


def runtime(mock, *, mutate=None, outcome_fail=False):
    seen = {"prepare": [], "dispatch": [], "outcome": []}
    def prepare(request):
        body = json.loads(request.content)
        seen["prepare"].append(body)
        response = approval_response(body)
        if mutate:
            mutate(response)
        seen["approved"] = response
        return httpx.Response(201, json=response)
    def dispatch(request):
        seen["dispatch"].append(json.loads(request.content))
        approved = seen["approved"]
        return httpx.Response(200, json={"operation_id": PARAMS["operation_id"], "dispatch_state": "claimed",
                                        "approval_sha256": approved["approval_sha256"], "approval": approved["approval"],
                                        "effective_evidence_mode": approved["effective_evidence_mode"], "approval_expires_at": approved["approval_expires_at"]})
    def outcome(request):
        report = json.loads(request.content)
        seen["outcome"].append(report)
        if outcome_fail:
            return httpx.Response(503, json={"error": {"code": "offline", "message": "offline"}})
        return httpx.Response(200, json={**seen["approved"], "status": "succeeded" if report["target_state"] == "response_observed" else "unknown",
                                        "target_state": report["target_state"], "evidence_state": "customer_reported"})
    mock.post(BASE + "/v1/execute").mock(side_effect=prepare)
    mock.post(BASE + "/v1/executions/refund-123/dispatch").mock(side_effect=dispatch)
    route = mock.post(BASE + "/v1/executions/refund-123/outcome").mock(side_effect=outcome)
    return seen, route


@pytest.mark.asyncio
async def test_receipt_flow_keeps_credentials_local_and_dedupes(tmp_path, monkeypatch):
    sends = []
    monkeypatch.setattr("allowly.execution._provider_send", lambda *args: sends.append(args) or OBSERVED)
    with respx.mock as mock:
        seen, _ = runtime(mock)
        async with Allowly("runtime-secret", base_url=BASE, agent_token="identity-secret") as client:
            result = await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
            with pytest.raises(ExecutionRecoveryRequired):
                await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
    assert len(sends) == len(seen["dispatch"]) == len(seen["outcome"]) == 1
    assert sends[0][1]["authorization"] == "Bearer private-token"
    assert result.execution.status == "succeeded" and result.decision_receipt_verified is False
    assert seen["outcome"][0]["response_sha256"] == OBSERVED["body_sha256"]
    journal = (tmp_path / hashlib.sha256(b"refund-123").hexdigest() / "journal.json")
    for secret in ("private-token", "runtime-secret", "identity-secret", PARAMS["body"]):
        assert secret not in journal.read_text()
        assert secret not in json.dumps(seen)
    assert journal.stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
@pytest.mark.parametrize("decision,status", [("deny", "denied"), ("confirm", "confirmation_required"), ("escalate", "escalation_required")])
async def test_nonallow_never_claims_or_sends(tmp_path, monkeypatch, decision, status):
    monkeypatch.setattr("allowly.execution._provider_send", lambda *a: pytest.fail("provider called"))
    with respx.mock as mock:
        seen, _ = runtime(mock, mutate=lambda r: r.update(decision=decision, status=status))
        async with Allowly("key", base_url=BASE) as client:
            result = await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
    assert result.execution.decision == decision
    assert not seen["dispatch"] and not seen["outcome"]


@pytest.mark.asyncio
async def test_outcome_upload_retry_never_repeats_provider(tmp_path, monkeypatch):
    sends = []
    monkeypatch.setattr("allowly.execution._provider_send", lambda *a: sends.append(1) or OBSERVED)
    with respx.mock as mock:
        seen, route = runtime(mock, outcome_fail=True)
        async with Allowly("key", base_url=BASE) as client:
            result = await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
            assert result.outcome_pending and result.response == OBSERVED
            route.mock(return_value=httpx.Response(200, json={**seen["approved"], "status": "succeeded"}))
            await client.flush_execution_outcome(result.operation_dir)
    assert len(sends) == 1 and len(seen["dispatch"]) == 1


@pytest.mark.asyncio
async def test_uncertain_send_is_unknown_and_not_retried(tmp_path, monkeypatch):
    def uncertain(*args):
        raise TimeoutError("response lost")
    monkeypatch.setattr("allowly.execution._provider_send", uncertain)
    with respx.mock as mock:
        seen, _ = runtime(mock)
        async with Allowly("key", base_url=BASE) as client:
            result = await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
    assert result.execution.status == "unknown"
    assert seen["outcome"][0]["target_state"] == "unknown"
    assert "http_status" not in seen["outcome"][0]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["hash", "body", "expiry", "downgrade"])
async def test_invalid_approval_never_dispatches(tmp_path, monkeypatch, kind):
    monkeypatch.setattr("allowly.execution._provider_send", lambda *a: pytest.fail("provider called"))
    def mutate(r):
        if kind == "hash":
            r["approval_sha256"] = "sha256:" + "0" * 64
        elif kind == "body":
            r["approval"]["request"]["body_sha256"] = "sha256:" + "0" * 64
        elif kind == "expiry":
            r["approval"]["expires_at"] = "2000-01-01T00:00:00Z"
        else:
            r["effective_evidence_mode"] = "receipt"
            r["approval"]["evidence_mode"] = "receipt"
        if kind != "hash":
            r["approval_sha256"] = "sha256:" + hash_seal_value(r["approval"])
    with respx.mock as mock:
        seen, _ = runtime(mock, mutate=mutate)
        async with Allowly("key", base_url=BASE) as client:
            with pytest.raises(AllowlyProtocolError):
                await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path), evidence_mode="witnessed" if kind == "downgrade" else "receipt")
    assert not seen["dispatch"]


@pytest.mark.parametrize("url", ["http://billing.example.com/v1/refunds", "https://127.0.0.1/a", "https://u:p@billing.example.com/a", "https://billing.example.com/%252e%252e/refunds", "https://billing.example.com/%0d%0a"])
def test_unsafe_urls_rejected(url):
    with pytest.raises(ValueError):
        _request(url, "GET", {}, "")


@pytest.mark.asyncio
@pytest.mark.parametrize("response_case", ["valid", "corrupt_hash", "proof_mismatch", "artifact_mismatch", "attestation_mismatch", "stdout_mismatch"])
@pytest.mark.parametrize("configured", [False, True])
async def test_witness_gate_claims_before_release_and_preserves_evidence(tmp_path, monkeypatch, response_case, configured):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    trust = tmp_path / "notary.json"
    trust.write_text(json.dumps({"alg": 2, "data": list(key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint))}))
    binary = tmp_path / "fake-native"
    binary.write_text(f"#!{sys.executable}\nresponse_case={response_case!r}\n" + '''import hashlib, json, pathlib, sys, time
data=json.load(sys.stdin)
assert 'private-token' in data['request']['headers']['authorization']
out=pathlib.Path(sys.argv[sys.argv.index('--output')+1]); out.mkdir(mode=0o700)
(out/'args.json').write_text(json.dumps(sys.argv[1:]))
(out/'witness.ready.json').write_text(json.dumps({'approval_sha256':data['approval_sha256']}))
deadline=time.monotonic()+5
while not (out/'dispatch.approved.json').exists():
    if time.monotonic()>deadline: sys.exit(2)
    time.sleep(.01)
assert json.loads((out/'dispatch.approved.json').read_text()) == {'approval_sha256':data['approval_sha256']}
response={'status':201,'body':'{}','headers':{},'body_bytes':2,'body_sha256':'a'*64 if response_case == 'corrupt_hash' else hashlib.sha256(b'{}').hexdigest()}
(out/'response.json').write_text(json.dumps(response))
verified_response={**response,'body':'no','body_sha256':hashlib.sha256(b'no').hexdigest()} if response_case == 'proof_mismatch' else response
(out/'presentation.json').write_text('{}')
(out/'attestation.json').write_text('{}')
verified={'verified':True,'approval_sha256':data['approval_sha256'],'request_binding_verification':'verified_from_full_presentation','response':verified_response,'artifact_sha256':'sha256:' + hashlib.sha256(b'other' if response_case == 'artifact_mismatch' else b'{}').hexdigest(),'attestation_sha256':'sha256:' + hashlib.sha256(b'other' if response_case == 'attestation_mismatch' else b'{}').hexdigest()}
(out/'verified.json').write_text(json.dumps(verified))
if response_case == 'stdout_mismatch':
    verified={**verified,'response':{**response,'body':'no','body_sha256':hashlib.sha256(b'no').hexdigest()}}
print(json.dumps(verified))
''')
    binary.chmod(0o700)
    if configured:
        config = tmp_path / "witness" / "ws_1" / "config.json"
        config.parent.mkdir(parents=True)
        ca = config.parent / "witness-ca.pem"
        ca_bytes = b"-----BEGIN CERTIFICATE-----\nlocal-test-ca\n-----END CERTIFICATE-----\n"
        ca.write_bytes(ca_bytes)
        config.write_text(json.dumps({"version": 1, "workspaceId": "ws_1",
                                      "nativeBinaryPath": str(binary), "trustedNotaryKeyPath": str(trust),
                                      "fingerprintSha256": _notary_fingerprint(trust),
                                      "trustedWitnessCaPath": str(ca),
                                      "witnessCaFingerprintSha256": hashlib.sha256(ca_bytes).hexdigest()}))
        monkeypatch.setenv("ALLOWLY_CONFIG_DIR", str(tmp_path))
    def mutate(r):
        r["witness_session"] = {"session_id": "wit_1", "witness_url": "wss://witness.example.com/sessions/wit_1",
                                "native_profile": "customer_held_tlsn_bundle_v1", "trusted_notary_key_fingerprint_sha256": _notary_fingerprint(trust)}
    with respx.mock as mock:
        seen, _ = runtime(mock, mutate=mutate)
        mock.post(BASE + "/v1/executions/refund-123/witness-session-token").mock(side_effect=lambda request: httpx.Response(200, json={
            **seen["approved"]["witness_session"], "workspace_id": "ws_1", "approval_sha256": seen["approved"]["approval_sha256"], "admission_token": "a" * 43}))
        async with Allowly("key", base_url=BASE) as client:
            result = await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path / "journal"), evidence_mode="witnessed",
                                               native_binary=None if configured else str(binary),
                                               trusted_notary_key=None if configured else str(trust))
            if response_case == "proof_mismatch":
                with pytest.raises(ExecutionRecoveryRequired):
                    await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path / "journal"), evidence_mode="witnessed",
                                              native_binary=None if configured else str(binary),
                                              trusted_notary_key=None if configured else str(trust))
    assert len(seen["dispatch"]) == 1
    native_args = json.loads((tmp_path / "journal" / hashlib.sha256(b"refund-123").hexdigest() / "witness" / "args.json").read_text())
    assert ("--witness-ca-cert" in native_args) is configured
    if configured:
        assert native_args[native_args.index("--witness-ca-cert") + 1] == str(ca)
    if response_case != "valid":
        assert result.response is None
        assert seen["outcome"][0]["target_state"] == "unknown"
        assert "notary_attestation" not in seen["outcome"][0]
        if response_case == "proof_mismatch":
            journal = json.loads((tmp_path / "journal" / hashlib.sha256(b"refund-123").hexdigest() / "journal.json").read_text())
            assert journal["authorization"]["decision"] == "allow"
            assert journal["outcome"]["body"]["target_state"] == "unknown"
            assert len(seen["prepare"]) == len(seen["outcome"]) == 1
    else:
        assert result.response["status"] == 201
        assert seen["outcome"][0]["notary_attestation"] == {}
        assert seen["outcome"][0]["evidence_bundle_sha256"] == "sha256:" + hashlib.sha256(b"{}").hexdigest()


def test_changed_local_witness_ca_fails_before_dispatch(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    trust = tmp_path / "notary.json"
    trust.write_text(json.dumps({"alg": 2, "data": list(key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint))}))
    binary = tmp_path / "helper"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o700)
    workspace = tmp_path / "witness" / "ws_1"
    workspace.mkdir(parents=True)
    ca = workspace / "witness-ca.pem"
    ca.write_bytes(b"original certificate")
    (workspace / "config.json").write_text(json.dumps({
        "version": 1, "workspaceId": "ws_1", "nativeBinaryPath": str(binary),
        "trustedNotaryKeyPath": str(trust), "fingerprintSha256": _notary_fingerprint(trust),
        "trustedWitnessCaPath": str(ca),
        "witnessCaFingerprintSha256": hashlib.sha256(ca.read_bytes()).hexdigest(),
    }))
    monkeypatch.setenv("ALLOWLY_CONFIG_DIR", str(tmp_path))
    ca.write_bytes(b"changed certificate")
    with pytest.raises(AllowlyProtocolError, match="witness CA differs"):
        _witness_files("ws_1", None, None)


@pytest.mark.asyncio
async def test_missing_witness_setup_can_be_retried_after_install(tmp_path, monkeypatch):
    monkeypatch.setenv("ALLOWLY_CONFIG_DIR", str(tmp_path / "config"))
    def mutate(response):
        response["witness_session"] = {"trusted_notary_key_fingerprint_sha256": "0" * 64}
    with respx.mock as mock:
        seen, _ = runtime(mock, mutate=mutate)
        async with Allowly("key", base_url=BASE) as client:
            with pytest.raises(ValueError, match="allowly setup witness"):
                await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path / "journal"), evidence_mode="witnessed")
    assert not seen["dispatch"] and not (tmp_path / "journal").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("config_error", ["workspace", "fingerprint"])
async def test_witness_setup_is_bound_to_workspace_and_confirmed_key(tmp_path, monkeypatch, config_error):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    trust = tmp_path / "notary.json"
    trust.write_text(json.dumps({"alg": 2, "data": list(key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint))}))
    binary = tmp_path / "helper"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o700)
    config = tmp_path / "config" / "witness" / "ws_1" / "config.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"version": 1, "workspaceId": "ws_2" if config_error == "workspace" else "ws_1",
                                  "nativeBinaryPath": str(binary), "trustedNotaryKeyPath": str(trust),
                                  "fingerprintSha256": "0" * 64 if config_error == "fingerprint" else _notary_fingerprint(trust)}))
    monkeypatch.setenv("ALLOWLY_CONFIG_DIR", str(tmp_path / "config"))
    def mutate(response):
        response["witness_session"] = {"trusted_notary_key_fingerprint_sha256": _notary_fingerprint(trust)}
    with respx.mock as mock:
        seen, _ = runtime(mock, mutate=mutate)
        async with Allowly("key", base_url=BASE) as client:
            expected_error = ValueError if config_error == "workspace" else AllowlyProtocolError
            with pytest.raises(expected_error):
                await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path / "journal"), evidence_mode="witnessed")
    assert not seen["dispatch"] and not (tmp_path / "journal").exists()


@pytest.mark.asyncio
async def test_receipt_finalization_checks_hash_linkage_without_provider(tmp_path, monkeypatch):
    monkeypatch.setattr("allowly.execution._provider_send", lambda *a: OBSERVED)
    monkeypatch.setattr("allowly.verify.verify_receipt", lambda *a, **k: None)
    with respx.mock as mock:
        seen, _ = runtime(mock)
        async with Allowly("key", base_url=BASE) as client:
            result = await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
            receipt = {"receipt_id": "rcp_1", "decision": "allow", "action": "billing.refund", "authorization_id": "auth_1",
                       "context": {"execution": {"approval_sha256": seen["approved"]["approval_sha256"]}}}
            route = mock.get(BASE + "/v1/receipts/rcp_1").mock(return_value=httpx.Response(200, json={"status": "signed", "receipt": receipt}))
            package = await complete_execution_evidence(client, result.operation_dir, public_keys=[], expected_workspace_id="ws_1")
            assert package["decision_receipt_verified"] is True
            receipt["context"]["execution"]["approval_sha256"] = "sha256:" + "0" * 64
            route.mock(return_value=httpx.Response(200, json={"status": "signed", "receipt": receipt}))
            with pytest.raises(AllowlyProtocolError):
                await complete_execution_evidence(client, result.operation_dir, public_keys=[], expected_workspace_id="ws_1")
    assert len(seen["dispatch"]) == 1


def test_approval_expiry_during_tls_prevents_request(monkeypatch):
    descriptor, headers = _request(URL, PARAMS["method"], PARAMS["headers"], PARAMS["body"])
    approval = {"issued_at": "2000-01-01T00:00:00Z", "expires_at": "2999-01-01T00:00:00Z"}
    class Socket:
        def settimeout(self, value): pass
        def connect(self, value): pass
        def close(self): pass
    class TLS:
        def wrap_socket(self, raw, **kwargs):
            approval["expires_at"] = "2001-01-01T00:00:00Z"
            return raw
    class Connection:
        def __init__(self, *args, **kwargs): pass
        def request(self, *args, **kwargs): pytest.fail("expired approval sent provider bytes")
        def close(self): pass
    monkeypatch.setattr("allowly.execution.socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("1.1.1.1", 443))])
    monkeypatch.setattr("allowly.execution.socket.socket", lambda *a: Socket())
    monkeypatch.setattr("allowly.execution.ssl.create_default_context", TLS)
    monkeypatch.setattr("allowly.execution.http.client.HTTPSConnection", Connection)
    with pytest.raises(AllowlyProtocolError, match="not currently valid"):
        _provider_send(descriptor, headers, PARAMS["body"], 1, approval)


@pytest.mark.asyncio
async def test_disk_failure_after_effect_retains_unknown_report(tmp_path, monkeypatch):
    sends = []
    monkeypatch.setattr("allowly.execution._provider_send", lambda *a: sends.append(1) or OBSERVED)
    def save(path, value):
        if path.name == "response.json":
            raise OSError("disk full")
        _save(path, value)
    monkeypatch.setattr("allowly.execution._save", save)
    with respx.mock as mock:
        seen, _ = runtime(mock)
        async with Allowly("key", base_url=BASE) as client:
            with pytest.raises(OSError):
                await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))
            folder = tmp_path / hashlib.sha256(b"refund-123").hexdigest()
            recovered = await client.flush_execution_outcome(str(folder))
    assert recovered.status == "unknown" and len(sends) == 1
    assert len(seen["dispatch"]) == 1


@pytest.mark.asyncio
async def test_remote_outage_ignores_check_fail_open_setting(tmp_path, monkeypatch):
    monkeypatch.setattr("allowly.execution._provider_send", lambda *a: pytest.fail("provider called"))
    with respx.mock as mock:
        mock.post(BASE + "/v1/execute").mock(side_effect=httpx.ConnectError("API down"))
        async with Allowly("key", base_url=BASE, fallback_by_action={"billing.refund": "fail_open"}) as client:
            with pytest.raises(httpx.ConnectError):
                await client.execute_http(URL, **PARAMS, storage_dir=str(tmp_path))


@pytest.mark.asyncio
async def test_inline_authorization_keeps_exact_executable_grant():
    from allowly import ActionEntry, ExecutableOperationGrant
    grant = ExecutableOperationGrant("exe_1", "stripe", "stripe.refunds.create", "r1", "sha256:" + "a" * 64, "witnessed")
    with respx.mock as mock:
        route = mock.post(BASE + "/v1/authorizations").mock(return_value=httpx.Response(201, json={
            "authorization_id": "auth_1", "created_at": "2026-09-27T00:00:00Z", "expires_at": "2027-01-01T00:00:00Z",
            "requires_confirm_for": [], "requires_escalation_for": [], "requires_deny_for": [], "escalation_targets": {},
            "receipt": {"status": "pending", "receipt_id": "rcp_1", "ready_at_estimate": None, "url": BASE + "/v1/receipts/rcp_1"}}))
        async with Allowly("key", base_url=BASE) as client:
            await client.authorizations.create(user_id="u1", agent_id="a1", expires_at="2027-01-01T00:00:00Z",
                                               actions=[ActionEntry("billing.refund", executable_operations=[grant])])
    actual = json.loads(route.calls[0].request.content)["actions"][0]["executable_operations"][0]
    assert actual["minimum_evidence_mode"] == "witnessed" and actual["definition_fingerprint"] == grant.definition_fingerprint
