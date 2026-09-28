"""Customer-side HTTP execution with remote approval and durable no-resend state.

The journal holds commitments and outcomes, not provider credentials. Native
TLS evidence and the optional local response are private customer-held files.
"""
from __future__ import annotations

import asyncio
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlsplit

from .error import AllowlyProtocolError
from .types import ExecutionResponse

if TYPE_CHECKING:
    from .client import Allowly

_FORBIDDEN = {"host", "content-length", "transfer-encoding", "connection",
              "keep-alive", "te", "trailer", "upgrade", "proxy-authorization",
              "proxy-connection", "accept-encoding", "expect"}


@dataclass
class LocalExecutionResult:
    execution: ExecutionResponse
    operation_dir: str
    response: dict[str, Any] | None = None
    outcome_pending: bool = False
    decision_receipt_verified: bool = False


class ExecutionRecoveryRequired(RuntimeError):
    """The existing operation must be reconciled; it must not be sent again."""

    def __init__(self, operation_dir: Path):
        super().__init__("Operation already exists; use get_execution or flush_execution_outcome, not a new operation ID")
        self.operation_dir = str(operation_dir)


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def _save(path: Path, value: Any) -> None:
    """Replace one private file atomically, persisting it before the next effect."""
    fd, temporary = tempfile.mkstemp(prefix=".allowly-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(_json(value))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            parent = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _read(path: Path, maximum: int = 2 * 1024 * 1024) -> Any:
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise AllowlyProtocolError("execution artifact exceeds its limit")
    return json.loads(data)


def _request(url: str, method: str, headers: dict[str, str], body: str) -> tuple[dict[str, Any], dict[str, str]]:
    if not isinstance(body, str) or url != url.strip() or "\\" in url:
        raise ValueError("execute_http requires a UTF-8 string body and normalized HTTPS URL")
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if (parsed.scheme != "https" or not host or parsed.port not in (None, 443)
            or parsed.username is not None or parsed.password is not None or parsed.fragment
            or not re.fullmatch(r"[a-z0-9.-]+", host) or "." not in host):
        raise ValueError("execution destination must be a public HTTPS DNS origin on port 443")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("IP-literal execution destinations are not supported")
    method = method.upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("unsupported HTTP method")
    path, query = parsed.path or "/", parsed.query
    if any(not 0x21 <= ord(c) <= 0x7e for c in path + query):
        raise ValueError("encode the URL path and query before execution")
    for segment in path.split("/"):
        decoded = segment
        for _ in range(4):
            decoded = unquote(decoded, errors="strict")
        if (decoded in {".", ".."} or any(c in decoded for c in "/\\") or "%" in decoded
                or any(ord(c) < 0x20 or ord(c) == 0x7f for c in decoded)):
            raise ValueError("ambiguous path segment")
    normalized: dict[str, str] = {}
    for name, value in headers.items():
        name = name.lower()
        if (not re.fullmatch(r"[a-z0-9-]+", name) or name in _FORBIDDEN or name in normalized
                or not isinstance(value, str) or value != value.strip()
                or any(not 0x20 <= ord(c) <= 0x7e for c in value)):
            raise ValueError("unsafe, duplicate, or unsupported request header")
        normalized[name] = value
    if body and not normalized.get("content-type"):
        raise ValueError("a body requires a content-type header")
    encoded = body.encode("utf-8")
    if len(encoded) > 256 * 1024:
        raise ValueError("request body exceeds 256 KiB")
    descriptor = {"method": method, "origin": "https://" + host,
                  "path": path, "query": query,
                  "headers": [{"name": name, "value_sha256": _sha(b"allowly.execution.header.v1\0" + name.encode() + b"\0" + normalized[name].encode())}
                              for name in sorted(normalized)],
                  "body_sha256": _sha(encoded), "body_size": len(encoded),
                  "content_type": normalized.get("content-type")}
    return descriptor, normalized


def _validate_approval(result: ExecutionResponse, requested: dict[str, Any]) -> dict[str, Any]:
    from .verify import hash_seal_value
    approval = result.approval
    if not isinstance(approval, dict):
        raise AllowlyProtocolError("missing execution approval")
    if "sha256:" + hash_seal_value(approval) != result.approval_sha256:
        raise AllowlyProtocolError("execution approval hash does not match")
    executable = approval.get("executable", {})
    expected = {"operation_id": requested["operation_id"], "authorization_id": requested["authorization_id"],
                "action": requested["action"], "profile": "allowly.execution.approval.v1"}
    if any(approval.get(k) != v for k, v in expected.items()):
        raise AllowlyProtocolError("execution approval identity does not match")
    if (executable.get("enabled_executable_id") != requested["enabled_executable_id"]
            or executable.get("catalog_operation_id") != requested["catalog_operation_id"]
            or approval.get("policy_input_sha256") != "sha256:" + hash_seal_value(requested["policy_input"])):
        raise AllowlyProtocolError("execution approval scope does not match")
    actual = dict(approval.get("request", {}))
    provider_idempotency = actual.pop("provider_idempotency", None)
    if actual != requested["http_request"] or provider_idempotency != {"kind": "none"}:
        raise AllowlyProtocolError("execution approval request does not match")
    mode = result.effective_evidence_mode
    if (mode not in {"receipt", "witnessed"} or approval.get("evidence_mode") != mode
            or (requested["evidence_mode"] == "witnessed" and mode != "witnessed")):
        raise AllowlyProtocolError("execution evidence mode was downgraded or is invalid")
    _live(approval)
    return approval


def _live(approval: dict[str, Any]) -> None:
    try:
        issued = datetime.fromisoformat(approval["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(approval["expires_at"].replace("Z", "+00:00"))
        valid = issued <= datetime.now(timezone.utc) < expires
    except (KeyError, TypeError, ValueError):
        valid = False
    if not valid:
        raise AllowlyProtocolError("execution approval is not currently valid")


def _provider_send(descriptor: dict[str, Any], headers: dict[str, str], body: str, timeout: float, approval: dict[str, Any]) -> dict[str, Any]:
    """One DNS lookup, pinned IP, original TLS SNI, no proxies or redirects."""
    host = urlsplit(descriptor["origin"]).hostname
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
        raise ValueError("provider DNS includes a non-public address")
    family, kind, protocol, _, address = addresses[0]
    connection = http.client.HTTPSConnection(host, timeout=timeout)
    raw = socket.socket(family, kind, protocol)
    raw.settimeout(timeout)
    try:
        raw.connect(address)
        connection.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        target = descriptor["path"] + ("?" + descriptor["query"] if descriptor["query"] else "")
        _live(approval)  # DNS, TCP, or TLS setup may have consumed the remaining lease.
        connection.request(descriptor["method"], target, body=body.encode(),
                           headers={**headers, "Accept-Encoding": "identity", "Connection": "close"})
        response = connection.getresponse()
        content = response.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise ValueError("provider response exceeds 1 MiB")
        return {"status": response.status, "headers": dict(response.getheaders()),
                "body": content.decode("utf-8"), "body_bytes": len(content), "body_sha256": _sha(content)}
    finally:
        connection.close()
        raw.close()


def _observed_response(value: Any, maximum: int) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("body"), str):
        raise AllowlyProtocolError("malformed local provider response")
    status = value.get("status")
    content = value["body"].encode("utf-8")
    if (isinstance(status, bool) or not isinstance(status, int) or not 200 <= status <= 599
            or len(content) > maximum or type(value.get("body_bytes")) is not int
            or value["body_bytes"] != len(content)
            or value.get("body_sha256") not in {_sha(content), _sha(content)[7:]}):
        raise AllowlyProtocolError("local response bytes do not match its metadata")
    return {**value, "body_sha256": _sha(content)}


def _notary_fingerprint(path: Path) -> str:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = _read(path, 4096)
    if key.get("alg") != 2:
        raise ValueError("notary key must be P-256")
    public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(key["data"]))
    return hashlib.sha256(public.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)).hexdigest()


def _witness_files(
    workspace_id: str, native_binary: str | None, trusted_notary_key: str | None,
) -> tuple[str, Path, str]:
    """Resolve CLI-installed witness files and verify its locally pinned key."""
    pinned_fingerprint: str | None = None
    if native_binary is None or trusted_notary_key is None:
        if not isinstance(workspace_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", workspace_id):
            raise AllowlyProtocolError("invalid witness workspace ID")
        config_dir = Path(os.environ.get("ALLOWLY_CONFIG_DIR") or Path.home() / ".allowly")
        config_path = config_dir / "witness" / workspace_id / "config.json"
        try:
            config = _read(config_path, 4096)
        except FileNotFoundError:
            raise ValueError(f"witness setup is missing for {workspace_id}; run `allowly setup witness`") from None
        except (OSError, ValueError, UnicodeError):
            raise ValueError(f"witness setup is invalid for {workspace_id}; run `allowly setup witness`") from None
        if (not isinstance(config, dict) or type(config.get("version")) is not int
                or config["version"] != 1 or config.get("workspaceId") != workspace_id
                or not isinstance(config.get("nativeBinaryPath"), str)
                or not isinstance(config.get("trustedNotaryKeyPath"), str)
                or not isinstance(config.get("fingerprintSha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", config["fingerprintSha256"])):
            raise ValueError(f"witness setup is invalid for {workspace_id}; run `allowly setup witness`")
        native_binary = native_binary or config["nativeBinaryPath"]
        trusted_notary_key = trusted_notary_key or config["trustedNotaryKeyPath"]
        pinned_fingerprint = config["fingerprintSha256"]
    binary_path = Path(native_binary).expanduser()
    trust_path = Path(trusted_notary_key).expanduser()
    if not binary_path.is_absolute() or not trust_path.is_absolute():
        raise ValueError("witness binary and public key paths must be absolute")
    native = binary_path.resolve(strict=True)
    trust = trust_path.resolve(strict=True)
    if not native.is_file() or not os.access(native, os.X_OK):
        raise ValueError("witness binary is missing or not executable")
    if not trust.is_file():
        raise ValueError("witness public key file is missing")
    fingerprint = _notary_fingerprint(trust)
    if pinned_fingerprint is not None and fingerprint != pinned_fingerprint:
        raise AllowlyProtocolError("witness public key differs from the locally confirmed fingerprint")
    return str(native), trust, fingerprint


async def execute_http(
    client: Allowly, url: str, *, operation_id: str, authorization_id: str,
    enabled_executable_id: str, catalog_operation_id: str, action: str,
    method: str = "GET", headers: dict[str, str] | None = None, body: str = "",
    evidence_mode: str = "receipt", policy_input: dict[str, Any] | None = None,
    storage_dir: str = ".allowly/executions", agent_token: str | None = None,
    native_binary: str | None = None, trusted_notary_key: str | None = None,
    timeout: float = 30.0,
) -> LocalExecutionResult:
    """Replace a normal HTTP call with remote approval followed by local sending.

    Use a business-stable operation ID (for example the refund ID), not a fresh
    UUID per retry. Repeating this call never repeats an existing local run.
    Install ``allowly[verifier]``; witnessed calls use the CLI's confirmed
    witness setup unless both file paths are supplied explicitly.
    """
    from .verify import hash_seal_value
    if not operation_id or evidence_mode not in {"receipt", "witnessed"} or not 0 < timeout <= 150:
        raise ValueError("operation ID, evidence mode, or timeout is invalid")
    descriptor, private_headers = _request(url, method, headers or {}, body)
    policy = {"resource": None, "context": {}, "estimated_cost_micros": None, **(policy_input or {})}
    requested = {"operation_id": operation_id, "authorization_id": authorization_id,
                 "enabled_executable_id": enabled_executable_id, "catalog_operation_id": catalog_operation_id,
                 "action": action, "http_request": descriptor, "policy_input": policy,
                 "evidence_mode": evidence_mode}
    parent = Path(storage_dir).expanduser().resolve()
    folder = parent / hashlib.sha256(operation_id.encode()).hexdigest()
    if folder.exists():
        raise ExecutionRecoveryRequired(folder)
    result = await client.prepare_execution(**requested, client_timestamp=_now(),
                                            idempotency_key=operation_id, agent_token=agent_token)
    approved = result.decision == "allow" and result.status == "approved"
    approval = _validate_approval(result, requested) if approved else None
    witness_files: tuple[str, Path, str] | None = None
    if approved and result.effective_evidence_mode == "witnessed":
        assert approval is not None
        witness_files = _witness_files(approval["workspace_id"], native_binary, trusted_notary_key)
        if witness_files[2] != (result.witness_session or {}).get("trusted_notary_key_fingerprint_sha256"):
            raise AllowlyProtocolError("configured notary key differs from admitted witness")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        folder.mkdir(mode=0o700)
    except FileExistsError:
        raise ExecutionRecoveryRequired(folder) from None
    state: dict[str, Any] = {"version": 1, "operation_id": operation_id,
                             "request_sha256": "sha256:" + hash_seal_value(requested),
                             "phase": "authorized", "authorization": asdict(result)}
    journal = folder / "journal.json"
    _save(journal, state)
    if not approved:
        return LocalExecutionResult(result, str(folder))
    binding = {"approval_sha256": result.approval_sha256, "approval": approval}
    _save(folder / "approval.json", binding)
    response: dict[str, Any] | None = None
    attestation: dict[str, Any] | None = None
    bundle_sha256: str | None = None

    async def claim() -> None:
        _live(approval)
        started = _now()
        state.update(phase="dispatch_attempted", dispatch_attempted_at=started,
                     outcome={"idempotency_key": operation_id, "body": {
                         "approval_sha256": result.approval_sha256, "target_state": "unknown",
                         "dispatch_started_at": started, "completed_at": started}})
        _save(journal, state)  # An ambiguous API claim must never trigger a retry.
        claimed = await client.claim_execution_dispatch(operation_id, approval_sha256=result.approval_sha256,
                                                        agent_token=agent_token)
        if claimed.get("approval") != approval or claimed.get("effective_evidence_mode") != result.effective_evidence_mode:
            raise AllowlyProtocolError("dispatch claim differs from approval")
        _live(approval)

    if result.effective_evidence_mode == "witnessed":
        assert witness_files is not None
        native, trust, _ = witness_files
        session = result.witness_session or {}
        target = descriptor["path"] + ("?" + descriptor["query"] if descriptor["query"] else "")
        estimated = (f"{descriptor['method']} {target} HTTP/1.1\r\nHost: {urlsplit(descriptor['origin']).hostname}\r\nConnection: close\r\nAccept-Encoding: identity\r\n"
                     + "".join(f"{k}: {v}\r\n" for k, v in sorted(private_headers.items()))
                     + f"Content-Length: {len(body.encode())}\r\n\r\n" + body)
        if len(estimated.encode()) > 2048:
            raise ValueError("request exceeds the native witness 2 KiB limit")
        admission = await client.get_execution_witness_token(operation_id, approval_sha256=result.approval_sha256, agent_token=agent_token)
        for key in ("session_id", "witness_url", "trusted_notary_key_fingerprint_sha256", "native_profile"):
            if admission.get(key) != session.get(key):
                raise AllowlyProtocolError("witness admission differs from prepared session")
        if admission.get("workspace_id") != approval.get("workspace_id"):
            raise AllowlyProtocolError("witness admission workspace differs")
        output = folder / "witness"
        stdin = {**binding, "request": {"headers": private_headers, "body": body},
                 "require_dispatch_ack": True,
                 "witness": {"url": admission["witness_url"], "session_id": admission["session_id"],
                             "workspace_id": admission["workspace_id"], "admission_token": admission["admission_token"]}}
        # Never pass API/provider credentials through argv or environment.
        process = await asyncio.create_subprocess_exec(native, "prove-execute", "--output", str(output), "--trusted-key", str(trust),
                                                      stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.DEVNULL,
                                                      stderr=asyncio.subprocess.DEVNULL, env={"PATH": os.defpath})
        communication = asyncio.create_task(process.communicate(_json(stdin)))
        try:
            async def witnessed_run() -> None:
                while not (output / "witness.ready.json").exists():
                    if communication.done():
                        raise AllowlyProtocolError("witness failed before dispatch")
                    await asyncio.sleep(0.025)
                if _read(output / "witness.ready.json", 1024) != {"approval_sha256": result.approval_sha256}:
                    raise AllowlyProtocolError("witness ready gate differs from approval")
                await claim()
                _save(output / "dispatch.approved.json", {"approval_sha256": result.approval_sha256})
                await communication
            await asyncio.wait_for(witnessed_run(), timeout=150)
        except Exception:
            if state["phase"] != "dispatch_attempted":
                raise
        finally:
            if process.returncode is None:
                process.kill()
            await process.wait()
            if not communication.done():
                communication.cancel()
            await asyncio.gather(communication, return_exceptions=True)
        try:
            if (output / "response.json").exists():
                response = _observed_response(_read(output / "response.json"), 16 * 1024)
            if process.returncode == 0:
                verified = _read(output / "verified.json")
                if (verified.get("verified") is not True or verified.get("approval_sha256") != result.approval_sha256
                        or verified.get("request_binding_verification") != "verified_from_full_presentation"):
                    raise AllowlyProtocolError("native verification result differs from approval")
                attestation = _read(output / "attestation.json")
                bundle_sha256 = _sha((output / "presentation.json").read_bytes())
        except Exception:
            # Corrupt/missing local artifacts after dispatch leave a durable
            # unknown report, never a second provider call or a false proof.
            response, attestation, bundle_sha256 = None, None, None
    else:
        await claim()
        try:
            response = _observed_response(await asyncio.to_thread(_provider_send, descriptor, private_headers, body, timeout, approval), 1024 * 1024)
        except Exception:
            # Provider bytes may have left this process; never repeat the call.
            response = None
    if response is not None:
        _save(folder / "response.json", response)
    outcome = {"approval_sha256": result.approval_sha256,
               "target_state": "response_observed" if response is not None else "unknown",
               "dispatch_started_at": state["dispatch_attempted_at"], "completed_at": _now()}
    if response is not None:
        outcome.update(http_status=response["status"], response_sha256=response["body_sha256"], response_size=response["body_bytes"])
    if attestation is not None:
        outcome.update(notary_attestation=attestation, evidence_bundle_sha256=bundle_sha256)
    state.update(phase="outcome_pending", outcome={"idempotency_key": operation_id, "body": outcome})
    _save(journal, state)
    try:
        final = await flush_execution_outcome(client, str(folder), agent_token=agent_token)
    except Exception:
        return LocalExecutionResult(result, str(folder), response, outcome_pending=True)
    return LocalExecutionResult(final, str(folder), response)


async def flush_execution_outcome(client: Allowly, operation_dir: str, *, agent_token: str | None = None) -> ExecutionResponse:
    folder = Path(operation_dir).expanduser().resolve()
    state = _read(folder / "journal.json")
    if state.get("version") != 1 or not isinstance(state.get("outcome"), dict):
        raise ExecutionRecoveryRequired(folder)
    report = state["outcome"]
    result = await client.report_execution_outcome(state["operation_id"], outcome=report["body"],
                                                   idempotency_key=report["idempotency_key"], agent_token=agent_token)
    state.update(phase="complete", final_response=asdict(result))
    _save(folder / "journal.json", state)
    return result


async def complete_execution_evidence(client: Allowly, operation_dir: str, *, public_keys: list[Any], expected_workspace_id: str) -> dict[str, Any]:
    """Fetch/verify the decision receipt later, without contacting the provider.

    This verifies the Allowly half of the package. Native ``verify-execute``
    independently verifies the customer-held TLS proof and request binding.
    """
    from .verify import hash_seal_value, verify_receipt
    folder = Path(operation_dir).expanduser().resolve()
    state = _read(folder / "journal.json")
    binding = _read(folder / "approval.json")
    envelope = state["authorization"]["decision_receipt"]
    receipt = envelope["receipt"] if envelope["status"] == "signed" else await client.receipts.fetch_signed(envelope["receipt_id"])
    verify_receipt(receipt, public_keys, expected_workspace_id=expected_workspace_id)
    approval = binding["approval"]
    if ("sha256:" + hash_seal_value(approval) != binding["approval_sha256"]
            or approval.get("workspace_id") != expected_workspace_id
            or receipt.get("context", {}).get("execution", {}).get("approval_sha256") != binding["approval_sha256"]
            or receipt.get("decision") != "allow" or receipt.get("action") != approval.get("action")
            or receipt.get("authorization_id") != approval.get("authorization_id")):
        raise AllowlyProtocolError("signed decision receipt does not bind this approval")
    package = {"profile": "allowly.execution.customer_bundle.v1", **binding,
               "decision_receipt": receipt, "decision_receipt_verified": True,
               "tls_presentation": "witness/presentation.json" if approval["evidence_mode"] == "witnessed" else None,
               "tls_verification": "separate_native_verification_required" if approval["evidence_mode"] == "witnessed" else "not_requested"}
    _save(folder / "evidence-package.json", package)
    return package
