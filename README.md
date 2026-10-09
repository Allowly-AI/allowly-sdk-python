# Allowly Python SDK

Async Python client for the Allowly runtime API.

## Confirmation receipts

Confirmation responses expose `receipt`, a pending resolution envelope or
`None` for an older runtime/replay. The decision is `approved` or
`not_approved`; `denied_by_user` remains accepted for older runtimes. Poll
`client.receipts.fetch_signed(response.receipt.receipt_id)` when a receipt is
present, then verify it with your configured workspace and trusted keys.
The signature authenticates the recorded client report, not a named human's
identity or approval. Resolution does not dispatch an action. A standalone
Check integration re-checks with its original authorization; native Execute
continues its saved operation as described below.

SDK 0.7.0 requires `allowly-receipt-format>=4.3.1,<5.0.0` from PyPI through
the `verifier` extra to verify `confirmation.resolve` receipts on wire
format 4. Install `allowly[verifier]` when you need local verification.
Native continuation requires a runtime that supports
`/v1/executions/{operation_id}/continue`; upgrading this SDK does not deploy
that runtime. Earlier SDK packages do not gain these methods.

## Resolution webhook setup and verification

Use a setup/CLI credential to manage the workspace's one existing callback:

```python
import os
from allowly import Allowly, verify_resolution_webhook

async with Allowly(api_key=os.environ["ALLOWLY_SETUP_KEY"]) as setup:
    configured = await setup.resolution_webhook.configure(
        "https://customer.example/allowly-resolution"
    )
    signing_secret = configured.signing_secret  # Store privately for the receiver.
    configuration = await setup.resolution_webhook.get()
    deliveries = await setup.resolution_webhook.deliveries()
    # rotated = await setup.resolution_webhook.rotate()
    # await setup.resolution_webhook.disable()

event = verify_resolution_webhook(
    raw_body, request_headers,
    signing_secret=os.environ["ALLOWLY_RESOLUTION_SIGNING_SECRET"],
    expected_workspace_id=os.environ["ALLOWLY_WORKSPACE_ID"],
)
```

Runtime keys cannot manage callbacks. Only configure/rotate return the signing
secret; configuration reads omit it. Coordinate changes with the existing
receiver: URL changes, re-enabling, and rotation cancel queued older-version
events. The delivery list contains at most 20 summaries, without raw payloads
or secrets. These methods use the existing API contract; no new endpoint is added.

Preserve the exact raw request bytes before JSON parsing and reject duplicate
signature headers at your HTTP boundary. Verification authenticates the fixed
HMAC-SHA256 [Standard Webhooks profile](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md)
with a 300-second attempt-timestamp tolerance and validates
the configured workspace and bounded event fields. It does not prove a human's
identity or verify the referenced receipts. Store event IDs durably before
acknowledging; duplicate deliveries must not become duplicate business jobs.

Select the saved job by its trusted workspace, review kind/ID, and original
source receipt ID. A null or mismatched source cannot select a native Execute
job. Read current prompt status, then wake `continue_http_execution` with the
unchanged original operation and arguments. A verified callback or an approved
status is not dispatch permission; Continue validates current permission before
one claim. Do not run an extra enforcing Check before native continuation.
For standalone Check integrations, perform the existing fresh Check instead.
Rejected, invalid, mismatched, or unavailable review never permits dispatch.

MCP middleware ships inside this SDK: `pip install 'allowly[fastmcp]'`, then `from allowly.mcp import AllowlyMCPMiddleware`. In TypeScript, it lives in the separate `@allowly/mcp` package.

## Subject authorization pattern

Do not send raw user/customer PII to Allowly receipts unless you intentionally
want it in your audit trail. Create one authorization per subject, store the
returned authorization ID in your own app database, and use that ID for later checks.

```python
import asyncio
import os

from allowly import Allowly


async def main() -> None:
    async with Allowly(
        api_key=os.environ["ALLOWLY_API_KEY"],
        base_url=os.getenv("ALLOWLY_API_URL", "https://api.allowly.ai"),
    ) as allowly:
        # Your app creates a stable internal subject ID.
        subject_id = "subject_abc123"

        # Store this in your app table, for example:
        # allowly_authorizations(subject_id, policy_id, allowly_authorization_id, status)
        authorization = await allowly.authorizations.create(
            user_id=f"subject:{subject_id}",
            policy_id="research_agent",
            metadata={"source": "import"},
        )

        # Before the agent acts, check whether this action is allowed.
        decision = await allowly.check(
            authorization_id=authorization.authorization_id,
            actions=["web.search"],
            resource=f"subject:{subject_id}",
            context={"stage": "research"},
        )

    if decision.results["web.search"].decision != "allow":
        raise RuntimeError("Action is not authorized")


asyncio.run(main())
```

## Allowly agent identity

Create the agent in the dashboard, then run `allowly agent enroll <exact-agent-id>`
from the Allowly CLI. Store the resulting private credential on the trusted
machine that runs the agent. Define its policy, then create a **new authorization**
for that agent. CLI-only setups can still create a live policy before enrollment.
The credential identifies the agent; the authorization and policy still decide
what it may do. The workspace runtime API key is still required.

```python
import os
from allowly import Allowly, NativeAgentCredential

credential = NativeAgentCredential.from_file("/secure/path/agent.json")
allowly = Allowly(
    api_key=os.environ["ALLOWLY_API_KEY"],
    agent_token_supplier=credential.token,
)

decision = await allowly.check(
    authorization_id="auth_...",
    actions=["order.submit"],
)
```

The SDK signs a fresh 60-second token for each request. The private key remains
in your runtime; do not commit or log the credential file. The CLI registers
only its public key with Allowly.

## Existing Auth0 agent identity

For an authorization bound to an Auth0 machine identity, supply the short-lived
access token separately from the Allowly runtime key. A token supplier runs for
each check or execution. Use your existing OAuth client library to fetch and
cache Auth0 tokens; keep the client secret outside this SDK. New self-service
Auth0 setup is unavailable. Contact us to add your own identity provider.

```python
from datetime import datetime, timezone

allowly = Allowly(
    api_key=os.environ["ALLOWLY_API_KEY"],
    agent_token_supplier=get_auth0_agent_token,
)

decision = await allowly.check(
    authorization_id="auth_...",
    actions=["order.submit"],
    client_timestamp=datetime.now(timezone.utc),
)
```

The SDK sends the agent token in the `X-Allowly-Agent-Token` header for checks
and customer-hosted execution calls. Provider credentials stay in your runtime.

## Receipt acknowledgments

After fetching the complete signed receipt, the verifier extra can calculate
the canonical receipt hash for an acknowledgment:

```python
from allowly.verify import hash_seal_value

ack = await allowly.acknowledge_receipt(
    receipt_id=signed_receipt["receipt_id"],
    receipt_sha256=hash_seal_value(signed_receipt),
    client_timestamp=datetime.now(timezone.utc),
    idempotency_key=f"ack:{signed_receipt['receipt_id']}",
)

# Retrieve the same acknowledgment later by its returned ID.
ack = await allowly.get_receipt_acknowledgment(
    signed_receipt["receipt_id"],
    ack.acknowledgment_id,
)
```

Client timestamps are customer-reported and must include a timezone. They do
not replace the timestamp issued by Allowly in a receipt.

## Execute from customer code

Enable an app in **Settings → Executables**, then bind its exact operation to
the policy action. Enabling an app alone does not grant permission. Install
`allowly[verifier]` for the customer execution helper.

```python
from allowly import Allowly

async with Allowly(api_key=ALLOWLY_RUNTIME_KEY, agent_token=AGENT_TOKEN) as allowly:
    result = await allowly.execute_http(
        "https://api.stripe.com/v1/refunds",
        operation_id="refund-order-123",  # stable across retries
        authorization_id="auth_...",
        enabled_executable_id="exe_...",
        catalog_operation_id="stripe.refunds.create",
        action="billing.refund",
        method="POST",
        headers={"authorization": f"Bearer {STRIPE_KEY}",
                 "content-type": "application/x-www-form-urlencoded"},
        body="payment_intent=pi_example&amount=2500",
        evidence_mode="receipt",
    )
    # result.response stays local; Allowly receives commitments and outcome metadata.
```

Use the operation ID from the catalog returned by your deployment; the initial
catalog contains documentation-checked candidates, not a live compatibility
guarantee. Policy inputs such as `policy_input={"context": {"amount": 2500}}`
are customer-reported. Neither a receipt nor the compact witness record proves
that those inputs match the meaning of the provider body.

The helper calls remote `/v1/execute`, validates the approval, and claims dispatch
once before sending locally. It fails closed on unavailable checks and stops on
deny. Confirmation and escalation return `status="waiting_for_review"` with a
typed `review` containing its kind, opaque ID, source receipt ID, and expiry.
No provider request is sent while review is pending. Low-level customer methods are `prepare_execution`,
`continue_execution`, `claim_execution_dispatch`, `get_execution_witness_token`,
`report_execution_outcome`, and `get_execution`.

Read the review without running another Check or creating a receipt:

```python
if result.execution.review.kind == "confirm":
    status = await allowly.confirmations.get_status(result.execution.review.id)
else:
    status = await allowly.escalations.get_status(result.execution.review.id)
```

These typed responses return the recorded choice, source/resolution receipt IDs,
and current grant lifecycle. Use the opaque `cnf_` monitor ID for confirmation,
never its bearer nonce. `status="approved"` is only a wake-up signal: continue
the saved operation so Allowly validates current permission. Null or unknown
evidence is not an allow. `await allowly.readiness()` reads `/readyz`; readiness
is not permission, and network/protocol errors raise rather than returning an allow.

Allowly receives the origin, path, query string and policy inputs. Header values
and body bytes are committed by hash. Keep provider credentials in local headers,
not in the URL, query string or policy context.

Keep the original URL, method, headers, body, and policy inputs in your own
durable job store. A verified approval webhook can wake that job; polling the
approval resource is another option. A webhook is not permission to send.
Continue with the **same arguments and operation ID**:

```python
result = await allowly.continue_http_execution(original_url, **original_arguments)
```

`original_arguments` must include the original `operation_id`, authorization,
executable, action, headers, body, policy inputs, evidence mode, and journal
directory. Restore credentials from your local credential store. The SDK checks
the saved request hash and sends only the original request commitments and review
binding to `/v1/executions/{operation_id}/continue`. The runtime validates the
review and current permission before the SDK claims dispatch. Still-pending
review remains waiting; rejected, expired, or revoked permission never sends.
Do not call a separate enforcing Check before continuation: continuation itself
performs the fresh evaluation, including any one-use escalation grant.

The private journal defaults to `.allowly/executions`; put it on persistent
storage and use a separate directory per workspace. It retains the original
prepare timestamp, request hash, review binding, and outcome, not raw provider
headers, request body, or confirmation bearer nonce. The initial response can
carry that nonce for your confirmation flow; do not log it. Version-1 journals and incomplete initial prepare
attempts cannot be reopened through continuation. A repeated Execute raises
`ExecutionRecoveryRequired` with its directory. Reconcile with `get_execution`
or call `flush_execution_outcome(operation_dir)` to retry a saved report. Neither
repeats the provider action. An interrupted or timed-out send may already have
acted; never generate a replacement operation ID automatically. There is no
exactly-once guarantee for arbitrary providers. If `result.outcome_pending` is
true, its API response still describes approval; `result.response` contains the
locally observed response and the journal retains the report for upload.
The Python helper also raises `ExecutionRecoveryRequired` for a duplicate
completed continuation instead of returning a cached local response. Use
`get_execution` to read the outcome; do not turn that error into another send.
Install witness setup before a witnessed Execute. A missing or invalid setup
leaves a durable pre-dispatch journal, but never claims dispatch or sends.

Run `allowly setup witness` in the Allowly CLI for each workspace that will use
witnessed execution. The default path downloads a verified precompiled Rust
helper. Use `allowly setup witness --build-from-source` to download reviewed
Allowly adapter source and build it with pinned official TLSNotary libraries.
That path needs Rust 1.95.0, Cargo, Git, Bash, and a native C build toolchain.
Both paths verify release checksums and remain blocked until reviewed
`witness-v0.1.0` assets are published and their manifest digest is pinned in the CLI.
Offline setup still accepts
`--archive FILE --sha256 HEX` or a reviewed `--helper FILE`.
The command downloads that workspace's **public** witness key, shows its locally
calculated fingerprint,
and opens the authenticated workspace key page for you to compare and confirm.
The CLI saves the confirmed fingerprint and local file paths in
`~/.allowly/witness/<workspace-id>/config.json` (or below `ALLOWLY_CONFIG_DIR`).
The SDK reads that setup automatically for the workspace in the execution
approval and checks the public key against the confirmed fingerprint on every
witnessed call. Keep this config and the public key available to the runtime
user on the machine that sends provider requests. No private witness key is
downloaded.
For a local witness with a private CA, `allowly setup witness --witness-ca-cert`
also pins that CA. The SDK checks its fingerprint before dispatch and passes it
to the helper for the witness socket only. Provider HTTPS trust is unchanged.

Set `evidence_mode="witnessed"` to request the native witness transport; a
policy can also require this mode. Existing deployments may pass both
`native_binary` and an independently provisioned `trusted_notary_key` file
explicitly. The SDK compares the configured key with the witness session and
waits for online witness admission and MPC setup before claiming dispatch. It
never silently falls back to a regular receipt. The experimental native profile
supports HTTP/1.1 over TLS 1.2, a **2 KiB complete request** and **16 KiB response**,
with UTF-8 bodies, no compression or redirect following. Unsupported responses
can be discovered after a provider action and leave an evidence gap.

Signing stays asynchronous. To assemble the Allowly side of the evidence later:

```python
from allowly import complete_execution_evidence

package = await complete_execution_evidence(
    allowly, result.operation_dir,
    public_keys=trusted_workspace_keys, expected_workspace_id="ws_...",
)
```

This verifies the decision receipt signature and its exact approval hash. For
witnessed execution, independently run the native `verify-execute` command on
the full customer-held presentation using the trusted notary key. The compact
record held by Allowly proves the notary's approval reference; full request-byte
verification needs the customer presentation. Keep that presentation private:
it includes provider credentials and response data. HTTP status is not proof of
business completion. Native transport setup and limitations are documented in
the workspace's `allowly_mcp/witness/EXECUTE.md`. That same repository owns the
Allowly-hosted Witness Bridge source. The customer helper wraps unchanged
TLSNotary libraries pinned to `v0.1.0-alpha.15` /
`47aee45b53e06648c1b2ad3689b367b8c923fdec`. Setup does not install a second MCP
package or start the hosted witnessing socket/service.

## FastMCP identity mapping

FastMCP middleware maps policy inputs explicitly. Raw tool arguments are
available to the callback, but the middleware does not copy them into Allowly
context. Provide `trusted_user_id` from your server's authenticated session or
token.

```python
from allowly.mcp import AllowlyMCPMiddleware, MCPCheckInput

middleware = AllowlyMCPMiddleware(
    api_key=os.environ["ALLOWLY_API_KEY"],
    user_id_fn=trusted_user_id,
    authorization_id_fn=lambda user_id: authorization_id_for(user_id),
    agent_token_fn=lambda request: auth0_agent_token_for(request.fastmcp_context),
    check_input_fn=lambda request: MCPCheckInput(
        action="email.send",
        resource=f"gmail:thread:{request.arguments['thread_id']}",
        context={"recipient_domain": request.arguments["recipient_domain"]},
        client_timestamp=datetime.now(timezone.utc),
        idempotency_key=request.arguments["operation_id"],
    ),
)
mcp.add_middleware(middleware)
```

The three resolver callbacks may be synchronous or asynchronous. When an
`agent_token_fn` is configured, an error or an empty result blocks the tool
before the check. Map only the fields the policy needs; ordinary tool arguments
do not automatically satisfy policy context.

Local development against the documented Caddy endpoint requires the edge
token that Cloudflare injects for public traffic. Pass it explicitly:

```python
Allowly(
    api_key=os.environ["ALLOWLY_API_KEY"],
    base_url="http://localhost:8443",
    dangerously_allow_insecure_base_url=True,
    edge_token=os.environ["ALLOWLY_EDGE_TOKEN"],
)
```

The token is only sent when provided; never set it for the public API.

## Send JSON through a private SEAL webhook

Copy the private URL from the dashboard's **SEAL** page. The URL is the only
credential this client sends; it does not use an ordinary API key.

```python
import asyncio
import os

from allowly import SealWebhookClient


async def seal_event(raw_json: str, event_id: str):
    async with SealWebhookClient(os.environ["ALLOWLY_SEAL_WEBHOOK_URL"]) as webhook:
        delivery = await webhook.send(
            raw_json,
            idempotency_key=event_id,
            type="invoice",
            reference="INV-1042",
            statement="Approved for payment",
        )
        while delivery.status in {"received", "signing"}:
            await asyncio.sleep(1)
            delivery = await webhook.get_delivery(delivery.attempt_id)
        if delivery.status != "sealed":
            raise RuntimeError(delivery.error_code or "SEAL delivery failed")
        return delivery.receipt, await webhook.get_keys()
```

The webhook processes your JSON to create a fingerprint; Allowly stores the
fingerprint and signed receipt. Keep the original record in your workflow.
Receipt details are sent in the three explicit `Allowly-Seal-*` headers. Their
values must use printable ASCII, may contain interior spaces, and must not have
leading or trailing whitespace. The client rejects invalid values instead of
changing them. Direct API metadata still supports its existing Unicode values.
When a signed receipt is present, the client returns its signed metadata and
rejects a conflicting top-level delivery projection.
Treat the full URL like a password and keep it out of logs, tickets, and source
control. Regenerating or disabling it stops the old URL. Delivery associations
and status remain available for 7 days; preserve signed receipts and keys under
your own retention policy. With no `idempotency_key`, retrying after a lost
response can create another seal.

## Seal a JSON record with local hashing

`seal` hashes strict raw JSON in your process, sends only its digest to Allowly,
and waits for the full signed receipt. Generate and persist `request_id` in
your workflow so a retry recovers the same seal:

```python
import uuid

request_id = str(uuid.uuid4())
sealed = await allowly.seal(
    raw_json,
    request_id=request_id,
    metadata={"source": "invoice-workflow"},
)
save_beside_record(sealed.receipt)
```

Use `seal_value(parsed_json, ...)` only when the original JSON text is no
longer available. A parsed value cannot reveal duplicate object names or the
original number spelling, so `seal` is the safer input boundary.

To verify later, preserve the authenticated `workspace_id` response and a key
document fetched from Allowly through an authenticated or previously trusted
source. Keep the signature and record checks separate:

```python
from allowly.verify import load_keys_from_json, verify_seal_json

result = verify_seal_json(
    raw_json,
    sealed.receipt,
    load_keys_from_json(keys_doc),
    expected_workspace_id=sealed.workspace_id,
    trusted_key_fingerprints=configured_key_fingerprints,
)
assert result.signature_verified
assert result.record_matches
```

Inline authorization creation requires `agent_id`, `actions`, and `expires_at`.
Policy-based creation uses `policy_id` instead and rejects inline action or
decision-override fields.

Unavailable checks fail closed unless an action is explicitly mapped to
`"fail_open"` with `fallback_by_action`. Unmapped actions always fail closed.
Identity-enabled checks always fail closed, including token supplier failures
and `identity_verification_unavailable` responses.

For actions that need third-party approval, define the escalation rule on the
agent policy, create the authorization from that `policy_id`, and then resolve
returned escalation results with
`await allowly.escalations.approve(escalation_id, resolved_by="manager:123")`
or `reject(...)`, then re-check before running the action.

Read a confirmation or escalation without resolving it:

```python
# confirmation_id comes from a confirm check result. It is not confirm_nonce.
confirmation = await allowly.confirmations.get(confirmation_id)
escalation = await allowly.escalations.get(escalation_id)
print(confirmation.status, confirmation.authority_status)
print(escalation.status, escalation.authority_status)
```

The released `get` names remain aliases of `get_status`; both return the same
typed status object. `ConfirmationStatusResponse` and `EscalationStatusResponse`
are aliases of the existing `ConfirmationStatus` and `EscalationStatus` types.
Each read makes one authenticated request. Repeat it in your application's own
bounded polling loop if needed. The prompt `status` is `pending`, `approved`,
`rejected`, `expired`, or `unknown`; `unknown` means a legacy record does not
show the choice. An approved choice stays approved after its grant expires,
is revoked, or (for escalations) is consumed. `authority_status="available"`
is a lifecycle snapshot, not permission. For standalone Check integrations,
make a fresh `allowly.check(...)` with the original authorization and execute
only an `allow`. For native Execute, continue the saved original operation;
do not insert an extra enforcing Check. These reads never execute actions,
consume approval, or create receipts. Nullable receipt IDs refer to existing
records. Older check responses may omit `confirmation_id`.

If you need lookup by email later, import `from_email` from
`allowly.identifiers` and store `from_email(email, pepper=APP_PII_PEPPER)`.
The helper trims and lowercases only, prefixes the result with `email_hmac:v1`,
and never sends the raw email or pepper to Allowly. Keep the pepper stable and
backed up; changing it changes derived user IDs. Keep raw names, emails,
documents, and profile URLs out of Allowly receipts unless those fields are
intentionally part of your audit record.

Do not add raw HTTP fallbacks in application code for APIs the SDK is missing.
Patch this SDK first, then use the typed client from the app. That keeps the
integration examples honest and makes SDK gaps visible early.

## Offline receipt verification

Install `allowly[verifier]` to hash SEAL records and verify signed receipts
locally. The 0.7.0 extra uses `allowly-receipt-format>=4.3.1,<5.0.0`, which verifies
receipt wire format 4 (the package major equals the wire format). `alg` and
`key_id` are signed top-level fields, and `signature` is the base64url string.

Wire format 4 also supports daily `receipt.checkpoint` commitments. For an
untrusted receipt bundle, pass caller-trusted key fingerprints to
`verify_receipt`; a fingerprint copied from that same bundle is not a trust
anchor.

Key-document fetching requires HTTPS by default. For the documented local
Caddy endpoint only, pass `dangerously_allow_insecure_base_url=True` and its
`edge_token` to `fetch_keys_doc`, matching the client options above.
