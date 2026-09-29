# Allowly Python SDK

Async Python client for the Allowly runtime API.

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

## Auth0 agent identity

For an authorization bound to an Auth0 machine identity, supply the short-lived
access token separately from the Allowly runtime key. A token supplier runs for
each check or execution. Use your existing OAuth client library to fetch and
cache Auth0 tokens; keep the client secret outside this SDK.

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
deny, confirmation, or escalation. Low-level customer methods are `prepare_execution`,
`claim_execution_dispatch`, `get_execution_witness_token`,
`report_execution_outcome`, and `get_execution`.

Allowly receives the origin, path, query string and policy inputs. Header values
and body bytes are committed by hash. Keep provider credentials in local headers,
not in the URL, query string or policy context.

The private journal defaults to `.allowly/executions`; put it on persistent
storage and use a separate directory per workspace. A repeated operation raises
`ExecutionRecoveryRequired` with its directory. Reconcile with `get_execution`
or call `flush_execution_outcome(operation_dir)` to retry a saved report. Neither
repeats the provider action. An interrupted or timed-out send may already have
acted; never generate a replacement operation ID automatically. There is no
exactly-once guarantee for arbitrary providers. If `result.outcome_pending` is
true, its API response still describes approval; `result.response` contains the
locally observed response and the journal retains the report for upload.

Run `allowly setup witness` in the Allowly CLI for each workspace that will use
witnessed execution. The command installs the Rust helper, downloads that
workspace's **public** witness key, shows its locally calculated fingerprint,
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
the workspace's `mcp-allowly_tlsnotary/EXECUTE.md`.

## FastMCP identity mapping

FastMCP middleware maps policy inputs explicitly. Raw tool arguments are
available to the callback, but the middleware does not copy them into Allowly
context.

```python
from allowly.mcp import AllowlyMCPMiddleware, MCPCheckInput

middleware = AllowlyMCPMiddleware(
    api_key=os.environ["ALLOWLY_API_KEY"],
    user_id_fn=lambda request: request.fastmcp_context.session.user_id,
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
locally. The extra uses `allowly-receipt-format>=4.2.0,<5.0.0`, which verifies
receipt wire format 4 (the package major equals the wire format). `alg` and
`key_id` are signed top-level fields, and `signature` is the base64url string.

Wire format 4 also supports daily `receipt.checkpoint` commitments. For an
untrusted receipt bundle, pass caller-trusted key fingerprints to
`verify_receipt`; a fingerprint copied from that same bundle is not a trust
anchor.

Key-document fetching requires HTTPS by default. For the documented local
Caddy endpoint only, pass `dangerously_allow_insecure_base_url=True` and its
`edge_token` to `fetch_keys_doc`, matching the client options above.
