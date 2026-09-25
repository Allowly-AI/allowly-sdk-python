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

## Auth0 agent identity and managed execution

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

execution = await allowly.execute(
    operation_id="order-123-attempt-1",
    authorization_id="auth_...",
    destination_id="dst_...",
    payload={"order": {"id": "123", "amount_micros": 1_250_000}},
    client_timestamp=datetime.now(timezone.utc),
    idempotency_key="order-123-attempt-1",
)
if execution.status == "unknown":
    execution = await allowly.get_execution("order-123-attempt-1")
```

Persist the operation ID, idempotency key, and exact payload together. Never
retry an unknown outcome under a new ID. `succeeded` reports a downstream 2xx
HTTP result; it does not prove that the destination completed its business
work. Allowly uses the destination credential stored in its registered
destination. Do not put that credential in `payload`.

Each execution response includes `request_fingerprint_profile` and the exact
`request_descriptor`. To reproduce `request_fingerprint`, calculate
`"sha256:" + hash_seal_value({"profile": profile, "descriptor": descriptor,
"payload": exact_original_payload})`; `dataclasses.asdict()` preserves the
descriptor's wire field names.

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
