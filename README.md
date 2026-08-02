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

Inline authorization creation requires `agent_id`, `actions`, and `expires_at`.
Policy-based creation uses `policy_id` instead and rejects inline action or
decision-override fields.

Unavailable checks fail closed unless an action is explicitly mapped to
`"fail_open"` with `fallback_by_action`. Unmapped actions always fail closed.

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

Install `allowly[verifier]` to verify signed receipts locally. The extra uses
`allowly-receipt-format>=4.0.0,<5.0.0`, which verifies receipt wire format 4 (the package major equals the wire format). `alg` and
`key_id` are signed top-level fields, and `signature` is the base64url string.

Wire format 4 also supports daily `receipt.checkpoint` commitments. For an
untrusted receipt bundle, pass caller-trusted key fingerprints to
`verify_receipt`; a fingerprint copied from that same bundle is not a trust
anchor.

Key-document fetching requires HTTPS by default. For the documented local
Caddy endpoint only, pass `dangerously_allow_insecure_base_url=True` and its
`edge_token` to `fetch_keys_doc`, matching the client options above.
