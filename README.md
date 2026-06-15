# Allowly Python SDK

Async Python client for the Allowly runtime API.

## Subject authorization pattern

Do not send raw user/customer PII to Allowly receipts unless you intentionally
want it in your audit trail. Create one authorization per subject, store the
returned authorization ID in your own app database, and use that ID for later checks.

```python
from allowly import Allowly

allowly = Allowly(
    api_key=os.environ["ALLOWLY_API_KEY"],
    base_url=os.getenv("ALLOWLY_API_URL", "https://api.allowly.ai"),
)

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
```

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
